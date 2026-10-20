use crate::config::Config;
use crate::crypto::{self, CipherPair};
use anyhow::Context;
use log::{debug, error};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Run the proxy, accepting connections until cancelled.
pub async fn run_proxy(config: Config, cancel: CancellationToken) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let bind_addr = format!("{}:{}", config.bind_address, config.listen_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind to {}", bind_addr))?;
    log::info!("Listening on {}", bind_addr);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (ua_socket, peer_addr) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Accept error: {}", e);
                        continue;
                    }
                };
                debug!("Accepted connection from {}", peer_addr);
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(config, ua_socket).await {
                        error!("Connection ended: {:#}", e);
                    }
                });
            }
            _ = cancel.cancelled() => {
                log::info!("Proxy shutting down (cancel requested)");
                break;
            }
        }
    }

    Ok(())
}

/// Connection-wide idle tracker shared by both forwarding directions.
///
/// The AHP server keeps a single per-connection deadline that is refreshed by
/// any read or write in either direction. Mirroring that here avoids killing a
/// long download (idle uplink) or a long upload (idle downlink) after `timeout`.
struct IdleTracker {
    start: Instant,
    last_ms: AtomicU64,
}

impl IdleTracker {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    /// Record activity in either direction.
    fn touch(&self) {
        let now_ms = self.start.elapsed().as_millis() as u64;
        self.last_ms.store(now_ms, Ordering::Relaxed);
    }

    /// How long the connection has been completely idle.
    fn idle_for(&self) -> Duration {
        let now_ms = self.start.elapsed().as_millis() as u64;
        let last_ms = self.last_ms.load(Ordering::Relaxed);
        Duration::from_millis(now_ms.saturating_sub(last_ms))
    }
}

/// Cancel the connection once both directions have been idle for `limit`.
async fn idle_watchdog(idle: Arc<IdleTracker>, limit: Duration, cancel: CancellationToken) {
    loop {
        let idle_for = idle.idle_for();
        if idle_for >= limit {
            debug!("Idle timeout after {}s", limit.as_secs());
            cancel.cancel();
            return;
        }
        tokio::time::sleep(limit - idle_for).await;
        if cancel.is_cancelled() {
            return;
        }
    }
}

async fn handle_connection(config: Arc<Config>, ua_socket: TcpStream) -> anyhow::Result<()> {
    let timeout_dur = Duration::from_secs(config.timeout);
    let cipher_kind = config
        .cipher_kind
        .context("Invalid cipher configured")?;

    // Proxied HTTP is dominated by small writes; Nagle would add latency.
    if let Err(e) = ua_socket.set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY on client socket: {}", e);
    }

    // 1. Connect to proxy server
    let proxy_addr = format!(
        "{}:{}",
        config.proxy_server_address, config.proxy_server_port
    );
    debug!("Connecting to proxy server {}", proxy_addr);
    let ps_socket = timeout(timeout_dur, TcpStream::connect(&proxy_addr))
        .await
        .with_context(|| format!("Connect timeout to {}", proxy_addr))?
        .with_context(|| format!("Failed to connect to {}", proxy_addr))?;
    if let Err(e) = ps_socket.set_nodelay(true) {
        debug!("Failed to set TCP_NODELAY on server socket: {}", e);
    }

    // 2. Generate key + IV, create cipher pair
    let key = crypto::random_bytes(cipher_kind.key_len());
    let iv = crypto::random_bytes(16);
    let CipherPair {
        mut encryptor,
        mut decryptor,
    } = crypto::create_cipher_pair(cipher_kind, &key, &iv)?;

    // 3. Build cipher_info_raw (86 bytes)
    let mut raw = [0u8; 86];
    raw[0] = b'A';
    raw[1] = b'H';
    raw[2] = b'P';
    let has_auth_key = !config.auth_key.is_empty();
    let pv: u8 = if has_auth_key { 1 } else { 0 };
    raw[3] = pv;
    if pv == 0 {
        raw[5] = cipher_kind.code();
        raw[7..7 + 16].copy_from_slice(&iv);
        raw[23..23 + key.len()].copy_from_slice(&key);
    } else {
        raw[4] = 1;
        raw[5] = cipher_kind.code();
        let h = crypto::sha256(config.auth_key.as_bytes());
        raw[6..6 + 32].copy_from_slice(&h);
        raw[38..38 + 16].copy_from_slice(&iv);
        raw[54..54 + key.len()].copy_from_slice(&key);
    }

    // 4. RSA encrypt & send cipher info
    let pub_key = crypto::parse_public_key(&config.rsa_public_key)?;
    let enc_info = crypto::rsa_encrypt(&pub_key, &raw)?;
    let (mut ua_read, mut ua_write) = ua_socket.into_split();
    let (mut ps_read, mut ps_write) = ps_socket.into_split();
    timeout(timeout_dur, ps_write.write_all(&enc_info))
        .await
        .context("Write cipher info timeout")?
        .context("Failed to write cipher info")?;
    debug!("Handshake complete, starting tunnel transfer");

    // 5. Bidirectional encrypted forwarding.
    //
    // Both directions share one idle deadline (like the server) instead of
    // timing out each read independently. EOF is propagated as a half-close;
    // the peer direction is allowed to finish delivering its data instead of
    // being aborted immediately.
    let idle = Arc::new(IdleTracker::new());
    let conn_cancel = CancellationToken::new();
    let watchdog = tokio::spawn(idle_watchdog(
        Arc::clone(&idle),
        timeout_dur,
        conn_cancel.clone(),
    ));

    let upgoing = {
        let idle = Arc::clone(&idle);
        let cancel = conn_cancel.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let n = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = ua_read.read(&mut buf) => match result {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) => {
                            debug!("UA read: {}", e);
                            break;
                        }
                    },
                };
                idle.touch();
                encryptor.encrypt(&mut buf[..n]);

                let write_result = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = ps_write.write_all(&buf[..n]) => result,
                };
                if let Err(e) = write_result {
                    debug!("PS write: {}", e);
                    break;
                }
                idle.touch();
            }
            let _ = ps_write.shutdown().await;
        })
    };

    let downgoing = {
        let idle = Arc::clone(&idle);
        let cancel = conn_cancel.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let n = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = ps_read.read(&mut buf) => match result {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) => {
                            debug!("PS read: {}", e);
                            break;
                        }
                    },
                };
                idle.touch();
                decryptor.decrypt(&mut buf[..n]);

                let write_result = tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = ua_write.write_all(&buf[..n]) => result,
                };
                if let Err(e) = write_result {
                    debug!("UA write: {}", e);
                    break;
                }
                idle.touch();
            }
            let _ = ua_write.shutdown().await;
        })
    };

    // Wait for both halves instead of aborting the peer on the first EOF:
    // the remaining direction may still have response bytes in flight.
    let _ = tokio::join!(upgoing, downgoing);
    watchdog.abort();

    Ok(())
}
