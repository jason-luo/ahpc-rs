use crate::config::{CipherKind, Config};
use crate::crypto::{self, CipherPair};
use anyhow::Context;
use log::{debug, error};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

pub async fn run_proxy(config: Config) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let bind_addr = format!("{}:{}", config.bind_address, config.listen_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind to {}", bind_addr))?;
    log::info!("Listening on {}", bind_addr);

    loop {
        let (ua_socket, peer_addr) = match listener.accept().await {
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
}

async fn handle_connection(config: Arc<Config>, ua_socket: TcpStream) -> anyhow::Result<()> {
    let timeout_dur = Duration::from_secs(config.timeout);
    let cipher_kind = CipherKind::parse(&config.cipher).context("Invalid cipher configured")?;

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

    // 5. Bidirectional encrypted forwarding
    let mut upgoing = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let n = match timeout(timeout_dur, ua_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    debug!("UA read: {}", e);
                    break;
                }
                Err(_) => {
                    debug!("UA read timeout");
                    break;
                }
            };
            encryptor.encrypt(&mut buf[..n]);
            if let Err(e) = timeout(timeout_dur, ps_write.write_all(&buf[..n])).await {
                debug!("PS write: {}", e);
                break;
            }
        }
        let _ = ps_write.shutdown().await;
    });

    let mut downgoing = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let n = match timeout(timeout_dur, ps_read.read(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    debug!("PS read: {}", e);
                    break;
                }
                Err(_) => {
                    debug!("PS read timeout");
                    break;
                }
            };
            decryptor.decrypt(&mut buf[..n]);
            if let Err(e) = timeout(timeout_dur, ua_write.write_all(&buf[..n])).await {
                debug!("UA write: {}", e);
                break;
            }
        }
        let _ = ua_write.shutdown().await;
    });

    tokio::select! {
        _ = &mut upgoing => { downgoing.abort(); }
        _ = &mut downgoing => { upgoing.abort(); }
    }
    Ok(())
}
