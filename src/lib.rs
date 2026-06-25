pub mod config;
pub mod connection;
pub mod crypto;

use anyhow::Context;
use config::Config;
use log::info;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::Mutex;
use tokio_util::sync::CancellationToken;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Proxy handle for C FFI ──

#[allow(dead_code)]
struct ProxyHandle {
    runtime: tokio::runtime::Runtime,
    cancel: CancellationToken,
}

// Safety: Runtime is Send + Sync, Mutex provides Sync
unsafe impl Send for ProxyHandle {}
unsafe impl Sync for ProxyHandle {}

static STATE: Mutex<Option<ProxyHandle>> = Mutex::new(None);

// ── C FFI ──

/// Start the proxy with a JSON config string.
///
/// Returns:
/// -  0 = started successfully
/// - -1 = config parse/validation error, or runtime creation failure
/// - -2 = proxy already running
#[no_mangle]
pub extern "C" fn ahpc_start(config_json: *const c_char) -> i32 {
    // Initialize logger on first call so log::error!() output appears on stderr
    let _ = env_logger::try_init();

    let json_str = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let config: Config = match serde_json::from_str(json_str) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to parse config JSON: {}", e);
            return -1;
        }
    };

    if let Err(e) = config.validate() {
        log::error!("Config validation failed: {}", e);
        return -1;
    }

    let mut state = STATE.lock().unwrap();
    if state.is_some() {
        log::warn!("Proxy already running");
        return -2;
    }

    let cancel = CancellationToken::new();
    let cancel_for_spawn = cancel.clone();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.workers)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("Failed to create Tokio runtime: {}", e);
            return -1;
        }
    };

    // Spawn the proxy task on the runtime
    runtime.spawn(async move {
        if let Err(e) = connection::run_proxy(config, cancel_for_spawn).await {
            log::error!("Proxy exited with error: {:#}", e);
        }
    });

    *state = Some(ProxyHandle { runtime, cancel });

    info!("AHP client v{} started", VERSION);
    0
}

/// Stop the proxy gracefully.
///
/// Returns:
/// -  0 = stopped successfully
/// - -3 = proxy not running
#[no_mangle]
pub extern "C" fn ahpc_stop() -> i32 {
    let mut state = STATE.lock().unwrap();
    let handle = match state.take() {
        Some(h) => h,
        None => {
            log::warn!("Proxy not running");
            return -3;
        }
    };

    // Cancel signals the accept loop to exit
    handle.cancel.cancel();
    // Dropping the runtime cancels all active connection tasks
    drop(handle);

    info!("AHP client stopped");
    0
}

/// Check proxy status.
///
/// Returns 1 if running, 0 if stopped.
#[no_mangle]
pub extern "C" fn ahpc_status() -> i32 {
    let state = STATE.lock().unwrap();
    if state.is_some() { 1 } else { 0 }
}

// ── Rust API (for CLI binary / testing) ──

/// Run the proxy with a JSON config string, blocking until Ctrl+C is received.
pub fn run_proxy_from_json(json: &str) -> anyhow::Result<()> {
    let config: Config =
        serde_json::from_str(json).context("Failed to parse config JSON")?;
    config.validate()?;

    info!("AHP client version {}", VERSION);
    info!(
        "server address: {}:{}",
        config.proxy_server_address, config.proxy_server_port
    );
    info!("local address: {}:{}", config.bind_address, config.listen_port);
    info!("cipher: {}", config.cipher);

    let cancel = CancellationToken::new();
    let cancel_ctrl_c = cancel.clone();

    // Handle Ctrl+C in a separate thread
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(tokio::signal::ctrl_c()).ok();
        info!("Shutting down...");
        cancel_ctrl_c.cancel();
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.workers)
        .enable_all()
        .build()?;

    rt.block_on(async { connection::run_proxy(config, cancel).await })
}
