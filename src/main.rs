mod config;
mod connection;
mod crypto;

use anyhow::Context;
use clap::Parser;
use log::info;
use std::path::PathBuf;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "ahpc",
    version = VERSION,
    about = "AHP Client - Azure HTTP Proxy (Rust)"
)]
struct Args {
    /// Configuration file path
    #[arg(short = 'c', long = "config", default_value = "client.json")]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    let config_data = std::fs::read_to_string(&args.config).with_context(|| {
        format!("Failed to read config file: {}", args.config.display())
    })?;

    let config: config::Config = serde_json::from_str(&config_data)
        .context("Failed to parse config JSON")?;

    config.validate()?;

    info!("AHP client version {}", VERSION);
    info!(
        "server address: {}:{}",
        config.proxy_server_address, config.proxy_server_port
    );
    info!("local address: {}:{}", config.bind_address, config.listen_port);
    info!("cipher: {}", config.cipher);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.workers)
        .enable_all()
        .build()?;

    rt.block_on(async {
        // Shutdown signal handler
        tokio::spawn(async {
            tokio::signal::ctrl_c().await.ok();
            info!("Shutting down...");
            std::process::exit(0);
        });

        connection::run_proxy(config).await
    })
}
