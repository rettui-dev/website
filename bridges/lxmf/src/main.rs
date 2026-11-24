//! `lxmf-bridge [bridge.toml]`: see the README.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use lxmf_bridge::config::{Config, read_secret};
use lxmf_bridge::lxmf::Lxmf;
use lxmf_bridge::queue::Retry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_ansi(false).with_target(false).init();
    let mut args = std::env::args().skip(1);
    let first = args.next();
    let healthcheck = first.as_deref() == Some("--healthcheck");
    let path = PathBuf::from(if healthcheck { args.next() } else { first }.unwrap_or_else(|| "bridge.toml".into()));
    match start(&path, healthcheck).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            // The reasons never hold the secret.
            eprintln!("lxmf-bridge: {why}");
            ExitCode::FAILURE
        }
    }
}

async fn start(path: &std::path::Path, healthcheck: bool) -> Result<(), String> {
    let config = Config::load(path).map_err(|e| e.to_string())?;
    if healthcheck {
        return healthy(&config).await;
    }
    let secret = read_secret(&config.secret_file, |warning| tracing::warn!("{warning}")).map_err(|e| e.to_string())?;
    let listener = TcpListener::bind(config.listen).await.map_err(|e| format!("cannot listen on {}: {e}", config.listen))?;
    let lxmf = Arc::new(Lxmf::start(&config).await?);
    let named = if config.website_recipients { ", and the addresses the website names" } else { "" };
    tracing::info!("listening on {}; {} recipient(s){named}", config.listen, config.recipients.len());
    lxmf_bridge::run(&config, secret, listener, lxmf.clone(), Retry::default(), shutdown_signal()).await;
    tracing::info!("stopping");
    lxmf.shutdown().await;
    Ok(())
}

/// Asks the running bridge for /healthz (for the container's health check, which has no curl).
async fn healthy(config: &Config) -> Result<(), String> {
    let mut address = config.listen;
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() { std::net::Ipv4Addr::LOCALHOST.into() } else { std::net::Ipv6Addr::LOCALHOST.into() });
    }
    let ask = async {
        let mut stream = TcpStream::connect(address).await.map_err(|e| e.to_string())?;
        stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n").await.map_err(|e| e.to_string())?;
        let mut answer = Vec::new();
        stream.take(1024).read_to_end(&mut answer).await.map_err(|e| e.to_string())?;
        if answer.starts_with(b"HTTP/1.1 200 ") { Ok(()) } else { Err("the bridge did not answer ok".to_string()) }
    };
    tokio::time::timeout(Duration::from_secs(4), ask).await.map_err(|_| "no answer from the bridge".to_string())?
}

/// Finishes on Ctrl-C, or on SIGTERM (what `docker stop` sends).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
