mod http;
mod matcher;
mod models;
mod notifier;
mod poller;
mod store;

use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

#[tokio::main]
async fn main() {
    // Load .env file if present (ignored in production where env vars are injected directly)
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cycle_de_vie=debug".into()),
        )
        .json()
        .init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "3020".to_string());
    let dashboard_url = std::env::var("DASHBOARD_URL").ok().filter(|s| !s.is_empty());
    let poll_interval: u64 = std::env::var("POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let whitelist_path = std::env::var("WHITELIST_PATH")
        .unwrap_or_else(|_| "config/whitelist".to_string());

    info!(service = "cycle-de-vie", "Service starting");

    let whitelist = match store::WhitelistStore::load(&whitelist_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!(error = %e, "Failed to load whitelist");
            std::process::exit(1);
        }
    };

    info!(count = whitelist.images().len(), "Whitelist loaded");
    for image in whitelist.images() {
        info!(image = %image.name, packages = image.sbom.packages.len(), "Registered image");
    }

    let (cve_tx, cve_rx) = broadcast::channel(32);
    let (match_tx, match_rx) = mpsc::channel(32);
    let notification_store = notifier::new_store();

    tokio::spawn(poller::run(cve_tx, Arc::clone(&whitelist), poll_interval));
    tokio::spawn(matcher::run(cve_rx, Arc::clone(&whitelist), match_tx));
    tokio::spawn(notifier::run(
        match_rx,
        Arc::clone(&notification_store),
        dashboard_url,
    ));

    let router = http::router(Arc::clone(&whitelist), Arc::clone(&notification_store));
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await.unwrap();
    info!(addr = %addr, "HTTP server listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    info!("Shutdown complete");
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
    }
    info!("Shutdown signal received");
}
