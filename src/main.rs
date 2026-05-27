mod db;
mod http;
mod matcher;
mod models;
mod notifier;
mod poller;
mod sbom;

use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cycle_de_vie=debug".into()),
        )
        .json()
        .init();

    // ── Configuration ─────────────────────────────────────────────────────────
    let port = std::env::var("PORT").unwrap_or_else(|_| "3020".to_string());
    let dashboard_url = std::env::var("DASHBOARD_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let database_url = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty());
    let poll_interval: u64 = std::env::var("POLL_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let sbom_dir = std::env::var("SBOM_DIR").unwrap_or_else(|_| "sboms".to_string());
    let syft_bin = std::env::var("SYFT_BIN").unwrap_or_else(|_| "syft".to_string());

    info!(service = "cycle-de-vie", "Starting");

    // ── Database ──────────────────────────────────────────────────────────────
    let db_pool = match database_url {
        Some(ref url) => match db::connect(url).await {
            Ok(pool) => {
                info!("Connected to PostgreSQL");
                Some(pool)
            }
            Err(e) => {
                warn!(error = %e, "Could not connect to PostgreSQL — falling back to file-based SBOM store");
                None
            }
        },
        None => {
            warn!("DATABASE_URL not set — SBOMs will be stored as local files (lost on container restart)");
            None
        }
    };

    // ── SBOM store ────────────────────────────────────────────────────────────
    let sbom_store = match &db_pool {
        Some(pool) => match sbom::SbomStore::open_with_db(pool.clone()).await {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "Failed to open DB-backed SBOM store");
                std::process::exit(1);
            }
        },
        None => match sbom::SbomStore::open(&sbom_dir) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, dir = %sbom_dir, "Failed to open file-backed SBOM store");
                std::process::exit(1);
            }
        },
    };
    info!("SBOM store ready");

    // ── Channels ──────────────────────────────────────────────────────────────
    let (cve_tx, cve_rx) = broadcast::channel(32);
    let (match_tx, match_rx) = mpsc::channel(32);
    let notification_store = notifier::new_store();

    // ── Background tasks ──────────────────────────────────────────────────────
    // 1. OSV poller — queries CVEs for every SBOM stored in the DB
    tokio::spawn(poller::run(cve_tx, Arc::clone(&sbom_store), poll_interval));

    // 2. Matcher — finds which images are affected by each CVE
    tokio::spawn(matcher::run(cve_rx, Arc::clone(&sbom_store), match_tx));

    // 3. Notifier
    tokio::spawn(notifier::run(
        match_rx,
        Arc::clone(&notification_store),
        dashboard_url,
    ));

    // ── HTTP server ───────────────────────────────────────────────────────────
    let router = http::router(
        Arc::clone(&notification_store),
        Arc::clone(&sbom_store),
        syft_bin,
    );
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
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.expect("ctrl-c handler");
    }
    info!("Shutdown signal received");
}
