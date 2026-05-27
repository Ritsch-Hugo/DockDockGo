mod db;
mod http;
mod matcher;
mod models;
mod notifier;
mod poller;
mod sbom;
mod store;

use std::sync::Arc;
use std::time::Duration;
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
    let port           = std::env::var("PORT").unwrap_or_else(|_| "3020".to_string());
    let dashboard_url  = std::env::var("DASHBOARD_URL").ok().filter(|s| !s.is_empty());
    let database_url   = std::env::var("DATABASE_URL").ok().filter(|s| !s.is_empty());
    let poll_interval: u64 = std::env::var("POLL_INTERVAL_SECS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(60);
    let whitelist_path = std::env::var("WHITELIST_PATH")
        .unwrap_or_else(|_| "config/whitelist".to_string());
    // Directory where per-image SBOM JSON files are stored.
    let sbom_dir       = std::env::var("SBOM_DIR")
        .unwrap_or_else(|_| "sboms".to_string());
    // Path/name of the Syft executable.
    let syft_bin       = std::env::var("SYFT_BIN")
        .unwrap_or_else(|_| "syft".to_string());
    // How often (seconds) to regenerate SBOMs for all whitelisted images.
    // 0 = disabled (generate once on startup for missing images, then stop).
    let sbom_refresh: u64 = std::env::var("SBOM_REFRESH_INTERVAL_SECS")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(86_400); // 24 h

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

    // ── Whitelist ─────────────────────────────────────────────────────────────
    let whitelist = match store::WhitelistStore::load(&whitelist_path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!(error = %e, path = %whitelist_path, "Failed to load whitelist");
            std::process::exit(1);
        }
    };
    info!(count = whitelist.images().len(), path = %whitelist_path, "Whitelist loaded");

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
    let (cve_tx, cve_rx)   = broadcast::channel(32);
    let (match_tx, match_rx) = mpsc::channel(32);
    let notification_store  = notifier::new_store();

    // ── Background tasks ──────────────────────────────────────────────────────
    // 1. SBOM generation — fills missing SBOMs at startup, then refreshes periodically
    {
        let store     = Arc::clone(&whitelist);
        let sbom_st   = Arc::clone(&sbom_store);
        let syft      = syft_bin.clone();
        tokio::spawn(async move {
            sbom_refresh_loop(store, sbom_st, syft, sbom_refresh).await;
        });
    }

    // 2. OSV poller
    tokio::spawn(poller::run(
        cve_tx,
        Arc::clone(&whitelist),
        Arc::clone(&sbom_store),
        poll_interval,
    ));

    // 3. Matcher
    tokio::spawn(matcher::run(cve_rx, Arc::clone(&whitelist), match_tx));

    // 4. Notifier
    tokio::spawn(notifier::run(
        match_rx,
        Arc::clone(&notification_store),
        dashboard_url,
    ));

    // ── HTTP server ───────────────────────────────────────────────────────────
    let router = http::router(
        Arc::clone(&whitelist),
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

/// On startup: generate SBOMs for images that don't have one yet.
/// Then, if `interval_secs > 0`, regenerate all SBOMs every `interval_secs`.
async fn sbom_refresh_loop(
    whitelist: Arc<store::WhitelistStore>,
    sbom_store: Arc<sbom::SbomStore>,
    syft_bin: String,
    interval_secs: u64,
) {
    // Initial pass — only generate missing SBOMs so startup is fast.
    for img in whitelist.images() {
        if sbom_store.get(&img.name).is_none() {
            info!(image = %img.name, "No SBOM found — generating");
            if let Err(e) = sbom::generate_and_store(&sbom_store, &img.name, &syft_bin).await {
                warn!(image = %img.name, error = %e, "Initial SBOM generation failed");
            }
        } else {
            info!(image = %img.name, "SBOM already present — skipping initial generation");
        }
    }

    if interval_secs == 0 {
        info!("SBOM_REFRESH_INTERVAL_SECS=0 — periodic refresh disabled");
        return;
    }

    // Periodic full refresh
    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        info!("Periodic SBOM refresh starting");
        for img in whitelist.images() {
            if let Err(e) = sbom::generate_and_store(&sbom_store, &img.name, &syft_bin).await {
                warn!(image = %img.name, error = %e, "Periodic SBOM refresh failed");
            }
        }
        info!("Periodic SBOM refresh complete");
    }
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
