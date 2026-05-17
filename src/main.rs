mod matcher;
mod models;
mod notifier;
mod poller;
mod store;

use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cycle_de_vie=debug".into()),
        )
        .json()
        .init();

    info!(service = "cycle-de-vie", "Service starting");

    let whitelist = match store::WhitelistStore::load("config/whitelist") {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!(error = %e, "Failed to load whitelist");
            std::process::exit(1);
        }
    };

    info!(count = whitelist.images().len(), "Whitelist loaded");
    for image in whitelist.images() {
        info!(
            image = %image.name,
            packages = image.sbom.packages.len(),
            "Registered image"
        );
    }

    let (cve_tx, cve_rx) = broadcast::channel(32);
    let (match_tx, match_rx) = mpsc::channel(32);
    let notification_store = notifier::new_store();

    tokio::spawn(poller::run(cve_tx, 5));
    tokio::spawn(matcher::run(cve_rx, Arc::clone(&whitelist), match_tx));
    tokio::spawn(notifier::run(
        match_rx,
        Arc::clone(&notification_store),
        None, // no dashboard URL in Phase 1
    ));

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
    info!("Shutting down");
}
