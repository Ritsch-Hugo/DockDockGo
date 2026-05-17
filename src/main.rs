mod matcher;
mod models;
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

    let store = match store::WhitelistStore::load("config/whitelist") {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!(error = %e, "Failed to load whitelist");
            std::process::exit(1);
        }
    };

    info!(count = store.images().len(), "Whitelist loaded");
    for image in store.images() {
        info!(
            image = %image.name,
            packages = image.sbom.packages.len(),
            "Registered image"
        );
    }

    let (cve_tx, cve_rx) = broadcast::channel(32);
    let (match_tx, mut match_rx) = mpsc::channel(32);

    tokio::spawn(poller::run(cve_tx, 5));
    tokio::spawn(matcher::run(cve_rx, Arc::clone(&store), match_tx));

    // temporary: log matches until the notifier is wired up (step 6)
    tokio::spawn(async move {
        while let Some(m) = match_rx.recv().await {
            info!(cve_id = %m.cve_id, image = %m.image_name, "Match received by main");
        }
    });

    tokio::signal::ctrl_c().await.expect("failed to listen for ctrl-c");
    info!("Shutting down");
}
