mod models;
mod store;

use std::sync::Arc;
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
}
