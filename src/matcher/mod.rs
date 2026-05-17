use crate::models::{Cve, MatchResult, Package};
use crate::store::WhitelistStore;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

pub async fn run(
    mut cve_rx: broadcast::Receiver<Cve>,
    store: Arc<WhitelistStore>,
    match_tx: mpsc::Sender<MatchResult>,
) {
    loop {
        match cve_rx.recv().await {
            Ok(cve) => {
                for result in find_matches(&cve, &store) {
                    info!(
                        cve_id = %result.cve_id,
                        image = %result.image_name,
                        packages = ?result.matched_packages,
                        "Match found"
                    );
                    if match_tx.send(result).await.is_err() {
                        return;
                    }
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(skipped = n, "CVE receiver lagged, some CVEs skipped");
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn find_matches(cve: &Cve, store: &WhitelistStore) -> Vec<MatchResult> {
    store
        .images()
        .iter()
        .filter_map(|image| {
            let matched: Vec<Package> = cve
                .affected_packages
                .iter()
                .filter(|affected| {
                    image
                        .sbom
                        .packages
                        .iter()
                        .any(|pkg| pkg.name == affected.name && pkg.version == affected.version)
                })
                .cloned()
                .collect();

            if matched.is_empty() {
                None
            } else {
                Some(MatchResult {
                    cve_id: cve.id.clone(),
                    image_name: image.name.clone(),
                    matched_packages: matched,
                })
            }
        })
        .collect()
}
