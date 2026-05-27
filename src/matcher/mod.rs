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
                    severity: cve.severity.clone(),
                    description: cve.description.clone(),
                    published_at: cve.published_at,
                })
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Sbom, Severity, WhitelistedImage};
    use chrono::Utc;

    fn make_cve(id: &str, pkg_name: &str, pkg_version: &str) -> Cve {
        Cve {
            id: id.to_string(),
            description: String::new(),
            severity: Severity::High,
            affected_packages: vec![Package {
                name: pkg_name.to_string(),
                version: pkg_version.to_string(),
                ecosystem: None,
            }],
            published_at: Utc::now(),
        }
    }

    fn make_store(images: Vec<(&str, Vec<(&str, &str)>)>) -> WhitelistStore {
        WhitelistStore::from_images(
            images
                .into_iter()
                .map(|(name, pkgs)| WhitelistedImage {
                    name: name.to_string(),
                    sbom: Sbom {
                        packages: pkgs
                            .into_iter()
                            .map(|(n, v)| Package {
                                name: n.to_string(),
                                version: v.to_string(),
                                ecosystem: None,
                            })
                            .collect(),
                    },
                })
                .collect(),
        )
    }

    #[test]
    fn matches_image_with_affected_package() {
        let store = make_store(vec![("nginx:1.25", vec![("openssl", "3.0.7")])]);
        let cve = make_cve("CVE-2024-0001", "openssl", "3.0.7");
        let results = find_matches(&cve, &store);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].image_name, "nginx:1.25");
    }

    #[test]
    fn no_match_when_version_differs() {
        let store = make_store(vec![("nginx:1.25", vec![("openssl", "3.0.8")])]);
        let cve = make_cve("CVE-2024-0001", "openssl", "3.0.7");
        assert!(find_matches(&cve, &store).is_empty());
    }

    #[test]
    fn no_match_when_package_absent() {
        let store = make_store(vec![("nginx:1.25", vec![("zlib", "1.2.13")])]);
        let cve = make_cve("CVE-2024-0001", "openssl", "3.0.7");
        assert!(find_matches(&cve, &store).is_empty());
    }

    #[test]
    fn matches_multiple_images() {
        let store = make_store(vec![
            ("nginx:1.25", vec![("openssl", "3.0.7")]),
            ("postgres:16", vec![("openssl", "3.0.7")]),
            ("redis:7.2", vec![("jemalloc", "5.3.0")]),
        ]);
        let cve = make_cve("CVE-2024-0001", "openssl", "3.0.7");
        let results = find_matches(&cve, &store);
        assert_eq!(results.len(), 2);
    }
}
