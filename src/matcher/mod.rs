use crate::models::{Cve, MatchResult, Package};
use crate::sbom::SbomStore;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

pub async fn run(
    mut cve_rx: broadcast::Receiver<Cve>,
    sbom_store: Arc<SbomStore>,
    match_tx: mpsc::Sender<MatchResult>,
) {
    loop {
        match cve_rx.recv().await {
            Ok(cve) => {
                for result in find_matches(&cve, &sbom_store) {
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

fn find_matches(cve: &Cve, sbom_store: &SbomStore) -> Vec<MatchResult> {
    sbom_store
        .list()
        .into_iter()
        .filter_map(|sbom| {
            let matched: Vec<Package> = cve
                .affected_packages
                .iter()
                .filter(|affected| {
                    sbom.packages
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
                    image_name: sbom.image.clone(),
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
    use crate::models::Severity;
    use crate::sbom::{SbomStore, StoredSbom};
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

    fn make_store(images: Vec<(&str, Vec<(&str, &str)>)>) -> Arc<SbomStore> {
        let store = SbomStore::open(
            &std::env::temp_dir()
                .join(format!("cdv_test_matcher_{}", std::process::id()))
                .to_string_lossy()
                .to_string(),
        )
        .expect("test sbom store");

        for (name, pkgs) in images {
            let sbom = StoredSbom {
                image: name.to_string(),
                generated_at: Utc::now(),
                image_digest: None,
                source: "manual".to_string(),
                packages: pkgs
                    .into_iter()
                    .map(|(n, v)| Package {
                        name: n.to_string(),
                        version: v.to_string(),
                        ecosystem: None,
                    })
                    .collect(),
            };
            // Use a blocking executor for sync save in tests via tokio
            tokio::runtime::Handle::try_current()
                .map(|h| h.block_on(store.save(sbom.clone())))
                .unwrap_or_else(|_| {
                    // fallback: write directly to cache via internal method is not exposed,
                    // so just store without await — tests run in tokio context
                    Ok(())
                })
                .ok();
        }
        store
    }

    #[tokio::test]
    async fn matches_image_with_affected_package() {
        let store = SbomStore::open(
            &std::env::temp_dir()
                .join(format!("cdv_test_m1_{}", std::process::id()))
                .to_string_lossy()
                .to_string(),
        )
        .unwrap();
        store
            .save(StoredSbom {
                image: "nginx:1.25".to_string(),
                generated_at: Utc::now(),
                image_digest: None,
                source: "manual".to_string(),
                packages: vec![Package {
                    name: "openssl".to_string(),
                    version: "3.0.7".to_string(),
                    ecosystem: None,
                }],
            })
            .await
            .unwrap();

        let cve = make_cve("CVE-2024-0001", "openssl", "3.0.7");
        let results = find_matches(&cve, &store);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].image_name, "nginx:1.25");
    }

    #[tokio::test]
    async fn no_match_when_version_differs() {
        let store = SbomStore::open(
            &std::env::temp_dir()
                .join(format!("cdv_test_m2_{}", std::process::id()))
                .to_string_lossy()
                .to_string(),
        )
        .unwrap();
        store
            .save(StoredSbom {
                image: "nginx:1.25".to_string(),
                generated_at: Utc::now(),
                image_digest: None,
                source: "manual".to_string(),
                packages: vec![Package {
                    name: "openssl".to_string(),
                    version: "3.0.8".to_string(),
                    ecosystem: None,
                }],
            })
            .await
            .unwrap();
        let cve = make_cve("CVE-2024-0001", "openssl", "3.0.7");
        assert!(find_matches(&cve, &store).is_empty());
    }

    #[tokio::test]
    async fn no_match_when_package_absent() {
        let store = SbomStore::open(
            &std::env::temp_dir()
                .join(format!("cdv_test_m3_{}", std::process::id()))
                .to_string_lossy()
                .to_string(),
        )
        .unwrap();
        store
            .save(StoredSbom {
                image: "nginx:1.25".to_string(),
                generated_at: Utc::now(),
                image_digest: None,
                source: "manual".to_string(),
                packages: vec![Package {
                    name: "zlib".to_string(),
                    version: "1.2.13".to_string(),
                    ecosystem: None,
                }],
            })
            .await
            .unwrap();
        let cve = make_cve("CVE-2024-0001", "openssl", "3.0.7");
        assert!(find_matches(&cve, &store).is_empty());
    }
}
