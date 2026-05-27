use crate::models::{Cve, Package, Severity};
use crate::sbom::SbomStore;
use crate::store::WhitelistStore;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::sleep;
use tracing::{error, info, warn};

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const MAX_RETRIES: u32 = 3;

// ── OSV request types ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct BatchRequest {
    queries: Vec<Query>,
}

#[derive(Serialize)]
struct Query {
    package: QueryPkg,
    version: String,
}

#[derive(Serialize)]
struct QueryPkg {
    name: String,
    ecosystem: String,
}

// ── OSV response types ───────────────────────────────────────────────────────

fn null_as_empty<'de, D, T>(de: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(de)?.unwrap_or_default())
}

#[derive(Deserialize)]
struct BatchResponse {
    #[serde(default, deserialize_with = "null_as_empty")]
    results: Vec<QueryResult>,
}

#[derive(Deserialize)]
struct QueryResult {
    #[serde(default, deserialize_with = "null_as_empty")]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    severity: Vec<OsvSeverityEntry>,
    #[serde(default, deserialize_with = "null_as_empty")]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    published: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct OsvSeverityEntry {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize)]
struct OsvAffected {
    package: OsvAffectedPkg,
    #[serde(default, deserialize_with = "null_as_empty")]
    versions: Vec<String>,
}

#[derive(Deserialize)]
struct OsvAffectedPkg {
    name: String,
    ecosystem: String,
}

// ── Mapping ──────────────────────────────────────────────────────────────────

fn parse_severity(entries: &[OsvSeverityEntry]) -> Severity {
    for entry in entries {
        if entry.kind.starts_with("CVSS_V") {
            let highs = ["C:H", "I:H", "A:H"]
                .iter()
                .filter(|&&m| entry.score.contains(m))
                .count();
            return match highs {
                3 => Severity::Critical,
                2 => Severity::High,
                1 => Severity::Medium,
                _ => Severity::Low,
            };
        }
    }
    Severity::High
}

fn to_cve(vuln: OsvVuln) -> Cve {
    let severity = parse_severity(&vuln.severity);
    let affected_packages: Vec<Package> = vuln
        .affected
        .iter()
        .flat_map(|a| {
            a.versions.iter().map(|v| Package {
                name: a.package.name.clone(),
                version: v.clone(),
                ecosystem: Some(a.package.ecosystem.clone()),
            })
        })
        .collect();

    let description = match (vuln.summary, vuln.details) {
        (Some(s), _) => s,
        (None, Some(d)) => d.chars().take(200).collect(),
        (None, None) => String::new(),
    };

    Cve {
        id: vuln.id,
        description,
        severity,
        affected_packages,
        published_at: vuln.published.unwrap_or_else(Utc::now),
    }
}

// ── OSV HTTP call ────────────────────────────────────────────────────────────

async fn fetch_batch(client: &Client, queries: Vec<Query>) -> anyhow::Result<Vec<OsvVuln>> {
    let body = BatchRequest { queries };
    let mut delay = Duration::from_secs(2);

    for attempt in 1..=MAX_RETRIES {
        match client.post(OSV_BATCH_URL).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                let text = resp.text().await?;
                let batch: BatchResponse = serde_json::from_str(&text).map_err(|e| {
                    tracing::debug!(body = %text, "OSV response body that failed to parse");
                    anyhow::anyhow!("failed to parse OSV response: {e}")
                })?;
                return Ok(batch.results.into_iter().flat_map(|r| r.vulns).collect());
            }
            Ok(resp) if resp.status().as_u16() == 429 => {
                warn!(attempt, "OSV rate limited — backing off");
                sleep(delay).await;
                delay *= 2;
            }
            Ok(resp) => {
                let status = resp.status().as_u16();
                warn!(attempt, status, "OSV returned error status");
                sleep(delay).await;
                delay *= 2;
            }
            Err(e) => {
                warn!(attempt, error = %e, "OSV request failed");
                if attempt < MAX_RETRIES {
                    sleep(delay).await;
                    delay *= 2;
                }
            }
        }
    }

    anyhow::bail!("OSV query failed after {MAX_RETRIES} attempts")
}

// ── Package resolution ────────────────────────────────────────────────────────

/// Returns the effective package list for an image:
/// 1. Syft-generated SBOM from `SbomStore` (preferred — real, up-to-date)
/// 2. Fallback packages from `whitelist.toml`   (static, used before first scan)
fn effective_packages<'a>(
    image_name: &str,
    toml_packages: &'a [crate::models::Package],
    sbom_store: &SbomStore,
) -> Vec<crate::models::Package> {
    if let Some(stored) = sbom_store.get(image_name) {
        if !stored.packages.is_empty() {
            return stored.packages;
        }
    }
    toml_packages.to_vec()
}

// ── Main loop ────────────────────────────────────────────────────────────────

pub async fn run(
    tx: broadcast::Sender<Cve>,
    store: Arc<WhitelistStore>,
    sbom_store: Arc<SbomStore>,
    poll_interval_secs: u64,
) {
    let client = Client::new();
    let mut seen: HashSet<String> = HashSet::new();

    loop {
        // Build OSV queries using stored SBOMs (or TOML fallback)
        let queries: Vec<Query> = store
            .images()
            .iter()
            .flat_map(|img| {
                let packages = effective_packages(&img.name, &img.sbom.packages, &sbom_store);
                packages.into_iter().filter_map(|pkg| {
                    pkg.ecosystem.map(|eco| Query {
                        package: QueryPkg {
                            name: pkg.name,
                            ecosystem: eco,
                        },
                        version: pkg.version,
                    })
                })
            })
            .collect();

        if queries.is_empty() {
            warn!(
                "No packages with ecosystem set — \
                 waiting for Syft to generate SBOMs or add `ecosystem` fields to whitelist.toml"
            );
        } else {
            match fetch_batch(&client, queries).await {
                Ok(vulns) => {
                    let mut new_count = 0u32;
                    for vuln in vulns {
                        if seen.insert(vuln.id.clone()) {
                            let cve = to_cve(vuln);
                            info!(cve_id = %cve.id, severity = ?cve.severity, "New CVE from OSV");
                            let _ = tx.send(cve);
                            new_count += 1;
                        }
                    }
                    info!(
                        new = new_count,
                        total_seen = seen.len(),
                        "OSV poll complete"
                    );
                }
                Err(e) => error!(error = %e, "OSV poll failed"),
            }
        }

        sleep(Duration::from_secs(poll_interval_secs)).await;
    }
}
