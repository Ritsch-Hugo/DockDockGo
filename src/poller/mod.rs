use crate::models::{Cve, Package, Severity};
use chrono::Utc;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};
use tracing::info;

fn fixtures() -> Vec<Cve> {
    vec![
        Cve {
            id: "CVE-2024-0001".to_string(),
            description: "Buffer overflow in openssl 3.0.7".to_string(),
            severity: Severity::Critical,
            affected_packages: vec![Package {
                name: "openssl".to_string(),
                version: "3.0.7".to_string(),
            }],
            published_at: Utc::now(),
        },
        Cve {
            id: "CVE-2024-0002".to_string(),
            description: "Use-after-free in zlib 1.2.13".to_string(),
            severity: Severity::High,
            affected_packages: vec![Package {
                name: "zlib".to_string(),
                version: "1.2.13".to_string(),
            }],
            published_at: Utc::now(),
        },
        Cve {
            id: "CVE-2024-0003".to_string(),
            description: "Remote code execution in libxml2 2.10.3".to_string(),
            severity: Severity::Critical,
            affected_packages: vec![Package {
                name: "libxml2".to_string(),
                version: "2.10.3".to_string(),
            }],
            published_at: Utc::now(),
        },
        Cve {
            id: "CVE-2024-0004".to_string(),
            description: "Information disclosure in jemalloc 5.3.0".to_string(),
            severity: Severity::Medium,
            affected_packages: vec![Package {
                name: "jemalloc".to_string(),
                version: "5.3.0".to_string(),
            }],
            published_at: Utc::now(),
        },
        Cve {
            id: "CVE-2024-0005".to_string(),
            description: "Heap overflow in libpng 1.6.37".to_string(),
            severity: Severity::High,
            affected_packages: vec![Package {
                name: "libpng".to_string(),
                version: "1.6.37".to_string(),
            }],
            published_at: Utc::now(),
        },
    ]
}

pub async fn run(tx: broadcast::Sender<Cve>, poll_interval_secs: u64) {
    let cves = fixtures();
    let mut ticker = interval(Duration::from_secs(poll_interval_secs));
    let mut index = 0;

    loop {
        ticker.tick().await;

        let cve = cves[index % cves.len()].clone();
        index += 1;

        info!(
            cve_id = %cve.id,
            severity = ?cve.severity,
            "New CVE detected"
        );

        // receivers lagging behind simply miss old CVEs — acceptable for Phase 1
        let _ = tx.send(cve);
    }
}
