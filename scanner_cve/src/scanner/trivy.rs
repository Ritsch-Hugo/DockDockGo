use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

const MAX_OUTPUT_SIZE: usize = 50 * 1024 * 1024; // 50 MB

pub async fn run_trivy(rootfs: &Path) -> Result<Value> {
    let timeout_secs: u64 = std::env::var("TRIVY_TIMEOUT_SECS")
        .unwrap_or_else(|_| "300".to_string())
        .parse()
        .unwrap_or(300);
    let trivy_timeout = Duration::from_secs(timeout_secs);

    // TRIVY_SKIP_DB_UPDATE=true → passe --skip-db-update à Trivy.
    // À activer quand la DB est pré-téléchargée par trivy-db-init (docker-compose).
    // Évite les tentatives de mise à jour réseau à chaque scan.
    let skip_db_update = std::env::var("TRIVY_SKIP_DB_UPDATE")
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    let run = async {
        let mut cmd = Command::new("trivy");
        cmd.arg("fs")
            .arg(rootfs)
            .arg("--quiet")
            .arg("--format")
            .arg("json");

        if skip_db_update {
            cmd.arg("--skip-db-update");
        }

        let output = cmd
            .output()
            .await
            .with_context(|| "failed to execute trivy")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("trivy scan failed: {}", stderr.trim());
        }

        if output.stdout.len() > MAX_OUTPUT_SIZE {
            anyhow::bail!(
                "trivy output too large ({} bytes, limit {} bytes)",
                output.stdout.len(),
                MAX_OUTPUT_SIZE
            );
        }

        let json: Value =
            serde_json::from_slice(&output.stdout).with_context(|| "invalid trivy json")?;

        Ok(json)
    };

    timeout(trivy_timeout, run)
        .await
        .unwrap_or_else(|_| anyhow::bail!("trivy scan timed out after {} seconds", timeout_secs))
}
