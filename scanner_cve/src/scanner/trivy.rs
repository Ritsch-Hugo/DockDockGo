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

    let run = async {
        let output = Command::new("trivy")
            .arg("fs")
            .arg(rootfs)
            .arg("--quiet")
            .arg("--format")
            .arg("json")
            .output()
            .await
            .with_context(|| "failed to execute trivy")?;

        if !output.status.success() {
            anyhow::bail!("trivy scan failed");
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
