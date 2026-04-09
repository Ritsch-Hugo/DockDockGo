use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

const TRIVY_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
const MAX_OUTPUT_SIZE: usize = 50 * 1024 * 1024; // 50 MB

pub async fn run_trivy(rootfs: &Path) -> Result<Value> {
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

    timeout(TRIVY_TIMEOUT, run)
        .await
        .unwrap_or_else(|_| anyhow::bail!("trivy scan timed out after 5 minutes"))
}
