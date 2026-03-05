use std::process::Command;
use std::path::Path;

use anyhow::{Result, Context};
use serde_json::Value;

pub fn run_trivy(rootfs: &Path) -> Result<Value> {

    let output = Command::new("trivy")
        .arg("fs")
        .arg(rootfs)
        .arg("--quiet")
        .arg("--format")
        .arg("json")
        .output()
        .with_context(|| "failed to execute trivy")?;

    if !output.status.success() {
        anyhow::bail!("trivy scan failed");
    }

    let json: Value = serde_json::from_slice(&output.stdout)
        .with_context(|| "invalid trivy json")?;

    Ok(json)
}