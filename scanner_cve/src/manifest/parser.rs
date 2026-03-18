use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
pub struct Manifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    pub config: Descriptor,

    pub layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
pub struct Descriptor {
    pub digest: String,
}

#[derive(Debug)]
pub struct ParsedManifest {
    pub config_digest: String,
    pub layer_digests: Vec<String>,
}

pub fn parse_manifest(path: &str) -> Result<ParsedManifest> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read manifest {}", path))?;

    let manifest: Manifest = serde_json::from_str(&raw).context("invalid manifest JSON")?;

    let layer_digests = manifest.layers.into_iter().map(|l| l.digest).collect();

    Ok(ParsedManifest {
        config_digest: manifest.config.digest,
        layer_digests,
    })
}
