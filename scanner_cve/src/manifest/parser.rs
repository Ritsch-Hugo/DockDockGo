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

const TAR_MEDIA_TYPES: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.docker.image.rootfs.diff.tar",
];

#[derive(Debug, Deserialize)]
pub struct Descriptor {
    pub digest: String,
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
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

    validate_digest(&manifest.config.digest).context("invalid config digest")?;

    let layer_digests: Vec<String> = manifest
        .layers
        .into_iter()
        .enumerate()
        .filter(|(_, l)| {
            l.media_type
                .as_deref()
                .map(|mt| TAR_MEDIA_TYPES.contains(&mt))
                .unwrap_or(true) // si pas de mediaType, on tente quand même
        })
        .map(|(i, l)| {
            validate_digest(&l.digest)
                .with_context(|| format!("invalid digest for layer {}", i))?;
            Ok(l.digest)
        })
        .collect::<Result<_>>()?;

    Ok(ParsedManifest {
        config_digest: manifest.config.digest,
        layer_digests,
    })
}

fn validate_digest(digest: &str) -> Result<()> {
    let hash = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("digest must start with 'sha256:': {}", digest))?;

    if hash.len() != 64 {
        anyhow::bail!("digest hash must be 64 characters: {}", digest);
    }

    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("digest hash must be lowercase hex: {}", digest);
    }

    Ok(())
}
