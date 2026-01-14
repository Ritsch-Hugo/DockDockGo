use crate::models::{ManifestData, MissingArtifact, MissingArtifactKind, RawBlob};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Availability {
    pub has_config: bool,
    pub layers_total: u32,
    pub layers_received: u32,
    pub missing: Vec<MissingArtifact>,
}

pub fn compute_availability(manifest: &ManifestData, blobs: &[RawBlob]) -> Availability {
    let present: HashSet<&str> = blobs.iter().map(|b| b.digest.as_str()).collect();

    let mut missing: Vec<MissingArtifact> = Vec::new();

    // Config
    let has_config = match manifest.config_digest.as_deref() {
        Some(cfg) => present.contains(cfg),
        none => false,
    };
    if let Some(cfg) = manifest.config_digest.as_deref() {
        if !present.contains(cfg) {
            missing.push(MissingArtifact {
                kind: MissingArtifactKind::Config,
                digest: cfg.to_string(),
            });
        }
    }

    // Layers
    let layers_total = manifest.layer_digests.len() as u32;
    let mut layers_received: u32 = 0;

    for d in &manifest.layer_digests {
        if present.contains(d.as_str()) {
            layers_received += 1;
        } else {
            missing.push(MissingArtifact {
                kind: MissingArtifactKind::Layer,
                digest: d.clone(),
            });
        }
    }

    Availability {
        has_config,
        layers_total,
        layers_received,
        missing,
    }
}
