use crate::engine::{run_rules, Rule};
use crate::fs::overlay::{apply_layer, FsIndex, FsNodeKind};
use crate::models::*;
use crate::rules::*;

use serde_json::Value;
use std::collections::{HashMap, HashSet};

fn empty_config() -> ImageConfig {
    ImageConfig {
        user: None,
        env: HashMap::new(),
        labels: HashMap::new(),
        entrypoint: Vec::new(),
        cmd: Vec::new(),
        working_dir: None,
        exposed_ports: Vec::new(),
        volumes: Vec::new(),
    }
}

fn parse_manifest_data(manifest_raw: &str) -> Result<ManifestData, String> {
    let v: Value = serde_json::from_str(manifest_raw)
        .map_err(|e| format!("invalid manifest_raw JSON: {e}"))?;

    // mediaType
    let media_type = v
        .get("mediaType")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    // annotations
    let mut annotations: HashMap<String, String> = HashMap::new();
    if let Some(obj) = v.get("annotations").and_then(|x| x.as_object()) {
        for (k, vv) in obj.iter() {
            annotations.insert(k.clone(), vv.to_string());
        }
    }

    // config digest
    let config_digest = v
        .get("config")
        .and_then(|x| x.get("digest"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    // config media type
    let _config_media_type = v
        .get("config")
        .and_then(|x| x.get("mediaType"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    // layers
    let mut layers: Vec<ManifestLayer> = Vec::new();

    if let Some(arr) = v.get("layers").and_then(|x| x.as_array()) {
        for layer in arr {
            let digest = layer
                .get("digest")
                .and_then(|x| x.as_str())
                .ok_or_else(|| "manifest layer missing digest".to_string())?
                .to_string();

            let media_type = layer
                .get("mediaType")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());

            // ⚠️ IMPORTANT : seulement si ton struct a size
            let _size = layer.get("size").and_then(|x| x.as_u64());

            layers.push(ManifestLayer { digest, media_type });
        }
    }

    Ok(ManifestData {
        media_type,
        layers_count: Some(layers.len() as u32), // ⚠️ requis par ton struct
        annotations,
        config_digest,
        layers,
    })
}

/// Maximum number of layers accepted in a single manifest.
const MAX_LAYERS: usize = 256;

/// Convertit un ScanRequest en ImageData (pipeline identique à ton CLI actuel)
pub fn image_from_scan_request(req: ScanRequest) -> Result<ImageData, String> {
    if req.manifest_raw.len() > 1024 * 1024 {
        return Err(format!(
            "manifest_raw too large: {} bytes (max 1 MB)",
            req.manifest_raw.len()
        ));
    }

    let manifest = parse_manifest_data(&req.manifest_raw)?;

    if manifest.layers.len() > MAX_LAYERS {
        return Err(format!(
            "manifest declares too many layers: {} (max {})",
            manifest.layers.len(),
            MAX_LAYERS
        ));
    }

    // Étape 2 : compute availability depuis manifest + blobs reçus
    let avail = crate::availability::compute_availability(&manifest, &req.blobs);

    // --- Étape 3 (4.1): parse config blob best-effort si dispo ---
    let mut parsed_config = empty_config();
    let mut config_parsed_ok = false;

    if avail.has_config {
        if let Some(cfg_digest) = manifest.config_digest.as_deref() {
            if let Some(blob) = req.blobs.iter().find(|b| b.digest == cfg_digest) {
                match crate::blob_reader::blob_bytes(blob)
                    .and_then(|bytes| crate::config_parser::parse_oci_config_json(&bytes))
                {
                    Ok(cfg) => {
                        parsed_config = cfg;
                        config_parsed_ok = true;
                    }
                    Err(e) => {
                        eprintln!("Config parse error for {}: {}", cfg_digest, e);
                    }
                }
            }
        }
    }

    let final_has_config = avail.has_config && config_parsed_ok;

    // --- Étape 5.1/5.2: parse layers + overlay (FINAL ONLY) ---
    let fs_layers: Vec<&ManifestLayer> = manifest
        .layers
        .iter()
        .filter(|layer| {
            let mt = layer.media_type.as_deref().unwrap_or("");
            mt.contains("application/vnd.oci.image.layer")
                || mt.contains("application/vnd.docker.image.rootfs.diff.tar")
        })
        .collect();

    let present: HashSet<&str> = req
        .blobs
        .iter()
        .filter(|b| b.path.is_some())
        .map(|b| b.digest.as_str())
        .collect();

    let fs_layers_total = fs_layers.len() as u32;
    let fs_layers_received = fs_layers
        .iter()
        .filter(|l| present.contains(l.digest.as_str()))
        .count() as u32;

    let final_has_fs = fs_layers_total > 0 && fs_layers_received == fs_layers_total;

    let mut per_layer_entries: Vec<Vec<FsEntry>> = Vec::new();

    for layer in fs_layers.iter() {
        if !present.contains(layer.digest.as_str()) {
            continue;
        }

        if let Some(b) = req.blobs.iter().find(|x| x.digest == layer.digest) {
            if let Some(p) = b.path.as_deref() {
                match crate::fs::layer_reader::read_layer_entries(p) {
                    Ok(entries) => per_layer_entries.push(entries),
                    Err(e) => eprintln!("Layer parse error for {}: {}", layer.digest, e),
                }
            }
        }
    }

    let fs_entries: Vec<FsEntry> = if final_has_fs {
        let mut fs_index: FsIndex = FsIndex::new();
        for entries in per_layer_entries.iter() {
            apply_layer(&mut fs_index, entries);
        }

        fs_index
            .into_iter()
            .map(|(path, node)| FsEntry {
                path,
                mode: node.mode,
                kind: Some(
                    match node.kind {
                        FsNodeKind::File => "file",
                        FsNodeKind::Dir => "dir",
                        FsNodeKind::Symlink => "symlink",
                        FsNodeKind::Other => "other",
                    }
                    .to_string(),
                ),
                link_target: node.link_target,
            })
            .collect()
    } else {
        let mut out: Vec<FsEntry> = Vec::new();
        for mut entries in per_layer_entries {
            out.append(&mut entries);
        }
        out
    };

    let image_ref = req
        .image_ref
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    Ok(ImageData {
        meta: ImageMeta {
            image_ref,
            digest: None,
        },

        has_manifest: true,
        has_config: final_has_config,
        has_fs: final_has_fs,

        scan: ScanInfo {
            stage: req.stage.clone(),
            inputs: InputsSummary {
                has_manifest: true,
                has_config: final_has_config,
                has_fs: final_has_fs,
                layers_total: avail.layers_total,
                layers_received: avail.layers_received,
            },
        },

        missing_artifacts: avail.missing.clone(),

        config: if final_has_config {
            parsed_config
        } else {
            empty_config()
        },

        fs_paths: Vec::new(),
        fs_entries,

        manifest: Some(manifest),
    })
}

/// Charge un fichier JSON (legacy ImageData OU ScanRequest) -> ImageData
pub fn load_image_from_json_file(path: &str) -> Result<ImageData, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;

    let probe: Value =
        serde_json::from_str(&content).map_err(|e| format!("failed to parse JSON {path}: {e}"))?;

    let is_scan_request = probe.get("manifest_raw").is_some() && probe.get("stage").is_some();

    if !is_scan_request {
        return serde_json::from_str::<ImageData>(&content)
            .map_err(|e| format!("failed to parse legacy ImageData {path}: {e}"));
    }

    let req: ScanRequest =
        serde_json::from_value(probe).map_err(|e| format!("invalid ScanRequest: {e}"))?;

    image_from_scan_request(req)
}

/// Liste de règles "standard" (identique à ton main.rs actuel)
pub fn default_rules() -> Vec<Box<dyn Rule>> {
    vec![
        // Config/runtime rules
        Box::new(NonRootUserRule),
        Box::new(SensitiveEnvRule),
        Box::new(EntrypointCmdRule),
        Box::new(WorkingDirRule),
        Box::new(RequiredLabelsRule),
        Box::new(ExposedPortsRule),
        Box::new(VolumesRule),
        // FS rules
        Box::new(ForbiddenBinariesRule),
        Box::new(DangerousPermissionsRule),
        Box::new(FsSecretsRule),
        Box::new(FsHygieneRule),
        Box::new(FsWeakConfigsRule),
        // Manifest rules
        Box::new(ManifestMediaTypeRule),
        Box::new(ManifestLayersCountRule),
        Box::new(ManifestAnnotationsRule),
    ]
}

/// Scan complet depuis ImageData -> Report (déterministe)
pub fn scan_image(image: &ImageData) -> Report {
    let rules = default_rules();
    let mut report = run_rules(image, &rules);

    report.pseudo_dockerfile = crate::dockerfile_hint::generate_pseudo_dockerfile(image);

    report.findings.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    report.missing_artifacts.sort_by(|a, b| {
        let ka = (format!("{:?}", a.kind), a.digest.as_str());
        let kb = (format!("{:?}", b.kind), b.digest.as_str());
        ka.cmp(&kb)
    });

    report
}
