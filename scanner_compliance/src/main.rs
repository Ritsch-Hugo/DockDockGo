mod availability;
mod engine;
mod models;
mod rules;

mod config_parser;
mod blob_reader;

mod fs;

use crate::engine::run_rules;
use crate::models::*;
use crate::rules::*;
use serde_json::Value;
use std::collections::HashMap;
use std::process;

fn usage() -> String {
    "Usage:\n  cargo run --bin scanner_compliance -- <input.json>\nExample:\n  cargo run --bin scanner_compliance -- samples/request_manifest_only.json\n"
        .to_string()
}

fn parse_manifest_data(manifest_raw: &str) -> Result<ManifestData, String> {
    let v: Value =
        serde_json::from_str(manifest_raw).map_err(|e| format!("invalid manifest_raw JSON: {e}"))?;

    // mediaType
    let media_type = v
        .get("mediaType")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    // annotations
    let mut annotations: HashMap<String, String> = HashMap::new();
    if let Some(obj) = v.get("annotations").and_then(|x| x.as_object()) {
        for (k, vv) in obj.iter() {
            if let Some(s) = vv.as_str() {
                annotations.insert(k.clone(), s.to_string());
            } else {
                annotations.insert(k.clone(), vv.to_string());
            }
        }
    }

    // config.digest
    let config_digest = v
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    // layers: digest + mediaType
    let mut layers: Vec<ManifestLayer> = Vec::new();
    if let Some(arr) = v.get("layers").and_then(|x| x.as_array()) {
        for layer in arr {
            let digest = layer
                .get("digest")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());

            if digest.is_none() {
                continue;
            }

            let layer_media_type = layer
                .get("mediaType")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());

            layers.push(ManifestLayer {
                digest: digest.unwrap(),
                media_type: layer_media_type,
            });
        }
    }

    let layers_count = Some(layers.len() as u32);

    Ok(ManifestData {
        media_type,
        layers_count,
        annotations,
        config_digest,
        layers,
    })
}

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

fn load_input(path: &str) -> Result<ImageData, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;

    let probe: Value =
        serde_json::from_str(&content).map_err(|e| format!("failed to parse JSON {path}: {e}"))?;

    // Nouveau format si "manifest_raw" + "stage"
    let is_scan_request = probe.get("manifest_raw").is_some() && probe.get("stage").is_some();

    if !is_scan_request {
        // Ancien format : ImageData complet
        return serde_json::from_str::<ImageData>(&content)
            .map_err(|e| format!("failed to parse legacy ImageData {path}: {e}"));
    }

    // --- Nouveau format : ScanRequest ---
    let req: ScanRequest =
        serde_json::from_value(probe).map_err(|e| format!("invalid ScanRequest: {e}"))?;

    let manifest = parse_manifest_data(&req.manifest_raw)?;

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
                        // ✅ config JSON valide même si config:{} vide
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

    // --- Étape 5.1: parse received filesystem layers (tar/tar.gz) into raw fs_entries ---
    // IMPORTANT: on ne met PAS has_fs=true ici (pas d'overlay/whiteouts, pas final)
    let mut fs_entries: Vec<FsEntry> = Vec::new();

    for layer in manifest.layers.iter() {
        let mt = layer.media_type.as_deref().unwrap_or("");

        // Filtrage V1 : ne tenter que les mediaTypes de layer "rootfs diff tar"
        let looks_like_fs_layer = mt.contains("application/vnd.oci.image.layer")
            || mt.contains("application/vnd.docker.image.rootfs.diff.tar");

        if !looks_like_fs_layer {
            continue;
        }

        if let Some(b) = req.blobs.iter().find(|x| x.digest == layer.digest) {
            if let Some(p) = b.path.as_deref() {
                match crate::fs::layer_reader::read_layer_entries(p) {
                    Ok(mut entries) => fs_entries.append(&mut entries),
                    Err(e) => eprintln!("Layer parse error for {}: {}", layer.digest, e),
                }
            }
        }
    }

    let image_ref = req.image_ref.clone().unwrap_or_else(|| "unknown".to_string());

    Ok(ImageData {
        meta: ImageMeta {
            image_ref,
            digest: None,
        },

        has_manifest: true,
        has_config: final_has_config,
        has_fs: false,

        scan: ScanInfo {
            stage: req.stage.clone(),
            inputs: InputsSummary {
                has_manifest: true,
                has_config: final_has_config,
                has_fs: false,
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("{}", usage());
        process::exit(2);
    }

    let input_path = &args[1];

    let image = match load_input(input_path) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("{e}");
            process::exit(2);
        }
    };

    // ✅ Noms EXACTS depuis src/rules/mod.rs
    let rules: Vec<Box<dyn crate::engine::Rule>> = vec![
        // Config/runtime rules
        Box::new(NonRootUserRule),
        Box::new(SensitiveEnvRule),
        Box::new(EntrypointCmdRule),
        Box::new(WorkingDirRule),
        Box::new(RequiredLabelsRule),
        Box::new(ExposedPortsRule),
        Box::new(VolumesRule),

        // FS rules (restent SKIP tant que has_fs=false / fs non assemblé)
        Box::new(ForbiddenBinariesRule),
        Box::new(DangerousPermissionsRule),
        Box::new(FsSecretsRule),
        Box::new(FsHygieneRule),
        Box::new(FsWeakConfigsRule),

        // Manifest rules
        Box::new(ManifestMediaTypeRule),
        Box::new(ManifestLayersCountRule),
        Box::new(ManifestAnnotationsRule),
    ];

    let report = run_rules(&image, &rules);

    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    println!("{json}");

    if report.summary.fail > 0 {
        process::exit(1);
    }
}
