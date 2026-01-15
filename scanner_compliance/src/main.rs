mod availability;
mod blob_reader;
mod config_parser;
mod engine;
mod models;
mod rules;

use crate::engine::run_rules;
use crate::models::*;
use crate::rules::*;
use serde_json::Value;
use std::collections::HashMap;
use std::process;

fn usage() -> String {
    "Usage:\n  cargo run -- <input.json>\nExample:\n  cargo run -- samples/request_manifest_only.json\n"
        .to_string()
}

/// Parse le manifest brut et extrait ce qui est utile à la compliance image-level.
/// V1: on extrait mediaType, annotations, config.digest, layers[].digest
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

    // layers digests
    let mut layer_digests: Vec<String> = Vec::new();
    if let Some(arr) = v.get("layers").and_then(|x| x.as_array()) {
        for layer in arr {
            if let Some(d) = layer.get("digest").and_then(|x| x.as_str()) {
                layer_digests.push(d.to_string());
            }
        }
    }

    let layers_count = Some(layer_digests.len() as u32);

    Ok(ManifestData {
        media_type,
        layers_count,
        annotations,
        config_digest,
        layer_digests,
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

/// Charge l’input JSON.
/// - Si c'est un ScanRequest (manifest_raw + stage), on construit un ImageData minimal et progressif.
/// - Sinon, on parse l’ancien ImageData (legacy) pour ne pas casser l’existant.
fn load_input(path: &str) -> Result<ImageData, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;

    let probe: Value =
        serde_json::from_str(&content).map_err(|e| format!("failed to parse JSON {path}: {e}"))?;

    let is_scan_request = probe.get("manifest_raw").is_some() && probe.get("stage").is_some();

    if is_scan_request {
        let req: ScanRequest =
            serde_json::from_value(probe).map_err(|e| format!("invalid ScanRequest: {e}"))?;

        let manifest = parse_manifest_data(&req.manifest_raw)?;

        // Étape 2 : availability = config/layers présents (content-aware)
        let avail = crate::availability::compute_availability(&manifest, &req.blobs);

        // Étape 3 : si config content dispo → parse config blob réel
        let mut parsed_config = empty_config();

        if avail.has_config {
            if let Some(cfg_digest) = manifest.config_digest.as_deref() {
                if let Some(blob) = req.blobs.iter().find(|b| b.digest == cfg_digest) {
                    match crate::blob_reader::blob_bytes(blob)
                        .and_then(|bytes| crate::config_parser::parse_oci_config_json(&bytes))
                    {
                        Ok(cfg) => parsed_config = cfg,
                        Err(e) => {
                            // V1: ne pas crash. On laisse has_config devenir false (voir final_has_config)
                            eprintln!("Config parse error for {}: {}", cfg_digest, e);
                        }
                    }
                }
            }
        }

        // has_config "réel" : parsing a effectivement fourni quelque chose d’exploitable
        let final_has_config = {
            let looks_parsed = parsed_config.user.is_some()
                || !parsed_config.env.is_empty()
                || !parsed_config.labels.is_empty()
                || !parsed_config.entrypoint.is_empty()
                || !parsed_config.cmd.is_empty()
                || parsed_config.working_dir.is_some()
                || !parsed_config.exposed_ports.is_empty()
                || !parsed_config.volumes.is_empty();

            avail.has_config && looks_parsed
        };

        let image_ref = req.image_ref.unwrap_or_else(|| "unknown".to_string());

        // ImageData minimal (FS non dispo à l’étape 3)
        let img = ImageData {
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

            // Pour aider le MCP
            missing_artifacts: avail.missing.clone(),

            // Runtime config parsée si dispo, sinon vide.
            config: parsed_config,

            // FS vide tant qu’on n’a pas assemblé le rootfs (étape 5)
            fs_paths: Vec::new(),
            fs_entries: Vec::new(),

            // Résumé manifest
            manifest: Some(manifest),
        };

        Ok(img)
    } else {
        // Legacy ImageData complet (compat)
        serde_json::from_str::<ImageData>(&content)
            .map_err(|e| format!("failed to parse legacy ImageData {path}: {e}"))
    }
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

    // ⚠️ Mets ici les noms EXACTS exportés dans src/rules/mod.rs chez toi
    let rules: Vec<Box<dyn crate::engine::Rule>> = vec![
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
    ];

    let report = run_rules(&image, &rules);

    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    println!("{json}");

    if report.summary.fail > 0 {
        process::exit(1);
    }
}
