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
                // best-effort: stringify
                annotations.insert(k.clone(), vv.to_string());
            }
        }
    }

    // layers count (OCI image manifest)
    let layers_count = v
        .get("layers")
        .and_then(|x| x.as_array())
        .map(|arr| arr.len() as u32);

    Ok(ManifestData {
        media_type,
        layers_count,
        annotations,
    })
}

fn load_input(path: &str) -> Result<ImageData, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;

    // Détection du format : nouveau ScanRequest si "manifest_raw" présent
    let probe: Value =
        serde_json::from_str(&content).map_err(|e| format!("failed to parse JSON {path}: {e}"))?;

    let is_scan_request = probe.get("manifest_raw").is_some() && probe.get("stage").is_some();

    if is_scan_request {
        let req: ScanRequest =
            serde_json::from_value(probe).map_err(|e| format!("invalid ScanRequest: {e}"))?;

        let manifest = parse_manifest_data(&req.manifest_raw)?;

        let image_ref = req.image_ref.unwrap_or_else(|| "unknown".to_string());

        // ImageData minimal : PAS de config/fs à ce stage
        let mut img = ImageData {
            meta: ImageMeta {
                image_ref,
                digest: None,
            },
            has_manifest: true,
            has_config: false,
            has_fs: false,
            scan: ScanInfo {
                stage: req.stage.clone(),
                inputs: InputsSummary {
                    has_manifest: true,
                    has_config: false,
                    has_fs: false,
                    layers_total: manifest.layers_count.unwrap_or(0),
                },
            },
            config: ImageConfig {
                user: None,
                env: HashMap::new(),
                labels: HashMap::new(),
                entrypoint: Vec::new(),
                cmd: Vec::new(),
                working_dir: None,
                exposed_ports: Vec::new(),
                volumes: Vec::new(),
            },
            fs_paths: Vec::new(),
            fs_entries: Vec::new(),
            manifest: Some(manifest),
        };

        // Defensive : si manifest absent => has_manifest false
        if img.manifest.is_none() {
            img.has_manifest = false;
            img.scan.inputs.has_manifest = false;
        }

        Ok(img)
    } else {
        // Ancien format : ImageData complet
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
