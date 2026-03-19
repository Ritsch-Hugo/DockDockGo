use serde_json::Value;
use std::{env, fs, path::PathBuf};

fn looks_like_json(path: &PathBuf) -> bool {
    if let Ok(bytes) = fs::read(path) {
        return bytes.first() == Some(&b'{');
    }
    false
}

fn digest_to_blob_path(blobs_dir: &PathBuf, digest: &str) -> PathBuf {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    blobs_dir.join(hex)
}

fn main() {
    // Usage:
    // cargo run --bin make_request -- <image_dir> [manifest_number]
    //
    // image_dir exemple:
    // ../quarantaine/library/alpine/latest
    //
    // Attendu:
    // <image_dir>/manifests/*.json
    // <image_dir>/blobs/sha256/<hex>

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: make_request <image_dir> [manifest_number]");
        std::process::exit(2);
    }

    let image_dir = PathBuf::from(&args[1]);
    let manifests_dir = image_dir.join("manifests");
    let blobs_dir = image_dir.join("blobs").join("sha256");

    let mut manifests: Vec<PathBuf> = fs::read_dir(&manifests_dir)
        .unwrap_or_else(|_| panic!("Cannot read manifests dir: {:?}", manifests_dir))
        .filter_map(|e| e.ok().map(|x| x.path()))
        .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        .collect();

    manifests.sort();

    if manifests.is_empty() {
        panic!("No manifest found in {:?}", manifests_dir);
    }

    // Create samples/ and remove old step4 files to avoid mixing manifests
    fs::create_dir_all("samples").expect("create samples/");
    let _ = fs::remove_file("samples/request_step4_0.json");
    let _ = fs::remove_file("samples/request_step4_1.json");
    let _ = fs::remove_file("samples/request_step4_2.json");

    // ----- Select manifest -----
    // Goal:
    // - pick an image manifest (has layers)
    // - config blob exists AND looks like JSON
    // - at least layer[0] blob exists (otherwise step4_1 cannot be generated)
    // - prefer if layer[1] blob also exists (so we can generate step4_2)
    let chosen: PathBuf = if args.len() >= 3 {
        let idx: usize = args[2].parse().expect("manifest_number must be an integer");
        manifests.get(idx).cloned().unwrap_or_else(|| {
            panic!(
                "manifest_number out of range. found {} manifests",
                manifests.len()
            )
        })
    } else {
        let mut best_two_layers: Option<PathBuf> = None;
        let mut best_one_layer: Option<PathBuf> = None;

        for m in &manifests {
            let raw = fs::read_to_string(m).expect("read manifest");
            let v: Value = serde_json::from_str(&raw).expect("manifest json");

            // must be an image manifest with layers array
            let Some(layers_arr) = v.get("layers").and_then(|x| x.as_array()) else {
                continue;
            };
            if layers_arr.is_empty() {
                continue;
            }

            // must have config.digest
            let Some(cfg_digest) = v
                .get("config")
                .and_then(|c| c.get("digest"))
                .and_then(|d| d.as_str())
            else {
                continue;
            };

            let cfg_path = digest_to_blob_path(&blobs_dir, cfg_digest);

            // config blob must exist and look like JSON
            if !cfg_path.exists() {
                continue;
            }
            if !looks_like_json(&cfg_path) {
                continue;
            }

            // require at least layer[0] digest and blob exists (so step4_1 is meaningful)
            let Some(l1_digest) = layers_arr[0].get("digest").and_then(|d| d.as_str()) else {
                continue;
            };
            let l1_path = digest_to_blob_path(&blobs_dir, l1_digest);
            if !l1_path.exists() {
                continue;
            }

            // if layer[1] exists AND blob exists, prefer this manifest (step4_2 possible)
            let mut has_two_layers = false;
            if layers_arr.len() >= 2 {
                if let Some(l2_digest) = layers_arr[1].get("digest").and_then(|d| d.as_str()) {
                    let l2_path = digest_to_blob_path(&blobs_dir, l2_digest);
                    if l2_path.exists() {
                        has_two_layers = true;
                    }
                }
            }

            if has_two_layers {
                best_two_layers = Some(m.clone());
                break; // best possible
            } else if best_one_layer.is_none() {
                best_one_layer = Some(m.clone());
            }
        }

        best_two_layers
            .or(best_one_layer)
            .unwrap_or_else(|| manifests[0].clone())
    };

    // ----- Read and parse chosen manifest -----
    let manifest_raw = fs::read_to_string(&chosen).expect("read chosen manifest");
    let v: Value = serde_json::from_str(&manifest_raw).expect("chosen manifest json");

    let cfg_digest = v
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
        .expect("manifest missing config.digest")
        .to_string();

    let layers = v
        .get("layers")
        .and_then(|x| x.as_array())
        .expect("manifest missing layers array");

    if layers.is_empty() {
        panic!("chosen manifest has 0 layers -> not useful for step4");
    }

    // layer1 must exist (we ensured it during selection)
    let layer1 = layers[0]
        .get("digest")
        .and_then(|d| d.as_str())
        .expect("layer[0].digest missing")
        .to_string();

    // layer2 optional (only if blob exists)
    let layer2_opt: Option<String> = if layers.len() >= 2 {
        let d = layers[1]
            .get("digest")
            .and_then(|x| x.as_str())
            .expect("layer[1].digest missing")
            .to_string();
        let p = digest_to_blob_path(&blobs_dir, &d);
        if p.exists() {
            Some(d)
        } else {
            None
        }
    } else {
        None
    };

    // ----- Resolve paths (must exist for config + layer1) -----
    let cfg_path = digest_to_blob_path(&blobs_dir, &cfg_digest);
    if !cfg_path.exists() {
        panic!("config blob path not found: {:?}", cfg_path);
    }

    let l1_path = digest_to_blob_path(&blobs_dir, &layer1);
    if !l1_path.exists() {
        panic!("layer1 blob path not found: {:?}", l1_path);
    }

    // Canonicalize to make requests robust (cwd-independent)
    let cfg_path_s = cfg_path
        .canonicalize()
        .expect("canonicalize cfg_path")
        .to_string_lossy()
        .to_string();

    let l1_path_s = l1_path
        .canonicalize()
        .expect("canonicalize l1_path")
        .to_string_lossy()
        .to_string();

    // 0) manifest_config (config only)
    let req0 = serde_json::json!({
        "stage": "manifest_config",
        "image_ref": image_dir.to_string_lossy(),
        "manifest_raw": manifest_raw,
        "blobs": [
            { "digest": cfg_digest, "path": cfg_path_s }
        ]
    });
    fs::write(
        "samples/request_step4_0.json",
        serde_json::to_string_pretty(&req0).unwrap(),
    )
    .unwrap();

    // 1) partial_layers (config + 1 layer)
    let req1 = serde_json::json!({
        "stage": "partial_layers",
        "image_ref": image_dir.to_string_lossy(),
        "manifest_raw": manifest_raw,
        "blobs": [
            { "digest": cfg_digest, "path": cfg_path_s },
            { "digest": layer1, "path": l1_path_s }
        ]
    });
    fs::write(
        "samples/request_step4_1.json",
        serde_json::to_string_pretty(&req1).unwrap(),
    )
    .unwrap();

    // 2) partial_layers (config + 2 layers) only if we have layer2 blob present
    if let Some(layer2_digest) = layer2_opt {
        let l2_path = digest_to_blob_path(&blobs_dir, &layer2_digest);
        let l2_path_s = l2_path
            .canonicalize()
            .expect("canonicalize l2_path")
            .to_string_lossy()
            .to_string();

        let req2 = serde_json::json!({
            "stage": "partial_layers",
            "image_ref": image_dir.to_string_lossy(),
            "manifest_raw": manifest_raw,
            "blobs": [
                { "digest": cfg_digest, "path": cfg_path_s },
                { "digest": layer1, "path": l1_path_s },
                { "digest": layer2_digest, "path": l2_path_s }
            ]
        });
        fs::write(
            "samples/request_step4_2.json",
            serde_json::to_string_pretty(&req2).unwrap(),
        )
        .unwrap();

        println!("Wrote: samples/request_step4_2.json");
    } else {
        eprintln!(
            "Note: chosen manifest has no second layer blob present -> step4_2 not generated."
        );
    }

    println!("Chosen manifest: {:?}", chosen);
    println!("Wrote: samples/request_step4_0.json");
    println!("Wrote: samples/request_step4_1.json");
}
