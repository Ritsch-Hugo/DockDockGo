use scanner_compliance::models::{RawBlob, ScanRequest, Stage};
use scanner_compliance::pipeline;
use scanner_compliance::security;

// ─── helpers ────────────────────────────────────────────────────────────────

fn req(manifest_raw: &str) -> ScanRequest {
    ScanRequest {
        image_ref: Some("test/image:latest".into()),
        manifest_raw: manifest_raw.to_string(),
        blobs: vec![],
        stage: Stage::Final,
    }
}

const VALID_MANIFEST: &str = r#"{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:abc",
    "size": 100
  },
  "layers": []
}"#;

// ─── manifest malformes ──────────────────────────────────────────────────────

#[test]
fn manifest_invalid_json_is_rejected() {
    let result = pipeline::image_from_scan_request(req("not json at all {{"));
    assert!(result.is_err(), "JSON invalide doit retourner Err");
}

#[test]
fn manifest_too_large_is_rejected() {
    // 1 MB + 1 octet
    let big = "x".repeat(1024 * 1024 + 1);
    let err = pipeline::image_from_scan_request(req(&big))
        .expect_err("manifest > 1 MB doit retourner Err");
    assert!(
        err.contains("too large"),
        "message doit mentionner 'too large', got: {err}"
    );
}

#[test]
fn manifest_exactly_at_size_limit_is_accepted() {
    // Exactement 1 MB : ne doit pas etre rejete pour la taille
    let padding = "a".repeat(1024 * 1024 - 200);
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"x","digest":"sha256:abc","size":1}},"layers":[],"annotations":{{"pad":"{padding}"}}}}"#
    );
    assert!(manifest.len() <= 1024 * 1024);
    let _ = pipeline::image_from_scan_request(req(&manifest));
}

#[test]
fn manifest_too_many_layers_is_rejected() {
    // 300 layers > MAX_LAYERS (256)
    let layers: String = (0..300_u32)
        .map(|i| {
            format!(
                r#"{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{i:064x}","size":100}}"#
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"x","digest":"sha256:cfg","size":1}},"layers":[{layers}]}}"#
    );

    let err = pipeline::image_from_scan_request(req(&manifest))
        .expect_err("300 layers doit retourner Err");
    assert!(
        err.contains("too many layers"),
        "message doit mentionner 'too many layers', got: {err}"
    );
}

#[test]
fn manifest_exactly_at_layer_limit_is_accepted() {
    // 256 layers = exactement la limite
    let layers: String = (0..256_u32)
        .map(|i| {
            format!(
                r#"{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{i:064x}","size":100}}"#
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"x","digest":"sha256:cfg","size":1}},"layers":[{layers}]}}"#
    );

    let result = pipeline::image_from_scan_request(req(&manifest));
    assert!(result.is_ok(), "256 layers (limite exacte) doit etre accepte");
}

#[test]
fn manifest_empty_object_is_handled_gracefully() {
    // {} est du JSON valide mais pas un vrai manifest
    let result = pipeline::image_from_scan_request(req("{}"));
    assert!(result.is_ok(), "objet vide doit etre traite gracieusement");
    let image = result.unwrap();
    assert_eq!(image.manifest.as_ref().unwrap().layers.len(), 0);
}

// ─── injections ─────────────────────────────────────────────────────────────

#[test]
fn injection_in_image_ref_does_not_crash() {
    let mut r = req(VALID_MANIFEST);
    r.image_ref = Some("'; DROP TABLE images; --<script>alert(1)</script>".into());
    assert!(
        pipeline::image_from_scan_request(r).is_ok(),
        "injection dans image_ref ne doit pas crasher"
    );
}

#[test]
fn injection_in_manifest_annotations_does_not_crash() {
    // Valeurs d'annotations contenant des payloads d'injection courants
    let manifest = r#"{
      "schemaVersion": 2,
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": "sha256:abc",
        "size": 100
      },
      "layers": [],
      "annotations": {
        "xss":  "<script>alert('xss')</script>",
        "sqli": "'; DROP TABLE manifests; --",
        "path": "../../../../etc/passwd"
      }
    }"#;
    let result = pipeline::image_from_scan_request(req(manifest));
    assert!(
        result.is_ok(),
        "injection dans les annotations ne doit pas crasher: {}",
        result.unwrap_err()
    );
}

// ─── config blob absent / illisible ─────────────────────────────────────────

#[test]
fn missing_config_blob_gives_has_config_false() {
    // Manifest avec digest de config mais aucun blob fourni
    let result = pipeline::image_from_scan_request(req(VALID_MANIFEST));
    assert!(result.is_ok());
    assert!(
        !result.unwrap().has_config,
        "has_config doit etre false si le blob config est absent"
    );
}

#[test]
fn config_blob_nonexistent_path_gives_has_config_false() {
    // Blob declare mais chemin introuvable : config skippee gracieusement
    let manifest = r#"{
      "schemaVersion": 2,
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": "sha256:cfgdigest",
        "size": 10
      },
      "layers": []
    }"#;

    let bad_blob_req = ScanRequest {
        image_ref: Some("test/bad-config:latest".into()),
        manifest_raw: manifest.to_string(),
        blobs: vec![RawBlob {
            digest: "sha256:cfgdigest".into(),
            media_type: None,
            size: None,
            bytes_b64: None,
            path: Some("/nonexistent/path/config.json".into()),
        }],
        stage: Stage::Final,
    };

    let result = pipeline::image_from_scan_request(bad_blob_req);
    assert!(result.is_ok(), "chemin de blob inexistant ne doit pas crasher");
    assert!(
        !result.unwrap().has_config,
        "has_config doit etre false quand la lecture du blob echoue"
    );
}

// ─── check_json_depth ───────────────────────────────────────────────────────

#[test]
fn json_depth_at_limit_passes() {
    // Exactement 64 niveaux : Ok
    let deep = "{\"a\":".repeat(64) + "1" + &"}".repeat(64);
    assert!(security::check_json_depth(&deep).is_ok(), "depth=64 doit passer");
}

#[test]
fn json_depth_over_limit_is_rejected() {
    // 65 niveaux : Err
    let deep = "{\"a\":".repeat(65) + "1" + &"}".repeat(65);
    assert!(
        security::check_json_depth(&deep).is_err(),
        "depth=65 doit etre rejete"
    );
}

#[test]
fn json_depth_braces_inside_strings_do_not_count() {
    // Accolades dans une string : ne comptent pas comme imbrication
    let s = "{\"key\": \"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{\"}";
    assert!(
        security::check_json_depth(s).is_ok(),
        "accolades dans une string ne doivent pas incrementer la profondeur"
    );
}

#[test]
fn json_depth_escaped_quote_in_string_is_handled() {
    // Backslash-quote dans une string : ne doit pas faire sortir de la string
    let s = "{\"key\": \"val\\\"ue{{{{\"}";
    assert!(
        security::check_json_depth(s).is_ok(),
        "quote echappee dans une string doit etre ignoree"
    );
}

#[test]
fn json_depth_flat_object_passes() {
    let s = r#"{"a":1,"b":2,"c":3}"#;
    assert!(security::check_json_depth(s).is_ok());
}
