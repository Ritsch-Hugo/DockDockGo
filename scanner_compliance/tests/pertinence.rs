use scanner_compliance::models::{
    ImageConfig, ImageData, ImageMeta, InputsSummary, ManifestData, Report, ScanInfo, ScanRequest,
    Stage, Status,
};
use scanner_compliance::pipeline;
use std::collections::HashMap;

// ─── helpers ────────────────────────────────────────────────────────────────

fn assert_finding(report: &Report, rule_id: &str, expected: Status) {
    let finding = report
        .findings
        .iter()
        .find(|f| f.rule_id == rule_id)
        .unwrap_or_else(|| panic!("regle '{}' non trouvee dans le report", rule_id));
    assert_eq!(
        finding.status, expected,
        "regle '{}': attendu {:?}, obtenu {:?} — {}",
        rule_id, expected, finding.status, finding.message
    );
}

fn scan_sample(name: &str) -> Report {
    let path = format!("{}/samples/{}", env!("CARGO_MANIFEST_DIR"), name);
    let image = pipeline::load_image_from_json_file(&path)
        .unwrap_or_else(|e| panic!("echec chargement {}: {}", name, e));
    pipeline::scan_image(&image)
}

// ─── image_ok : bien configuree, 0 FAIL attendu ─────────────────────────────

#[test]
fn image_ok_has_no_failures() {
    let report = scan_sample("image_ok.json");
    let failures: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.status == Status::FAIL)
        .collect();
    assert!(
        failures.is_empty(),
        "image_ok doit avoir 0 FAIL, got: {:?}",
        failures.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}

#[test]
fn image_ok_non_root_passes() {
    assert_finding(&scan_sample("image_ok.json"), "NON_ROOT_USER", Status::PASS);
}

#[test]
fn image_ok_no_sensitive_env() {
    assert_finding(
        &scan_sample("image_ok.json"),
        "SENSITIVE_ENV_VARS",
        Status::PASS,
    );
}

#[test]
fn image_ok_has_entrypoint() {
    assert_finding(
        &scan_sample("image_ok.json"),
        "ENTRYPOINT_CMD_PRESENT",
        Status::PASS,
    );
}

// ─── image_root : user root → NON_ROOT_USER=FAIL ────────────────────────────

#[test]
fn image_root_fails_non_root_check() {
    assert_finding(
        &scan_sample("image_root.json"),
        "NON_ROOT_USER",
        Status::FAIL,
    );
}

#[test]
fn image_root_other_rules_not_affected() {
    let report = scan_sample("image_root.json");
    // L'entrypoint est present : ne doit pas FAIL pour ca
    assert_finding(&report, "ENTRYPOINT_CMD_PRESENT", Status::PASS);
    assert_finding(&report, "SENSITIVE_ENV_VARS", Status::PASS);
}

// ─── image_env_secret : secrets en env → SENSITIVE_ENV_VARS=FAIL ────────────

#[test]
fn image_env_secret_fails_sensitive_env_check() {
    assert_finding(
        &scan_sample("image_env_secret.json"),
        "SENSITIVE_ENV_VARS",
        Status::FAIL,
    );
}

#[test]
fn image_env_secret_non_root_still_passes() {
    // Le secret env ne doit pas impacter les autres regles
    assert_finding(
        &scan_sample("image_env_secret.json"),
        "NON_ROOT_USER",
        Status::PASS,
    );
}

// ─── image_bad_runtime : pas d'entrypoint, port 22, volume ──────────────────

#[test]
fn image_bad_runtime_fails_entrypoint_check() {
    assert_finding(
        &scan_sample("image_bad_runtime.json"),
        "ENTRYPOINT_CMD_PRESENT",
        Status::FAIL,
    );
}

#[test]
fn image_bad_runtime_warns_on_port_22() {
    // Port 22 (SSH) est dans la liste des ports sensibles
    assert_finding(
        &scan_sample("image_bad_runtime.json"),
        "EXPOSED_PORTS_POLICY",
        Status::WARN,
    );
}

#[test]
fn image_bad_runtime_warns_on_volumes() {
    assert_finding(
        &scan_sample("image_bad_runtime.json"),
        "VOLUMES_POLICY",
        Status::WARN,
    );
}

// ─── image_missing_labels : labels vides → REQUIRED_OCI_LABELS=FAIL ─────────

#[test]
fn image_missing_labels_fails_required_labels_check() {
    assert_finding(
        &scan_sample("image_missing_labels.json"),
        "REQUIRED_OCI_LABELS",
        Status::FAIL,
    );
}

// ─── image_bad_perms : world-writable + setuid → DANGEROUS_PERMISSIONS=WARN ─

#[test]
fn image_bad_perms_warns_on_dangerous_permissions() {
    // mode 0o777 (world-writable) et 0o4755 (setuid) doivent etre detectes
    assert_finding(
        &scan_sample("image_bad_perms.json"),
        "DANGEROUS_PERMISSIONS",
        Status::WARN,
    );
}

// ─── image_fs_secret : .env et id_rsa → FS_SECRETS=FAIL ─────────────────────

#[test]
fn image_fs_secret_fails_fs_secrets_check() {
    // /app/.env et /root/.ssh/id_rsa sont des secrets connus
    assert_finding(
        &scan_sample("image_fs_secret.json"),
        "FS_SECRETS",
        Status::FAIL,
    );
}

// ─── image_forbidden_bins : /bin/nc → FORBIDDEN_BINARIES=WARN ────────────────

#[test]
fn image_forbidden_bins_warns_on_netcat() {
    // /bin/nc est dans la liste des binaires interdits
    assert_finding(
        &scan_sample("image_forbidden_bins.json"),
        "FORBIDDEN_BINARIES",
        Status::WARN,
    );
}

// ─── alpine manifest-only : pas de config/blobs → config+FS rules = SKIP ────

#[test]
fn alpine_manifest_only_skips_config_and_fs_rules() {
    // Simule la reception d'un manifest alpine:3.21 sans config ni layers
    // (cas reel : le proxy envoie d'abord le manifest seul)
    let manifest_raw = r#"{
      "schemaVersion": 2,
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "config": {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": "sha256:e7b39c54cdeca0d2aae83114bb605753a5f5bc511fe8be7590e38f6d9f915dad",
        "size": 611
      },
      "layers": [
        {
          "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
          "digest": "sha256:1074353eec0db2c1d81d5af2671e56e00cf5738486f5762609ea33d606f88612",
          "size": 3860104
        }
      ],
      "annotations": {
        "org.opencontainers.image.version": "3.21.0"
      }
    }"#;

    let req = ScanRequest {
        image_ref: Some("library/alpine:3.21".into()),
        manifest_raw: manifest_raw.to_string(),
        blobs: vec![],
        stage: Stage::ManifestOnly,
    };

    let image = pipeline::image_from_scan_request(req)
        .expect("ScanRequest alpine valide doit etre accepte");
    let report = pipeline::scan_image(&image);

    // Sans config ni blobs : toutes les regles config et FS doivent etre SKIP
    for rule_id in &[
        "NON_ROOT_USER",
        "SENSITIVE_ENV_VARS",
        "ENTRYPOINT_CMD_PRESENT",
        "WORKING_DIR_PRESENT",
        "REQUIRED_OCI_LABELS",
        "EXPOSED_PORTS_POLICY",
        "VOLUMES_POLICY",
        "FORBIDDEN_BINARIES",
        "DANGEROUS_PERMISSIONS",
        "FS_SECRETS",
        "FS_HYGIENE",
        "FS_WEAK_CONFIGS",
    ] {
        assert_finding(&report, rule_id, Status::SKIP);
    }

    assert_eq!(report.summary.fail, 0, "manifest-only doit avoir 0 FAIL");
}

// ─── image parfaite synthetique : reference pour prouver qu'un 0 FAIL est possible

fn perfect_image() -> ImageData {
    let mut labels = HashMap::new();
    labels.insert(
        "org.opencontainers.image.source".into(),
        "https://github.com/example/app".into(),
    );
    labels.insert("org.opencontainers.image.revision".into(), "abc123".into());

    let mut annotations = HashMap::new();
    annotations.insert(
        "org.opencontainers.image.source".into(),
        "https://github.com/example/app".into(),
    );

    ImageData {
        meta: ImageMeta {
            image_ref: "example/perfect:1.0".into(),
            digest: None,
        },
        has_manifest: true,
        has_config: true,
        has_fs: false,
        scan: ScanInfo {
            stage: Stage::Final,
            inputs: InputsSummary {
                has_manifest: true,
                has_config: true,
                has_fs: false,
                layers_total: 1,
                layers_received: 1,
            },
        },
        config: ImageConfig {
            user: Some("1000".into()),
            env: HashMap::new(),
            labels,
            entrypoint: vec!["/app/server".into()],
            cmd: vec![],
            working_dir: Some("/app".into()),
            exposed_ports: vec![],
            volumes: vec![],
        },
        fs_paths: vec![],
        fs_entries: vec![],
        manifest: Some(ManifestData {
            media_type: Some("application/vnd.oci.image.manifest.v1+json".into()),
            layers_count: Some(1),
            annotations,
            config_digest: None,
            layers: vec![],
        }),
        missing_artifacts: vec![],
    }
}

#[test]
fn perfect_image_has_zero_failures() {
    let report = pipeline::scan_image(&perfect_image());
    let failures: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.status == Status::FAIL)
        .collect();
    assert!(
        failures.is_empty(),
        "image parfaite doit avoir 0 FAIL, got: {:?}",
        failures.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
    );
}
