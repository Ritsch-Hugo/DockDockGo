use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --------------------
// Data models (Step 1)
// --------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageData {
    pub meta: ImageMeta,
    pub config: ImageConfig,

    #[serde(default)]
    pub fs_paths: Vec<String>,

    #[serde(default)]
    pub fs_entries: Vec<FsEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta {
    pub image_ref: String,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(default)]
    pub user: Option<String>,

    #[serde(default)]
    pub env: HashMap<String, String>,

    #[serde(default)]
    pub labels: HashMap<String, String>,

    #[serde(default)]
    pub entrypoint: Vec<String>,

    #[serde(default)]
    pub cmd: Vec<String>,

    #[serde(default)]
    pub working_dir: Option<String>,

    #[serde(default)]
    pub exposed_ports: Vec<String>,

    #[serde(default)]
    pub volumes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEntry {
    pub path: String,

    /// Mode Unix (ex: 0o100644). Optionnel.
    #[serde(default)]
    pub mode: Option<u32>,

    /// "file" | "dir" | "symlink" (optionnel, pour plus tard)
    #[serde(default)]
    pub kind: Option<String>,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub meta: ImageMeta,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Summary {
    pub pass: u32,
    pub warn: u32,
    pub fail: u32,
    pub skip: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub status: Status,
    pub message: String,

    #[serde(default)]
    pub evidence: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Status {
    PASS,
    WARN,
    FAIL,
    SKIP,
}

// --------------------
// Rules (Step 2/3)
// --------------------

pub trait Rule {
    fn id(&self) -> &'static str;
    fn evaluate(&self, image: &ImageData) -> Finding;
}

/// Rule: l'image ne doit pas tourner en root.
pub struct NonRootUserRule;

impl Rule for NonRootUserRule {
    fn id(&self) -> &'static str {
        "NON_ROOT_USER"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let mut evidence = HashMap::new();

        let user = image.config.user.clone().unwrap_or_default();
        evidence.insert("config.user".to_string(), user.clone());

        let is_root = user.is_empty() || user == "root" || user == "0";

        if is_root {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::FAIL,
                message: "Container runs as root (config.user is empty/root/0)".to_string(),
                evidence,
            }
        } else {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "Container runs as non-root user".to_string(),
                evidence,
            }
        }
    }
}

/// Rule: labels OCI requis pour traçabilité.
pub struct RequiredLabelsRule;

impl Rule for RequiredLabelsRule {
    fn id(&self) -> &'static str {
        "REQUIRED_OCI_LABELS"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        // Liste minimale (tu pourras l'étendre)
        let required = [
            "org.opencontainers.image.source",
            "org.opencontainers.image.revision",
        ];

        let labels = &image.config.labels;

        let mut missing: Vec<&str> = Vec::new();
        for key in required {
            if !labels.contains_key(key) {
                missing.push(key);
            }
        }

        let mut evidence = HashMap::new();
        evidence.insert(
            "missing_labels".to_string(),
            missing.join(", "),
        );

        if labels.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::FAIL,
                message: "No OCI labels found: image is not traceable".to_string(),
                evidence,
            };
        }

        if !missing.is_empty() {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::WARN,
                message: "Some required OCI labels are missing".to_string(),
                evidence,
            }
        } else {
            Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "Required OCI labels are present".to_string(),
                evidence: HashMap::new(),
            }
        }
    }
}

/// Rule: détecte des variables d'environnement potentiellement sensibles.
pub struct SensitiveEnvRule;

impl SensitiveEnvRule {
    fn is_sensitive_key(key: &str) -> bool {
        let k = key.to_ascii_uppercase();

        let patterns = [
            "PASSWORD",
            "PASS",
            "TOKEN",
            "SECRET",
            "API_KEY",
            "AWS_SECRET",
            "PRIVATE_KEY",
            "ACCESS_KEY",
        ];

        patterns.iter().any(|p| k.contains(p))
    }

    fn mask_value(value: &str) -> String {
        if value.is_empty() {
            return "".to_string();
        }
        format!("*** (len={})", value.len())
    }
}

impl Rule for SensitiveEnvRule {
    fn id(&self) -> &'static str {
        "SENSITIVE_ENV_VARS"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let mut found: Vec<(String, String)> = Vec::new();

        for (k, v) in &image.config.env {
            if Self::is_sensitive_key(k) {
                found.push((k.clone(), Self::mask_value(v)));
            }
        }

        if found.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No sensitive environment variables detected".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut evidence = HashMap::new();
        for (k, masked) in found {
            evidence.insert(format!("env.{k}"), masked);
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::FAIL,
            message: "Sensitive environment variables detected".to_string(),
            evidence,
        }
    }
}

/// Rule: détecte des fichiers secrets dans l'image via chemins connus.
pub struct FsSecretsRule;

impl Rule for FsSecretsRule {
    fn id(&self) -> &'static str {
        "FS_SECRETS"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let paths = all_paths(image);

        let suspicious_suffixes = [".env", ".pem", ".key", ".p12", ".pfx"];
        let suspicious_exact = ["id_rsa", "id_ed25519", "kubeconfig", ".npmrc", ".pypirc"];

        let mut hits: Vec<String> = Vec::new();

        for p in paths {
            let lower = p.to_ascii_lowercase();

            if suspicious_exact.iter().any(|x| lower.ends_with(x) || lower.contains(x)) {
                hits.push(p);
                continue;
            }

            if suspicious_suffixes.iter().any(|s| lower.ends_with(s)) {
                hits.push(p);
                continue;
            }

            if lower.contains("/.ssh/") || lower.contains("/secrets/") {
                hits.push(p);
                continue;
            }
        }

        if hits.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No obvious secret files detected in filesystem".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut evidence = HashMap::new();
        for (i, h) in hits.iter().take(25).enumerate() {
            evidence.insert(format!("hit_{i}"), h.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::FAIL,
            message: "Potential secret files detected in image filesystem".to_string(),
            evidence,
        }
    }
}

/// Rule: binaires/services interdits (surface d'attaque).
pub struct ForbiddenBinariesRule;

impl Rule for ForbiddenBinariesRule {
    fn id(&self) -> &'static str {
        "FORBIDDEN_BINARIES"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let paths = all_paths(image);

        let forbidden_names = [
            "sshd",
            "dropbear",
            "nc",
            "netcat",
            "socat",
            "telnet",
            "gcc",
            "g++",
            "clang",
            "make",
            "perl",
            "python",
        ];

        let mut hits: Vec<String> = Vec::new();

        for p in paths {
            let base = p.rsplit('/').next().unwrap_or(&p);
            let b = base.to_ascii_lowercase();

            if forbidden_names.iter().any(|name| b == *name) {
                hits.push(p);
            }
        }

        if hits.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No forbidden binaries detected (by filename)".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut evidence = HashMap::new();
        for (i, h) in hits.iter().take(25).enumerate() {
            evidence.insert(format!("bin_{i}"), h.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::WARN,
            message: "Forbidden binaries detected (hardening recommended)".to_string(),
            evidence,
        }
    }
}

/// Rule: permissions dangereuses (world-writable, SUID/SGID).
/// Si on n'a pas les modes => SKIP (normal en V1).
pub struct DangerousPermissionsRule;

impl Rule for DangerousPermissionsRule {
    fn id(&self) -> &'static str {
        "DANGEROUS_PERMISSIONS"
    }

    fn evaluate(&self, image: &ImageData) -> Finding {
        let pairs = path_modes(image);

        if pairs.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::SKIP,
                message: "No file modes provided (fs_entries.mode missing), cannot evaluate permissions".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut world_writable: Vec<String> = Vec::new();
        let mut suid_sgid: Vec<String> = Vec::new();

        for (path, mode) in pairs {
            if (mode & 0o002) != 0 {
                world_writable.push(format!("{path} (mode={:#o})", mode));
            }

            if (mode & 0o4000) != 0 || (mode & 0o2000) != 0 {
                suid_sgid.push(format!("{path} (mode={:#o})", mode));
            }
        }

        if world_writable.is_empty() && suid_sgid.is_empty() {
            return Finding {
                rule_id: self.id().to_string(),
                status: Status::PASS,
                message: "No dangerous permissions detected (world-writable/SUID/SGID)".to_string(),
                evidence: HashMap::new(),
            };
        }

        let mut evidence = HashMap::new();
        for (i, h) in world_writable.iter().take(15).enumerate() {
            evidence.insert(format!("world_writable_{i}"), h.clone());
        }
        for (i, h) in suid_sgid.iter().take(15).enumerate() {
            evidence.insert(format!("suid_sgid_{i}"), h.clone());
        }

        Finding {
            rule_id: self.id().to_string(),
            status: Status::WARN,
            message: "Dangerous permissions detected (world-writable and/or SUID/SGID)".to_string(),
            evidence,
        }
    }
}




// --------------------
// Mini engine (Step 2)
// --------------------

pub fn run_rules(image: &ImageData, rules: &[Box<dyn Rule>]) -> Report {
    let mut findings: Vec<Finding> = Vec::new();
    let mut summary = Summary::default();

    for rule in rules {
        let finding = rule.evaluate(image);

        match finding.status {
            Status::PASS => summary.pass += 1,
            Status::WARN => summary.warn += 1,
            Status::FAIL => summary.fail += 1,
            Status::SKIP => summary.skip += 1,
        }

        findings.push(finding);
    }

    Report {
        meta: image.meta.clone(),
        summary,
        findings,
    }
}

fn all_paths(image: &ImageData) -> Vec<String> {
    if !image.fs_entries.is_empty() {
        return image
            .fs_entries
            .iter()
            .map(|e| e.path.clone())
            .collect();
    }
    image.fs_paths.clone()
}

fn path_modes(image: &ImageData) -> Vec<(&str, u32)> {
    image
        .fs_entries
        .iter()
        .filter_map(|e| e.mode.map(|m| (e.path.as_str(), m)))
        .collect()
}


fn load_image_from_json(path: &str) -> Result<ImageData, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {path}: {e}"))?;

    serde_json::from_str::<ImageData>(&content)
        .map_err(|e| format!("failed to parse JSON {path}: {e}"))
}

fn usage() -> String {
    "Usage:\n  cargo run -- <input.json>\nExample:\n  cargo run -- samples/image_ok.json\n".to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("{}", usage());
        std::process::exit(2);
    }

    let input_path = &args[1];
    let image = match load_image_from_json(input_path) {
        Ok(img) => img,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(NonRootUserRule),
        Box::new(RequiredLabelsRule),
        Box::new(SensitiveEnvRule),
        Box::new(FsSecretsRule),
        Box::new(ForbiddenBinariesRule),
        Box::new(DangerousPermissionsRule),
    ];

    let report = run_rules(&image, &rules);

    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    println!("{json}");

    // Exit code simple (utile plus tard en CI)
    // 0 = aucun FAIL, 1 = au moins un FAIL
    if report.summary.fail > 0 {
        std::process::exit(1);
    }
}
