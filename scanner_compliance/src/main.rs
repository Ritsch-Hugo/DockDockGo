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

        // patterns simples (tu pourras affiner)
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
        // Masquage simple : on ne veut pas afficher un secret en clair
        // On garde juste la longueur pour debug.
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

        // Evidence: on liste les clés et valeurs masquées
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

fn main() {
    // Test en dur pour Step 3 (pas de samples pour l'instant)
    let mut env = HashMap::new();
    env.insert("APP_ENV".to_string(), "prod".to_string());
    env.insert("API_TOKEN".to_string(), "supersecretvalue".to_string()); // => FAIL SensitiveEnvRule

    let mut labels = HashMap::new();
    labels.insert(
        "org.opencontainers.image.source".to_string(),
        "https://github.com/example/app".to_string(),
    );
    // revision manquant => WARN RequiredLabelsRule

    let image = ImageData {
        meta: ImageMeta {
            image_ref: "example/app:1.0".to_string(),
            digest: Some("sha256:deadbeef".to_string()),
        },
        config: ImageConfig {
            user: Some("1000".to_string()), // PASS non-root
            env,
            labels,
            entrypoint: vec!["/app/server".to_string()],
            cmd: vec!["--port".to_string(), "8080".to_string()],
            working_dir: Some("/app".to_string()),
            exposed_ports: vec!["8080/tcp".to_string()],
            volumes: vec![],
        },
        fs_paths: vec![],
    };

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(NonRootUserRule),
        Box::new(RequiredLabelsRule),
        Box::new(SensitiveEnvRule),
    ];

    let report = run_rules(&image, &rules);

    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    println!("{json}");
}
