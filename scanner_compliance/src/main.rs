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
// Rules (Step 2)
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

        // On récupère user (Option<String>) et on normalise
        let user = image.config.user.clone().unwrap_or_default();
        evidence.insert("config.user".to_string(), user.clone());

        // Cas considérés "root"
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
    // Test local en dur (pas de JSON, pas de samples pour l'instant)
    let image = ImageData {
        meta: ImageMeta {
            image_ref: "example/app:1.0".to_string(),
            digest: Some("sha256:deadbeef".to_string()),
        },
        config: ImageConfig {
            user: Some("root".to_string()), // change en "1000" pour voir PASS
            env: HashMap::new(),
            labels: HashMap::new(),
            entrypoint: vec![],
            cmd: vec![],
        },
        fs_paths: vec![],
    };

    let rules: Vec<Box<dyn Rule>> = vec![Box::new(NonRootUserRule)];

    let report = run_rules(&image, &rules);

    // On affiche le report en JSON propre (utile pour voir le format)
    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    println!("{json}");
}
