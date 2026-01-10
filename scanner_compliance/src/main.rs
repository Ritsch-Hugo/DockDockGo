use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageData {
    pub meta: ImageMeta,
    pub config: ImageConfig,

    /// Vue simplifiée du filesystem final (optionnelle pour l'instant)
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

    /// Preuve exploitable plus tard par "le docteur"
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

fn main() {
    println!("scanner_compliance: data models ready (step 1)");
}
