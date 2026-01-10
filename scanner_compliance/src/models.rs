use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageData {
    pub meta: ImageMeta,
    pub config: ImageConfig,

    #[serde(default)]
    pub fs_paths: Vec<String>,

    #[serde(default)]
    pub fs_entries: Vec<FsEntry>,

    #[serde(default)]
    pub manifest: Option<ManifestData>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestData {
    #[serde(default)]
    pub media_type: Option<String>,

    #[serde(default)]
    pub layers_count: Option<u32>,

    #[serde(default)]
    pub annotations: HashMap<String, String>,
}
