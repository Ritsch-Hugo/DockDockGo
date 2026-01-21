use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageData {
    pub meta: ImageMeta,

    /// ⚠️ Pour ne pas casser l'existant : par défaut on considère que config/fs sont dispos.
    /// Quand on construit ImageData depuis ScanRequest stage1, on mettra ces flags à false.
    #[serde(default = "default_true")]
    pub has_manifest: bool,

    #[serde(default = "default_true")]
    pub has_config: bool,

    #[serde(default = "default_true")]
    pub has_fs: bool,

    /// Infos scan (stage + inputs observés). Absent dans l’ancien JSON => default.
    #[serde(default)]
    pub scan: ScanInfo,

    /// Runtime config (toujours présent dans l’ancien format JSON)
    pub config: ImageConfig,

    /// FS (ancien format) : on garde pour compat.
    #[serde(default)]
    pub fs_paths: Vec<String>,

    #[serde(default)]
    pub fs_entries: Vec<FsEntry>,

    /// Manifest "résumé" (pas le raw)
    #[serde(default)]
    pub manifest: Option<ManifestData>,

    #[serde(default)]
pub missing_artifacts: Vec<MissingArtifact>,
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

    /// "file" | "dir" | "symlink" (optionnel)
    #[serde(default)]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanInfo {
    #[serde(default)]
    pub stage: Stage,

    #[serde(default)]
    pub inputs: InputsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InputsSummary {
    #[serde(default)]
    pub has_manifest: bool,
    #[serde(default)]
    pub has_config: bool,
    #[serde(default)]
    pub has_fs: bool,

    #[serde(default)]
    pub layers_total: u32,
    
    #[serde(default)]
pub layers_received: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    ManifestOnly,
    ManifestConfig,
    PartialLayers,
    Final,
    /// Pour les vieux appels qui n'ont pas de stage
    Legacy,
}

impl Default for Stage {
    fn default() -> Self {
        Stage::Legacy
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub meta: ImageMeta,

    /// Pour compat : si absent on a Default()
    #[serde(default)]
    pub scan: ScanInfo,

    pub summary: Summary,
    pub findings: Vec<Finding>,

    #[serde(default)]
pub missing_artifacts: Vec<MissingArtifact>,

    /// Pseudo-Dockerfile informatif (FINAL ONLY)
    #[serde(default)]
    pub pseudo_dockerfile: Option<String>,

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestLayer {
    pub digest: String,
    pub media_type: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestData {
    pub media_type: Option<String>,
    pub layers_count: Option<u32>,
    pub annotations: HashMap<String, String>,
    pub config_digest: Option<String>,
    pub layers: Vec<ManifestLayer>,
}


/// --- NOUVEAU : contrat d’entrée raw (Étape 1: manifest-only) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub stage: Stage,

    /// Optionnel (si le MCP veut le passer)
    #[serde(default)]
    pub image_ref: Option<String>,

    /// Manifest JSON brut (string)
    pub manifest_raw: String,

    /// Pour Étape 1 on ne l’utilise pas encore
    #[serde(default)]
    pub blobs: Vec<RawBlob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawBlob {
    pub digest: String,

    #[serde(default)]
    pub media_type: Option<String>,

    #[serde(default)]
    pub size: Option<u64>,

    /// V1: bytes en base64 (optionnel)
    #[serde(default)]
    pub bytes_b64: Option<String>,

    /// V1: path local (optionnel)
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingArtifact {
    pub kind: MissingArtifactKind,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingArtifactKind {
    Config,
    Layer,
}

