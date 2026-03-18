use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Identifiant optionnel (corrélation orchestrateur)
    pub request_id: Option<String>,

    /// Chemin vers le manifest JSON (OCI / Docker v2)
    pub manifest_path: String,

    /// Chemin vers le config JSON (optionnel en V1)
    pub config_path: Option<String>,

    /// Racine du blob-store local, ex: "/var/lib/dockdockgo/blobs"
    /// On supposera ensuite blobs/sha256/<digest>
    pub blob_store_dir: String,

    /// Métadonnées libres (image_ref, registry, etc.)
    #[serde(default)]
    pub meta: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanStatus {
    Pending,
    Complete,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub vulnerabilities_total: u64,
    #[serde(default)]
    pub severity_count: SeverityCount,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCount {
    pub unknown: u64,
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub critical: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveFinding {
    pub cve_id: String,
    pub package: Option<String>,
    pub installed_version: Option<String>,
    pub fixed_version: Option<String>,
    pub severity: String,

    /// CVSS (si dispo plus tard via Trivy). On le met déjà dans le modèle.
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,

    /// Description courte optionnelle
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResponse {
    pub request_id: Option<String>,
    pub status: ScanStatus,

    /// Si PENDING : quelles layers manquent (digest "sha256:...")
    #[serde(default)]
    pub missing_layers: Vec<String>,

    /// Message humain (debug)
    pub message: Option<String>,

    /// Résumé (quand COMPLETE)
    pub summary: Option<ScanSummary>,

    /// Détails (quand COMPLETE)
    #[serde(default)]
    pub findings: Vec<CveFinding>,

    /// Optionnel : output brut Trivy
    pub raw_trivy_json: Option<serde_json::Value>,

    /// Recopie meta utile pour l’orchestrateur
    #[serde(default)]
    pub meta: serde_json::Value,
}
