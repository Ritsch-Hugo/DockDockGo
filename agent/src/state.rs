use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Etat global d'une analyse DockDockGo (1 run = 1 AgentState).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    /// Identifiant unique pour tracer logs et résultats.
    pub run_id: String,

    /// Référence de l'image analysée (ex: "nginx:latest" ou digest).
    pub image_ref: String,

    /// Manifest brut ou résumé (optionnel selon votre pipeline).
    pub manifest: Option<Value>,

    /// SBOM normalisé (optionnel, rempli après génération/récupération).
    pub sbom: Option<Value>,

    /// Résultats de scans (statique/dynamique/compliance/obsolescence).
    pub scan_results: Vec<ScanResult>,

    /// Rapport final (optionnel, rempli à la fin).
    pub final_report: Option<Value>,
}
