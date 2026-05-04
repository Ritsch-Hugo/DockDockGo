use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================
// Artefacts OCI
// ============================================================

/// Identifiant de contenu OCI (algorithme + valeur hex).
/// Structure identique à celle de l'orchestrateur — ne pas modifier
/// sans synchroniser avec l'équipe.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest {
    pub algorithm: String,
    pub value: String,
}

impl Digest {
    /// Nom du fichier dans la quarantaine (la valeur seule, sans algorithme).
    pub fn filename(&self) -> &str {
        &self.value
    }

    /// Représentation complète : "sha256:abc123..."
    pub fn full(&self) -> String {
        format!("{}:{}", self.algorithm, self.value)
    }
}

/// Contexte d'un pull Docker envoyé par l'orchestrateur.
/// Doit rester strictement identique à la définition dans l'orchestrateur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullContext {
    pub uuid: Uuid,
    pub ip_client: String,
    pub registry: String,
    pub repository: String,
    pub tag: String,

    pub manifest_digests: Vec<Digest>,
    pub blob_digests: Vec<Digest>,
    pub referrers_digests: Vec<Digest>,

    pub manifest_racine_digest: Option<Digest>,
    pub digests_possible: Vec<Digest>,
    pub digests_expected: Vec<Digest>,

    pub os: String,
    pub arch: String,
    pub pull_completed: bool,
}

// ============================================================
// Contenu des artefacts lus depuis la quarantaine
// ============================================================

/// Contenu d'un fichier artefact.
/// Les binaires (layers gzip) ne sont jamais chargés en mémoire entièrement :
/// on conserve uniquement leur taille pour éviter de surcharger les prompts.
#[derive(Debug, Clone)]
pub enum ArtifactContent {
    /// Fichier JSON (config OCI, attestation in-toto, manifest) — envoyable dans un prompt.
    Json(String),
    /// Fichier binaire (layer gzip) — on note seulement la taille, le contenu est ignoré.
    Binary { size_bytes: u64 },
}

/// Un artefact individuel avec son digest et son contenu.
#[derive(Debug, Clone)]
pub struct ArtifactFile {
    pub digest: String,
    pub content: ArtifactContent,
}

/// Ensemble complet des artefacts d'une image, prêts pour l'analyse LLM.
#[derive(Debug, Clone)]
pub struct ArtifactBundle {
    pub pull_context: PullContext,
    pub manifests: Vec<ArtifactFile>,
    pub blobs: Vec<ArtifactFile>,
    pub referrers: Vec<ArtifactFile>,
    /// Contenu du sbom.json (CycloneDX 1.5 JSON) si présent dans la quarantaine.
    pub sbom: Option<String>,
}

// ============================================================
// Messages LLM
// ============================================================

/// Message dans une conversation LLM, format compatible OpenAI / Ollama.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// "system" | "user" | "assistant"
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: "system".to_string(),
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: "user".to_string(),
            content: content.into(),
        }
    }
}

// ============================================================
// Tool calling
// ============================================================

/// Un appel d'outil émis par le LLM (format OpenAI tool_calls).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Nom de l'outil à appeler (ex: "run_static_scan").
    pub name: String,
    /// Arguments parsés depuis le JSON retourné par le LLM.
    pub arguments: serde_json::Value,
}

/// Réponse possible d'un LLM en mode tool calling.
///
/// Le LLM peut soit répondre avec du texte (analyse libre),
/// soit émettre un ou plusieurs tool calls (décision d'exécuter des scans).
#[derive(Debug, Clone)]
pub enum LlmResponse {
    /// Le LLM a répondu avec du texte libre (pas de scan demandé).
    Text(String),
    /// Le LLM a demandé l'exécution d'un ou plusieurs outils.
    ToolCalls(Vec<ToolCall>),
}

// ============================================================
// Décision de scan
// ============================================================

/// Vote d'un LLM worker sur les scans à effectuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmVote {
    /// Identifiant du modèle ayant voté (ex: "qwen3:7b").
    pub model_id: String,
    pub run_static_scan: bool,
    pub run_compliance_scan: bool,
    pub run_dynamic_scan: bool,
    /// Confiance du modèle dans sa propre décision (0.0 – 1.0).
    pub confidence: f64,
    /// Explication du vote, conservée pour audit et historique.
    pub reasoning: String,
}

// ============================================================
// Types phase 3 — rapport final
// ============================================================

/// Verdict final de l'image : décision ALLOW/DENY + score de vulnérabilité.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    /// "ALLOW" ou "DENY"
    pub decision: String,
    /// Score de vulnérabilité CVSS-like (0.0 = aucun risque, 10.0 = critique).
    pub vulnerability_score: f64,
    pub confidence: f64,
    pub rationale: String,
}

/// Résultat d'un scan individuel avec résumé produit par les LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub executed: bool,
    pub llm_summary: Option<String>,
    pub raw_result: Option<serde_json::Value>,
}

/// Résultats des trois types de scan (statique, compliance, dynamique).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAnalysis {
    /// Champ JSON "static" — mot-clé Rust, renommé via serde.
    #[serde(rename = "static")]
    pub static_scan: ScanResult,
    pub compliance: ScanResult,
    pub dynamic: ScanResult,
}

/// Analyse de vulnérabilité produite par un worker en phase 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerAnalysis {
    pub model: String,
    /// "ok" | "failed"
    pub status: String,
    pub vulnerability_score: Option<f64>,
    pub confidence: Option<f64>,
    pub reasoning: Option<String>,
}

/// Verdict de synthèse produit par l'arbitre en phase 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbiterAnalysis {
    pub model: String,
    pub vulnerability_score: f64,
    pub confidence: f64,
    pub reasoning: String,
}

/// Raisonnements des workers et de l'arbitre sur les résultats des scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReasoning {
    pub workers: Vec<WorkerAnalysis>,
    pub arbiter: ArbiterAnalysis,
}

/// Image alternative proposée quand la décision est DENY.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alternative {
    pub image: String,
    pub reason: String,
    pub confidence: f64,
}

/// Métadonnées d'un worker en phase 1 (décision des scans), pour audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionWorkerMeta {
    pub model: String,
    pub status: String,
    pub run_static_scan: Option<bool>,
    pub run_compliance_scan: Option<bool>,
    pub run_dynamic_scan: Option<bool>,
    pub confidence: Option<f64>,
    pub reasoning: Option<String>,
}

/// Métadonnées de l'arbitre en phase 1, pour audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionArbiterMeta {
    pub model: String,
    pub reasoning: String,
}

/// Métadonnées complètes de la phase 1 conservées dans le rapport final pour audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionMetadata {
    pub workers: Vec<DecisionWorkerMeta>,
    pub arbiter: DecisionArbiterMeta,
}

/// Rapport final complet retourné à l'orchestrateur après les phases 1, 2 et 3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalReport {
    pub pull_id: Uuid,
    pub image: String,
    /// Horodatage ISO 8601 de l'analyse (ex: "2026-04-25T13:14:02Z").
    pub analysed_at: String,
    pub verdict: Verdict,
    pub scan_analysis: ScanAnalysis,
    pub scan_reasoning: ScanReasoning,
    pub alternatives: Vec<Alternative>,
    pub decision_metadata: DecisionMetadata,
}

// ============================================================
// Décision finale après arbitrage (phase 1+2)
// ============================================================

/// Décision finale après arbitrage, retournée à l'orchestrateur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDecision {
    /// UUID du pull concerné, pour corrélation avec l'orchestrateur.
    pub pull_id: Uuid,

    // --- Décision ---
    pub run_static_scan: bool,
    pub run_compliance_scan: bool,
    pub run_dynamic_scan: bool,
    /// Confiance finale de l'arbitre (0.0 – 1.0).
    pub final_confidence: f64,
    /// Explication de l'arbitre sur sa décision finale.
    pub arbiter_rationale: String,
    /// Votes des 3 workers, conservés pour audit et historique.
    pub votes: Vec<LlmVote>,
    /// Indices (0-based) des workers dont le raisonnement a été déterminant.
    /// Ex : [0, 2] si l'arbitre a suivi les workers 1 et 3.
    /// Vide si aucun worker n'a fourni de preuve convaincante (fail-safe ou image propre).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selected_worker_indices: Vec<usize>,

    // --- Résultats des scans exécutés via MCP ---
    /// Résultat du scan statique CVE (Trivy). None si non lancé ou échoué.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_scan_result: Option<serde_json::Value>,
    /// Résultat du scan de conformité. None si non lancé ou échoué.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance_scan_result: Option<serde_json::Value>,
    /// Résultat du scan dynamique. None si non lancé ou non implémenté.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_scan_result: Option<serde_json::Value>,
}
