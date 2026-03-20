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
    pub confidence: f32,
    /// Explication du vote, conservée pour audit et historique.
    pub reasoning: String,
}

/// Décision finale après arbitrage, retournée à l'orchestrateur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDecision {
    /// UUID du pull concerné, pour corrélation avec l'orchestrateur.
    pub pull_id: Uuid,
    pub run_static_scan: bool,
    pub run_compliance_scan: bool,
    pub run_dynamic_scan: bool,
    /// Confiance finale de l'arbitre (0.0 – 1.0).
    pub final_confidence: f32,
    /// Explication de l'arbitre sur sa décision finale.
    pub arbiter_rationale: String,
    /// Votes des 3 workers, conservés pour audit et historique.
    pub votes: Vec<LlmVote>,
}
