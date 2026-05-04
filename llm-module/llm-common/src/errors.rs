use thiserror::Error;

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("Erreur HTTP : {0}")]
    Http(String),

    #[error("Réponse JSON invalide du modèle {model} : {reason}")]
    InvalidResponse { model: String, reason: String },

    #[error("Timeout dépassé ({timeout_secs}s) pour le modèle {model}")]
    Timeout { model: String, timeout_secs: u64 },

    #[error("Artefact introuvable dans la quarantaine : {0}")]
    ArtifactNotFound(String),

    #[error("Erreur lecture fichier : {0}")]
    Io(#[from] std::io::Error),

    #[error("Backend LLM indisponible : {0}")]
    BackendUnavailable(String),

    #[error("Pipeline LLM dégradé : {0}")]
    PipelineFailed(String),

    #[error("Entrée invalide : {0}")]
    InvalidInput(String),
}
