use async_trait::async_trait;

use crate::errors::LlmError;
use crate::types::ChatMessage;

/// Abstraction du backend d'inférence LLM.
///
/// Permet de swapper Ollama ↔ vLLM sans toucher à la logique décisionnelle.
/// Toute la logique de llm-decision et llm-manager utilise ce trait,
/// jamais les types concrets directement.
#[async_trait]
pub trait LlmBackend: Send + Sync {
    /// Envoie une conversation à un modèle et retourne la réponse texte brute.
    ///
    /// # Sécurité
    /// Les messages doivent avoir été sanitisés (prompt injection) avant cet appel.
    async fn chat(
        &self,
        model: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<String, LlmError>;

    /// Vérifie que le backend est disponible et que le modèle spécifié est chargé.
    async fn is_healthy(&self, model: &str) -> Result<bool, LlmError>;
}
