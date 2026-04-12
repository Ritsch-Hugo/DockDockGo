use async_trait::async_trait;

use crate::errors::LlmError;
use crate::types::{ChatMessage, LlmResponse};

/// Abstraction du backend d'inférence LLM.
///
/// Permet de swapper Ollama ↔ vLLM sans toucher à la logique décisionnelle.
/// Toute la logique de llm-decision et llm-manager utilise ce trait,
/// jamais les types concrets directement.
#[async_trait]
pub trait LlmBackend: Send + Sync {
    /// Envoie une conversation à un modèle avec des tool schemas optionnels.
    ///
    /// `tools` est une liste de schemas au format OpenAI function calling :
    /// `[{"type":"function","function":{"name":"...","description":"...","parameters":{...}}}]`
    ///
    /// Retourne soit du texte libre, soit une liste de tool calls selon la réponse du LLM.
    ///
    /// # Sécurité
    /// Les messages doivent avoir été sanitisés (prompt injection) avant cet appel.
    async fn chat_with_tools(
        &self,
        model: &str,
        messages: Vec<ChatMessage>,
        tools: Vec<serde_json::Value>,
    ) -> Result<LlmResponse, LlmError>;

    /// Envoie une conversation sans tools — retourne toujours du texte brut.
    ///
    /// Implémentation par défaut : appelle `chat_with_tools` avec tools vide
    /// et extrait le texte. À utiliser pour les prompts simples (ex: arbitre,
    /// ou appels qui n'ont pas besoin de tool calling).
    async fn chat(
        &self,
        model: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<String, LlmError> {
        match self.chat_with_tools(model, messages, vec![]).await? {
            LlmResponse::Text(t) => Ok(t),
            LlmResponse::ToolCalls(calls) => {
                // Sans tools déclarés, le LLM ne devrait pas émettre de tool calls.
                // Si ça arrive quand même, on sérialise pour garder l'info.
                Ok(serde_json::to_string(&calls)
                    .unwrap_or_else(|_| "[]".to_string()))
            }
        }
    }

    /// Vérifie que le backend est disponible et que le modèle spécifié est chargé.
    async fn is_healthy(&self, model: &str) -> Result<bool, LlmError>;
}
