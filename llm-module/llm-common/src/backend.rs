use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

use crate::errors::LlmError;
use crate::traits::LlmBackend;
use crate::types::ChatMessage;

// ============================================================
// Structures pour l'API native Ollama (/api/chat)
// On utilise l'API native et non l'endpoint OpenAI-compatible
// car "format: json" n'est supporté que sur /api/chat.
// Sur /v1/chat/completions (OpenAI), le champ serait
// response_format: {type: json_object} — différent.
// ============================================================

#[derive(Serialize)]
struct OllamaChatOptions {
    /// Température basse = réponses plus déterministes et structurées.
    temperature: f32,
}

#[derive(Serialize)]
struct OllamaChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage>,
    stream: bool,
    /// "json" force le modèle à produire du JSON valide — natif Ollama /api/chat.
    format: &'static str,
    options: OllamaChatOptions,
}

/// Réponse de /api/chat (format natif Ollama).
/// Contrairement à /v1/chat/completions, la réponse contient
/// "message" (singulier) et non "choices" (tableau OpenAI).
#[derive(Deserialize)]
struct OllamaChatResponse {
    message: OllamaMessage,
}

#[derive(Deserialize)]
struct OllamaMessage {
    content: String,
}

#[derive(Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModelInfo>,
}

#[derive(Deserialize)]
pub struct OllamaModelInfo {
    pub name: String,
}

// ============================================================
// OllamaBackend — implémentation concrète de LlmBackend
// Partagée entre llm-manager (gestion) et llm-decision (inférence)
// ============================================================

pub struct OllamaBackend {
    client: Client,
    base_url: String,
    timeout_secs: u64,
}

impl OllamaBackend {
    pub fn new(base_url: String, timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs + 10))
            .build()
            .expect("Impossible de créer le client HTTP");

        Self { client, base_url, timeout_secs }
    }

    /// Liste tous les modèles disponibles dans Ollama.
    pub async fn list_models(&self) -> Result<Vec<OllamaModelInfo>, LlmError> {
        let url = format!("{}/api/tags", self.base_url);

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| LlmError::BackendUnavailable(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(LlmError::BackendUnavailable(format!(
                "GET /api/tags retourné HTTP {}",
                resp.status()
            )));
        }

        let tags: OllamaTagsResponse =
            resp.json().await.map_err(|e| LlmError::Http(e.to_string()))?;

        Ok(tags.models)
    }

    /// Vérifie qu'Ollama répond (appel léger).
    pub async fn ping(&self) -> Result<(), LlmError> {
        let url = format!("{}/api/version", self.base_url);
        self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| LlmError::BackendUnavailable(format!("Ollama injoignable : {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl LlmBackend for OllamaBackend {
    async fn chat(
        &self,
        model: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<String, LlmError> {
        // API native Ollama : /api/chat (supporte format: "json")
        let url = format!("{}/api/chat", self.base_url);

        let body = OllamaChatRequest {
            model,
            messages,
            stream: false,
            format: "json",
            options: OllamaChatOptions { temperature: 0.1 },
        };

        let fut = self.client.post(&url).json(&body).send();

        let resp = timeout(Duration::from_secs(self.timeout_secs), fut)
            .await
            .map_err(|_| LlmError::Timeout {
                model: model.to_string(),
                timeout_secs: self.timeout_secs,
            })?
            .map_err(|e| LlmError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(LlmError::Http(format!(
                "Ollama HTTP {} pour le modèle {}",
                resp.status(),
                model
            )));
        }

        let chat_resp: OllamaChatResponse =
            resp.json().await.map_err(|e| LlmError::InvalidResponse {
                model: model.to_string(),
                reason: e.to_string(),
            })?;

        Ok(chat_resp.message.content)
    }

    async fn is_healthy(&self, model: &str) -> Result<bool, LlmError> {
        self.ping().await?;
        let models = self.list_models().await?;
        Ok(models
            .iter()
            .any(|m| m.name == model || m.name.starts_with(&format!("{model}:"))))
    }
}
