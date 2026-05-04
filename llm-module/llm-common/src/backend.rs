use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

use crate::errors::LlmError;
use crate::traits::LlmBackend;
use crate::types::{ChatMessage, LlmResponse, ToolCall};

// ============================================================
// Structures pour l'API OpenAI-compat (Ollama, vLLM, etc.)
// POST /v1/chat/completions — supporte le tool calling natif.
// ============================================================

/// Requête envoyée à /v1/chat/completions.
#[derive(Serialize)]
struct OpenAiRequest<'a> {
    model: &'a str,
    messages: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<&'a str>,
    stream: bool,
    temperature: f32,
}

/// Réponse de /v1/chat/completions.
#[derive(Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

#[derive(Deserialize)]
struct OpenAiMessage {
    /// Présent quand le LLM répond en texte libre.
    content: Option<String>,
    /// Présent quand le LLM décide d'appeler un ou plusieurs tools.
    tool_calls: Option<Vec<OpenAiToolCall>>,
}

#[derive(Deserialize)]
struct OpenAiToolCall {
    function: OpenAiFunction,
}

#[derive(Deserialize)]
struct OpenAiFunction {
    name: String,
    /// Les arguments sont un JSON sérialisé en string par le format OpenAI.
    arguments: String,
}

// ============================================================
// Structures pour les endpoints de découverte des modèles
// vLLM : GET /v1/models  (format OpenAI standard)
// ============================================================

/// Réponse de GET /v1/models (format OpenAI).
#[derive(Deserialize)]
struct ModelsListResponse {
    data: Vec<ModelInfo>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ModelInfo {
    /// Identifiant du modèle : chemin HuggingFace (ex: "ibm-granite/granite-3.3-8b-instruct")
    /// ou nom court selon le backend.
    pub id: String,
}

// ============================================================
// OpenAiBackend — implémentation concrète de LlmBackend
// Compatible avec tout backend exposant l'API OpenAI : vLLM, Ollama, etc.
// Partagée entre llm-manager (gestion) et llm-decision (inférence)
// ============================================================

pub struct OpenAiBackend {
    client: Client,
    base_url: String,
    timeout_secs: u64,
    api_key: Option<String>,
}

impl OpenAiBackend {
    pub fn new(base_url: String, timeout_secs: u64, api_key: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs + 10))
            .build()
            .expect("Impossible de créer le client HTTP");

        Self { client, base_url, timeout_secs, api_key }
    }

    pub fn http_client(&self) -> &Client {
        &self.client
    }

    /// Liste tous les modèles disponibles via GET /v1/models (format OpenAI standard).
    pub async fn list_models(&self) -> Result<Vec<ModelInfo>, LlmError> {
        let url = format!("{}/v1/models", self.base_url);

        let mut req = self.client.get(&url);
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| LlmError::BackendUnavailable(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(LlmError::BackendUnavailable(format!(
                "GET /v1/models retourné HTTP {}",
                resp.status()
            )));
        }

        let list: ModelsListResponse =
            resp.json().await.map_err(|e| LlmError::Http(e.to_string()))?;

        Ok(list.data)
    }

    /// Vérifie que le backend LLM répond.
    /// vLLM/Ollama : GET /health — OpenRouter : GET /v1/models (pas de /health).
    pub async fn ping(&self) -> Result<(), LlmError> {
        let url = if self.api_key.is_some() {
            format!("{}/v1/models", self.base_url)
        } else {
            format!("{}/health", self.base_url)
        };

        let mut req = self.client.get(&url);
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| LlmError::BackendUnavailable(format!("LLM backend injoignable : {e}")))?;

        if !resp.status().is_success() {
            return Err(LlmError::BackendUnavailable(format!(
                "ping retourné HTTP {}",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Convertit un ChatMessage en serde_json::Value au format OpenAI.
    fn message_to_json(msg: &ChatMessage) -> serde_json::Value {
        serde_json::json!({
            "role": msg.role,
            "content": msg.content,
        })
    }
}

#[async_trait]
impl LlmBackend for OpenAiBackend {
    /// Appel principal — POST /v1/chat/completions avec tool schemas optionnels.
    ///
    /// Si `tools` est vide, Ollama répond en texte libre.
    /// Si `tools` contient des schemas, le LLM peut émettre des tool_calls.
    async fn chat_with_tools(
        &self,
        model: &str,
        messages: Vec<ChatMessage>,
        tools: Vec<serde_json::Value>,
    ) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/v1/chat/completions", self.base_url);

        // "required" force le modèle à faire un tool call plutôt que répondre en texte.
        // Sans ça, les modèles tendent à ignorer les tools et répondre en texte libre.
        let tool_choice = if tools.is_empty() { None } else { Some("required") };

        let body = OpenAiRequest {
            model,
            messages: messages.iter().map(Self::message_to_json).collect(),
            tools,
            tool_choice,
            stream: false,
            temperature: 0.0,
        };

        let mut req = self.client.post(&url).json(&body);
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
        let fut = req.send();

        let resp = timeout(Duration::from_secs(self.timeout_secs), fut)
            .await
            .map_err(|_| LlmError::Timeout {
                model: model.to_string(),
                timeout_secs: self.timeout_secs,
            })?
            .map_err(|e| LlmError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(LlmError::Http(format!(
                "LLM backend HTTP {} pour le modèle {}",
                resp.status(),
                model
            )));
        }

        let openai_resp: OpenAiResponse =
            resp.json().await.map_err(|e| LlmError::InvalidResponse {
                model: model.to_string(),
                reason: e.to_string(),
            })?;

        let message = openai_resp
            .choices
            .into_iter()
            .next()
            .map(|c| c.message)
            .ok_or_else(|| LlmError::InvalidResponse {
                model: model.to_string(),
                reason: "Réponse LLM backend sans aucun choix".to_string(),
            })?;

        // Cas 1 : le LLM a émis des tool_calls
        if let Some(tool_calls) = message.tool_calls {
            if !tool_calls.is_empty() {
                let calls = tool_calls
                    .into_iter()
                    .map(|tc| {
                        // Les arguments arrivent comme string JSON — on les parse
                        let arguments =
                            serde_json::from_str(&tc.function.arguments).unwrap_or_else(|_| {
                                serde_json::Value::String(tc.function.arguments.clone())
                            });
                        ToolCall {
                            name: tc.function.name,
                            arguments,
                        }
                    })
                    .collect();
                return Ok(LlmResponse::ToolCalls(calls));
            }
        }

        // Cas 2 : le LLM a répondu en texte libre
        let text = message.content.unwrap_or_default();
        Ok(LlmResponse::Text(text))
    }

    async fn is_healthy(&self, model: &str) -> Result<bool, LlmError> {
        self.ping().await?;
        let models = self.list_models().await?;
        let model_lower = model.to_lowercase();
        // Correspondance flexible : le nom court peut être contenu dans l'id complet
        // (ex: "granite3.3:8b" ⊂ "ibm-granite/granite-3.3-8b-instruct")
        // ou être identique pour les backends qui retournent des noms courts.
        Ok(models.iter().any(|m| {
            let id_lower = m.id.to_lowercase();
            id_lower == model_lower
                || id_lower.contains(&model_lower)
                || model_lower.contains(&id_lower)
        }))
    }
}
