use reqwest::Client;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;

use llm_common::LlmError;

// ============================================================
// Client MCP HTTP — JSON-RPC 2.0 stateless
// ============================================================

/// Client HTTP simple pour le mcp-tools-server.
///
/// Utilise le mode stateless+JSON : chaque POST est indépendant,
/// pas de session ni de handshake `initialize` à gérer.
///
/// Format JSON-RPC 2.0 :
///   POST /mcp
///   Content-Type: application/json
///   { "jsonrpc":"2.0", "id":N, "method":"tools/list" }
///   → { "jsonrpc":"2.0", "id":N, "result":{...} }
pub struct McpClient {
    client: Client,
    base_url: String,
    request_id: AtomicU64,
}

impl McpClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .expect("Impossible de créer le client HTTP MCP"),
            base_url,
            request_id: AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Envoie une requête JSON-RPC et retourne le champ `result`.
    async fn rpc(&self, method: &str, params: Option<Value>) -> Result<Value, LlmError> {
        let id = self.next_id();
        let mut body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
        });
        if let Some(p) = params {
            body["params"] = p;
        }

        let resp = self
            .client
            .post(&self.base_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::BackendUnavailable(format!("MCP server injoignable : {e}")))?;

        if !resp.status().is_success() {
            return Err(LlmError::Http(format!(
                "MCP server HTTP {} pour la méthode {}",
                resp.status(),
                method
            )));
        }

        let value: Value = resp
            .json()
            .await
            .map_err(|e| LlmError::Http(format!("MCP JSON invalide : {e}")))?;

        if let Some(err) = value.get("error") {
            return Err(LlmError::Http(format!("Erreur MCP : {}", err)));
        }

        Ok(value["result"].clone())
    }

    /// Récupère la liste des tools exposés par le serveur MCP.
    /// Retourne les schémas au format MCP natif (inputSchema).
    pub async fn list_tools(&self) -> Result<Vec<Value>, LlmError> {
        let result = self.rpc("tools/list", None).await?;
        let tools = result["tools"].as_array().cloned().unwrap_or_default();
        info!("MCP tools disponibles : {}", tools.len());
        for t in &tools {
            info!("  - {}", t["name"].as_str().unwrap_or("?"));
        }
        Ok(tools)
    }

    /// Exécute un tool MCP et retourne le texte du résultat.
    ///
    /// Le résultat MCP est un tableau `content` avec des items de type `text`.
    /// On concatène tous les textes en une seule chaîne.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<String, LlmError> {
        info!("Exécution MCP tool : {}", name);

        let result = self
            .rpc(
                "tools/call",
                Some(json!({
                    "name": name,
                    "arguments": arguments,
                })),
            )
            .await?;

        // Extraire tous les items texte du tableau content
        let text = result["content"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| item["text"].as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();

        Ok(text)
    }

    /// Vérifie que le serveur MCP répond (appel tools/list léger).
    pub async fn ping(&self) -> Result<(), LlmError> {
        self.list_tools().await?;
        Ok(())
    }
}

// ============================================================
// Conversion MCP → OpenAI function calling
// ============================================================

/// Convertit un schéma MCP natif en format OpenAI function calling.
///
/// Ajoute deux champs au schéma de paramètres :
/// - `quarantine_path` : chemin exact de la quarantaine pour cette image
/// - `reasoning` : explication du worker (pourquoi ce scan est nécessaire)
/// - `confidence` : niveau de confiance du worker (0.0–1.0)
///
/// Ces champs supplémentaires sont ignorés par le serveur MCP lors de
/// l'exécution réelle (serde ignore les champs inconnus par défaut).
pub fn mcp_to_openai_schema(mcp_tool: &Value, quarantine_path: &str) -> Value {
    let name = mcp_tool["name"].as_str().unwrap_or("unknown");
    let description = mcp_tool["description"].as_str().unwrap_or("");

    json!({
        "type": "function",
        "function": {
            "name": name,
            "description": format!(
                "Call this tool to RECOMMEND running this scan (do not call it if you think the scan is unnecessary). {}",
                description
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "quarantine_path": {
                        "type": "string",
                        "description": format!(
                            "Absolute path to the quarantine folder for this image. \
                             Use exactly this value: {}",
                            quarantine_path
                        )
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Specific evidence from the image artifacts that justifies \
                                        running this scan. Be precise: cite concrete findings \
                                        (package names, versions, env vars, labels, entrypoint, etc.)."
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Your confidence level that this scan is needed (0.0 = uncertain, 1.0 = certain)"
                    }
                },
                "required": ["quarantine_path", "reasoning", "confidence"]
            }
        }
    })
}

/// Retourne le schéma OpenAI de l'outil `image_is_clean`.
///
/// Cet outil est appelé par un worker quand il estime qu'aucun scan n'est nécessaire.
/// Il permet d'utiliser le format tool calling même pour un verdict "image propre",
/// ce qui est requis par `tool_choice: "required"`.
pub fn image_is_clean_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "image_is_clean",
            "description": "Call this tool if you have analyzed all artifacts and determined \
                            that NO security scans are needed. The image appears safe and clean.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reasoning": {
                        "type": "string",
                        "description": "Explain specifically why no scans are needed: \
                                        what did you check and why is the image considered safe?"
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Your confidence that no scans are needed (0.0 = uncertain, 1.0 = certain)"
                    }
                },
                "required": ["reasoning", "confidence"]
            }
        }
    })
}
