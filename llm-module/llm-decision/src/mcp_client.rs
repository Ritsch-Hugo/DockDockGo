use reqwest::Client;
use serde_json::{json, Value};
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
    pub fn new(base_url: String, timeout_secs: u64) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_secs))
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
            .header("MCP-Protocol-Version", "2025-03-26")
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

/// Retourne le schéma OpenAI de l'outil `make_security_decision`.
///
/// Cet outil est appelé par l'arbitre pour soumettre sa décision finale.
/// Utiliser tool calling au lieu de JSON texte libre évite que le mode
/// "thinking" de Qwen3.5 pollue la réponse avec du texte non parseable.
pub fn make_security_decision_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "make_security_decision",
            "description": "Submit the final security verdict for the Docker image. \
                            You MUST call this tool — do not respond in plain text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "run_static_scan": {
                        "type": "boolean",
                        "description": "Whether to run a static CVE scan (Trivy)"
                    },
                    "run_compliance_scan": {
                        "type": "boolean",
                        "description": "Whether to run a compliance scan"
                    },
                    "run_dynamic_scan": {
                        "type": "boolean",
                        "description": "Whether to run a dynamic behavioral scan"
                    },
                    "final_confidence": {
                        "type": "number",
                        "description": "Confidence in this decision (0.0 = very uncertain, 1.0 = very certain)"
                    },
                    "arbiter_rationale": {
                        "type": "string",
                        "description": "Explanation citing which workers had strong or weak reasoning and why. Be specific about the evidence quality."
                    },
                    "selected_worker_indices": {
                        "type": "array",
                        "items": { "type": "integer" },
                        "description": "0-based indices of workers whose reasoning was decisive. \
                                        E.g. [0, 2] if workers 1 and 3 had the strongest reasoning. \
                                        Empty array if no worker provided convincing evidence."
                    }
                },
                "required": [
                    "run_static_scan",
                    "run_compliance_scan",
                    "run_dynamic_scan",
                    "final_confidence",
                    "arbiter_rationale",
                    "selected_worker_indices"
                ]
            }
        }
    })
}

/// Retourne le schéma OpenAI de l'outil `submit_vulnerability_analysis` (workers phase 3).
///
/// Les workers analysent les résultats des scans et soumettent leur évaluation
/// de vulnérabilité. Les alternatives sont traitées dans un second tour séparé
/// pour éviter que la possibilité de proposer des alternatives ne biaise le score.
pub fn submit_vulnerability_analysis_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "submit_vulnerability_analysis",
            "description": "Submit your vulnerability assessment of the Docker image scan results. \
                            You MUST call this tool — do not respond in plain text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "vulnerability_score": {
                        "type": "number",
                        "description": "Vulnerability score from 0.0 (no risk) to 10.0 (critical). \
                                        CVSS-like scale: 0–3.9 low, 4–6.9 medium, 7–8.9 high, 9–10 critical. \
                                        Base your score strictly on what the scan results show."
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Your confidence in this assessment (0.0 = uncertain, 1.0 = certain)"
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Detailed reasoning: which findings are most concerning and why. \
                                        Reference specific CVE IDs, CVSS scores, compliance rule failures."
                    },
                    "static_summary": {
                        "type": "string",
                        "description": "If a static CVE scan was run: 1-2 sentence summary. \
                                        Mention critical CVEs, affected packages, and whether a fix version exists."
                    },
                    "compliance_summary": {
                        "type": "string",
                        "description": "If a compliance scan was run: 1-2 sentence summary. \
                                        Mention specific failed rules and their security impact."
                    }
                },
                "required": ["vulnerability_score", "confidence", "reasoning"]
            }
        }
    })
}

/// Retourne le schéma OpenAI de l'outil `make_final_verdict` (arbitre phase 3).
///
/// L'arbitre synthétise les analyses des workers et produit le verdict final.
/// Les alternatives sont gérées dans un second tour séparé si la décision est DENY.
pub fn make_final_verdict_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "make_final_verdict",
            "description": "Submit the final security verdict after synthesizing all worker assessments. \
                            You MUST call this tool — do not respond in plain text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "decision": {
                        "type": "string",
                        "enum": ["ALLOW", "DENY"],
                        "description": "ALLOW if the image is safe to run, DENY if it should be blocked."
                    },
                    "vulnerability_score": {
                        "type": "number",
                        "description": "Final vulnerability score 0.0–10.0, synthesized from worker assessments."
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence in this verdict (0.0 = uncertain, 1.0 = certain)"
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Explanation of the verdict: which workers had strong reasoning, \
                                        which findings were decisive, and why ALLOW or DENY."
                    }
                },
                "required": ["decision", "vulnerability_score", "confidence", "rationale"]
            }
        }
    })
}

/// Retourne le schéma OpenAI de l'outil `suggest_alternatives` (workers phase 3, second tour).
///
/// Appelé uniquement si le verdict est DENY. Les workers suggèrent des images
/// alternatives en se basant sur le type de l'image refusée et les raisons du refus.
pub fn suggest_alternatives_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "suggest_alternatives",
            "description": "Suggest safer alternative Docker images to replace the denied image. \
                            You MUST call this tool — do not respond in plain text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alternatives": {
                        "type": "array",
                        "description": "List of 1-3 safer alternative images. \
                                        Base suggestions on the image type and the denial reasons.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "image": {
                                    "type": "string",
                                    "description": "Full image reference (e.g. cgr.dev/chainguard/alpine-base:latest). \
                                                    Only suggest images you are confident exist."
                                },
                                "reason": {
                                    "type": "string",
                                    "description": "Why this alternative is safer and compatible with the same workload."
                                },
                                "confidence": {
                                    "type": "number",
                                    "description": "Confidence that this alternative is suitable (0.0–1.0)"
                                }
                            },
                            "required": ["image", "reason", "confidence"]
                        }
                    }
                },
                "required": ["alternatives"]
            }
        }
    })
}

/// Retourne le schéma OpenAI de l'outil `finalize_alternatives` (arbitre phase 3, second tour).
///
/// L'arbitre sélectionne les meilleures alternatives parmi les suggestions des workers,
/// en évaluant la qualité du raisonnement de chacun.
pub fn finalize_alternatives_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "finalize_alternatives",
            "description": "Select the best alternative images from worker suggestions. \
                            You MUST call this tool — do not respond in plain text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alternatives": {
                        "type": "array",
                        "description": "Final curated list of 1-3 alternatives. \
                                        Select from worker suggestions based on reasoning quality. \
                                        You may consolidate duplicates or adjust wording, \
                                        but only include images that at least one worker argued for specifically.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "image": {
                                    "type": "string",
                                    "description": "Full image reference as suggested by a worker."
                                },
                                "reason": {
                                    "type": "string",
                                    "description": "Why this alternative was selected: cite the worker reasoning \
                                                    that made it convincing."
                                },
                                "confidence": {
                                    "type": "number",
                                    "description": "Confidence that this alternative is suitable (0.0–1.0)"
                                }
                            },
                            "required": ["image", "reason", "confidence"]
                        }
                    }
                },
                "required": ["alternatives"]
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
