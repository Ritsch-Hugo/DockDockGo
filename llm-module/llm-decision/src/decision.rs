use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{error, info, warn};
use uuid::Uuid;

use llm_common::{ArtifactBundle, Config, LlmBackend, LlmError, LlmResponse, LlmVote, ScanDecision, ToolCall};

use crate::mcp_client::McpClient;
use crate::prompt::{build_arbiter_prompt, build_worker_prompt};

// ============================================================
// Structures de parsing
// ============================================================

/// Format JSON attendu de l'arbitre.
#[derive(Deserialize)]
struct ArbiterResponse {
    run_static_scan: bool,
    run_compliance_scan: bool,
    run_dynamic_scan: bool,
    final_confidence: f32,
    arbiter_rationale: String,
}

// ============================================================
// Décision fail-safe
// ============================================================

/// Décision fail-safe : si tous les workers échouent, on lance tous les scans.
/// Principe de précaution — mieux vaut trop scanner que pas assez.
fn fail_safe_decision(pull_id: Uuid) -> ScanDecision {
    error!("Fail-safe activé : tous les scans seront lancés");
    ScanDecision {
        pull_id,
        run_static_scan: true,
        run_compliance_scan: true,
        run_dynamic_scan: true,
        final_confidence: 0.0,
        arbiter_rationale: "Fail-safe : tous les workers LLM ont échoué. \
            Tous les scans sont lancés par précaution."
            .to_string(),
        votes: vec![],
        static_scan_result: None,
        compliance_scan_result: None,
        dynamic_scan_result: None,
    }
}

// ============================================================
// Parsing des votes workers (depuis tool calls)
// ============================================================

/// Convertit la réponse LLM d'un worker en LlmVote.
///
/// Le worker exprime ses recommandations via des tool calls :
/// - `run_static_scan` appelé → recommande le scan statique
/// - `run_compliance_scan` appelé → recommande le scan compliance
/// - `run_dynamic_scan` appelé → recommande le scan dynamique
/// - Aucun tool appelé → aucun scan recommandé (vote valide)
///
/// Si le LLM répond en texte libre (pas de tool calls), on log un avertissement
/// et on traite ça comme "aucun scan recommandé" (réponse valide mais inhabituelle).
fn parse_worker_vote(model: &str, response: LlmResponse) -> LlmVote {
    match response {
        LlmResponse::ToolCalls(calls) => extract_vote_from_tool_calls(model, calls),
        LlmResponse::Text(text) => {
            warn!(
                "Worker {} : réponse texte au lieu de tool calls (\"{}...\")",
                model,
                text.chars().take(80).collect::<String>()
            );
            // Texte libre = le modèle n'a pas retourné de tool calls valides.
            // Traité comme "aucun scan recommandé" avec faible confiance.
            LlmVote {
                model_id: model.to_string(),
                run_static_scan: false,
                run_compliance_scan: false,
                run_dynamic_scan: false,
                confidence: 0.3,
                reasoning: format!(
                    "Model returned text instead of tool calls — interpreted as no scans needed. \
                     Raw response: {}",
                    text.chars().take(200).collect::<String>()
                ),
            }
        }
    }
}

/// Extrait un LlmVote depuis la liste de tool calls d'un worker.
fn extract_vote_from_tool_calls(model: &str, calls: Vec<ToolCall>) -> LlmVote {
    let mut run_static = false;
    let mut run_compliance = false;
    let mut run_dynamic = false;
    let mut reasonings: Vec<String> = Vec::new();
    let mut confidences: Vec<f32> = Vec::new();

    for tc in &calls {
        let reasoning = tc.arguments
            .get("reasoning")
            .and_then(|v| v.as_str())
            .unwrap_or("No reasoning provided")
            .to_string();

        let confidence = tc.arguments
            .get("confidence")
            .and_then(|v| v.as_f64())
            .map(|f| f as f32)
            .unwrap_or(0.7_f32)
            .clamp(0.0, 1.0);

        match tc.name.as_str() {
            "run_static_scan" => {
                run_static = true;
                reasonings.push(format!("[static] {}", reasoning));
                confidences.push(confidence);
            }
            "run_compliance_scan" => {
                run_compliance = true;
                reasonings.push(format!("[compliance] {}", reasoning));
                confidences.push(confidence);
            }
            "run_dynamic_scan" => {
                run_dynamic = true;
                reasonings.push(format!("[dynamic] {}", reasoning));
                confidences.push(confidence);
            }
            "image_is_clean" => {
                // Le worker estime que l'image est propre — aucun scan recommandé.
                reasonings.push(format!("[clean] {}", reasoning));
                confidences.push(confidence);
            }
            unknown => {
                warn!("Worker {} : tool call inconnu ignoré : {}", model, unknown);
            }
        }
    }

    // Confiance moyenne sur les tools appelés (0.5 si aucun tool appelé)
    let confidence = if confidences.is_empty() {
        0.5
    } else {
        confidences.iter().sum::<f32>() / confidences.len() as f32
    };

    let reasoning = if reasonings.is_empty() {
        // Ne devrait pas arriver avec tool_choice:"required" — mais géré par sécurité
        "No tool called (unexpected) — treated as no scan needed.".to_string()
    } else {
        reasonings.join(" | ")
    };

    LlmVote {
        model_id: model.to_string(),
        run_static_scan: run_static,
        run_compliance_scan: run_compliance,
        run_dynamic_scan: run_dynamic,
        confidence,
        reasoning,
    }
}

// ============================================================
// Exécution des scans via MCP
// ============================================================

/// Exécute les scans décidés par l'arbitre via le serveur MCP.
///
/// Pour chaque scan activé, appelle le tool MCP correspondant et stocke
/// le résultat JSON dans le ScanDecision pour l'orchestrateur.
async fn execute_scans(
    decision: &mut ScanDecision,
    mcp_client: &McpClient,
    quarantine_path: &str,
) {
    let args = json!({ "quarantine_path": quarantine_path });

    if decision.run_static_scan {
        info!("Exécution scan statique CVE via MCP...");
        match mcp_client.call_tool("run_static_scan", args.clone()).await {
            Ok(result_text) => {
                // Le résultat est du JSON retourné par Trivy
                let parsed: Value = serde_json::from_str(&result_text)
                    .unwrap_or_else(|_| Value::String(result_text));
                decision.static_scan_result = Some(parsed);
                info!("Scan statique terminé");
            }
            Err(e) => {
                error!("Scan statique échoué : {}", e);
                decision.static_scan_result = Some(json!({
                    "error": e.to_string(),
                    "status": "ERROR"
                }));
            }
        }
    }

    if decision.run_compliance_scan {
        info!("Exécution scan compliance via MCP...");
        match mcp_client.call_tool("run_compliance_scan", args.clone()).await {
            Ok(result_text) => {
                let parsed: Value = serde_json::from_str(&result_text)
                    .unwrap_or_else(|_| Value::String(result_text));
                decision.compliance_scan_result = Some(parsed);
                info!("Scan compliance terminé");
            }
            Err(e) => {
                error!("Scan compliance échoué : {}", e);
                decision.compliance_scan_result = Some(json!({
                    "error": e.to_string(),
                    "status": "ERROR"
                }));
            }
        }
    }

    if decision.run_dynamic_scan {
        info!("Exécution scan dynamique via MCP...");
        match mcp_client.call_tool("run_dynamic_scan", args.clone()).await {
            Ok(result_text) => {
                let parsed: Value = serde_json::from_str(&result_text)
                    .unwrap_or_else(|_| Value::String(result_text));
                decision.dynamic_scan_result = Some(parsed);
                info!("Scan dynamique terminé (stub)");
            }
            Err(e) => {
                error!("Scan dynamique échoué : {}", e);
                decision.dynamic_scan_result = Some(json!({
                    "error": e.to_string(),
                    "status": "ERROR"
                }));
            }
        }
    }
}

// ============================================================
// Pipeline principal
// ============================================================

/// Orchestre le pipeline complet de décision + exécution :
///
/// Phase 1 — Décision (tool calling)
///   1. Construit le prompt avec les artefacts et les tool schemas
///   2. Interroge les 3 workers via `chat_with_tools` → chaque worker émet des tool calls
///   3. Convertit les tool calls en LlmVote (quels scans recommandés + raisonnement)
///   4. Passe les votes à l'arbitre qui évalue la QUALITÉ des raisonnements
///
/// Phase 2 — Exécution (MCP)
///   5. Exécute les scans décidés par l'arbitre via le serveur MCP
///   6. Stocke les résultats dans le ScanDecision final
///
/// Exécution séquentielle (un modèle à la fois) pour respecter la contrainte
/// 8GB VRAM sur laptop. Sur serveur GPU, remplacer par tokio::join! pour parallélisme.
pub async fn run_decision(
    bundle: &ArtifactBundle,
    backend: &dyn LlmBackend,
    config: &Config,
    tool_schemas: Vec<Value>,
    mcp_client: &McpClient,
    quarantine_path: &str,
) -> Result<ScanDecision, LlmError> {
    let ctx = &bundle.pull_context;
    let image = format!("{}/{}:{}", ctx.registry, ctx.repository, ctx.tag);

    info!("Début analyse LLM pour {}", image);


    let worker_messages = build_worker_prompt(bundle, quarantine_path);
    let mut votes: Vec<LlmVote> = Vec::new();

    // --- Phase 1a : Workers séquentiels avec tool calling ---
    for model in &config.worker_models {
        info!("Worker {} en cours...", model);
        match backend
            .chat_with_tools(model, worker_messages.clone(), tool_schemas.clone())
            .await
        {
            Ok(response) => {
                let vote = parse_worker_vote(model, response);
                info!(
                    "Worker {} → static={} compliance={} dynamic={} confidence={:.2}",
                    model,
                    vote.run_static_scan,
                    vote.run_compliance_scan,
                    vote.run_dynamic_scan,
                    vote.confidence,
                );
                votes.push(vote);
            }
            Err(e) => warn!("Worker {} échoué : {}", model, e),
        }
    }

    if votes.is_empty() {
        return Ok(fail_safe_decision(ctx.uuid));
    }

    info!(
        "{}/{} workers ont répondu, envoi à l'arbitre",
        votes.len(),
        config.worker_models.len()
    );

    // --- Phase 1b : Arbitre — évalue la qualité des raisonnements ---
    let arbiter_messages = build_arbiter_prompt(&votes, &image);

    let arbiter_raw = backend
        .chat(&config.arbiter_model, arbiter_messages)
        .await
        .map_err(|e| {
            error!("Arbitre {} échoué : {}", config.arbiter_model, e);
            e
        })?;

    // L'arbitre répond en JSON texte (pas de tool calls)
    let arbiter = match serde_json::from_str::<ArbiterResponse>(&arbiter_raw) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                "Arbitre JSON invalide ({}) — activation fail-safe. Réponse : {}",
                e, arbiter_raw
            );
            return Ok(fail_safe_decision(ctx.uuid));
        }
    };

    info!(
        "Décision arbitre : static={} compliance={} dynamic={} confidence={:.2}",
        arbiter.run_static_scan,
        arbiter.run_compliance_scan,
        arbiter.run_dynamic_scan,
        arbiter.final_confidence,
    );

    let mut decision = ScanDecision {
        pull_id: ctx.uuid,
        run_static_scan: arbiter.run_static_scan,
        run_compliance_scan: arbiter.run_compliance_scan,
        run_dynamic_scan: arbiter.run_dynamic_scan,
        final_confidence: arbiter.final_confidence.clamp(0.0, 1.0),
        arbiter_rationale: arbiter.arbiter_rationale,
        votes,
        static_scan_result: None,
        compliance_scan_result: None,
        dynamic_scan_result: None,
    };

    // --- Phase 2 : Exécution des scans via MCP ---
    if decision.run_static_scan || decision.run_compliance_scan || decision.run_dynamic_scan {
        info!("Exécution des scans via MCP...");
        execute_scans(&mut decision, mcp_client, quarantine_path).await;
    } else {
        info!("Aucun scan requis pour {}", image);
    }

    Ok(decision)
}

// ============================================================
// Tests unitaires
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_vote_depuis_tool_calls_tous_scans() {
        let calls = vec![
            ToolCall {
                name: "run_static_scan".to_string(),
                arguments: serde_json::json!({
                    "quarantine_path": "/quarantaine/library/alpine/latest",
                    "reasoning": "Packages suspects détectés dans le SBOM",
                    "confidence": 0.9
                }),
            },
            ToolCall {
                name: "run_compliance_scan".to_string(),
                arguments: serde_json::json!({
                    "quarantine_path": "/quarantaine/library/alpine/latest",
                    "reasoning": "Entrypoint contient un script shell avec des permissions larges",
                    "confidence": 0.8
                }),
            },
        ];

        let vote = extract_vote_from_tool_calls("test-model", calls);
        assert!(vote.run_static_scan);
        assert!(vote.run_compliance_scan);
        assert!(!vote.run_dynamic_scan);
        assert!((vote.confidence - 0.85).abs() < 0.01);
        assert!(vote.reasoning.contains("[static]"));
        assert!(vote.reasoning.contains("[compliance]"));
    }

    #[test]
    fn test_vote_depuis_zero_tool_calls() {
        let calls: Vec<ToolCall> = vec![];
        let vote = extract_vote_from_tool_calls("clean-model", calls);
        assert!(!vote.run_static_scan);
        assert!(!vote.run_compliance_scan);
        assert!(!vote.run_dynamic_scan);
        assert_eq!(vote.confidence, 0.5);
        assert!(vote.reasoning.contains("No tool called"));
    }

    #[test]
    fn test_vote_depuis_texte_libre() {
        let response = LlmResponse::Text("This image looks clean to me.".to_string());
        let vote = parse_worker_vote("text-model", response);
        assert!(!vote.run_static_scan);
        assert!(!vote.run_compliance_scan);
        assert!(!vote.run_dynamic_scan);
        assert_eq!(vote.confidence, 0.3);
    }

    #[test]
    fn test_fail_safe_tous_scans_actives() {
        let id = Uuid::new_v4();
        let decision = fail_safe_decision(id);
        assert_eq!(decision.pull_id, id);
        assert!(decision.run_static_scan);
        assert!(decision.run_compliance_scan);
        assert!(decision.run_dynamic_scan);
        assert_eq!(decision.final_confidence, 0.0);
        assert!(decision.votes.is_empty());
        assert!(decision.static_scan_result.is_none());
    }

    #[test]
    fn test_confidence_clampee() {
        let calls = vec![ToolCall {
            name: "run_static_scan".to_string(),
            arguments: serde_json::json!({
                "quarantine_path": "/q",
                "reasoning": "Test",
                "confidence": 99.0  // hors limites
            }),
        }];
        let vote = extract_vote_from_tool_calls("model", calls);
        assert!(vote.confidence <= 1.0);
    }
}
