use llm_common::{
    Alternative, ArbiterAnalysis, ArtifactBundle, Config, DecisionArbiterMeta, DecisionMetadata,
    DecisionWorkerMeta, FinalReport, LlmBackend, LlmError, LlmResponse, LlmVote, ScanAnalysis,
    ScanDecision, ScanReasoning, ScanResult, ToolCall, Verdict, WorkerAnalysis,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{error, info, warn};

use crate::mcp_client::{
    finalize_alternatives_schema, make_final_verdict_schema, make_security_decision_schema,
    submit_vulnerability_analysis_schema, suggest_alternatives_schema, McpClient,
};
use crate::prompt::{
    build_arbiter_alternatives_prompt, build_arbiter_analysis_prompt, build_arbiter_prompt,
    build_worker_alternatives_prompt, build_worker_analysis_prompt, build_worker_prompt,
};

// ============================================================
// Structures de parsing
// ============================================================

/// Arguments du tool call `make_security_decision` retourné par l'arbitre.
#[derive(Deserialize)]
struct ArbiterResponse {
    run_static_scan: bool,
    run_compliance_scan: bool,
    run_dynamic_scan: bool,
    final_confidence: f64,
    arbiter_rationale: String,
    /// Indices (0-based) des workers dont le raisonnement a été déterminant.
    #[serde(default)]
    selected_worker_indices: Vec<usize>,
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
    let mut confidences: Vec<f64> = Vec::new();

    for tc in &calls {
        let reasoning = tc
            .arguments
            .get("reasoning")
            .and_then(|v| v.as_str())
            .unwrap_or("No reasoning provided")
            .to_string();

        let confidence = tc
            .arguments
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.7)
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
        confidences.iter().sum::<f64>() / confidences.len() as f64
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
async fn execute_scans(decision: &mut ScanDecision, mcp_client: &McpClient, quarantine_path: &str) {
    let args = json!({ "quarantine_path": quarantine_path });
    let run_static = decision.run_static_scan;
    let run_compliance = decision.run_compliance_scan;
    let run_dynamic = decision.run_dynamic_scan;

    // Lancer les scans activés en parallèle
    let static_fut = async {
        if run_static {
            info!("Exécution scan statique CVE via MCP...");
            Some(mcp_client.call_tool("run_static_scan", args.clone()).await)
        } else {
            None
        }
    };
    let compliance_fut = async {
        if run_compliance {
            info!("Exécution scan compliance via MCP...");
            Some(
                mcp_client
                    .call_tool("run_compliance_scan", args.clone())
                    .await,
            )
        } else {
            None
        }
    };
    let dynamic_fut = async {
        if run_dynamic {
            info!("Exécution scan dynamique via MCP...");
            Some(mcp_client.call_tool("run_dynamic_scan", args.clone()).await)
        } else {
            None
        }
    };

    let (static_res, compliance_res, dynamic_res) =
        tokio::join!(static_fut, compliance_fut, dynamic_fut);

    if let Some(r) = static_res {
        decision.static_scan_result = Some(match r {
            Ok(text) => {
                info!("Scan statique terminé");
                serde_json::from_str(&text).unwrap_or(Value::String(text))
            }
            Err(e) => {
                error!("Scan statique échoué : {}", e);
                json!({"error": e.to_string(), "status": "ERROR"})
            }
        });
    }
    if let Some(r) = compliance_res {
        decision.compliance_scan_result = Some(match r {
            Ok(text) => {
                info!("Scan compliance terminé");
                serde_json::from_str(&text).unwrap_or(Value::String(text))
            }
            Err(e) => {
                error!("Scan compliance échoué : {}", e);
                json!({"error": e.to_string(), "status": "ERROR"})
            }
        });
    }
    if let Some(r) = dynamic_res {
        decision.dynamic_scan_result = Some(match r {
            Ok(text) => {
                info!("Scan dynamique terminé (stub)");
                serde_json::from_str(&text).unwrap_or(Value::String(text))
            }
            Err(e) => {
                error!("Scan dynamique échoué : {}", e);
                json!({"error": e.to_string(), "status": "ERROR"})
            }
        });
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

    // --- Phase 1a : Workers en parallèle ---
    info!(
        "Lancement des {} workers en parallèle...",
        config.worker_models.len()
    );
    let [m0, m1, m2] = &config.worker_models;
    let (r0, r1, r2) = tokio::join!(
        backend.chat_with_tools(m0, worker_messages.clone(), tool_schemas.clone()),
        backend.chat_with_tools(m1, worker_messages.clone(), tool_schemas.clone()),
        backend.chat_with_tools(m2, worker_messages.clone(), tool_schemas),
    );

    let mut votes: Vec<LlmVote> = Vec::new();
    for (result, model) in [r0, r1, r2].into_iter().zip(config.worker_models.iter()) {
        match result {
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
                info!("Worker {} raisonnement : {}", model, vote.reasoning);
                votes.push(vote);
            }
            Err(e) => warn!("Worker {} échoué : {}", model, e),
        }
    }

    // Moins de 2 workers = signal insuffisant pour un arbitrage fiable
    if votes.len() < 2 {
        let reason = format!(
            "{}/{} workers ont répondu — signal insuffisant pour un arbitrage fiable",
            votes.len(),
            config.worker_models.len()
        );
        error!("{}", reason);
        return Err(LlmError::PipelineFailed(reason));
    }

    info!(
        "{}/{} workers ont répondu, envoi à l'arbitre",
        votes.len(),
        config.worker_models.len()
    );

    // --- Règle consensus : si tous les workers s'accordent unanimement, on suit sans consulter l'arbitre ---
    if votes.len() == config.worker_models.len() {
        let first = &votes[0];
        if votes.iter().all(|v| {
            v.run_static_scan == first.run_static_scan
                && v.run_compliance_scan == first.run_compliance_scan
                && v.run_dynamic_scan == first.run_dynamic_scan
        }) {
            info!(
                "Consensus unanime {}/{} workers : static={} compliance={} dynamic={} — arbitre non consulté",
                votes.len(), config.worker_models.len(),
                first.run_static_scan, first.run_compliance_scan, first.run_dynamic_scan
            );
            let avg_confidence =
                votes.iter().map(|v| v.confidence).sum::<f64>() / votes.len() as f64;
            let mut decision = ScanDecision {
                pull_id: ctx.uuid,
                run_static_scan: first.run_static_scan,
                run_compliance_scan: first.run_compliance_scan,
                run_dynamic_scan: first.run_dynamic_scan,
                final_confidence: avg_confidence,
                arbiter_rationale: format!(
                    "Unanimous consensus among all {} workers — arbiter not consulted.",
                    votes.len()
                ),
                votes,
                selected_worker_indices: vec![0, 1, 2],
                static_scan_result: None,
                compliance_scan_result: None,
                dynamic_scan_result: None,
            };
            if decision.run_static_scan || decision.run_compliance_scan || decision.run_dynamic_scan
            {
                execute_scans(&mut decision, mcp_client, quarantine_path).await;
            } else {
                info!("Aucun scan requis pour {} (consensus)", image);
            }
            return Ok(decision);
        }
    }

    // --- Phase 1b : Arbitre — évalue la qualité des raisonnements via tool call ---
    let arbiter_messages = build_arbiter_prompt(&votes, &image);
    let arbiter_schema = make_security_decision_schema();

    let arbiter_response = backend
        .chat_with_tools(
            &config.arbiter_model,
            arbiter_messages,
            vec![arbiter_schema],
        )
        .await
        .map_err(|e| {
            error!("Arbitre {} échoué : {}", config.arbiter_model, e);
            e
        })?;

    // L'arbitre doit appeler make_security_decision (tool call obligatoire)
    let arbiter = match arbiter_response {
        LlmResponse::ToolCalls(calls) => {
            match calls
                .into_iter()
                .find(|tc| tc.name == "make_security_decision")
            {
                Some(tc) => match serde_json::from_value::<ArbiterResponse>(tc.arguments) {
                    Ok(r) => r,
                    Err(e) => {
                        let reason = format!(
                            "Arbitre : arguments make_security_decision invalides : {}",
                            e
                        );
                        error!("{}", reason);
                        return Err(LlmError::PipelineFailed(reason));
                    }
                },
                None => {
                    let reason = "Arbitre : tool make_security_decision non appelé".to_string();
                    error!("{}", reason);
                    return Err(LlmError::PipelineFailed(reason));
                }
            }
        }
        LlmResponse::Text(text) => {
            let reason = format!(
                "Arbitre : réponse texte au lieu de tool call (\"{}...\")",
                text.chars().take(120).collect::<String>()
            );
            error!("{}", reason);
            return Err(LlmError::PipelineFailed(reason));
        }
    };

    info!(
        "Décision arbitre : static={} compliance={} dynamic={} confidence={:.2}",
        arbiter.run_static_scan,
        arbiter.run_compliance_scan,
        arbiter.run_dynamic_scan,
        arbiter.final_confidence,
    );
    info!("Arbitre raisonnement : {}", arbiter.arbiter_rationale);

    let mut decision = ScanDecision {
        pull_id: ctx.uuid,
        run_static_scan: arbiter.run_static_scan,
        run_compliance_scan: arbiter.run_compliance_scan,
        run_dynamic_scan: arbiter.run_dynamic_scan,
        final_confidence: arbiter.final_confidence.clamp(0.0, 1.0),
        arbiter_rationale: arbiter.arbiter_rationale,
        votes,
        selected_worker_indices: arbiter.selected_worker_indices,
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
// Phase 3 — analyse des résultats des scans
// ============================================================

/// Arguments du tool call `submit_vulnerability_analysis` retourné par un worker.
#[derive(Deserialize)]
struct WorkerAnalysisArgs {
    vulnerability_score: f64,
    confidence: f64,
    reasoning: String,
    #[serde(default)]
    static_summary: Option<String>,
    #[serde(default)]
    compliance_summary: Option<String>,
}

/// Résultat interne d'un worker en phase 3 (inclut les résumés de scans,
/// non présents dans le JSON de sortie final mais utilisés pour construire ScanResult).
struct WorkerAnalysisFull {
    analysis: WorkerAnalysis,
    static_summary: Option<String>,
    compliance_summary: Option<String>,
}

/// Arguments du tool call `make_final_verdict` retourné par l'arbitre.
#[derive(Deserialize)]
struct ArbiterVerdictArgs {
    decision: String,
    vulnerability_score: f64,
    confidence: f64,
    rationale: String,
}

/// Arguments du tool call `suggest_alternatives` retourné par un worker.
#[derive(Deserialize)]
struct SuggestAlternativesArgs {
    #[serde(default)]
    alternatives: Vec<AlternativeArgs>,
}

/// Arguments du tool call `finalize_alternatives` retourné par l'arbitre.
#[derive(Deserialize)]
struct FinalizeAlternativesArgs {
    #[serde(default)]
    alternatives: Vec<AlternativeArgs>,
}

#[derive(Deserialize)]
struct AlternativeArgs {
    image: String,
    reason: String,
    confidence: f64,
}

/// Parsé la réponse d'un worker en phase 3 (analyse de vulnérabilité).
fn parse_worker_analysis(model: &str, response: LlmResponse) -> WorkerAnalysisFull {
    let failed = || WorkerAnalysisFull {
        analysis: WorkerAnalysis {
            model: model.to_string(),
            status: "failed".to_string(),
            vulnerability_score: None,
            confidence: None,
            reasoning: None,
        },
        static_summary: None,
        compliance_summary: None,
    };

    let calls = match response {
        LlmResponse::ToolCalls(calls) => calls,
        LlmResponse::Text(text) => {
            warn!(
                "Worker {} phase 3 : réponse texte (\"{}...\")",
                model,
                text.chars().take(80).collect::<String>()
            );
            return failed();
        }
    };

    let tc = match calls
        .into_iter()
        .find(|tc| tc.name == "submit_vulnerability_analysis")
    {
        Some(tc) => tc,
        None => {
            warn!(
                "Worker {} phase 3 : tool submit_vulnerability_analysis non appelé",
                model
            );
            return failed();
        }
    };

    match serde_json::from_value::<WorkerAnalysisArgs>(tc.arguments) {
        Ok(args) => WorkerAnalysisFull {
            analysis: WorkerAnalysis {
                model: model.to_string(),
                status: "ok".to_string(),
                vulnerability_score: Some(args.vulnerability_score.clamp(0.0, 10.0)),
                confidence: Some(args.confidence.clamp(0.0, 1.0)),
                reasoning: Some(args.reasoning),
            },
            static_summary: args.static_summary,
            compliance_summary: args.compliance_summary,
        },
        Err(e) => {
            warn!("Worker {} phase 3 : arguments invalides : {}", model, e);
            failed()
        }
    }
}

/// Phase 3 — analyse des résultats de scans par les LLM.
///
/// Phase 3a : workers analysent les résultats → scores + raisonnements
/// Phase 3b : arbitre synthétise → verdict ALLOW/DENY
/// Phase 3c (si DENY) : workers suggèrent des alternatives
/// Phase 3d (si DENY) : arbitre sélectionne les meilleures alternatives
///
/// Retourne Err(PipelineFailed) si l'arbitre phase 3 ne produit pas de verdict valide.
pub async fn run_analysis(
    scan_decision: ScanDecision,
    bundle: &ArtifactBundle,
    backend: &dyn LlmBackend,
    config: &Config,
    image: &str,
) -> Result<FinalReport, LlmError> {
    info!(
        "Début phase 3 — analyse LLM des résultats de scans pour {}",
        image
    );

    let analysis_schema = submit_vulnerability_analysis_schema();
    let worker_messages = build_worker_analysis_prompt(&scan_decision, bundle);

    // --- Phase 3a : Workers analyse en parallèle ---
    info!(
        "Lancement des {} workers phase 3a en parallèle...",
        config.worker_models.len()
    );
    let [m0, m1, m2] = &config.worker_models;
    let (ra0, ra1, ra2) = tokio::join!(
        backend.chat_with_tools(m0, worker_messages.clone(), vec![analysis_schema.clone()]),
        backend.chat_with_tools(m1, worker_messages.clone(), vec![analysis_schema.clone()]),
        backend.chat_with_tools(m2, worker_messages.clone(), vec![analysis_schema]),
    );

    let mut full_analyses: Vec<WorkerAnalysisFull> = Vec::new();
    for (result, model) in [ra0, ra1, ra2].into_iter().zip(config.worker_models.iter()) {
        match result {
            Ok(response) => {
                let full = parse_worker_analysis(model, response);
                info!(
                    "Worker {} → score={:.1} confidence={:.2} status={}",
                    model,
                    full.analysis.vulnerability_score.unwrap_or(0.0),
                    full.analysis.confidence.unwrap_or(0.0),
                    full.analysis.status
                );
                if let Some(r) = &full.analysis.reasoning {
                    info!("Worker {} raisonnement phase 3 : {}", model, r);
                }
                full_analyses.push(full);
            }
            Err(e) => {
                warn!("Worker {} phase 3 échoué : {}", model, e);
                full_analyses.push(WorkerAnalysisFull {
                    analysis: WorkerAnalysis {
                        model: model.clone(),
                        status: "failed".to_string(),
                        vulnerability_score: None,
                        confidence: None,
                        reasoning: None,
                    },
                    static_summary: None,
                    compliance_summary: None,
                });
            }
        }
    }

    // --- Phase 3b : arbitre synthétise → verdict ALLOW/DENY ---
    let worker_analyses: Vec<WorkerAnalysis> =
        full_analyses.iter().map(|f| f.analysis.clone()).collect();
    let arbiter_messages = build_arbiter_analysis_prompt(&worker_analyses, image);
    let verdict_schema = make_final_verdict_schema();

    let (verdict, arbiter_analysis) = match backend
        .chat_with_tools(
            &config.arbiter_model,
            arbiter_messages,
            vec![verdict_schema],
        )
        .await
    {
        Ok(LlmResponse::ToolCalls(calls)) => {
            match calls.into_iter().find(|tc| tc.name == "make_final_verdict") {
                Some(tc) => match serde_json::from_value::<ArbiterVerdictArgs>(tc.arguments) {
                    Ok(args) => {
                        info!(
                            "Arbitre phase 3 → decision={} score={:.1} confidence={:.2}",
                            args.decision, args.vulnerability_score, args.confidence
                        );
                        info!("Arbitre phase 3 raisonnement : {}", args.rationale);
                        let arbiter = ArbiterAnalysis {
                            model: config.arbiter_model.clone(),
                            vulnerability_score: args.vulnerability_score.clamp(0.0, 10.0),
                            confidence: args.confidence.clamp(0.0, 1.0),
                            reasoning: args.rationale.clone(),
                        };
                        let verdict = Verdict {
                            decision: args.decision,
                            vulnerability_score: args.vulnerability_score.clamp(0.0, 10.0),
                            confidence: args.confidence.clamp(0.0, 1.0),
                            rationale: args.rationale,
                        };
                        (verdict, arbiter)
                    }
                    Err(e) => {
                        let reason = format!(
                            "Arbitre phase 3 : arguments make_final_verdict invalides : {}",
                            e
                        );
                        error!("{}", reason);
                        return Err(LlmError::PipelineFailed(reason));
                    }
                },
                None => {
                    let reason = "Arbitre phase 3 : tool make_final_verdict non appelé".to_string();
                    error!("{}", reason);
                    return Err(LlmError::PipelineFailed(reason));
                }
            }
        }
        Ok(LlmResponse::Text(text)) => {
            let reason = format!(
                "Arbitre phase 3 : réponse texte (\"{}...\")",
                text.chars().take(120).collect::<String>()
            );
            error!("{}", reason);
            return Err(LlmError::PipelineFailed(reason));
        }
        Err(e) => {
            let reason = format!("Arbitre phase 3 échoué : {}", e);
            error!("{}", reason);
            return Err(LlmError::PipelineFailed(reason));
        }
    };

    // --- Phases 3c + 3d : alternatives (uniquement si DENY) ---
    let alternatives = if verdict.decision == "DENY" {
        run_alternatives_phase(backend, config, &verdict, image).await
    } else {
        info!("Décision ALLOW — phases alternatives ignorées");
        vec![]
    };

    // Résumés LLM pour scan_analysis (premier worker OK qui a fourni un résumé)
    let static_summary = full_analyses
        .iter()
        .filter(|f| f.analysis.status == "ok")
        .find_map(|f| f.static_summary.clone());
    let compliance_summary = full_analyses
        .iter()
        .filter(|f| f.analysis.status == "ok")
        .find_map(|f| f.compliance_summary.clone());

    // Métadonnées phase 1 — tous les modèles (dont ceux qui ont échoué)
    let decision_workers: Vec<DecisionWorkerMeta> = config
        .worker_models
        .iter()
        .map(
            |model| match scan_decision.votes.iter().find(|v| &v.model_id == model) {
                Some(vote) => DecisionWorkerMeta {
                    model: model.clone(),
                    status: "ok".to_string(),
                    run_static_scan: Some(vote.run_static_scan),
                    run_compliance_scan: Some(vote.run_compliance_scan),
                    run_dynamic_scan: Some(vote.run_dynamic_scan),
                    confidence: Some(vote.confidence),
                    reasoning: Some(vote.reasoning.clone()),
                },
                None => DecisionWorkerMeta {
                    model: model.clone(),
                    status: "failed".to_string(),
                    run_static_scan: None,
                    run_compliance_scan: None,
                    run_dynamic_scan: None,
                    confidence: None,
                    reasoning: None,
                },
            },
        )
        .collect();

    let analysed_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    Ok(FinalReport {
        pull_id: scan_decision.pull_id,
        image: image.to_string(),
        analysed_at,
        verdict,
        scan_analysis: ScanAnalysis {
            static_scan: ScanResult {
                executed: scan_decision.run_static_scan,
                llm_summary: static_summary,
                raw_result: scan_decision.static_scan_result,
            },
            compliance: ScanResult {
                executed: scan_decision.run_compliance_scan,
                llm_summary: compliance_summary,
                raw_result: scan_decision.compliance_scan_result,
            },
            dynamic: ScanResult {
                executed: scan_decision.run_dynamic_scan,
                llm_summary: None,
                raw_result: scan_decision.dynamic_scan_result,
            },
        },
        scan_reasoning: ScanReasoning {
            workers: worker_analyses,
            arbiter: arbiter_analysis,
        },
        alternatives,
        decision_metadata: DecisionMetadata {
            workers: decision_workers,
            arbiter: DecisionArbiterMeta {
                model: config.arbiter_model.clone(),
                reasoning: scan_decision.arbiter_rationale,
            },
        },
    })
}

/// Phase 3c + 3d : workers suggèrent des alternatives, arbitre sélectionne.
#[allow(clippy::type_complexity)]
async fn run_alternatives_phase(
    backend: &dyn LlmBackend,
    config: &Config,
    verdict: &Verdict,
    image: &str,
) -> Vec<Alternative> {
    info!(
        "Phase alternatives — {} est DENY, recherche d'alternatives...",
        image
    );

    let alt_schema = suggest_alternatives_schema();
    let worker_messages = build_worker_alternatives_prompt(verdict, image);

    // Phase 3c : workers suggèrent des alternatives en parallèle
    info!(
        "Lancement des {} workers alternatives en parallèle...",
        config.worker_models.len()
    );
    let [m0, m1, m2] = &config.worker_models;
    let (rb0, rb1, rb2) = tokio::join!(
        backend.chat_with_tools(m0, worker_messages.clone(), vec![alt_schema.clone()]),
        backend.chat_with_tools(m1, worker_messages.clone(), vec![alt_schema.clone()]),
        backend.chat_with_tools(m2, worker_messages.clone(), vec![alt_schema]),
    );

    let mut worker_suggestions: Vec<(String, Vec<(String, String, f64)>)> = Vec::new();
    for (result, model) in [rb0, rb1, rb2].into_iter().zip(config.worker_models.iter()) {
        let suggestions = match result {
            Ok(LlmResponse::ToolCalls(calls)) => calls
                .into_iter()
                .find(|tc| tc.name == "suggest_alternatives")
                .and_then(|tc| serde_json::from_value::<SuggestAlternativesArgs>(tc.arguments).ok())
                .map(|args| {
                    args.alternatives
                        .into_iter()
                        .map(|a| (a.image, a.reason, a.confidence.clamp(0.0, 1.0)))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            Ok(LlmResponse::Text(text)) => {
                warn!(
                    "Worker {} alternatives : réponse texte (\"{}...\")",
                    model,
                    text.chars().take(80).collect::<String>()
                );
                vec![]
            }
            Err(e) => {
                warn!("Worker {} alternatives échoué : {}", model, e);
                vec![]
            }
        };
        info!(
            "Worker {} suggestions : {} alternatives",
            model,
            suggestions.len()
        );
        for (img, reason, conf) in &suggestions {
            info!("  → {} (confidence={:.2}) : {}", img, conf, reason);
        }
        worker_suggestions.push((model.clone(), suggestions));
    }

    // Phase 3d : arbitre sélectionne les meilleures alternatives
    let arbiter_messages = build_arbiter_alternatives_prompt(&worker_suggestions, image, verdict);
    let finalize_schema = finalize_alternatives_schema();

    match backend
        .chat_with_tools(
            &config.arbiter_model,
            arbiter_messages,
            vec![finalize_schema],
        )
        .await
    {
        Ok(LlmResponse::ToolCalls(calls)) => {
            match calls
                .into_iter()
                .find(|tc| tc.name == "finalize_alternatives")
            {
                Some(tc) => {
                    match serde_json::from_value::<FinalizeAlternativesArgs>(tc.arguments) {
                        Ok(args) => {
                            let alternatives: Vec<Alternative> = args
                                .alternatives
                                .into_iter()
                                .map(|a| Alternative {
                                    image: a.image,
                                    reason: a.reason,
                                    confidence: a.confidence.clamp(0.0, 1.0),
                                })
                                .collect();
                            info!(
                                "Arbitre alternatives → {} alternatives sélectionnées",
                                alternatives.len()
                            );
                            for alt in &alternatives {
                                info!(
                                    "  ✓ {} (confidence={:.2}) : {}",
                                    alt.image, alt.confidence, alt.reason
                                );
                            }
                            alternatives
                        }
                        Err(e) => {
                            warn!("Arbitre alternatives : arguments invalides : {}", e);
                            vec![]
                        }
                    }
                }
                None => {
                    warn!("Arbitre alternatives : tool finalize_alternatives non appelé");
                    vec![]
                }
            }
        }
        Ok(LlmResponse::Text(text)) => {
            warn!(
                "Arbitre alternatives : réponse texte (\"{}...\") — aucune alternative",
                text.chars().take(120).collect::<String>()
            );
            vec![]
        }
        Err(e) => {
            error!("Arbitre alternatives échoué : {}", e);
            vec![]
        }
    }
}

// ============================================================
// Tests unitaires
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_confidence_clampee() {
        let calls = vec![ToolCall {
            name: "run_static_scan".to_string(),
            arguments: serde_json::json!({
                "quarantine_path": "/q",
                "reasoning": "Test",
                "confidence": 99.0
            }),
        }];
        let vote = extract_vote_from_tool_calls("model", calls);
        assert!(vote.confidence <= 1.0);
    }

    // --- Tests parse_worker_analysis (phase 3) ---

    #[test]
    fn test_worker_analysis_valide() {
        let calls = vec![ToolCall {
            name: "submit_vulnerability_analysis".to_string(),
            arguments: serde_json::json!({
                "vulnerability_score": 7.5,
                "confidence": 0.9,
                "reasoning": "CVE-2024-1234 critique détecté",
                "static_summary": "1 CVE critique",
                "compliance_summary": null
            }),
        }];
        let full = parse_worker_analysis("model", LlmResponse::ToolCalls(calls));
        assert_eq!(full.analysis.status, "ok");
        assert!((full.analysis.vulnerability_score.unwrap() - 7.5).abs() < 0.01);
        assert_eq!(full.static_summary.as_deref(), Some("1 CVE critique"));
    }

    #[test]
    fn test_worker_analysis_score_clamp() {
        let calls = vec![ToolCall {
            name: "submit_vulnerability_analysis".to_string(),
            arguments: serde_json::json!({
                "vulnerability_score": 15.0, // hors limites
                "confidence": 0.8,
                "reasoning": "Test"
            }),
        }];
        let full = parse_worker_analysis("model", LlmResponse::ToolCalls(calls));
        assert!(full.analysis.vulnerability_score.unwrap() <= 10.0);
    }

    #[test]
    fn test_worker_analysis_texte_libre_echoue() {
        let response = LlmResponse::Text("Image looks risky.".to_string());
        let full = parse_worker_analysis("model", response);
        assert_eq!(full.analysis.status, "failed");
        assert!(full.analysis.vulnerability_score.is_none());
    }

    #[test]
    fn test_worker_analysis_mauvais_tool_echoue() {
        let calls = vec![ToolCall {
            name: "make_final_verdict".to_string(), // mauvais tool pour un worker
            arguments: serde_json::json!({"decision": "ALLOW"}),
        }];
        let full = parse_worker_analysis("model", LlmResponse::ToolCalls(calls));
        assert_eq!(full.analysis.status, "failed");
    }

    #[test]
    fn test_worker_analysis_arguments_invalides_echoue() {
        let calls = vec![ToolCall {
            name: "submit_vulnerability_analysis".to_string(),
            arguments: serde_json::json!({"champ_inexistant": true}), // manque vulnerability_score
        }];
        let full = parse_worker_analysis("model", LlmResponse::ToolCalls(calls));
        assert_eq!(full.analysis.status, "failed");
    }
}
