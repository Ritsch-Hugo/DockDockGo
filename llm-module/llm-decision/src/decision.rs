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

#[derive(Deserialize)]
struct ArbiterResponse {
    run_static_scan: bool,
    run_compliance_scan: bool,
    run_dynamic_scan: bool,
    final_confidence: f64,
    arbiter_rationale: String,
    #[serde(default)]
    selected_worker_indices: Vec<usize>,
}

// ============================================================
// Suivi des échecs workers
// ============================================================

struct WorkerFailure {
    model: String,
    kind: WorkerFailureKind,
}

enum WorkerFailureKind {
    Timeout(u64),
    Http(String),
    TextResponse(String),
    Other(String),
}

impl WorkerFailure {
    fn from_error(model: &str, e: LlmError) -> Self {
        let kind = match e {
            LlmError::Timeout { timeout_secs, .. } => WorkerFailureKind::Timeout(timeout_secs),
            LlmError::Http(d) => WorkerFailureKind::Http(d),
            other => WorkerFailureKind::Other(other.to_string()),
        };
        Self {
            model: model.to_string(),
            kind,
        }
    }

    fn from_text(model: &str, preview: String) -> Self {
        Self {
            model: model.to_string(),
            kind: WorkerFailureKind::TextResponse(preview),
        }
    }

    fn describe(&self) -> String {
        match &self.kind {
            WorkerFailureKind::Timeout(s) => format!("{}: timeout ({}s)", self.model, s),
            WorkerFailureKind::Http(d) => format!("{}: erreur HTTP ({})", self.model, d),
            WorkerFailureKind::TextResponse(p) => {
                format!("{}: réponse texte (\"{}...\")", self.model, p)
            }
            WorkerFailureKind::Other(d) => format!("{}: erreur ({})", self.model, d),
        }
    }
}

fn build_workers_failed_reason(failures: &[WorkerFailure], total: usize, phase: &str) -> String {
    let details = failures
        .iter()
        .map(|f| format!("  - {}", f.describe()))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{} : {}/{} workers ont échoué — signal insuffisant pour continuer:\n{}",
        phase,
        failures.len(),
        total,
        details
    )
}

// ============================================================
// Parsing des votes workers (depuis tool calls uniquement)
// ============================================================

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
                reasonings.push(format!("[clean] {}", reasoning));
                confidences.push(confidence);
            }
            unknown => {
                warn!("Worker {} : tool call inconnu ignoré : {}", model, unknown);
            }
        }
    }

    let confidence = if confidences.is_empty() {
        0.5
    } else {
        confidences.iter().sum::<f64>() / confidences.len() as f64
    };

    let reasoning = if reasonings.is_empty() {
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

/// Retourne la liste des noms de scans qui ont échoué.
async fn execute_scans(
    decision: &mut ScanDecision,
    mcp_client: &McpClient,
    quarantine_path: &str,
) -> Vec<String> {
    let args = json!({ "quarantine_path": quarantine_path });
    let run_static = decision.run_static_scan;
    let run_compliance = decision.run_compliance_scan;
    let run_dynamic = decision.run_dynamic_scan;

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

    let mut failed: Vec<String> = Vec::new();

    if let Some(r) = static_res {
        match r {
            Ok(text) => {
                info!("Scan statique terminé");
                decision.static_scan_result =
                    Some(serde_json::from_str(&text).unwrap_or(Value::String(text)));
            }
            Err(e) => {
                error!("Scan statique échoué : {}", e);
                decision.static_scan_result =
                    Some(json!({"error": e.to_string(), "status": "ERROR"}));
                failed.push("run_static_scan".to_string());
            }
        }
    }
    if let Some(r) = compliance_res {
        match r {
            Ok(text) => {
                info!("Scan compliance terminé");
                decision.compliance_scan_result =
                    Some(serde_json::from_str(&text).unwrap_or(Value::String(text)));
            }
            Err(e) => {
                error!("Scan compliance échoué : {}", e);
                decision.compliance_scan_result =
                    Some(json!({"error": e.to_string(), "status": "ERROR"}));
                failed.push("run_compliance_scan".to_string());
            }
        }
    }
    if let Some(r) = dynamic_res {
        match r {
            Ok(text) => {
                info!("Scan dynamique terminé (stub)");
                decision.dynamic_scan_result =
                    Some(serde_json::from_str(&text).unwrap_or(Value::String(text)));
            }
            Err(e) => {
                error!("Scan dynamique échoué : {}", e);
                decision.dynamic_scan_result =
                    Some(json!({"error": e.to_string(), "status": "ERROR"}));
                failed.push("run_dynamic_scan".to_string());
            }
        }
    }

    failed
}

// ============================================================
// Pipeline principal — Phase 1 + Phase 2
// ============================================================

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
    let mut failures: Vec<WorkerFailure> = Vec::new();

    for (result, model) in [r0, r1, r2].into_iter().zip(config.worker_models.iter()) {
        match result {
            Ok(LlmResponse::ToolCalls(calls)) => {
                let vote = extract_vote_from_tool_calls(model, calls);
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
            Ok(LlmResponse::Text(text)) => {
                let f = WorkerFailure::from_text(model, text.chars().take(80).collect());
                warn!("Worker {} phase 1 : {}", model, f.describe());
                failures.push(f);
            }
            Err(e) => {
                let f = WorkerFailure::from_error(model, e);
                warn!("Worker {} phase 1 : {}", model, f.describe());
                failures.push(f);
            }
        }
    }

    if failures.len() >= 2 {
        let reason = build_workers_failed_reason(&failures, config.worker_models.len(), "Phase 1");
        error!("{}", reason);
        return Err(LlmError::PipelineFailed(reason));
    }

    info!(
        "{}/{} workers ont répondu, envoi à l'arbitre",
        votes.len(),
        config.worker_models.len()
    );

    // --- Règle consensus : si tous les workers s'accordent unanimement, arbitre non consulté ---
    if votes.len() == config.worker_models.len() {
        let first = &votes[0];
        if votes.iter().all(|v| {
            v.run_static_scan == first.run_static_scan
                && v.run_compliance_scan == first.run_compliance_scan
                && v.run_dynamic_scan == first.run_dynamic_scan
        }) {
            info!(
                "Consensus unanime {}/{} workers : static={} compliance={} dynamic={} — arbitre non consulté",
                votes.len(),
                config.worker_models.len(),
                first.run_static_scan,
                first.run_compliance_scan,
                first.run_dynamic_scan
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
                let failed_scans = execute_scans(&mut decision, mcp_client, quarantine_path).await;
                if !failed_scans.is_empty() {
                    let reason = format!(
                        "Scans échoués : {} — pipeline interrompu",
                        failed_scans.join(", ")
                    );
                    error!("{}", reason);
                    return Err(LlmError::PipelineFailed(reason));
                }
            } else {
                info!("Aucun scan requis pour {} (consensus)", image);
            }
            return Ok(decision);
        }
    }

    // --- Phase 1b : Arbitre ---
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
            let reason = match &e {
                LlmError::Timeout { timeout_secs, .. } => {
                    format!("Arbitre phase 1 : timeout ({}s)", timeout_secs)
                }
                LlmError::Http(d) => format!("Arbitre phase 1 : erreur HTTP ({})", d),
                other => format!("Arbitre phase 1 échoué : {}", other),
            };
            error!("{}", reason);
            LlmError::PipelineFailed(reason)
        })?;

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
                            "Arbitre phase 1 : arguments make_security_decision invalides : {}",
                            e
                        );
                        error!("{}", reason);
                        return Err(LlmError::PipelineFailed(reason));
                    }
                },
                None => {
                    let reason =
                        "Arbitre phase 1 : tool make_security_decision non appelé".to_string();
                    error!("{}", reason);
                    return Err(LlmError::PipelineFailed(reason));
                }
            }
        }
        LlmResponse::Text(text) => {
            let reason = format!(
                "Arbitre phase 1 : réponse texte au lieu de tool call (\"{}...\")",
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
        let failed_scans = execute_scans(&mut decision, mcp_client, quarantine_path).await;
        if !failed_scans.is_empty() {
            let reason = format!(
                "Scans échoués : {} — pipeline interrompu",
                failed_scans.join(", ")
            );
            error!("{}", reason);
            return Err(LlmError::PipelineFailed(reason));
        }
    } else {
        info!("Aucun scan requis pour {}", image);
    }

    Ok(decision)
}

// ============================================================
// Phase 3 — analyse des résultats des scans
// ============================================================

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

struct WorkerAnalysisFull {
    analysis: WorkerAnalysis,
    static_summary: Option<String>,
    compliance_summary: Option<String>,
}

#[derive(Deserialize)]
struct ArbiterVerdictArgs {
    decision: String,
    vulnerability_score: f64,
    confidence: f64,
    rationale: String,
}

#[derive(Deserialize)]
struct SuggestAlternativesArgs {
    #[serde(default)]
    alternatives: Vec<AlternativeArgs>,
}

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

fn failed_worker_analysis(model: &str) -> WorkerAnalysisFull {
    WorkerAnalysisFull {
        analysis: WorkerAnalysis {
            model: model.to_string(),
            status: "failed".to_string(),
            vulnerability_score: None,
            confidence: None,
            reasoning: None,
        },
        static_summary: None,
        compliance_summary: None,
    }
}

fn parse_analysis_calls(model: &str, calls: Vec<ToolCall>) -> WorkerAnalysisFull {
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
            return failed_worker_analysis(model);
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
            failed_worker_analysis(model)
        }
    }
}

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
    let mut phase3_failures: Vec<WorkerFailure> = Vec::new();

    for (result, model) in [ra0, ra1, ra2].into_iter().zip(config.worker_models.iter()) {
        match result {
            Ok(LlmResponse::ToolCalls(calls)) => {
                let full = parse_analysis_calls(model, calls);
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
            Ok(LlmResponse::Text(text)) => {
                let f = WorkerFailure::from_text(model, text.chars().take(80).collect());
                warn!("Worker {} phase 3 : {}", model, f.describe());
                full_analyses.push(failed_worker_analysis(model));
                phase3_failures.push(f);
            }
            Err(e) => {
                let f = WorkerFailure::from_error(model, e);
                warn!("Worker {} phase 3 : {}", model, f.describe());
                full_analyses.push(failed_worker_analysis(model));
                phase3_failures.push(f);
            }
        }
    }

    if phase3_failures.len() >= 2 {
        let reason =
            build_workers_failed_reason(&phase3_failures, config.worker_models.len(), "Phase 3");
        error!("{}", reason);
        return Err(LlmError::PipelineFailed(reason));
    }

    // --- Phase 3b : arbitre → verdict ALLOW/DENY ---
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
                "Arbitre phase 3 : réponse texte au lieu de tool call (\"{}...\")",
                text.chars().take(120).collect::<String>()
            );
            error!("{}", reason);
            return Err(LlmError::PipelineFailed(reason));
        }
        Err(e) => {
            let reason = match &e {
                LlmError::Timeout { timeout_secs, .. } => {
                    format!("Arbitre phase 3 : timeout ({}s)", timeout_secs)
                }
                LlmError::Http(d) => format!("Arbitre phase 3 : erreur HTTP ({})", d),
                other => format!("Arbitre phase 3 échoué : {}", other),
            };
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

    let static_summary = full_analyses
        .iter()
        .filter(|f| f.analysis.status == "ok")
        .find_map(|f| f.static_summary.clone());
    let compliance_summary = full_analyses
        .iter()
        .filter(|f| f.analysis.status == "ok")
        .find_map(|f| f.compliance_summary.clone());

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

// ============================================================
// Phase 3c + 3d — alternatives (DENY uniquement, erreurs gracieuses)
// ============================================================

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
            Err(LlmError::Timeout { timeout_secs, .. }) => {
                warn!(
                    "Worker {} alternatives : timeout ({}s)",
                    model, timeout_secs
                );
                vec![]
            }
            Err(e) => {
                warn!("Worker {} alternatives : erreur ({})", model, e);
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
        Err(LlmError::Timeout { timeout_secs, .. }) => {
            error!(
                "Arbitre alternatives : timeout ({}s) — aucune alternative",
                timeout_secs
            );
            vec![]
        }
        Err(e) => {
            error!("Arbitre alternatives échoué : {} — aucune alternative", e);
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
        let full = parse_analysis_calls("model", calls);
        assert_eq!(full.analysis.status, "ok");
        assert!((full.analysis.vulnerability_score.unwrap() - 7.5).abs() < 0.01);
        assert_eq!(full.static_summary.as_deref(), Some("1 CVE critique"));
    }

    #[test]
    fn test_worker_analysis_score_clamp() {
        let calls = vec![ToolCall {
            name: "submit_vulnerability_analysis".to_string(),
            arguments: serde_json::json!({
                "vulnerability_score": 15.0,
                "confidence": 0.8,
                "reasoning": "Test"
            }),
        }];
        let full = parse_analysis_calls("model", calls);
        assert!(full.analysis.vulnerability_score.unwrap() <= 10.0);
    }

    #[test]
    fn test_worker_analysis_mauvais_tool_echoue() {
        let calls = vec![ToolCall {
            name: "make_final_verdict".to_string(),
            arguments: serde_json::json!({"decision": "ALLOW"}),
        }];
        let full = parse_analysis_calls("model", calls);
        assert_eq!(full.analysis.status, "failed");
    }

    #[test]
    fn test_worker_analysis_arguments_invalides_echoue() {
        let calls = vec![ToolCall {
            name: "submit_vulnerability_analysis".to_string(),
            arguments: serde_json::json!({"champ_inexistant": true}),
        }];
        let full = parse_analysis_calls("model", calls);
        assert_eq!(full.analysis.status, "failed");
    }

    #[test]
    fn test_worker_failure_describe_timeout() {
        let f = WorkerFailure {
            model: "minimax/minimax-m2.7".to_string(),
            kind: WorkerFailureKind::Timeout(120),
        };
        assert!(f.describe().contains("timeout (120s)"));
        assert!(f.describe().contains("minimax/minimax-m2.7"));
    }

    #[test]
    fn test_worker_failure_describe_texte() {
        let f = WorkerFailure::from_text("qwen/qwen3.5", "I think this image is safe".to_string());
        assert!(f.describe().contains("réponse texte"));
        assert!(f.describe().contains("qwen/qwen3.5"));
    }

    #[test]
    fn test_build_workers_failed_reason() {
        let failures = vec![
            WorkerFailure {
                model: "model-a".to_string(),
                kind: WorkerFailureKind::Timeout(120),
            },
            WorkerFailure {
                model: "model-b".to_string(),
                kind: WorkerFailureKind::Http("502".to_string()),
            },
        ];
        let reason = build_workers_failed_reason(&failures, 3, "Phase 1");
        assert!(reason.contains("2/3 workers"));
        assert!(reason.contains("Phase 1"));
        assert!(reason.contains("model-a"));
        assert!(reason.contains("model-b"));
        assert!(reason.contains("timeout (120s)"));
        assert!(reason.contains("erreur HTTP (502)"));
    }
}
