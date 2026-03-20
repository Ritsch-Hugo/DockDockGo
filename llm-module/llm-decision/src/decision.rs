use serde::Deserialize;
use tracing::{error, info, warn};
use uuid::Uuid;

use llm_common::{ArtifactBundle, Config, LlmBackend, LlmError, LlmVote, ScanDecision};

use crate::prompt::{build_arbiter_prompt, build_worker_prompt};

// ============================================================
// Structures de parsing des réponses LLM
// ============================================================

/// Format JSON attendu de chaque worker.
#[derive(Deserialize)]
struct WorkerResponse {
    run_static_scan: bool,
    run_compliance_scan: bool,
    run_dynamic_scan: bool,
    confidence: f32,
    reasoning: String,
}

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
// Logique principale
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
    }
}

/// Tente de parser la réponse JSON d'un worker.
/// Retourne None si le JSON est invalide ou incomplet.
fn parse_worker_response(model: &str, raw: &str) -> Option<LlmVote> {
    match serde_json::from_str::<WorkerResponse>(raw) {
        Ok(r) => Some(LlmVote {
            model_id: model.to_string(),
            run_static_scan: r.run_static_scan,
            run_compliance_scan: r.run_compliance_scan,
            run_dynamic_scan: r.run_dynamic_scan,
            confidence: r.confidence.clamp(0.0, 1.0),
            reasoning: r.reasoning,
        }),
        Err(e) => {
            warn!("Worker {} : JSON invalide ({}) — réponse brute : {}", model, e, raw);
            None
        }
    }
}

/// Orchestre le pipeline complet de décision :
/// 1. Construit le prompt depuis les artefacts
/// 2. Interroge les 3 workers séquentiellement
/// 3. Passe les votes à l'arbitre
/// 4. Retourne la ScanDecision finale
///
/// Exécution séquentielle (un modèle à la fois) pour respecter la contrainte
/// 8GB VRAM sur laptop. Sur serveur GPU, remplacer la boucle par tokio::join!
/// pour une exécution parallèle sans changer la logique.
pub async fn run_decision(
    bundle: &ArtifactBundle,
    backend: &dyn LlmBackend,
    config: &Config,
) -> Result<ScanDecision, LlmError> {
    let ctx = &bundle.pull_context;
    let image = format!("{}/{}:{}", ctx.registry, ctx.repository, ctx.tag);

    info!("Début analyse LLM pour {}", image);

    let worker_messages = build_worker_prompt(bundle);
    let mut votes: Vec<LlmVote> = Vec::new();

    // --- Workers séquentiels ---
    for model in &config.worker_models {
        info!("Worker {} en cours...", model);
        match backend.chat(model, worker_messages.clone()).await {
            Ok(raw) => {
                if let Some(vote) = parse_worker_response(model, &raw) {
                    info!(
                        "Worker {} : static={} compliance={} dynamic={} confidence={:.2}",
                        model,
                        vote.run_static_scan,
                        vote.run_compliance_scan,
                        vote.run_dynamic_scan,
                        vote.confidence
                    );
                    votes.push(vote);
                }
            }
            Err(e) => warn!("Worker {} échoué : {}", model, e),
        }
    }

    if votes.is_empty() {
        return Ok(fail_safe_decision(ctx.uuid));
    }

    info!("{}/{} workers ont répondu, envoi à l'arbitre", votes.len(), config.worker_models.len());

    // --- Arbitre ---
    let arbiter_messages = build_arbiter_prompt(&votes, &image);

    let arbiter_raw = backend
        .chat(&config.arbiter_model, arbiter_messages)
        .await
        .map_err(|e| {
            error!("Arbitre {} échoué : {}", config.arbiter_model, e);
            e
        })?;

    match serde_json::from_str::<ArbiterResponse>(&arbiter_raw) {
        Ok(r) => {
            let decision = ScanDecision {
                pull_id: ctx.uuid,
                run_static_scan: r.run_static_scan,
                run_compliance_scan: r.run_compliance_scan,
                run_dynamic_scan: r.run_dynamic_scan,
                final_confidence: r.final_confidence.clamp(0.0, 1.0),
                arbiter_rationale: r.arbiter_rationale,
                votes,
            };
            info!(
                "Décision finale : static={} compliance={} dynamic={} confidence={:.2}",
                decision.run_static_scan,
                decision.run_compliance_scan,
                decision.run_dynamic_scan,
                decision.final_confidence
            );
            Ok(decision)
        }
        Err(e) => {
            warn!(
                "Arbitre JSON invalide ({}) — activation fail-safe. Réponse brute : {}",
                e, arbiter_raw
            );
            Ok(fail_safe_decision(ctx.uuid))
        }
    }
}
