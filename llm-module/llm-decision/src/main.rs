mod artifacts;
mod decision;
mod mcp_client;
mod prompt;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::{DefaultBodyLimit, State}, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use serde_json::Value;
use tracing::{error, info};

use llm_common::{Config, Digest, OpenAiBackend, PullContext};
use mcp_client::{McpClient, image_is_clean_schema, mcp_to_openai_schema};

// ============================================================
// État partagé
// ============================================================

struct AppState {
    backend: OpenAiBackend,
    config: Config,
    /// Client MCP pour appeler les tools de scan après décision.
    mcp_client: Arc<McpClient>,
    /// Schémas bruts MCP des tools disponibles (chargés une fois au démarrage).
    /// Convertis en format OpenAI à chaque requête avec le bon quarantine_path.
    mcp_tools: Vec<Value>,
}

// ============================================================
// Validation du PullContext
// ============================================================

const MAX_COMPONENT_LEN: usize = 255;
const MAX_TAG_LEN: usize = 128;
const MAX_IP_LEN: usize = 45; // IPv6 max
const MAX_DIGESTS: usize = 50;

fn validate_digest(d: &Digest) -> bool {
    if d.algorithm == "sha256" {
        d.value.len() == 64 && d.value.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        // Autre algo : on exige juste que la valeur soit non vide et sans null bytes
        !d.value.is_empty() && !d.value.bytes().any(|b| b == 0)
    }
}

fn validate_pull_context(ctx: &PullContext) -> Result<(), &'static str> {
    if ctx.registry.is_empty() || ctx.registry.len() > MAX_COMPONENT_LEN {
        return Err("registry : longueur invalide (1–255)");
    }
    if ctx.repository.is_empty() || ctx.repository.len() > MAX_COMPONENT_LEN {
        return Err("repository : longueur invalide (1–255)");
    }
    if ctx.tag.is_empty() || ctx.tag.len() > MAX_TAG_LEN {
        return Err("tag : longueur invalide (1–128)");
    }
    if ctx.ip_client.len() > MAX_IP_LEN {
        return Err("ip_client : longueur invalide");
    }
    for field in [&ctx.registry, &ctx.repository, &ctx.tag] {
        if field.contains("..") || field.bytes().any(|b| b == 0) {
            return Err("champ invalide : séquence interdite ou caractère nul");
        }
    }
    let total_digests = ctx.manifest_digests.len()
        + ctx.blob_digests.len()
        + ctx.referrers_digests.len();
    if total_digests > MAX_DIGESTS * 3 {
        return Err("trop de digests dans le PullContext");
    }
    for digests in [&ctx.manifest_digests, &ctx.blob_digests, &ctx.referrers_digests] {
        if digests.len() > MAX_DIGESTS {
            return Err("trop de digests dans une liste");
        }
        for d in digests {
            if !validate_digest(d) {
                return Err("digest invalide : format non reconnu");
            }
        }
    }
    Ok(())
}

// ============================================================
// Tests unitaires de la validation
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use llm_common::Digest;

    fn valid_digest(value: &str) -> Digest {
        Digest { algorithm: "sha256".to_string(), value: value.to_string() }
    }

    fn base_ctx() -> PullContext {
        PullContext {
            uuid: uuid::Uuid::new_v4(),
            ip_client: "127.0.0.1".to_string(),
            registry: "ghcr.io".to_string(),
            repository: "library/alpine".to_string(),
            tag: "3.18".to_string(),
            manifest_digests: vec![valid_digest(&"a".repeat(64))],
            blob_digests: vec![],
            referrers_digests: vec![],
            manifest_racine_digest: None,
            digests_possible: vec![],
            digests_expected: vec![],
            os: "linux".to_string(),
            arch: "amd64".to_string(),
            pull_completed: true,
        }
    }

    #[test]
    fn test_ctx_valide() {
        assert!(validate_pull_context(&base_ctx()).is_ok());
    }

    #[test]
    fn test_registry_vide() {
        let mut ctx = base_ctx();
        ctx.registry = "".to_string();
        assert!(validate_pull_context(&ctx).is_err());
    }

    #[test]
    fn test_traversal_dans_registry() {
        let mut ctx = base_ctx();
        ctx.registry = "../../../etc".to_string();
        assert!(validate_pull_context(&ctx).is_err());
    }

    #[test]
    fn test_traversal_dans_tag() {
        let mut ctx = base_ctx();
        ctx.tag = "../../passwd".to_string();
        assert!(validate_pull_context(&ctx).is_err());
    }

    #[test]
    fn test_trop_de_digests() {
        let mut ctx = base_ctx();
        ctx.manifest_digests = (0..51).map(|i| valid_digest(&format!("{:0>64}", i))).collect();
        assert!(validate_pull_context(&ctx).is_err());
    }

    #[test]
    fn test_digest_sha256_invalide() {
        let mut ctx = base_ctx();
        ctx.manifest_digests = vec![Digest {
            algorithm: "sha256".to_string(),
            value: "pas_un_sha256".to_string(),
        }];
        assert!(validate_pull_context(&ctx).is_err());
    }

    #[test]
    fn test_tag_trop_long() {
        let mut ctx = base_ctx();
        ctx.tag = "a".repeat(129);
        assert!(validate_pull_context(&ctx).is_err());
    }
}

// ============================================================
// Health check
// ============================================================

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

// ============================================================
// Route principale
// ============================================================

/// POST /v1/decision
/// Reçoit un PullContext JSON de l'orchestrateur, charge les artefacts depuis
/// la quarantaine, lance l'analyse LLM et retourne une ScanDecision JSON.
async fn decide(
    State(state): State<Arc<AppState>>,
    Json(ctx): Json<PullContext>,
) -> impl IntoResponse {
    if let Err(reason) = validate_pull_context(&ctx) {
        return (StatusCode::BAD_REQUEST, format!("Requête invalide : {reason}")).into_response();
    }

    info!(
        "Requête reçue pour {}/{}:{} (uuid={})",
        ctx.registry, ctx.repository, ctx.tag, ctx.uuid
    );

    let bundle = match artifacts::load_artifacts(&ctx, &state.config.quarantine_path).await {
        Ok(b) => b,
        Err(e) => {
            error!("Impossible de charger les artefacts : {}", e);
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Artefacts introuvables : {e}"),
            )
                .into_response();
        }
    };

    // Construire le chemin quarantaine pour cette image spécifique
    let quarantine_path = state
        .config
        .quarantine_path
        .join(&ctx.registry)
        .join(&ctx.repository)
        .join(&ctx.tag)
        .to_string_lossy()
        .to_string();

    // Convertir les schémas MCP en format OpenAI avec le quarantine_path réel.
    // On ajoute image_is_clean en premier : avec tool_choice:"required", le worker
    // DOIT appeler au moins un tool — ce tool lui permet de dire "image propre".
    let mut openai_schemas: Vec<Value> = vec![image_is_clean_schema()];
    openai_schemas.extend(
        state
            .mcp_tools
            .iter()
            .map(|t| mcp_to_openai_schema(t, &quarantine_path)),
    );

    let image = format!("{}/{}:{}", ctx.registry, ctx.repository, ctx.tag);

    match decision::run_decision(
        &bundle,
        &state.backend,
        &state.config,
        openai_schemas,
        &state.mcp_client,
        &quarantine_path,
    )
    .await
    {
        Ok(scan_decision) => {
            match decision::run_analysis(
                scan_decision,
                &bundle,
                &state.backend,
                &state.config,
                &image,
            )
            .await
            {
                Ok(report) => (StatusCode::OK, Json(report)).into_response(),
                Err(e) => {
                    error!("Pipeline phase 3 dégradé : {}", e);
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(serde_json::json!({
                            "error": "pipeline_failed",
                            "reason": e.to_string()
                        })),
                    )
                        .into_response()
                }
            }
        }
        Err(llm_common::LlmError::PipelineFailed(reason)) => {
            error!("Pipeline phase 1 dégradé : {}", reason);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "pipeline_failed",
                    "reason": reason
                })),
            )
                .into_response()
        }
        Err(e) => {
            error!("Erreur pipeline décision : {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur analyse LLM : {e}"),
            )
                .into_response()
        }
    }
}

// ============================================================
// Point d'entrée
// ============================================================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env();
    let backend = OpenAiBackend::new(config.llm_base_url.clone(), config.llm_timeout_secs, config.api_key.clone());

    info!("llm-decision démarrage sur le port {}", config.decision_port);
    info!("LLM backend URL : {}", config.llm_base_url);
    info!("Quarantaine : {:?}", config.quarantine_path);
    info!("MCP server : {}", config.mcp_server_url);

    // Attendre que llm-manager soit prêt avant d'accepter des requêtes
    const MAX_RETRIES: u32 = 24; // 24 × 5s = 2 minutes max
    let manager_health = format!("{}/health", config.manager_url());
    info!("Attente de llm-manager sur {}...", manager_health);
    let mut manager_ready = false;
    for attempt in 1..=MAX_RETRIES {
        match backend.http_client().get(&manager_health).send().await {
            Ok(r) if r.status().is_success() => {
                info!("llm-manager prêt");
                manager_ready = true;
                break;
            }
            _ => {
                tracing::warn!(
                    "llm-manager pas encore prêt ({}/{}), nouvelle tentative dans 5s...",
                    attempt, MAX_RETRIES
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
    if !manager_ready {
        error!("llm-manager injoignable après {} tentatives, abandon.", MAX_RETRIES);
        std::process::exit(1);
    }

    // Charger les tool schemas depuis le serveur MCP (une seule fois au démarrage)
    let mcp_client = Arc::new(McpClient::new(config.mcp_server_url.clone(), config.mcp_timeout_secs));
    let mut mcp_tools_opt: Option<Vec<Value>> = None;
    for attempt in 1..=MAX_RETRIES {
        match mcp_client.list_tools().await {
            Ok(tools) if !tools.is_empty() => {
                info!("MCP tools chargés avec succès ({} tools)", tools.len());
                mcp_tools_opt = Some(tools);
                break;
            }
            Ok(_) => {
                tracing::warn!(
                    "MCP server accessible mais aucun tool disponible ({}/{}), retry dans 5s...",
                    attempt, MAX_RETRIES
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            Err(e) => {
                tracing::warn!(
                    "MCP server pas encore prêt ({}/{}) : {}, retry dans 5s...",
                    attempt, MAX_RETRIES, e
                );
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
    let mcp_tools = match mcp_tools_opt {
        Some(tools) => tools,
        None => {
            error!("MCP server injoignable après {} tentatives, abandon.", MAX_RETRIES);
            std::process::exit(1);
        }
    };

    let port = config.decision_port;
    let state = Arc::new(AppState {
        backend,
        config,
        mcp_client,
        mcp_tools,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/decision", post(decide))
        .layer(DefaultBodyLimit::max(1 * 1024 * 1024)) // 1 MB max
        .with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("Adresse invalide");
    info!("llm-decision en écoute sur http://{}", addr);

    axum::serve(
        tokio::net::TcpListener::bind(addr)
            .await
            .expect("Impossible de binder le port"),
        app,
    )
    .await
    .expect("Erreur serveur axum");
}
