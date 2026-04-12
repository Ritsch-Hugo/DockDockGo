mod artifacts;
mod decision;
mod mcp_client;
mod prompt;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use serde_json::Value;
use tracing::{error, info};

use llm_common::{Config, OllamaBackend, PullContext};
use mcp_client::{McpClient, image_is_clean_schema, mcp_to_openai_schema};

// ============================================================
// État partagé
// ============================================================

struct AppState {
    backend: OllamaBackend,
    config: Config,
    /// Client MCP pour appeler les tools de scan après décision.
    mcp_client: Arc<McpClient>,
    /// Schémas bruts MCP des tools disponibles (chargés une fois au démarrage).
    /// Convertis en format OpenAI à chaque requête avec le bon quarantine_path.
    mcp_tools: Vec<Value>,
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
        Ok(scan_decision) => (StatusCode::OK, Json(scan_decision)).into_response(),
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
    let backend = OllamaBackend::new(config.ollama_base_url.clone(), config.llm_timeout_secs);

    info!("llm-decision démarrage sur le port {}", config.decision_port);
    info!("Ollama URL : {}", config.ollama_base_url);
    info!("Quarantaine : {:?}", config.quarantine_path);
    info!("MCP server : {}", config.mcp_server_url);

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Impossible de créer le client HTTP");

    // Attendre que llm-manager soit prêt avant d'accepter des requêtes
    const MAX_RETRIES: u32 = 24; // 24 × 5s = 2 minutes max
    let manager_health = format!("{}/health", config.manager_url());
    info!("Attente de llm-manager sur {}...", manager_health);
    let mut manager_ready = false;
    for attempt in 1..=MAX_RETRIES {
        match http.get(&manager_health).send().await {
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
    let mcp_client = Arc::new(McpClient::new(config.mcp_server_url.clone()));
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
