mod artifacts;
mod decision;
mod prompt;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use tracing::{error, info};

use llm_common::{Config, OllamaBackend, PullContext};

// ============================================================
// État partagé
// ============================================================

struct AppState {
    backend: OllamaBackend,
    config: Config,
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

    match decision::run_decision(&bundle, &state.backend, &state.config).await {
        Ok(scan_decision) => (StatusCode::OK, Json(scan_decision)).into_response(),
        Err(e) => {
            error!("Erreur pipeline décision : {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Erreur analyse LLM : {e}")).into_response()
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

    // Attendre que llm-manager soit prêt avant d'accepter des requêtes
    let manager_health = format!("{}/health", config.manager_url());
    info!("Attente de llm-manager sur {}...", manager_health);

    let http = reqwest::Client::new();
    loop {
        match http.get(&manager_health).send().await {
            Ok(r) if r.status().is_success() => {
                info!("llm-manager prêt, démarrage du serveur");
                break;
            }
            _ => {
                tracing::warn!("llm-manager pas encore prêt, nouvelle tentative dans 5s...");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    let port = config.decision_port;
    let state = Arc::new(AppState { backend, config });

    let app = Router::new()
        .route("/v1/decision", post(decide))
        .with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("Adresse invalide");
    info!("llm-decision en écoute sur http://{}", addr);

    axum::serve(
        tokio::net::TcpListener::bind(addr).await.expect("Impossible de binder le port"),
        app,
    )
    .await
    .expect("Erreur serveur axum");
}
