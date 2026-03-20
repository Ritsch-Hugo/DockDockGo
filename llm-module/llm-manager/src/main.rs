use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;
use tracing::{error, info, warn};

use llm_common::{Config, LlmBackend, OllamaBackend};

// ============================================================
// État partagé entre les routes Axum
// ============================================================

struct AppState {
    backend: OllamaBackend,
    config: Config,
}

// ============================================================
// Structures de réponse HTTP
// ============================================================

#[derive(Serialize)]
struct ModelStatus {
    name: String,
    available: bool,
}

#[derive(Serialize)]
struct HealthResponse {
    /// "ok" = tous les modèles prêts | "degraded" = certains manquent | "unavailable" = Ollama injoignable
    status: &'static str,
    models: Vec<ModelStatus>,
}

#[derive(Serialize)]
struct ModelsResponse {
    models: Vec<String>,
}

// ============================================================
// Routes
// ============================================================

/// GET /health — vérifie qu'Ollama tourne et que tous les modèles requis sont chargés.
/// Utilisé par llm-decision au démarrage et par les health checks Kubernetes.
async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Vérifier chaque modèle requis (3 workers + 1 arbitre)
    let required: Vec<&str> = state
        .config
        .worker_models
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(state.config.arbiter_model.as_str()))
        .collect();

    let mut statuses: Vec<ModelStatus> = Vec::new();
    let mut all_ok = true;
    let mut ollama_up = true;

    for model in &required {
        match state.backend.is_healthy(model).await {
            Ok(true) => {
                info!("Modèle {} disponible", model);
                statuses.push(ModelStatus {
                    name: model.to_string(),
                    available: true,
                });
            }
            Ok(false) => {
                warn!("Modèle {} manquant dans Ollama", model);
                statuses.push(ModelStatus {
                    name: model.to_string(),
                    available: false,
                });
                all_ok = false;
            }
            Err(e) => {
                error!("Erreur vérification modèle {} : {}", model, e);
                statuses.push(ModelStatus {
                    name: model.to_string(),
                    available: false,
                });
                all_ok = false;
                ollama_up = false;
            }
        }
    }

    let status = if !ollama_up {
        "unavailable"
    } else if all_ok {
        "ok"
    } else {
        "degraded"
    };

    let http_code = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (http_code, Json(HealthResponse { status, models: statuses }))
}

/// GET /models — retourne la liste de tous les modèles disponibles dans Ollama.
async fn models(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.backend.list_models().await {
        Ok(list) => {
            let names = list.into_iter().map(|m| m.name).collect();
            (StatusCode::OK, Json(ModelsResponse { models: names })).into_response()
        }
        Err(e) => {
            error!("Impossible de lister les modèles Ollama : {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Ollama injoignable : {e}"),
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
    // Initialiser les logs (filtrables via RUST_LOG=info)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env();
    let backend = OllamaBackend::new(config.ollama_base_url.clone(), config.llm_timeout_secs);

    info!("llm-manager démarrage sur le port {}", config.manager_port);
    info!("Ollama URL : {}", config.ollama_base_url);
    info!(
        "Modèles requis : {:?} + arbitre {}",
        config.worker_models, config.arbiter_model
    );

    let port = config.manager_port;
    let state = Arc::new(AppState { backend, config });

    let app = Router::new()
        .route("/health", get(health))
        .route("/models", get(models))
        .with_state(state);
    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("Adresse invalide");

    info!("llm-manager en écoute sur http://{}", addr);

    axum::serve(
        tokio::net::TcpListener::bind(addr)
            .await
            .expect("Impossible de binder le port"),
        app,
    )
    .await
    .expect("Erreur serveur axum");
}
