use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;
use tracing::{error, info, warn};

use llm_common::{Config, OpenAiBackend};

// ============================================================
// État partagé entre les routes Axum
// ============================================================

struct AppState {
    backend: OpenAiBackend,
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

/// GET /health — vérifie que le backend LLM répond et que tous les modèles requis sont disponibles.
/// Utilisé par llm-decision au démarrage et par les health checks Kubernetes.
async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let required: Vec<&str> = state
        .config
        .worker_models
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(state.config.arbiter_model.as_str()))
        .collect();

    // Un seul ping + un seul list_models pour tous les modèles
    if let Err(e) = state.backend.ping().await {
        error!("Backend LLM injoignable : {}", e);
        let statuses = required
            .iter()
            .map(|m| ModelStatus {
                name: m.to_string(),
                available: false,
            })
            .collect();
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "unavailable",
                models: statuses,
            }),
        );
    }

    let available_models = match state.backend.list_models().await {
        Ok(m) => m,
        Err(e) => {
            error!("Impossible de lister les modèles : {}", e);
            let statuses = required
                .iter()
                .map(|m| ModelStatus {
                    name: m.to_string(),
                    available: false,
                })
                .collect();
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse {
                    status: "unavailable",
                    models: statuses,
                }),
            );
        }
    };

    let mut statuses: Vec<ModelStatus> = Vec::new();
    let mut all_ok = true;

    for model in &required {
        let model_lower = model.to_lowercase();
        let available = available_models.iter().any(|m| {
            let id = m.id.to_lowercase();
            id == model_lower || id.contains(&model_lower) || model_lower.contains(&id)
        });

        if available {
            info!("Modèle {} disponible", model);
        } else {
            warn!("Modèle {} manquant dans le backend LLM", model);
            all_ok = false;
        }
        statuses.push(ModelStatus {
            name: model.to_string(),
            available,
        });
    }

    let status = if all_ok { "ok" } else { "degraded" };
    let http_code = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        http_code,
        Json(HealthResponse {
            status,
            models: statuses,
        }),
    )
}

/// GET /models — retourne la liste de tous les modèles disponibles dans le backend LLM.
async fn models(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.backend.list_models().await {
        Ok(list) => {
            let names = list.into_iter().map(|m| m.id).collect();
            (StatusCode::OK, Json(ModelsResponse { models: names })).into_response()
        }
        Err(e) => {
            error!("Impossible de lister les modèles LLM : {}", e);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("LLM backend injoignable : {e}"),
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
    let backend = OpenAiBackend::new(
        config.llm_base_url.clone(),
        config.llm_timeout_secs,
        config.api_key.clone(),
    );

    info!("llm-manager démarrage sur le port {}", config.manager_port);
    info!("LLM backend URL : {}", config.llm_base_url);
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
