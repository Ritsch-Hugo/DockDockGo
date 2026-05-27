use crate::auth::{AppState, OidcState};
use axum::extract::DefaultBodyLimit;
use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum::{routing::get, Router};
use std::net::SocketAddr;
use tokio::signal;
use tower_http::limit::RequestBodyLimitLayer;

mod auth;
mod dashboard;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // ── Base de données ───────────────────────────────────────────────────────
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL doit être défini dans le .env");

    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("Echec de connexion à la DB");

    // ── État global ───────────────────────────────────────────────────────────
    let cdv_url = std::env::var("CYCLE_DE_VIE_URL")
        .ok()
        .filter(|s| !s.is_empty());

    let state = AppState {
        oidc_ctx: OidcState::default(),
        db: pool,
        cdv_url,
        http_client: reqwest::Client::new(),
    };

    // ── Routeur ───────────────────────────────────────────────────────────────
    let app = Router::new()
        // Auth OIDC
        .route("/", get(auth::login_handler))
        .route("/callback", get(auth::callback_handler))
        .route("/logout", get(auth::logout))
        .route("/logged-out", get(auth::logged_out_handler))
        // Healthcheck — pas besoin du state, réponse statique
        .route("/health", get(health_handler))
        // Dashboard
        .nest("/dashboard", dashboard::router())
        .with_state(state)
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024));

    // ── Adresse d'écoute ──────────────────────────────────────────────────────
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3010".to_string());
    let addr: SocketAddr = listen_addr.parse().expect("LISTEN_ADDR invalide");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Impossible de binder le port");

    println!("Dashboard listening on http://{addr}");

    // ── Graceful shutdown (SIGTERM + SIGINT) ──────────────────────────────────
    let server = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal());

    // On attend SOIT que le serveur finisse, SOIT que le signal de shutdown soit reçu
    tokio::select! {
        res = server => {
            if let Err(e) = res {
                eprintln!("Erreur serveur : {}", e);
            }
        },
        _ = shutdown_signal() => {
            println!("Arrêt immédiat forcé par l'utilisateur.");
        },
    }

    println!("Serveur arrêté proprement.");
}

// ── Handler /health ───────────────────────────────────────────────────────────
async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let db_status = match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => "ok",
        Err(_) => "error",
    };

    let status_code = if db_status == "ok" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status_code,
        axum::Json(serde_json::json!({
            "status": "ok",
            "database": db_status,
        })),
    )
}

// ── Signal handler : attend SIGTERM (Kubernetes) ou SIGINT (Ctrl+C) ──────────
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Impossible d'installer le handler CTRL+C");
    };

    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Impossible d'installer le handler SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c   => { println!("SIGINT reçu, arrêt..."); },
        _ = sigterm  => { println!("SIGTERM reçu, arrêt..."); },
    }
}
