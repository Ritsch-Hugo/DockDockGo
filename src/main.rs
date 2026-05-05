mod llm_mcp;

use anyhow::Result;
use axum::{routing::post, Router};
use dotenvy::dotenv;
use std::{env, net::SocketAddr};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let state = llm_mcp::AppState::new_from_env()?;

    let app = Router::new()
        .route("/v1/high-level", post(llm_mcp::high_level))
        .with_state(state);

    let bind = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:4000".to_string());
    let addr: SocketAddr = bind.parse()?;
    println!("[HIGH] listening on http://{addr}");

    axum::serve(tokio::net::TcpListener::bind(addr).await?, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    println!("[HIGH] Signal reçu, arrêt gracieux en cours...");
}
