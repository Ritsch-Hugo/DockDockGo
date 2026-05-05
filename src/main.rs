mod llm_mcp;

use anyhow::Result;
use axum::{routing::post, Router};
use dotenvy::dotenv;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok(); // Charge .env

    // Build state (reqwest + GEMINI key) utilisé par le handler HTTP
    let state = llm_mcp::AppState::new_from_env()?;

    // Endpoint attendu par l'orchestrateur : POST http://127.0.0.1:4000/v1/high-level
    let app = Router::new()
        .route("/v1/high-level", post(llm_mcp::high_level))
        .with_state(state);

    let addr: SocketAddr = "0.0.0.0:4000".parse().unwrap();
    println!("[HIGH] listening on http://{addr}");

    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}
