mod llm_mcp;

use anyhow::Result;
use llm_mcp::LlmService;
use rmcp::{transport::stdio, ServiceExt};
use dotenvy::dotenv;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok(); // Charge les variables d'environnement depuis .env
    let service = LlmService::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
