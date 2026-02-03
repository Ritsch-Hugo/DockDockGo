use anyhow::{anyhow, Result};
use rmcp::{
    ErrorData as McpError,
    handler::server::{tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars,
    tool, tool_handler, tool_router,
    ServerHandler,
};
use serde::Deserialize;

/// ===============================
/// Service MCP
/// ===============================
#[derive(Clone, Debug)]
pub struct LlmService {
    pub(crate) tool_router: ToolRouter<Self>,
}

/// ===============================
/// Paramètres MCP
/// ===============================
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LlmOpinionRequest {
    #[schemars(description = "Référence d'image Docker (ex: alpine:latest, ghcr.io/org/app:1.0)")]
    pub image: String,
}

/// ===============================
/// Image Docker parsée
/// ===============================
#[derive(Debug, Clone)]
struct ImageRef {
    registry: String,
    owner: String,
    name: String,
    tag: String,
}

/// ===============================
/// Router MCP
/// ===============================
#[tool_router]
impl LlmService {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Tool MCP principal
    #[tool(
        name = "llm_image_opinion",
        description = "Donne un avis DevSecOps sur une image Docker à partir de métadonnées (registry, owner, tag, popularité)."
    )]
    async fn llm_image_opinion(
        &self,
        Parameters(LlmOpinionRequest { image }): Parameters<LlmOpinionRequest>,
    ) -> Result<CallToolResult, McpError> {
        // 1️⃣ API key Gemini
        let api_key = std::env::var("GEMINI_API_KEY").map_err(|_| {
            McpError::internal_error(
                "La variable d'environnement GEMINI_API_KEY n'est pas définie",
                None,
            )
        })?;

        let client = reqwest::Client::new();

        // 2️⃣ Parsing image Docker
        let image_ref = parse_image_ref(&image);

        // 3️⃣ GitHub stars (best-effort)
        let github_stars = fetch_github_stars(
            &client,
            &image_ref.owner,
            &image_ref.name,
        )
        .await;

        // 4️⃣ Appel LLM
        let opinion = analyze_image_with_gemini(
            &client,
            &api_key,
            &image_ref,
            github_stars,
        )
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(opinion)]))
    }
}

/// ===============================
/// Parsing image Docker
/// ===============================
fn parse_image_ref(input: &str) -> ImageRef {
    let mut registry = "registry-1.docker.io".to_string();
    let mut owner = "library".to_string();
    let mut rest = input;

    // registry explicite
    if input.contains('/') && input.split('/').next().unwrap().contains('.') {
        let mut parts = input.splitn(2, '/');
        registry = parts.next().unwrap().to_string();
        rest = parts.next().unwrap();
    }

    let parts: Vec<&str> = rest.split('/').collect();
    let last = parts.last().unwrap();

    let (name, tag) = match last.split_once(':') {
        Some((n, t)) => (n.to_string(), t.to_string()),
        None => (last.to_string(), "latest".to_string()),
    };

    if parts.len() == 2 {
        owner = parts[0].to_string();
    }

    ImageRef {
        registry,
        owner,
        name,
        tag,
    }
}

/// ===============================
/// GitHub stars (best effort) sans erreur bloquante 
/// ===============================
async fn fetch_github_stars(
    client: &reqwest::Client,
    owner: &str,
    repo: &str,
) -> Option<u64> {
    let url = format!("https://api.github.com/repos/{owner}/{repo}");

    //appel HTTP Github 
    let resp = client 
        .get(&url)
        .header("User-Agent", "dockdockgo")
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let json: serde_json::Value = resp.json().await.ok()?;
    json.get("stargazers_count")?.as_u64()
}

/// ===============================
/// Appel Gemini
/// ===============================
async fn analyze_image_with_gemini(
    client: &reqwest::Client,
    api_key: &str,
    image: &ImageRef,
    github_stars: Option<u64>,
) -> Result<String> {
    let prompt = format!(
        "Tu es un expert DevSecOps spécialisé dans la supply chain Docker.\n\n\
        Informations connues sur l'image :\n\
        - Registry : {registry}\n\
        - Propriétaire : {owner}\n\
        - Image : {name}\n\
        - Tag : {tag}\n\
        - GitHub stars : {stars}\n\n\
        Analyse ces éléments et :\n\
        1. Évalue la fiabilité de la source et du registre.\n\
        2. Analyse les risques liés au tag utilisé.\n\
        3. Prends en compte la popularité si disponible.(Mentionne explicitement le nombre d’étoiles GitHub si disponible.)\n\
        4. Conclus par un niveau de risque supply-chain : FAIBLE / MOYEN / ÉLEVÉ.\n\n\
        Réponds en français, de manière claire et concise.",
        registry = image.registry,
        owner = image.owner,
        name = image.name,
        tag = image.tag,
        stars = github_stars
            .map(|s| s.to_string())
            .unwrap_or_else(|| "inconnu".to_string()),
    );

    let body = serde_json::json!({
        "contents": [
            { "parts": [ { "text": prompt } ] }
        ]
    });

    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={}",
        api_key
    );

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("Erreur HTTP Gemini: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("Gemini error {}: {}", status, truncate(&text, 500)));
    }

    #[derive(Deserialize)]
    struct GeminiResponse {
        candidates: Option<Vec<Candidate>>,
    }
    #[derive(Deserialize)]
    struct Candidate {
        content: Option<ContentInner>,
    }
    #[derive(Deserialize)]
    struct ContentInner {
        parts: Option<Vec<Part>>,
    }
    #[derive(Deserialize)]
    struct Part {
        text: Option<String>,
    }

    let resp_json: GeminiResponse = resp.json().await?;
    let text = resp_json
        .candidates
        .and_then(|mut c| c.pop())
        .and_then(|c| c.content)
        .and_then(|c| c.parts.and_then(|mut p| p.pop()))
        .and_then(|p| p.text)
        .ok_or_else(|| anyhow!("Réponse Gemini vide ou invalide"))?;

    Ok(text.trim().to_string())
}

/// utilitaire
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// ===============================
/// Infos serveur MCP
/// ===============================
#[tool_handler]
impl ServerHandler for LlmService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "DockDockGo MCP LLM server : fournit un avis DevSecOps à partir de métadonnées d'image Docker."
                    .to_string(),
            ),
        }
    }
}
