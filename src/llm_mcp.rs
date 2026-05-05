use anyhow::{anyhow, Result};

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use rmcp::{
    handler::server::{tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// ===============================
/// State HTTP (pour orchestrateur)
/// ===============================
#[derive(Clone)]
pub struct AppState {
    pub client: reqwest::Client,
    pub gemini_key: String,
}

impl AppState {
    pub fn new_from_env() -> anyhow::Result<Self> {
        let gemini_key = std::env::var("GEMINI_API_KEY")
            .map_err(|_| anyhow!("La variable d'environnement GEMINI_API_KEY n'est pas définie"))?;

        let client = reqwest::Client::new();

        Ok(Self { client, gemini_key })
    }
}

/// ===============================
/// Types compatibles avec le vrai PullContext proxy
/// ===============================
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullContext {
    pub uuid: Uuid,
    pub ip_client: String,
    pub registry: String,
    pub repository: String,
    pub tag: String,

    #[serde(default)]
    pub manifest_digests: Vec<Digest>,
    #[serde(default)]
    pub blob_digests: Vec<Digest>,
    #[serde(default)]
    pub referrers_digests: Vec<Digest>,

    #[serde(default)]
    pub manifest_racine_digest: Option<Digest>,
    #[serde(default)]
    pub digests_possible: Vec<Digest>,
    #[serde(default)]
    pub digests_expected: Vec<Digest>,

    pub os: String,
    pub arch: String,

    pub pull_completed: bool,

    #[serde(default)]
    pub scan_final_done: bool,
    #[serde(default)]
    pub in_whitelist: Option<bool>,
    #[serde(default)]
    pub in_blacklist: Option<bool>,
    #[serde(default)]
    pub in_cache: Option<bool>,
    #[serde(default)]
    pub check_if_verify_digest_completed: bool,
    #[serde(default)]
    pub scan_status: Option<String>,
    #[serde(default)]
    pub client_type: String,
}

#[derive(Deserialize)]
pub struct HighLevelRespIn {
    pub pull_id: Uuid,
    pub opinion: String,
}

#[derive(Serialize)]
pub struct HighLevelResp {
    pub pull_id: Uuid,
    pub opinion: String,
}

/// ===============================
/// Handler HTTP compatible orchestrateur
/// POST /v1/high-level  (body = PullContext)
/// ===============================
pub async fn high_level(
    State(st): State<AppState>,
    Json(ctx): Json<PullContext>,
) -> impl IntoResponse {
    let image_str = format!("{}/{}:{}", ctx.registry, ctx.repository, ctx.tag);
    let image_ref = parse_image_ref(&image_str);

    let github_stars = fetch_github_stars(&st.client, &image_ref.owner, &image_ref.name).await;

    match analyze_image_with_gemini(
        &st.client,
        &st.gemini_key,
        &image_ref,
        github_stars,
        Some(&ctx),
    )
    .await
    {
        Ok(opinion) => (
            StatusCode::OK,
            Json(HighLevelResp {
                pull_id: ctx.uuid,
                opinion,
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("high-level error: {e}"),
        )
            .into_response(),
    }
}

/// ===============================
/// Service MCP (toujours dispo)
/// ===============================
#[derive(Clone, Debug)]
pub struct LlmService {
    pub(crate) tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LlmOpinionRequest {
    #[schemars(description = "Référence d'image Docker (ex: alpine:latest, ghcr.io/org/app:1.0)")]
    pub image: String,
}

#[derive(Debug, Clone)]
struct ImageRef {
    registry: String,
    owner: String,
    name: String,
    tag: String,
}

#[tool_router]
impl LlmService {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        name = "llm_image_opinion",
        description = "Donne un avis DevSecOps sur une image Docker à partir de métadonnées (registry, owner, tag, popularité)."
    )]
    async fn llm_image_opinion(
        &self,
        Parameters(LlmOpinionRequest { image }): Parameters<LlmOpinionRequest>,
    ) -> Result<CallToolResult, McpError> {
        let api_key = std::env::var("GEMINI_API_KEY").map_err(|_| {
            McpError::internal_error(
                "La variable d'environnement GEMINI_API_KEY n'est pas définie",
                None,
            )
        })?;

        let client = reqwest::Client::new();

        let image_ref = parse_image_ref(&image);

        let github_stars = fetch_github_stars(&client, &image_ref.owner, &image_ref.name).await;

        let opinion = analyze_image_with_gemini(
            &client,
            &api_key,
            &image_ref,
            github_stars,
            None,
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
/// GitHub stars (best effort)
/// ===============================
async fn fetch_github_stars(client: &reqwest::Client, owner: &str, repo: &str) -> Option<u64> {
    let url = format!("https://api.github.com/repos/{owner}/{repo}");

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
    ctx: Option<&PullContext>,
) -> Result<String> {
    let repository = ctx
        .map(|c| c.repository.as_str())
        .unwrap_or(&image.name);

    let tag = ctx
        .map(|c| c.tag.as_str())
        .unwrap_or(&image.tag);

    let os = ctx
        .map(|c| c.os.as_str())
        .unwrap_or("unknown");

    let arch = ctx
        .map(|c| c.arch.as_str())
        .unwrap_or("unknown");

    let prompt = format!(
        "Tu es un expert DevSecOps spécialisé dans la supply chain Docker.\n\n\
        Informations connues sur l'image :\n\
        - Registry : {registry}\n\
        - Repository : {repository}\n\
        - Tag : {tag}\n\
        - OS : {os}\n\
        - Architecture : {arch}\n\
        - GitHub stars : {stars}\n\n\
        Analyse ces éléments et :\n\
        1. Évalue la fiabilité de la source et du registre.\n\
        2. Analyse les risques liés au tag utilisé.\n\
        3. Prends en compte la popularité si disponible.\n\
        4. Prends en compte le contexte technique minimal (OS/architecture) seulement si c'est pertinent.\n\
        5. Conclus par un niveau de risque supply-chain : FAIBLE / MOYEN / ÉLEVÉ.\n\
        6. Donne un score global de confiance entre 0 et 100 (0 = aucune confiance, 100 = confiance maximale).\n\n\
        CONTRAINTE DE FORMAT OBLIGATOIRE :\n\
        - La toute dernière ligne doit être exactement :\n\
          Resultat : NN\n\
          où NN est un entier entre 0 et 100\n\
        - N'ajoute rien après cette ligne.\n\n\
        Réponds en français, clair et concis.",
        registry = image.registry,
        repository = repository,
        tag = tag,
        os = os,
        arch = arch,
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