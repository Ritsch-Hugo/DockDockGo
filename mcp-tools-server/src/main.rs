use anyhow::Result;
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use rmcp::schemars;
use rmcp::schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

// ============================================================
// Configuration
// ============================================================

const DEFAULT_STATIC_URL: &str = "http://localhost:3002";
const DEFAULT_COMPLIANCE_URL: &str = "http://localhost:3001";

// ============================================================
// Paramètres des tools (schema JSON auto-généré via JsonSchema)
// ============================================================

#[derive(Deserialize, JsonSchema)]
struct ScanParams {
    #[schemars(
        description = "Absolute path to the quarantine folder for this image, e.g. /quarantaine/library/alpine/latest"
    )]
    quarantine_path: String,
}

// ============================================================
// Serveur MCP — expose les 3 tools de scan
// ============================================================

#[derive(Clone)]
struct DocDockGoTools {
    tool_router: ToolRouter<Self>,
    static_scanner_url: String,
    compliance_scanner_url: String,
    http: reqwest::Client,
}

impl DocDockGoTools {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            static_scanner_url: std::env::var("STATIC_SCANNER_URL")
                .unwrap_or_else(|_| DEFAULT_STATIC_URL.to_string()),
            compliance_scanner_url: std::env::var("COMPLIANCE_SCANNER_URL")
                .unwrap_or_else(|_| DEFAULT_COMPLIANCE_URL.to_string()),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }
}

// ============================================================
// Définition des tools MCP
// ============================================================

#[tool_router]
impl DocDockGoTools {
    /// Lance un scan statique CVE avec Trivy sur l'image dans la quarantaine.
    #[tool(description = "Run a static CVE scan using Trivy on a Docker image stored in the quarantine folder. Returns a JSON report with vulnerability findings, severity counts, and CVE details.")]
    async fn run_static_scan(&self, params: Parameters<ScanParams>) -> String {
        let quarantine_path = params.0.quarantine_path;
        match self.do_static_scan(&quarantine_path).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("static scan error: {e}");
                json!({"error": e.to_string(), "status": "ERROR"}).to_string()
            }
        }
    }

    /// Lance un scan de conformité sur l'image dans la quarantaine.
    #[tool(description = "Run a compliance scan on a Docker image stored in the quarantine folder. Checks security rules: root user, dangerous permissions, exposed secrets in env/fs, forbidden binaries, missing labels, unsafe entrypoint. Returns a JSON report with pass/warn/fail findings.")]
    async fn run_compliance_scan(&self, params: Parameters<ScanParams>) -> String {
        let quarantine_path = params.0.quarantine_path;
        match self.do_compliance_scan(&quarantine_path).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("compliance scan error: {e}");
                json!({"error": e.to_string(), "status": "ERROR"}).to_string()
            }
        }
    }

    /// Lance un scan dynamique comportemental avec Falco (non encore implémenté).
    #[tool(description = "Run a dynamic behavioral scan on a Docker image using Falco syscall monitoring. Detects suspicious runtime behavior. NOTE: Not yet implemented, returns a stub response.")]
    async fn run_dynamic_scan(&self, params: Parameters<ScanParams>) -> String {
        let _ = params;
        json!({
            "status": "NOT_IMPLEMENTED",
            "message": "Dynamic scanner (Falco) is not yet available. Scan skipped."
        })
        .to_string()
    }
}

// ============================================================
// ServerHandler — délègue au tool_router
// ============================================================

#[tool_handler]
impl ServerHandler for DocDockGoTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "DocDockGo security scan tools. \
                 Use run_static_scan for CVE analysis with Trivy, \
                 run_compliance_scan for security rules compliance, \
                 run_dynamic_scan for behavioral analysis (stub).",
            )
    }
}

// ============================================================
// Validation du chemin de quarantaine
// ============================================================

fn validate_quarantine_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > 4096 {
        anyhow::bail!("quarantine_path invalide : longueur hors limites");
    }
    if !path.starts_with('/') {
        anyhow::bail!("quarantine_path invalide : chemin absolu requis");
    }
    if path.contains("..") {
        anyhow::bail!("quarantine_path invalide : séquence de traversal interdite");
    }
    if path.bytes().any(|b| b == 0) {
        anyhow::bail!("quarantine_path invalide : caractère nul interdit");
    }
    Ok(())
}

// ============================================================
// Logique d'appel aux scanners
// ============================================================

impl DocDockGoTools {
    /// Lit les artefacts depuis la quarantaine et envoie un multipart au scanner CVE.
    async fn do_static_scan(&self, quarantine_path: &str) -> Result<String> {
        validate_quarantine_path(quarantine_path)?;
        let base = PathBuf::from(quarantine_path);
        let manifests_dir = base.join("manifests");
        let blobs_dir = base.join("blobs").join("sha256");

        // Trouver le manifest image OCI (celui qui a "layers"), pas le manifest index
        let manifest_path = find_image_manifest(&manifests_dir).await?
            .ok_or_else(|| anyhow::anyhow!("Aucun manifest image trouvé dans {}", manifests_dir.display()))?;

        let manifest_bytes = fs::read(&manifest_path).await?;

        let mut form = reqwest::multipart::Form::new().part(
            "manifest",
            reqwest::multipart::Part::bytes(manifest_bytes)
                .file_name("manifest.json")
                .mime_str("application/json")?,
        );

        // Ajouter les blobs non-gzip (config OCI, attestations)
        if blobs_dir.exists() {
            let mut entries = fs::read_dir(&blobs_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();

                // Valider que le nom est un digest sha256 (64 hex chars)
                if filename.len() != 64 || !filename.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }

                let data = fs::read(&path).await?;

                form = form.part(
                    "blob",
                    reqwest::multipart::Part::bytes(data)
                        .file_name(filename)
                        .mime_str("application/octet-stream")?,
                );
            }
        }

        let url = format!("{}/v1/scan-upload", self.static_scanner_url);
        info!("POST static scan → {}", url);

        let resp = self.http.post(&url).multipart(form).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("Scanner CVE retourné HTTP {}", resp.status()));
        }
        let text = resp.text().await?;
        Ok(text)
    }

    /// Construit un ScanRequest JSON avec paths vers la quarantaine et appelle le scanner compliance.
    async fn do_compliance_scan(&self, quarantine_path: &str) -> Result<String> {
        validate_quarantine_path(quarantine_path)?;
        let base = PathBuf::from(quarantine_path);
        let manifests_dir = base.join("manifests");
        let blobs_dir = base.join("blobs").join("sha256");

        // Lire le premier manifest
        let manifest_path = find_first_json(&manifests_dir).await?
            .ok_or_else(|| anyhow::anyhow!("Aucun manifest trouvé dans {}", manifests_dir.display()))?;

        let manifest_raw = fs::read_to_string(&manifest_path).await?;

        // Lister les blobs non-gzip avec leurs chemins absolus
        let mut blobs = Vec::new();
        if blobs_dir.exists() {
            let mut entries = fs::read_dir(&blobs_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let filename = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();

                if filename.len() != 64 || !filename.chars().all(|c| c.is_ascii_hexdigit()) {
                    continue;
                }

                let data = fs::read(&path).await?;
                if is_gzip(&data) {
                    info!("skip layer gzip: {}", filename);
                    continue;
                }

                // Le scanner compliance supporte les paths directs via le champ "path"
                blobs.push(json!({
                    "digest": format!("sha256:{}", filename),
                    "path": path.to_string_lossy()
                }));
            }
        }

        let body = json!({
            "stage": "final",
            "manifest_raw": manifest_raw,
            "blobs": blobs,
        });

        let url = format!("{}/v1/scan", self.compliance_scanner_url);
        info!("POST compliance scan → {}", url);

        let resp = self.http.post(&url).json(&body).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("Scanner compliance retourné HTTP {}", resp.status()));
        }
        let text = resp.text().await?;
        Ok(text)
    }
}

// ============================================================
// Helpers
// ============================================================

/// Détecte les archives gzip par leur magic number (0x1f 0x8b).
fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

/// Retourne le chemin du premier manifest OCI image (qui a un champ "layers"),
/// en ignorant les manifest index (qui ont un champ "manifests").
async fn find_image_manifest(dir: &PathBuf) -> Result<Option<PathBuf>> {
    let mut entries = fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if !path.extension().map(|x| x == "json").unwrap_or(false) {
            continue;
        }
        if let Ok(data) = fs::read(&path).await {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&data) {
                if v.get("layers").is_some() {
                    return Ok(Some(path));
                }
            }
        }
    }
    Ok(None)
}

/// Retourne le chemin du premier fichier .json trouvé dans un répertoire.
async fn find_first_json(dir: &PathBuf) -> Result<Option<PathBuf>> {
    let mut entries = fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().map(|x| x == "json").unwrap_or(false) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

// ============================================================
// Point d'entrée
// ============================================================

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port: u16 = std::env::var("MCP_SERVER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3004);

    info!("mcp-tools-server démarrage sur port {}", port);
    info!(
        "Scanner statique  : {}",
        std::env::var("STATIC_SCANNER_URL").unwrap_or_else(|_| DEFAULT_STATIC_URL.to_string())
    );
    info!(
        "Scanner compliance: {}",
        std::env::var("COMPLIANCE_SCANNER_URL")
            .unwrap_or_else(|_| DEFAULT_COMPLIANCE_URL.to_string())
    );

    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    };

    // Mode stateless + réponse JSON directe (pas de SSE, pas de session).
    // Chaque requête POST est indépendante — parfait pour un serveur de tools
    // appelé par llm-decision via JSON-RPC.
    let service: StreamableHttpService<DocDockGoTools, LocalSessionManager> =
        StreamableHttpService::new(
            || Ok(DocDockGoTools::new()),
            Default::default(),
            StreamableHttpServerConfig::default()
                .with_stateful_mode(false)
                .with_json_response(true),
        );

    let router = axum::Router::new().nest_service("/mcp", service);

    let addr: std::net::SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("En écoute sur http://0.0.0.0:{port}/mcp");

    axum::serve(listener, router).await?;

    Ok(())
}
