use std::path::PathBuf;

/// Configuration partagée entre llm-manager et llm-decision.
/// Toutes les valeurs sont lues depuis les variables d'environnement,
/// avec des valeurs par défaut pour le développement local.
///
/// En production Kubernetes, injecter via ConfigMap / Secret.
#[derive(Debug, Clone)]
pub struct Config {
    /// URL de base du backend LLM (vLLM, Ollama, ou tout backend OpenAI-compat).
    /// Valeur par défaut : http://localhost:8000 (port par défaut de vLLM)
    /// En production : pointer vers le service vLLM du cluster.
    pub llm_base_url: String,

    /// Clé API pour les backends cloud (OpenRouter, etc.).
    /// None pour les backends locaux (vLLM, Ollama).
    pub api_key: Option<String>,

    /// Chemin absolu vers le dossier quarantaine partagé.
    /// En Kubernetes : chemin vers le PersistentVolume monté.
    pub quarantine_path: PathBuf,

    /// Modèles des 3 workers LLM (doivent être chargés dans Ollama).
    pub worker_models: [String; 3],

    /// Modèle de l'arbitre (plus grand que les workers).
    pub arbiter_model: String,

    /// Timeout maximum en secondes pour un appel LLM.
    /// Valeur par défaut : 120s (les grands modèles peuvent être lents sur GPU limité).
    pub llm_timeout_secs: u64,

    /// Port d'écoute du service llm-decision.
    pub decision_port: u16,

    /// Port d'écoute du service llm-manager.
    pub manager_port: u16,

    /// Hôte du service llm-manager (pour llm-decision).
    /// Valeur par défaut : localhost (dev local)
    /// En Docker/Kubernetes : IP ou nom du service manager.
    pub manager_host: String,

    /// URL du serveur MCP (mcp-tools-server).
    /// llm-decision s'y connecte pour charger les tool schemas et exécuter les scans.
    pub mcp_server_url: String,

    /// Timeout en secondes pour les appels MCP (scans Trivy, compliance).
    /// Valeur par défaut : 300s (Trivy peut être lent sur de grosses images).
    pub mcp_timeout_secs: u64,
}

impl Config {
    /// Construit la config depuis les variables d'environnement.
    /// Toutes les variables sont optionnelles et ont des valeurs par défaut.
    pub fn from_env() -> Self {
        Self {
            llm_base_url: std::env::var("LLM_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:8000".to_string()),

            api_key: std::env::var("OPENROUTER_API_KEY").ok(),

            quarantine_path: PathBuf::from(
                std::env::var("QUARANTINE_PATH").unwrap_or_else(|_| "../quarantaine".to_string()),
            ),

            worker_models: [
                std::env::var("LLM_WORKER_1")
                    .unwrap_or_else(|_| "minimax/minimax-m2.7".to_string()),
                std::env::var("LLM_WORKER_2")
                    .unwrap_or_else(|_| "qwen/qwen3.5-35b-a3b".to_string()),
                std::env::var("LLM_WORKER_3")
                    .unwrap_or_else(|_| "google/gemma-4-31b-it".to_string()),
            ],

            arbiter_model: std::env::var("LLM_ARBITER")
                .unwrap_or_else(|_| "mistralai/mistral-small-2603".to_string()),

            llm_timeout_secs: std::env::var("LLM_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120),

            decision_port: std::env::var("DECISION_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3005),

            manager_port: std::env::var("MANAGER_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3003),

            manager_host: std::env::var("MANAGER_HOST").unwrap_or_else(|_| "localhost".to_string()),

            mcp_server_url: std::env::var("MCP_SERVER_URL")
                .unwrap_or_else(|_| "http://localhost:3004/mcp".to_string()),

            mcp_timeout_secs: std::env::var("MCP_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
        }
    }

    /// URL complète du service llm-manager (utilisée par llm-decision au démarrage).
    pub fn manager_url(&self) -> String {
        format!("http://{}:{}", self.manager_host, self.manager_port)
    }
}
