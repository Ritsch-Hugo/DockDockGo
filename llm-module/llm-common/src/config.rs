use std::path::PathBuf;

/// Configuration partagée entre llm-manager et llm-decision.
/// Toutes les valeurs sont lues depuis les variables d'environnement,
/// avec des valeurs par défaut pour le développement local.
///
/// En production Kubernetes, injecter via ConfigMap / Secret.
#[derive(Debug, Clone)]
pub struct Config {
    /// URL de base d'Ollama.
    /// Valeur par défaut : http://localhost:11434
    /// En production : pointer vers le service Ollama du cluster.
    pub ollama_base_url: String,

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
}

impl Config {
    /// Construit la config depuis les variables d'environnement.
    /// Toutes les variables sont optionnelles et ont des valeurs par défaut.
    pub fn from_env() -> Self {
        Self {
            ollama_base_url: std::env::var("OLLAMA_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:11434".to_string()),

            quarantine_path: PathBuf::from(
                std::env::var("QUARANTINE_PATH")
                    .unwrap_or_else(|_| "../quarantaine".to_string()),
            ),

            worker_models: [
                std::env::var("LLM_WORKER_1")
                    .unwrap_or_else(|_| "granite3.3:8b".to_string()),
                std::env::var("LLM_WORKER_2")
                    .unwrap_or_else(|_| "granite3.3:8b".to_string()),
                std::env::var("LLM_WORKER_3")
                    .unwrap_or_else(|_| "granite3.3:8b".to_string()),
            ],

            arbiter_model: std::env::var("LLM_ARBITER")
                .unwrap_or_else(|_| "granite3.3:8b".to_string()),

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

            manager_host: std::env::var("MANAGER_HOST")
                .unwrap_or_else(|_| "localhost".to_string()),

            mcp_server_url: std::env::var("MCP_SERVER_URL")
                .unwrap_or_else(|_| "http://localhost:3004/mcp".to_string()),
        }
    }

    /// URL complète du service llm-manager (utilisée par llm-decision au démarrage).
    pub fn manager_url(&self) -> String {
        format!("http://{}:{}", self.manager_host, self.manager_port)
    }
}
