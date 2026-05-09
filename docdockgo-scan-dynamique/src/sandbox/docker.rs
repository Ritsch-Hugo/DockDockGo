use bollard::Docker;
use bollard::container::{
    Config,
    CreateContainerOptions,
    StartContainerOptions,
    WaitContainerOptions,
    RemoveContainerOptions,
    StopContainerOptions,
};
use bollard::models::HostConfig;
use bollard::network::CreateNetworkOptions;
use anyhow::{Context, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use futures_util::StreamExt;
use tokio::time::{sleep, Duration};

// ─────────────────────────────────────────────
// MODE SANDBOX
// Enum extensible pour les futurs modes d'analyse
// (ex: Aggressive, Restricted, NetworkEnabled…)
// ─────────────────────────────────────────────
#[derive(Clone, Copy)]
pub enum SandboxMode {
    /// Exécution libre sous surveillance Falco passive.
    /// Toutes les restrictions ressources sont actives.
    Observe,
}

// ─────────────────────────────────────────────
// CONNEXION AU DAEMON DOCKER
// Connexion via socket Unix local.
// Requiert droits root ou appartenance au groupe docker.
// ─────────────────────────────────────────────
pub async fn connect() -> Result<Docker> {
    Docker::connect_with_unix(
        "/var/run/docker.sock",
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .context("Impossible de se connecter au Docker daemon. Vérifiez que Docker est lancé.")
}

// ─────────────────────────────────────────────
// RÉSEAU D'ANALYSE ISOLÉ
// Crée un réseau Docker interne sans accès internet.
// Si le réseau existe déjà, l'erreur est ignorée.
// ─────────────────────────────────────────────
pub async fn ensure_analysis_network(docker: &Docker) -> Result<()> {
    let options: CreateNetworkOptions<String> = CreateNetworkOptions {
        name:            "ddg_analysis_net".to_string(),
        internal:        true,          // Pas de routage externe
        check_duplicate: true,          // Évite les doublons
        ..Default::default()
    };

    let _ = docker.create_network(options).await; // Erreur ignorée intentionnellement
    Ok(())
}

// ─────────────────────────────────────────────
// GÉNÉRATION DU NOM DE CONTAINER
// Nom unique basé sur le timestamp Unix (secondes).
// Format : <prefix>_<timestamp>
// Évite les collisions entre scans successifs.
// ─────────────────────────────────────────────
fn generate_container_name(prefix: &str) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}_{}", prefix, ts)
}

// ─────────────────────────────────────────────
// ATTENTE DE FIN DU CONTAINER
// Bloque jusqu'à l'arrêt naturel du container.
// Consomme le premier événement du stream Docker wait.
// ─────────────────────────────────────────────
pub async fn wait_container(docker: &Docker, name: &str) {
    let mut stream = docker.wait_container(
        name,
        None::<WaitContainerOptions<String>>,
    );
    let _ = stream.next().await;
}

// ─────────────────────────────────────────────
// NETTOYAGE DU CONTAINER
// Stop gracieux (1s) puis suppression forcée.
// Le délai court évite d'attendre un container
// qui ne répond pas au SIGTERM.
// ─────────────────────────────────────────────
pub async fn cleanup_container(docker: &Docker, name: &str) {
    let _ = docker.stop_container(
        name,
        Some(StopContainerOptions { t: 1 }),
    ).await;

    let _ = docker.remove_container(
        name,
        Some(RemoveContainerOptions {
            force: true,
            ..Default::default()
        }),
    ).await;
}

// ─────────────────────────────────────────────
// ATTENTE DE SUPPRESSION EFFECTIVE
// Poll jusqu'à confirmation que le container n'existe plus.
// Évite les race conditions si un scan démarre immédiatement après.
// Timeout : 20 × 200ms = 4 secondes max.
// ─────────────────────────────────────────────
pub async fn wait_container_removal(docker: &Docker, name: &str) {
    for _ in 0..20 {
        if docker.inspect_container(name, None).await.is_err() {
            return;
        }
        sleep(Duration::from_millis(200)).await;
    }
    println!("[!] Avertissement : container {} toujours visible après suppression", name);
}

// ─────────────────────────────────────────────
// LANCEMENT DU CONTAINER SANDBOX
// Crée et démarre le container avec les restrictions
// de sécurité correspondant au mode choisi.
//
// Restrictions (mode Observe) :
//   - RAM         : 256 MB max
//   - CPU         : 1 vCPU max
//   - PIDs        : 128 max (anti fork bomb)
//   - Réseau      : réseau interne isolé
//   - Capabilities: toutes supprimées (cap_drop ALL)
//   - Privilèges  : escalade interdite (no-new-privileges)
//   - Filesystem  : lecture seule (readonly_rootfs)
//
// Retourne le nom du container pour les opérations suivantes.
// ─────────────────────────────────────────────
pub async fn run_sandbox_container(
    docker: &Docker,
    image: &str,
    mode: SandboxMode,
) -> Result<String> {
    let container_name = match mode {
        SandboxMode::Observe => generate_container_name("ddg_observe"),
    };

    let host_config = match mode {
        SandboxMode::Observe => HostConfig {
            memory:          Some(256 * 1024 * 1024),     // 256 MB RAM
            nano_cpus:       Some(1_000_000_000),          // 1 CPU
            pids_limit:      Some(128),                    // Anti fork bomb
            network_mode:    Some("ddg_analysis_net".to_string()),
            cap_drop:        Some(vec!["ALL".to_string()]),
            security_opt:    Some(vec!["no-new-privileges".to_string()]),
            readonly_rootfs: Some(true),                   // FS en lecture seule
            ..Default::default()
        },
    };

    let config: Config<String> = Config {
        image:       Some(image.to_string()),
        host_config: Some(host_config),
        ..Default::default()
    };

    docker
        .create_container(
            Some(CreateContainerOptions {
                name:     container_name.clone(),
                platform: None,
            }),
            config,
        )
        .await
        .context(format!("Impossible de créer le container pour '{}'", image))?;

    docker
        .start_container(
            &container_name,
            None::<StartContainerOptions<String>>,
        )
        .await
        .context(format!("Impossible de démarrer '{}'", container_name))?;

    Ok(container_name)
}