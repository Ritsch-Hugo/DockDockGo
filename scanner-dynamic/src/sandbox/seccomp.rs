use std::fs;
use anyhow::{Context, Result};

/// Charge le profil seccomp DockDockGo depuis le disque.
///
/// Le profil est :
/// - permissif (comportement observable)
/// - restrictif sur les syscalls d'évasion (mount, ptrace, etc.)
///
/// Aucun traitement ici :
/// c'est un contrat de sécurité, pas de la logique métier.
#[allow(dead_code)]
pub fn load_seccomp_profile() -> Result<String> {
    let path = "seccomp/seccomp-ddg.json";

    let content = fs::read_to_string(path)
        .with_context(|| format!("Impossible de lire le profil seccomp : {}", path))?;

    Ok(content)
}
