use crate::models::{ImageData, Stage};

fn quote_shell_words(words: &[String]) -> String {
    // V1: JSON array style pour ENTRYPOINT/CMD, safe et lisible
    let inner = words
        .iter()
        .map(|w| format!("{:?}", w)) // debug string => quoted
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

/// Génère un pseudo-Dockerfile informatif (best-effort), FINAL ONLY.
/// - Pas de FROM (on ne peut pas l’inférer proprement)
/// - Basé sur config OCI + quelques infos FS (ex: compteur d’entries)
pub fn generate_pseudo_dockerfile(image: &ImageData) -> Option<String> {
    // FINAL ONLY + on veut un état FS stable
    if image.scan.stage != Stage::Final {
        return None;
    }
    if !image.has_config || !image.has_fs {
        return None;
    }

    let mut lines: Vec<String> = Vec::new();

    lines.push("# PSEUDO-DOCKERFILE (best-effort, derived from OCI config + final filesystem)".to_string());
    lines.push("# NOTE: this is informational only; it does not represent the original Dockerfile.".to_string());

    // Petit hint FS
    lines.push(format!("# FS entries: {}", image.fs_entries.len()));

    // USER
    if let Some(user) = image.config.user.as_deref() {
        // On inclut même root, c'est informatif
        lines.push(format!("USER {}", user));
    }

    // WORKDIR
    if let Some(wd) = image.config.working_dir.as_deref() {
        lines.push(format!("WORKDIR {}", wd));
    }

    // EXPOSE
    if !image.config.exposed_ports.is_empty() {
        for p in &image.config.exposed_ports {
            lines.push(format!("EXPOSE {}", p));
        }
    }

    // VOLUME
    if !image.config.volumes.is_empty() {
        for v in &image.config.volumes {
            lines.push(format!("VOLUME {}", v));
        }
    }

    // ENTRYPOINT / CMD
    if !image.config.entrypoint.is_empty() {
        lines.push(format!("ENTRYPOINT {}", quote_shell_words(&image.config.entrypoint)));
    }
    if !image.config.cmd.is_empty() {
        lines.push(format!("CMD {}", quote_shell_words(&image.config.cmd)));
    }

    Some(lines.join("\n"))
}
