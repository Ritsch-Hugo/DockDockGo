use std::path::{Component, Path, PathBuf};

use llm_common::{
    ArtifactBundle, ArtifactContent, ArtifactFile, LlmError, PullContext,
};

/// Taille maximale d'un artefact lu en mémoire.
/// Au-delà, le fichier est traité comme binaire sans être chargé.
const MAX_ARTIFACT_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

/// Valide qu'un composant de chemin (registry, repository, tag) ne contient
/// pas de séquences dangereuses permettant un path traversal.
fn validate_path_component(value: &str, field: &str) -> Result<(), LlmError> {
    if value.is_empty() || value.len() > 255 {
        return Err(LlmError::InvalidInput(format!(
            "{field} invalide : longueur hors limites (1–255 caractères)"
        )));
    }
    if value.contains("..") {
        return Err(LlmError::InvalidInput(format!(
            "{field} invalide : séquence de traversal interdite"
        )));
    }
    if value.bytes().any(|b| b == 0) {
        return Err(LlmError::InvalidInput(format!(
            "{field} invalide : caractère nul interdit"
        )));
    }
    Ok(())
}

/// Normalise un chemin en résolvant les composants `.` et `..`
/// sans exiger que le chemin existe sur le système de fichiers.
fn normalize_path(path: &Path) -> PathBuf {
    let mut parts: Vec<Component> = Vec::new();
    for component in path.components() {
        match component {
            Component::ParentDir => { parts.pop(); }
            Component::CurDir => {}
            c => parts.push(c),
        }
    }
    parts.iter().collect()
}

/// Construit et valide le chemin racine vers les artefacts d'une image.
/// Vérifie que le chemin résultant reste dans la quarantaine.
fn image_root(quarantine_path: &Path, ctx: &PullContext) -> Result<PathBuf, LlmError> {
    validate_path_component(&ctx.registry, "registry")?;
    validate_path_component(&ctx.repository, "repository")?;
    validate_path_component(&ctx.tag, "tag")?;

    let root = quarantine_path
        .join(&ctx.registry)
        .join(&ctx.repository)
        .join(&ctx.tag);

    // Confinement : vérifier que le chemin normalisé reste dans la quarantaine
    let root_norm = normalize_path(&root);
    let quarantine_norm = normalize_path(quarantine_path);
    if !root_norm.starts_with(&quarantine_norm) {
        return Err(LlmError::InvalidInput(
            "Le chemin calculé sort de la quarantaine".to_string(),
        ));
    }

    Ok(root)
}

/// Lit un fichier et détermine s'il est JSON ou binaire.
/// Vérifie la taille avant lecture pour éviter de charger de gros fichiers en mémoire.
async fn read_artifact(path: &Path) -> Result<ArtifactContent, LlmError> {
    // Vérifier existence et taille avant toute lecture
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|e| LlmError::ArtifactNotFound(format!("{} : {}", path.display(), e)))?;

    let size_bytes = metadata.len();

    // Fichier trop grand → traiter directement comme binaire sans charger en mémoire
    if size_bytes > MAX_ARTIFACT_SIZE_BYTES {
        return Ok(ArtifactContent::Binary { size_bytes });
    }

    match tokio::fs::read_to_string(path).await {
        Ok(content) => {
            if serde_json::from_str::<serde_json::Value>(&content).is_ok() {
                Ok(ArtifactContent::Json(content))
            } else {
                Ok(ArtifactContent::Binary { size_bytes })
            }
        }
        Err(_) => {
            // Non UTF-8 → fichier binaire (layer gzip, etc.)
            Ok(ArtifactContent::Binary { size_bytes })
        }
    }
}

// ============================================================
// Tests unitaires
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(registry: &str, repository: &str, tag: &str) -> PullContext {
        PullContext {
            uuid: uuid::Uuid::new_v4(),
            ip_client: "127.0.0.1".to_string(),
            registry: registry.to_string(),
            repository: repository.to_string(),
            tag: tag.to_string(),
            manifest_digests: vec![],
            blob_digests: vec![],
            referrers_digests: vec![],
            manifest_racine_digest: None,
            digests_possible: vec![],
            digests_expected: vec![],
            os: "linux".to_string(),
            arch: "amd64".to_string(),
            pull_completed: true,
        }
    }

    #[test]
    fn test_path_traversal_registry() {
        let ctx = make_ctx("../../../etc", "alpine", "latest");
        let result = image_root(Path::new("/quarantaine"), &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_path_traversal_tag() {
        let ctx = make_ctx("registry-1.docker.io", "library/alpine", "../../passwd");
        let result = image_root(Path::new("/quarantaine"), &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_path_traversal_repository() {
        let ctx = make_ctx("ghcr.io", "../../etc/shadow", "latest");
        let result = image_root(Path::new("/quarantaine"), &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_chemin_valide() {
        let ctx = make_ctx("registry-1.docker.io", "library/alpine", "3.18");
        let result = image_root(Path::new("/quarantaine"), &ctx);
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.starts_with("/quarantaine"));
    }

    #[test]
    fn test_composant_vide() {
        let ctx = make_ctx("", "library/alpine", "latest");
        let result = image_root(Path::new("/quarantaine"), &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_composant_trop_long() {
        let ctx = make_ctx(&"a".repeat(256), "alpine", "latest");
        let result = image_root(Path::new("/quarantaine"), &ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_path_resout_parent() {
        let p = Path::new("/quarantaine/foo/../../../etc");
        let normalized = normalize_path(p);
        assert!(!normalized.starts_with("/quarantaine"));
    }
}

/// Charge tous les artefacts d'une image depuis la quarantaine.
/// Les fichiers introuvables sont ignorés avec un avertissement (non bloquant),
/// sauf si aucun artefact n'est disponible du tout.
pub async fn load_artifacts(
    ctx: &PullContext,
    quarantine_path: &Path,
) -> Result<ArtifactBundle, LlmError> {
    let root = image_root(quarantine_path, ctx)?;

    // --- Manifests ---
    let mut manifests = Vec::new();
    for digest in &ctx.manifest_digests {
        // Les manifests ont l'extension .json dans la quarantaine
        let path = root.join("manifests").join(format!("{}.json", digest.filename()));
        match read_artifact(&path).await {
            Ok(content) => manifests.push(ArtifactFile {
                digest: digest.full(),
                content,
            }),
            Err(e) => tracing::warn!("Manifest introuvable {}: {}", digest.full(), e),
        }
    }

    // --- Blobs ---
    let mut blobs = Vec::new();
    for digest in &ctx.blob_digests {
        // Les blobs n'ont pas d'extension, stockés dans blobs/sha256/
        let path = root.join("blobs").join("sha256").join(digest.filename());
        match read_artifact(&path).await {
            Ok(content) => blobs.push(ArtifactFile {
                digest: digest.full(),
                content,
            }),
            Err(e) => tracing::warn!("Blob introuvable {}: {}", digest.full(), e),
        }
    }

    // --- Referrers ---
    let mut referrers = Vec::new();
    for digest in &ctx.referrers_digests {
        let path = root.join("referrers").join(format!("{}.json", digest.filename()));
        match read_artifact(&path).await {
            Ok(content) => referrers.push(ArtifactFile {
                digest: digest.full(),
                content,
            }),
            Err(e) => tracing::warn!("Referrer introuvable {}: {}", digest.full(), e),
        }
    }

    // --- SBOM (optionnel) ---
    // Le sbom.json est à la racine du tag, pas dans un sous-dossier
    let sbom_path = root.join("sbom.json");
    let sbom = match tokio::fs::read_to_string(&sbom_path).await {
        Ok(content) => {
            tracing::info!("SBOM trouvé pour {}/{}", ctx.repository, ctx.tag);
            Some(content)
        }
        Err(_) => {
            tracing::info!("Pas de SBOM pour {}/{}", ctx.repository, ctx.tag);
            None
        }
    };

    if manifests.is_empty() && blobs.is_empty() {
        return Err(LlmError::ArtifactNotFound(format!(
            "Aucun artefact trouvé pour {}/{}:{} dans {:?}",
            ctx.registry, ctx.repository, ctx.tag, quarantine_path
        )));
    }

    Ok(ArtifactBundle {
        pull_context: ctx.clone(),
        manifests,
        blobs,
        referrers,
        sbom,
    })
}
