use sha2::{Digest as Sha2Digest, Sha256};
use std::path::{Component, Path, PathBuf};

use llm_common::{
    ArtifactBundle, ArtifactContent, ArtifactFile, Digest, LlmError, PullContext,
};

/// Taille maximale d'un artefact lu en mémoire.
/// Au-delà, le fichier est traité comme binaire sans être chargé (et le digest n'est pas vérifié).
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

/// Lit un fichier, valide son digest SHA256 si fourni, et détermine s'il est JSON ou binaire.
///
/// Les fichiers dépassant MAX_ARTIFACT_SIZE_BYTES ne sont pas chargés en mémoire :
/// ils sont traités comme binaires et la validation du digest est ignorée avec un avertissement.
async fn read_artifact(path: &Path, expected: Option<&Digest>) -> Result<ArtifactContent, LlmError> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|e| LlmError::ArtifactNotFound(format!("{} : {}", path.display(), e)))?;

    let size_bytes = metadata.len();

    if size_bytes > MAX_ARTIFACT_SIZE_BYTES {
        if let Some(d) = expected {
            tracing::warn!(
                "Fichier {} ({} bytes) dépasse la limite de {}B — digest {} non vérifié",
                path.display(), size_bytes, MAX_ARTIFACT_SIZE_BYTES, d.full()
            );
        }
        return Ok(ArtifactContent::Binary { size_bytes });
    }

    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| LlmError::ArtifactNotFound(format!("{} : {}", path.display(), e)))?;

    // Validation cryptographique du digest SHA256
    if let Some(digest) = expected {
        if digest.algorithm == "sha256" {
            let computed = format!("{:x}", Sha256::digest(&bytes));
            if computed != digest.value {
                return Err(LlmError::InvalidInput(format!(
                    "Digest invalide pour {} : annoncé sha256:{}, calculé sha256:{}",
                    path.display(), digest.value, computed
                )));
            }
        }
    }

    match String::from_utf8(bytes) {
        Ok(content) => {
            if serde_json::from_str::<serde_json::Value>(&content).is_ok() {
                Ok(ArtifactContent::Json(content))
            } else {
                Ok(ArtifactContent::Binary { size_bytes })
            }
        }
        Err(_) => Ok(ArtifactContent::Binary { size_bytes }),
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

    // --- Tests read_artifact ---

    #[tokio::test]
    async fn test_read_artifact_json_valide() {
        let dir = tempfile::tempdir().unwrap();
        let content = r#"{"schemaVersion":2}"#;
        let path = dir.path().join("manifest.json");
        tokio::fs::write(&path, content).await.unwrap();

        let result = read_artifact(&path, None).await.unwrap();
        assert!(matches!(result, ArtifactContent::Json(_)));
    }

    #[tokio::test]
    async fn test_read_artifact_binaire_gzip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("layer");
        // Magic number gzip = 0x1f 0x8b
        tokio::fs::write(&path, &[0x1f, 0x8b, 0x00, 0x00]).await.unwrap();

        let result = read_artifact(&path, None).await.unwrap();
        assert!(matches!(result, ArtifactContent::Binary { .. }));
    }

    #[tokio::test]
    async fn test_read_artifact_json_invalide_traite_comme_binaire() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        tokio::fs::write(&path, b"pas du json valide {{{").await.unwrap();

        let result = read_artifact(&path, None).await.unwrap();
        assert!(matches!(result, ArtifactContent::Binary { .. }));
    }

    #[tokio::test]
    async fn test_read_artifact_fichier_inexistant() {
        let result = read_artifact(Path::new("/inexistant/fichier.json"), None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_artifact_digest_valide() {
        let dir = tempfile::tempdir().unwrap();
        let content = br#"{"schemaVersion":2}"#;
        let path = dir.path().join("manifest.json");
        tokio::fs::write(&path, content).await.unwrap();

        // Calculer le vrai digest du contenu
        use sha2::{Digest as Sha2Digest, Sha256};
        let hash = format!("{:x}", Sha256::digest(content));
        let digest = llm_common::Digest { algorithm: "sha256".to_string(), value: hash };

        let result = read_artifact(&path, Some(&digest)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_read_artifact_digest_invalide() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        tokio::fs::write(&path, br#"{"schemaVersion":2}"#).await.unwrap();

        let mauvais_digest = llm_common::Digest {
            algorithm: "sha256".to_string(),
            value: "a".repeat(64), // digest inventé
        };

        let result = read_artifact(&path, Some(&mauvais_digest)).await;
        assert!(matches!(result, Err(LlmError::InvalidInput(_))));
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
        let path = root.join("manifests").join(format!("{}.json", digest.filename()));
        match read_artifact(&path, Some(digest)).await {
            Ok(content) => manifests.push(ArtifactFile {
                digest: digest.full(),
                content,
            }),
            Err(LlmError::InvalidInput(e)) => {
                tracing::error!("Manifest {} : {}", digest.full(), e);
                return Err(LlmError::InvalidInput(e));
            }
            Err(e) => tracing::warn!("Manifest introuvable {}: {}", digest.full(), e),
        }
    }

    // --- Blobs ---
    let mut blobs = Vec::new();
    for digest in &ctx.blob_digests {
        let path = root.join("blobs").join("sha256").join(digest.filename());
        match read_artifact(&path, Some(digest)).await {
            Ok(content) => blobs.push(ArtifactFile {
                digest: digest.full(),
                content,
            }),
            Err(LlmError::InvalidInput(e)) => {
                tracing::error!("Blob {} : {}", digest.full(), e);
                return Err(LlmError::InvalidInput(e));
            }
            Err(e) => tracing::warn!("Blob introuvable {}: {}", digest.full(), e),
        }
    }

    // --- Referrers ---
    let mut referrers = Vec::new();
    for digest in &ctx.referrers_digests {
        let path = root.join("referrers").join(format!("{}.json", digest.filename()));
        match read_artifact(&path, Some(digest)).await {
            Ok(content) => referrers.push(ArtifactFile {
                digest: digest.full(),
                content,
            }),
            Err(LlmError::InvalidInput(e)) => {
                tracing::warn!("Referrer {} digest invalide : {}", digest.full(), e);
            }
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
