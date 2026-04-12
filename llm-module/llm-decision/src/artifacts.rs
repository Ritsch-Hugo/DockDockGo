use std::path::Path;

use llm_common::{
    ArtifactBundle, ArtifactContent, ArtifactFile, LlmError, PullContext,
};

/// Construit le chemin racine vers les artefacts d'une image dans la quarantaine.
/// Structure : {quarantine_path}/{registry}/{repository}/{tag}/
fn image_root(quarantine_path: &Path, ctx: &PullContext) -> std::path::PathBuf {
    quarantine_path
        .join(&ctx.registry)
        .join(&ctx.repository)
        .join(&ctx.tag)
}

/// Lit un fichier et détermine s'il est JSON ou binaire.
/// On ne charge jamais le contenu binaire en mémoire — on note uniquement la taille.
async fn read_artifact(path: &Path) -> Result<ArtifactContent, LlmError> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => {
            // Vérifie que c'est bien du JSON valide avant de l'accepter
            if serde_json::from_str::<serde_json::Value>(&content).is_ok() {
                Ok(ArtifactContent::Json(content))
            } else {
                // Texte mais pas JSON valide → traiter comme binaire, récupérer la taille
                let size_bytes = tokio::fs::metadata(path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(content.len() as u64);
                Ok(ArtifactContent::Binary { size_bytes })
            }
        }
        Err(e) => {
            // Impossible à lire comme UTF-8 → fichier binaire (gzip layer) ou introuvable.
            // On tente metadata() pour la taille ; s'il échoue aussi, le fichier est introuvable.
            let size_bytes = tokio::fs::metadata(path)
                .await
                .map_err(|_| LlmError::ArtifactNotFound(format!("{} : {}", path.display(), e)))?
                .len();
            Ok(ArtifactContent::Binary { size_bytes })
        }
    }
}

/// Charge tous les artefacts d'une image depuis la quarantaine.
/// Les fichiers introuvables sont ignorés avec un avertissement (non bloquant),
/// sauf si aucun artefact n'est disponible du tout.
pub async fn load_artifacts(
    ctx: &PullContext,
    quarantine_path: &Path,
) -> Result<ArtifactBundle, LlmError> {
    let root = image_root(quarantine_path, ctx);

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
