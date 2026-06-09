// ════════════════════════════════════════════════════════════════
// quarantine.rs — Reconstruction d'image Docker depuis la quarantaine
//
// Le proxy DocDockGo stocke les artefacts OCI bruts dans une
// structure :
//
//   <quarantine_path>/
//   ├── manifests/        → un .json par manifest reçu
//   │                        (index multi-arch, manifests image, attestations)
//   ├── blobs/sha256/     → blobs bruts (config JSON, layers tar+gzip)
//   └── referrers/        → SBOM, signatures (ignoré ici)
//
// Ce module reconstruit une image Docker chargeable SANS jamais
// faire `docker pull` :
//   1. Sélectionne le manifest image de la bonne architecture
//   2. Construit un OCI layout temporaire jetable dans /tmp
//   3. Utilise skopeo pour convertir OCI layout → docker-archive (.tar)
//   4. Le .tar est ensuite chargeable via `docker load`
//
// La quarantaine d'origine n'est JAMAIS modifiée (lecture seule).
// Tous les fichiers temporaires sont nettoyés après usage.
// ════════════════════════════════════════════════════════════════

use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{Context, Result, bail};
use serde_json::Value;

/// Architecture cible pour la sélection du manifest.
/// La plupart des hôtes sont amd64 ; adaptable si besoin (arm64...).
const TARGET_ARCH: &str = "amd64";

/// Résultat de la reconstruction : le tag de l'image chargée
/// et le chemin du tar temporaire (à nettoyer par l'appelant).
pub struct ReconstructedImage {
    /// Tag de l'image chargée dans Docker (ex: "ddg-scan-alpine:3.18")
    pub image_tag: String,
    /// Répertoire temporaire à nettoyer après le scan
    pub temp_dir: PathBuf,
}

impl ReconstructedImage {
    /// Nettoie tous les fichiers temporaires créés pendant la reconstruction.
    /// Supprime aussi l'image Docker chargée (elle n'a servi qu'au scan).
    pub fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.temp_dir);
        // Retire l'image Docker reconstruite (best-effort)
        let _ = Command::new("docker")
            .args(["rmi", "-f", &self.image_tag])
            .output();
    }
}

/// Point d'entrée : reconstruit une image depuis un chemin de quarantaine.
///
/// `quarantine_path` : ex "/data/quarantaine/library/alpine/3.18"
///
/// Retourne le tag de l'image chargée dans Docker, prête à scanner.
pub fn reconstruct_from_quarantine(quarantine_path: &str) -> Result<ReconstructedImage> {
    let qpath = Path::new(quarantine_path);
    if !qpath.is_dir() {
        bail!("quarantine_path n'est pas un dossier : {}", quarantine_path);
    }

    let manifests_dir = qpath.join("manifests");
    let blobs_dir     = qpath.join("blobs").join("sha256");

    if !manifests_dir.is_dir() {
        bail!("Dossier manifests/ absent dans {}", quarantine_path);
    }
    if !blobs_dir.is_dir() {
        bail!("Dossier blobs/sha256/ absent dans {}", quarantine_path);
    }

    // 1. Sélectionne le manifest image de la bonne architecture
    let (manifest_digest, manifest_path) =
        select_image_manifest(&manifests_dir, &blobs_dir)
            .context("Sélection du manifest image échouée")?;

    // 2. Dérive un tag lisible depuis le chemin de quarantaine
    //    /data/quarantaine/library/alpine/3.18 → "ddg-scan-alpine:3.18"
    let image_tag = derive_image_tag(quarantine_path);

    // 3. Construit un OCI layout temporaire jetable
    let temp_dir = std::env::temp_dir().join(format!(
        "ddg-oci-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let oci_dir = temp_dir.join("oci");
    std::fs::create_dir_all(oci_dir.join("blobs").join("sha256"))
        .context("Création du répertoire OCI temporaire")?;

    // oci-layout
    std::fs::write(
        oci_dir.join("oci-layout"),
        r#"{"imageLayoutVersion":"1.0.0"}"#,
    )?;

    // Copie tous les blobs nécessaires (config + layers) depuis la quarantaine.
    // On copie tout le dossier blobs : skopeo ne lit que ce dont il a besoin.
    copy_blobs(&blobs_dir, &oci_dir.join("blobs").join("sha256"))
        .context("Copie des blobs")?;

    // Copie le manifest image comme blob (skopeo le lit via index.json)
    let manifest_bytes = std::fs::read(&manifest_path)?;
    std::fs::write(
        oci_dir.join("blobs").join("sha256").join(&manifest_digest),
        &manifest_bytes,
    )?;

    // index.json pointe vers le manifest image
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": format!("sha256:{}", manifest_digest),
            "size": manifest_bytes.len(),
        }]
    });
    std::fs::write(
        oci_dir.join("index.json"),
        serde_json::to_string_pretty(&index)?,
    )?;

    // 4. skopeo : OCI layout → docker-archive tar
    let tar_path = temp_dir.join("image.tar");
    let skopeo_src = format!("oci:{}", oci_dir.display());
    let skopeo_dst = format!(
        "docker-archive:{}:{}",
        tar_path.display(),
        image_tag
    );

    let output = Command::new("skopeo")
        .args([
            "copy",
            "--insecure-policy",
            &skopeo_src,
            &skopeo_dst,
        ])
        .output()
        .context("Échec d'exécution de skopeo (installé ?)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let _ = std::fs::remove_dir_all(&temp_dir);
        bail!("skopeo copy a échoué : {}", stderr);
    }

    // 5. docker load < image.tar
    let tar_file = std::fs::File::open(&tar_path)
        .context("Ouverture du tar reconstruit")?;
    let load = Command::new("docker")
        .args(["load"])
        .stdin(tar_file)
        .output()
        .context("Échec docker load")?;

    if !load.status.success() {
        let stderr = String::from_utf8_lossy(&load.stderr);
        let _ = std::fs::remove_dir_all(&temp_dir);
        bail!("docker load a échoué : {}", stderr);
    }

    Ok(ReconstructedImage { image_tag, temp_dir })
}

/// Sélectionne le manifest image de l'architecture cible.
///
/// Règle : mediaType == image.manifest ET config.architecture == TARGET_ARCH.
/// Ignore les index multi-arch et les attestations (arch "unknown").
///
/// Retourne (digest_hex, chemin_du_fichier_manifest).
fn select_image_manifest(
    manifests_dir: &Path,
    blobs_dir: &Path,
) -> Result<(String, PathBuf)> {
    let mut candidates: Vec<(String, PathBuf)> = Vec::new();

    for entry in std::fs::read_dir(manifests_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c)  => c,
            Err(_) => continue,
        };
        let json: Value = match serde_json::from_str(&content) {
            Ok(v)  => v,
            Err(_) => continue,
        };

        // Doit être un manifest image (pas un index)
        let media = json["mediaType"].as_str().unwrap_or("");
        if !media.contains("image.manifest") {
            continue;
        }

        // Vérifie l'architecture via la config pointée
        let config_digest = json["config"]["digest"]
            .as_str()
            .unwrap_or("")
            .strip_prefix("sha256:")
            .unwrap_or("");
        if config_digest.is_empty() {
            continue;
        }

        let config_path = blobs_dir.join(config_digest);
        let config_content = match std::fs::read_to_string(&config_path) {
            Ok(c)  => c,
            Err(_) => continue,
        };
        let config_json: Value = match serde_json::from_str(&config_content) {
            Ok(v)  => v,
            Err(_) => continue,
        };

        let arch = config_json["architecture"].as_str().unwrap_or("unknown");
        if arch == TARGET_ARCH {
            // Le digest du manifest = nom du fichier sans extension
            let digest = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            candidates.push((digest, path.clone()));
        }
    }

    match candidates.len() {
        0 => bail!(
            "Aucun manifest image pour l'architecture '{}' trouvé",
            TARGET_ARCH
        ),
        _ => Ok(candidates.remove(0)),
    }
}

/// Copie tous les blobs depuis la quarantaine vers l'OCI layout temporaire.
fn copy_blobs(src_blobs: &Path, dst_blobs: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src_blobs)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let filename = match path.file_name() {
            Some(n) => n,
            None    => continue,
        };
        std::fs::copy(&path, dst_blobs.join(filename))?;
    }
    Ok(())
}

/// Dérive un tag Docker unique depuis le chemin de quarantaine.
/// /data/quarantaine/library/alpine/3.18 → "ddg-scan-alpine:3.18"
fn derive_image_tag(quarantine_path: &str) -> String {
    let comps: Vec<&str> = Path::new(quarantine_path)
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    let n = comps.len();
    if n >= 2 {
        let repo = comps[n - 2];
        let tag  = comps[n - 1];
        format!("ddg-scan-{}:{}", repo, tag)
    } else {
        "ddg-scan-image:latest".to_string()
    }
}