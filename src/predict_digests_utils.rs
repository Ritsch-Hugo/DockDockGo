// ================================
// Imports nécessaires
// ================================
use anyhow::Result;
use futures::future::BoxFuture;
use futures::FutureExt;
use reqwest::Client;
use std::fs;
use std::fs::create_dir_all;
use std::path::Path;
use uuid::Uuid;

// Pour les types définis dans ton projet
use crate::models::{Digest, DigestVerificationState, ManifestList, PullContext, PullContextError};

use crate::registry_auth::RegistryClient;

/// Retourne l'OS et l'architecture d'un manifest Docker à partir de son digest.
/// Si l'information n'existe pas, renvoie ("unknown", "unknown").
pub fn get_os_arch_for_digest(
    manifest_racine: &serde_json::Value,
    digest_courant: &str,
) -> (String, String) {
    let manifests = match manifest_racine.get("manifests").and_then(|m| m.as_array()) {
        Some(m) => m,
        None => return ("unknown".into(), "unknown".into()),
    };

    let normalize = |d: &str| d.trim_start_matches("sha256:").to_string();

    let target = normalize(digest_courant);

    // 1️⃣ Indexer tous les manifests
    let mut by_digest = std::collections::HashMap::new();

    for m in manifests {
        if let Some(d) = m.get("digest").and_then(|d| d.as_str()) {
            by_digest.insert(normalize(d).to_string(), m);
        }
    }

    // 2️⃣ Trouver le manifest correspondant
    let manifest = match by_digest.get(&target) {
        Some(m) => *m,
        None => return ("unknown".into(), "unknown".into()),
    };

    let platform = manifest.get("platform");

    let os = platform
        .and_then(|p| p.get("os"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let arch = platform
        .and_then(|p| p.get("architecture"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // 3️⃣ Cas NORMAL → image réelle
    if os != "unknown" && arch != "unknown" {
        return (os.to_string(), arch.to_string());
    }

    // 4️⃣ Cas ATTESTATION → remonter vers le vrai digest
    if let Some(ref_digest) = manifest
        .get("annotations")
        .and_then(|a| a.get("vnd.docker.reference.digest"))
        .and_then(|v| v.as_str())
    {
        let ref_key = normalize(ref_digest);
        if let Some(real_manifest) = by_digest.get(&ref_key) {
            let platform = real_manifest.get("platform");
            let os = platform
                .and_then(|p| p.get("os"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let arch = platform
                .and_then(|p| p.get("architecture"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            return (os.to_string(), arch.to_string());
        }
    }

    ("unknown".into(), "unknown".into())
}

// Fonction interne pour parser un manifest et extraire ses digests
pub fn fetch_and_process_manifest<'a>(
    client: &'a Client,
    uuid: &'a Uuid,
    registry: &'a str,
    repository: &'a str,
    digest: &'a str,
    token: &'a str,
    digests: &'a mut Vec<Digest>,
) -> BoxFuture<'a, Result<()>> {
    async move {
        // Télécharger le manifest si absent
        let digest_clean = digest.strip_prefix("sha256:").unwrap_or(digest);
        let path = format!("tmp/{}/{}.json", uuid, digest_clean);

        if !Path::new(&path).exists() {
            let url = format!(
                "https://{}/v2/{}/manifests/{}",
                registry, repository, digest
            );
            let resp = client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header(
                    "Accept",
                    "application/vnd.docker.distribution.manifest.list.v2+json,\
                    application/vnd.docker.distribution.manifest.v2+json,\
                    application/vnd.oci.image.index.v1+json,\
                    application/vnd.oci.image.manifest.v1+json",
                )
                .send()
                .await?;
            let content = resp.bytes().await?;
            fs::write(&path, &content)?;
            println!("[PREDICT] Stored manifest blob: {}", path);
        }

        // Lire le manifest
        let content = fs::read(&path)?;
        let json: serde_json::Value = serde_json::from_slice(&content)?;

        //Log
        println!(
            "[FETCH DEBUG] manifest {}: config={:?}, layers={:?}",
            digest_clean,
            json.get("config"),
            json.get("layers")
        );

        // Ajouter digest du manifest lui-même
        if !digests.iter().any(|d| d.value == digest_clean) {
            digests.push(Digest {
                algorithm: "sha256".into(),
                value: digest_clean.into(),
            });
        }

        // Si manifest list → récursion (via BoxFuture)
        if json.get("manifests").is_some() {
            let manifest_list: ManifestList = serde_json::from_value(json)?;
            for m in manifest_list.manifests {
                fetch_and_process_manifest(
                    client, uuid, registry, repository, &m.digest, token, digests,
                )
                .await?;
            }
        } else {
            // Sinon, config + layers
            if let Some(config) = json
                .get("config")
                .and_then(|c| c.get("digest"))
                .and_then(|d| d.as_str())
            {
                let c = config.strip_prefix("sha256:").unwrap_or(config);
                digests.push(Digest {
                    algorithm: "sha256".into(),
                    value: c.into(),
                });
            }
            if let Some(layers) = json.get("layers").and_then(|l| l.as_array()) {
                for layer in layers {
                    if let Some(d) = layer.get("digest").and_then(|v| v.as_str()) {
                        let l = d.strip_prefix("sha256:").unwrap_or(d);
                        digests.push(Digest {
                            algorithm: "sha256".into(),
                            value: l.into(),
                        });
                    }
                }
            }
        }

        Ok(())
    }
    .boxed()
}

pub async fn predict_digests_docker(
    //Doit etre appellée lors du HEAD dans get_pull_context
    client: &Client,
    uuid: &Uuid,
    registry: &str,
    repository: &str,
    tag: &str,
    os: &str,
    arch: &str,
    manifest_racine_digest: &Digest,
) -> Result<Vec<Digest>> {
    println!(
        "LOG - MANIFEST RACINE DIGEST : {}",
        manifest_racine_digest.value
    );
    println!(
        "[PREDICT] Using provided manifest digest for {}:{}, target={}/{}",
        repository, tag, os, arch
    );

    // ============================
    // 1️⃣ Récupération du token
    // ============================

    /*
    let token_url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        repository
    );
    let token_resp = client.get(&token_url).send().await?;
    let token_json: serde_json::Value = token_resp.json().await?;

    let token = token_json
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Token Docker manquant"))?;
    */

    let token = RegistryClient::from_registry(registry)
        .get_token(client, repository)
        .await?;

    // ============================
    // 2️⃣ Préparer le stockage temporaire
    // ============================
    let digest_clean = manifest_racine_digest
        .value
        .strip_prefix("sha256:")
        .unwrap_or(&manifest_racine_digest.value);

    let tmp_dir = format!("tmp/{}", uuid);
    if !Path::new(&tmp_dir).exists() {
        create_dir_all(&tmp_dir)?;
    }

    let filename = format!("{}/{}.json", tmp_dir, digest_clean);

    // ============================
    // 3️⃣ Télécharger le manifest racine si absent
    // ============================
    if !Path::new(&filename).exists() {
        let manifest_url = format!(
            "https://{}/v2/{}/manifests/{}",
            registry, repository, manifest_racine_digest.value
        );

        let resp = client
            .get(&manifest_url)
            .header("Authorization", format!("Bearer {}", token))
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.list.v2+json,\
                application/vnd.docker.distribution.manifest.v2+json,\
                application/vnd.oci.image.index.v1+json,\
                application/vnd.oci.image.manifest.v1+json",
            )
            .send()
            .await?;

        let bytes = resp.bytes().await?;
        fs::write(&filename, &bytes)?;
        //println!("[PREDICT] Stored manifest blob: {} ({} bytes)", filename, bytes.len());
    } else {
        //println!("[PREDICT] Manifest already exists: {}", filename);
    }

    // ============================
    // 4️⃣ Lire le manifest depuis le fichier
    // ============================
    let bytes = fs::read(&filename)?;
    // ============================
    // 5️⃣ Initialiser digests avec le manifest racine
    // ============================
    let mut digests = Vec::new();
    digests.push(Digest {
        algorithm: "sha256".to_string(),
        value: digest_clean.to_string(),
    });

    // ============================
    // Parsing MANIFEST LIST
    // ============================
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;

    if let Some(_manifests) = json.get("manifests") {
        //println!("[PREDICT] Parsing manifest list");

        let manifest_list: ManifestList = serde_json::from_value(json)?;

        // 1️⃣ D'abord, récupérer le manifest correspondant à notre OS/ARCH
        let mut main_manifest_digest: Option<String> = None;

        for m in &manifest_list.manifests {
            if m.platform.os == os && m.platform.architecture == arch {
                /*println!(
                    "[PREDICT] Selected manifest {} for {}/{}",
                    m.digest, os, arch
                );*/

                let digest_clean = m
                    .digest
                    .strip_prefix("sha256:")
                    .ok_or_else(|| anyhow::anyhow!("Digest inattendu"))?
                    .to_string();

                digests.push(Digest {
                    algorithm: "sha256".to_string(),
                    value: digest_clean.clone(),
                });

                // Télécharger et stocker le manifest si absent
                let manifest_path = format!("tmp/{}/{}.json", uuid, digest_clean);
                if !Path::new(&manifest_path).exists() {
                    let manifest_url = format!(
                        "https://{}/v2/{}/manifests/{}",
                        registry, repository, m.digest
                    );

                    let resp = client
                        .get(&manifest_url)
                        .header("Authorization", format!("Bearer {}", token))
                        .header(
                            "Accept",
                            "application/vnd.docker.distribution.manifest.list.v2+json,\
                            application/vnd.docker.distribution.manifest.v2+json,\
                            application/vnd.oci.image.index.v1+json,\
                            application/vnd.oci.image.manifest.v1+json",
                        )
                        .send()
                        .await?;

                    let content = resp.bytes().await?;
                    fs::write(&manifest_path, &content)?;

                    /*println!(
                        "[PREDICT] Stored arch-specific manifest: {}",
                        manifest_path
                    );*/
                }

                main_manifest_digest = Some(m.digest.clone());
            }
        }

        // 2️⃣ Ensuite, gérer les manifests “unknown/unknown” qui pointent vers le digest principal
        for m in &manifest_list.manifests {
            if m.platform.os == "unknown" && m.platform.architecture == "unknown" {
                if let Some(annotations) = m.annotations.as_ref() {
                    if let Some(ref_digest) = annotations.get("vnd.docker.reference.digest") {
                        if Some(ref_digest) == main_manifest_digest.as_ref() {
                            /*println!(
                                "[PREDICT] Including unknown manifest {} linked to main manifest",
                                m.digest
                            );*/

                            let digest_clean = m
                                .digest
                                .strip_prefix("sha256:")
                                .ok_or_else(|| anyhow::anyhow!("Digest inattendu"))?
                                .to_string();

                            digests.push(Digest {
                                algorithm: "sha256".to_string(),
                                value: digest_clean.clone(),
                            });

                            // Télécharger et stocker
                            let manifest_path = format!("tmp/{}/{}.json", uuid, digest_clean);
                            if !Path::new(&manifest_path).exists() {
                                let manifest_url = format!(
                                    "https://{}/v2/{}/manifests/{}",
                                    registry, repository, m.digest
                                );

                                let resp = client
                                    .get(&manifest_url)
                                    .header("Authorization", format!("Bearer {}", token))
                                    .header(
                                        "Accept",
                                        "application/vnd.docker.distribution.manifest.list.v2+json,\
                                        application/vnd.docker.distribution.manifest.v2+json,\
                                        application/vnd.oci.image.index.v1+json,\
                                        application/vnd.oci.image.manifest.v1+json",
                                    )
                                    .send()
                                    .await?;

                                let content = resp.bytes().await?;
                                fs::write(&manifest_path, &content)?;

                                println!(
                                    "[PREDICT] Stored linked unknown manifest: {}",
                                    manifest_path
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    let manifest_list_digest_clean = manifest_racine_digest
        .value
        .strip_prefix("sha256:")
        .unwrap_or(&manifest_racine_digest.value)
        .to_string();

    // Collecter les digests des manifests téléchargés (arch-specific + unknown)
    let manifests_to_process: Vec<String> = digests
        .iter()
        .filter(|d| d.value != manifest_list_digest_clean) // exclure le manifest list racine
        .map(|d| format!("sha256:{}", d.value))
        .collect();

    // Parcourir chaque manifest pour extraire config + layers
    for digest in manifests_to_process {
        fetch_and_process_manifest(
            &client,
            uuid,
            registry,
            repository,
            &digest,
            &token,
            &mut digests,
        )
        .await?;
    }

    //affiche les digests prédites par predict_digests
    println!("[PREDICT] Collected digests:");
    for d in &digests {
        println!(" - {}:{}", d.algorithm, d.value);
    }

    Ok(digests)
}

pub async fn predict_digests_podman(
    client: &Client,
    uuid: &Uuid,
    registry: &str,
    repository: &str,
    os: &str,
    arch: &str,
    manifest_racine_digest: &Digest,
) -> Result<Vec<Digest>> {
    println!(
        "[PREDICT PODMAN] Démarrage pour {}/{} target={}/{}",
        repository, manifest_racine_digest.value, os, arch
    );

    // ============================
    // 1️⃣ Lire le manifest list racine depuis tmp/<uuid>/
    // Déjà téléchargé par create_context_from_tag
    // ============================
    let digest_clean = manifest_racine_digest
        .value
        .trim_start_matches("sha256:")
        .to_string();

    let manifest_list_path = format!("tmp/{}/{}.json", uuid, digest_clean);

    let bytes = std::fs::read(&manifest_list_path).map_err(|e| {
        anyhow::anyhow!(
            "[PREDICT PODMAN] Manifest list introuvable: {} ({})",
            manifest_list_path,
            e
        )
    })?;

    let manifest_list_json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("[PREDICT PODMAN] Manifest list JSON invalide: {}", e))?;

    // ============================
    // 2️⃣ Trouver le manifest linux/amd64
    // Ignorer unknown/unknown et toutes les autres architectures
    // ============================
    let manifests = manifest_list_json
        .get("manifests")
        .and_then(|m| m.as_array())
        .ok_or_else(|| anyhow::anyhow!("[PREDICT PODMAN] Champ 'manifests' absent"))?;

    let mut digest_amd64: Option<String> = None;

    for m in manifests {
        let platform = match m.get("platform") {
            Some(p) => p,
            None => continue,
        };

        let m_os = platform.get("os").and_then(|v| v.as_str()).unwrap_or("");

        let m_arch = platform
            .get("architecture")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // On skip tout ce qui n'est pas notre cible
        if m_os != os || m_arch != arch {
            println!(
                "[PREDICT PODMAN] Skip manifest {}/{} (on cherche {}/{})",
                m_os, m_arch, os, arch
            );
            continue;
        }

        // On a trouvé le bon manifest
        if let Some(d) = m.get("digest").and_then(|d| d.as_str()) {
            digest_amd64 = Some(d.trim_start_matches("sha256:").to_string());
            println!("[PREDICT PODMAN] Manifest {}/{} trouvé: {}", os, arch, d);
            break;
        }
    }

    let digest_amd64 = digest_amd64.ok_or_else(|| {
        anyhow::anyhow!(
            "[PREDICT PODMAN] Aucun manifest trouvé pour {}/{}",
            os,
            arch
        )
    })?;

    // ============================
    // 3️⃣ Télécharger le manifest linux/amd64 si absent
    // ============================
    let token = RegistryClient::from_registry(registry)
        .get_token(client, repository)
        .await?;

    let manifest_amd64_path = format!("tmp/{}/{}.json", uuid, digest_amd64);

    if !Path::new(&manifest_amd64_path).exists() {
        let manifest_url = format!(
            "https://{}/v2/{}/manifests/sha256:{}",
            registry, repository, digest_amd64
        );

        let resp = client
            .get(&manifest_url)
            .header("Authorization", format!("Bearer {}", token))
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.v2+json,\
                application/vnd.oci.image.manifest.v1+json",
            )
            .send()
            .await?;

        let content = resp.bytes().await?;
        fs::write(&manifest_amd64_path, &content)?;
        println!(
            "[PREDICT PODMAN] Manifest {}/{} stocké: {}",
            os, arch, manifest_amd64_path
        );
    } else {
        println!(
            "[PREDICT PODMAN] Manifest {}/{} déjà présent: {}",
            os, arch, manifest_amd64_path
        );
    }

    // ============================
    // 4️⃣ Lire le manifest linux/amd64 et extraire config + layers
    // ============================
    let manifest_bytes = fs::read(&manifest_amd64_path)?;
    let manifest_json: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;

    // ============================
    // 5️⃣ Construire digests_expected
    // [manifest_amd64, config, layer1, layer2, ...]
    // Sans manifest racine, sans unknown/unknown, sans referrers
    // ============================
    let mut digests: Vec<Digest> = Vec::new();

    // ← AJOUTER le digest racine en premier
    digests.push(Digest {
        algorithm: "sha256".to_string(),
        value: digest_clean.clone(), // digest_clean = manifest_racine_digest nettoyé
    });

    // manifest linux/amd64
    digests.push(Digest {
        algorithm: "sha256".to_string(),
        value: digest_amd64.clone(),
    });

    // config
    if let Some(config_digest) = manifest_json
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
    {
        let clean = config_digest.trim_start_matches("sha256:");
        digests.push(Digest {
            algorithm: "sha256".to_string(),
            value: clean.to_string(),
        });
        println!("[PREDICT PODMAN] Config: {}", clean);
    } else {
        eprintln!("[PREDICT PODMAN] Champ 'config.digest' absent du manifest");
    }

    // layers
    if let Some(layers) = manifest_json.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let Some(layer_digest) = layer.get("digest").and_then(|d| d.as_str()) {
                let clean = layer_digest.trim_start_matches("sha256:");
                digests.push(Digest {
                    algorithm: "sha256".to_string(),
                    value: clean.to_string(),
                });
                println!("[PREDICT PODMAN] Layer: {}", clean);
            }
        }
    } else {
        eprintln!("[PREDICT PODMAN] Champ 'layers' absent du manifest");
    }

    // ============================
    // Log récap
    // ============================
    println!("[PREDICT PODMAN] {} digests attendus:", digests.len());
    for d in &digests {
        println!("  - sha256:{}", d.value);
    }

    Ok(digests)
}

pub fn verify_downloaded_digests(
    ctx: &PullContext,
) -> Result<DigestVerificationState, PullContextError> {
    use std::collections::HashSet;

    // 🔹 Digests réellement téléchargés (sans doublons)
    let mut downloaded: HashSet<String> = HashSet::new();
    for d in &ctx.manifest_digests {
        downloaded.insert(d.value.clone());
    }
    for d in &ctx.blob_digests {
        downloaded.insert(d.value.clone());
    }
    for d in &ctx.referrers_digests {
        downloaded.insert(d.value.clone());
    }

    // 🔹 Digests attendus
    let expected: HashSet<String> = ctx
        .digests_expected
        .iter()
        .map(|d| d.value.clone())
        .collect();

    //CAS 1 — digest inattendu → ERREUR
    let extra: HashSet<_> = downloaded.difference(&expected).collect();
    if !extra.is_empty() {
        eprintln!("[VERIFY] Digest(s) inattendu(s) détecté(s):");
        for d in extra.iter() {
            eprintln!("  - {}", d);
        }
        return Err(PullContextError::DigestNotAllowed);
    }

    //CAS 2 — tout est téléchargé → FIN DU PULL
    if downloaded == expected && ctx.pull_completed == false {
        println!("[VERIFY] Pull terminé : tous les digests attendus ont été téléchargés");

        // Affichage lisible des digests en colonnes
        println!("{:<70} {:<10}", "Digest téléchargé", "Statut");
        println!("{}", "-".repeat(80));
        for d in downloaded.iter() {
            println!("{:<70} {:<10}", d, "OK");
        }
        return Ok(DigestVerificationState::Completed);
    }

    //CAS 3 — pull encore en cours (digests manquants)
    let missing: HashSet<_> = expected.difference(&downloaded).collect();
    if !missing.is_empty() {
        //println!("[VERIFY] Pull en cours : digests manquants:");
        for d in missing.iter() {
            println!("  - {}", d);
        }
    }

    Ok(DigestVerificationState::InProgress)
}
