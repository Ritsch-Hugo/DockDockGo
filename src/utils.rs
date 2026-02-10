// ===== Std =====
use std::fs;
use std::fs::create_dir_all;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

// ===== Tokio =====
use tokio::sync::Mutex as TokioMutex;
use tokio::time::sleep;

// ===== Hyper =====
use hyper::{
    Body,
    Method,
    Request,
    Response,
    StatusCode,
};
use hyper::body::to_bytes;

// ===== Reqwest =====
use reqwest::Client;

// ===== Crypto =====
use sha2::{Digest as ShaDigest, Sha256};

// ===== Serde / JSON =====
use serde_json;

// ===== UUID =====
use uuid::Uuid;

// ===== Errors =====
use anyhow::Result;

// ===== Crate (TES types / constantes) =====
use crate::{
    Digest,
    PullContext,
    PullContextList,
    CONTEXT_TIMEOUT,
    UPSTREAM,
};

use crate::digest_process_for_head;


/// 🔑 SHA256 réel (Docker compliant)
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// 💾 Sauvegarde en quarantaine
pub fn save_to_quarantine(
    path: &str,
    bytes: &[u8],
    ctx: &PullContext,
) {
    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();
    if parts.len() < 4 {
        return;
    }

    let base_dir = format!(
        "quarantaine/{}/{}",
        ctx.registry,
        ctx.repository
    );

    // Helper pour écrire un digest
    fn write_digest(
        base_dir: &str,
        category: &str,
        digest: &Digest,
        bytes: &[u8],
        ext: Option<&str>,
    ) {
        let dir = format!("{}/{}/{}/{}", base_dir, category, digest.algorithm, "");
        create_dir_all(&dir).ok();

        let filename = match ext {
            Some(e) => format!("{}/{}.{}", dir, digest.value, e),
            None => format!("{}/{}", dir, digest.value),
        };

        // Écriture idempotente
        if !std::path::Path::new(&filename).exists() {
            fs::write(&filename, bytes).ok();
        }
    }

    // ===== MANIFEST =====
    if parts[2] == "manifests" && parts[3].starts_with("sha256:") {
        let digest_value = parts[3].trim_start_matches("sha256:");
        let digest = Digest {
            algorithm: "sha256".to_string(),
            value: digest_value.to_string(),
        };

        write_digest(
            &base_dir,
            "manifests",
            &digest,
            bytes,
            Some("json"),
        );
        println!("Manifest Ajouté a la quarantaine");
    }

    // ===== BLOB =====
    else if parts[2] == "blobs" && parts[3].starts_with("sha256:") {
        let digest_value = parts[3].trim_start_matches("sha256:");
        let digest = Digest {
            algorithm: "sha256".to_string(),
            value: digest_value.to_string(),
        };

        write_digest(
            &base_dir,
            "blobs",
            &digest,
            bytes,
            None,
        );
        println!("Blob Ajouté a la quarantaine");
    }

    // ===== REFERRERS =====
    else if parts[2] == "referrers" && parts[3].starts_with("sha256:") {
        let digest_value = parts[3].trim_start_matches("sha256:");
        let digest = Digest {
            algorithm: "sha256".to_string(),
            value: digest_value.to_string(),
        };

        write_digest(
            &base_dir,
            "referrers",
            &digest,
            bytes,
            Some("json"),
        );
        println!("Refferer Ajouté a la quarantaine");
    }
}




/// 📦 Sert depuis le cache qui contient les images préalablement scannées
pub fn try_serve_from_cache(
    req: &Request<Body>,
    ctx: &PullContext,
) -> Option<Response<Body>> {
    let path = req.uri().path();
    let is_head = req.method() == Method::HEAD;

    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();
    if parts.len() < 4 {
        return None;
    }

    // Base dir conforme à l'arborescence
    let base_dir = format!(
        "cache/{}/{}",
        ctx.registry,
        ctx.repository
    );

    if req.method() != Method::GET {
        return None;
    }

    // ================= MANIFEST =================
    if parts[2] == "manifests" && parts[3].starts_with("sha256:") {
        let digest = parts[3].trim_start_matches("sha256:");
        let file = format!(
            "{}/manifests/sha256/{}.json",
            base_dir, digest
        );

        //prend la donné en lisant le fichier du cache
        if let Ok(data) = fs::read(&file) {
            if data.len() < 20 {
                return None;
            }

            let real_digest = sha256_hex(&data);

            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Docker-Distribution-API-Version", "registry/2.0")
                    .header(
                        "Content-Type",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    .header("Docker-Content-Digest", format!("sha256:{real_digest}"))
                    .header("Content-Length", data.len())
                    .body(if is_head { Body::empty() } else { Body::from(data) })
                    .unwrap(),
            );
        }
    }

    // ================= BLOB =================
    if parts[2] == "blobs" && parts[3].starts_with("sha256:") {
        let digest = parts[3].trim_start_matches("sha256:");
        let file = format!(
            "{}/blobs/sha256/{}",
            base_dir, digest
        );

        if let Ok(data) = fs::read(&file) {
            let real_digest = sha256_hex(&data);

            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/octet-stream")
                    .header("Docker-Content-Digest", format!("sha256:{real_digest}"))
                    .header("Content-Length", data.len())
                    .body(if is_head { Body::empty() } else { Body::from(data) })
                    .unwrap(),
            );
        }
    }

    // ================= REFERRERS =================
    if parts[2] == "referrers" && parts[3].starts_with("sha256:") {
        let digest = parts[3].trim_start_matches("sha256:");
        let file = format!(
            "{}/referrers/sha256/{}.json",
            base_dir, digest
        );

        if let Ok(data) = fs::read(&file) {
            if data.len() < 20 {
                return None;
            }

            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Docker-Distribution-API-Version", "registry/2.0")
                    .header("Content-Type", "application/vnd.oci.image.index.v1+json")
                    .header("Content-Length", data.len())
                    .body(if is_head { Body::empty() } else { Body::from(data) })
                    .unwrap(),
            );
        }
    }

    None
}


pub fn manifest_list_has_linux_amd64(bytes: &[u8]) -> bool {
    let v: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let manifests = match v.get("manifests").and_then(|m| m.as_array()) {
        Some(m) => m,
        None => return false,
    };

    for m in manifests {
        let platform = match m.get("platform") {
            Some(p) => p,
            None => continue,
        };

        let os = match platform.get("os").and_then(|v| v.as_str()) {
            Some(o) => o,
            None => continue,
        };

        let arch = match platform.get("architecture").and_then(|v| v.as_str()) {
            Some(a) => a,
            None => continue,
        };

        if os == "linux" && arch == "amd64" {
            return true;
        }
    }

    false
}

pub async fn store_digest(
    client: &Client,
    registry: &str,
    repository: &str,
    tag: &str,
    uuid: &Uuid,
) -> Result<Digest, anyhow::Error> {
    println!("[STORE] Téléchargement et stockage du manifest pour {}/{}", repository, tag);

    // Récupérer le digest racine
    let digest = digest_process_for_head(client, registry, repository, tag).await?;

    // Télécharger le manifest complet
    let token_url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        repository
    );
    let token_resp = client.get(&token_url).send().await?;
    let token_json: serde_json::Value = token_resp.json().await?;
    let token = token_json.get("token").and_then(|v| v.as_str()).unwrap();

    let manifest_url = format!("https://{}/v2/{}/manifests/{}", registry, repository, tag);
    let manifest_resp = client
        .get(&manifest_url)
        .header("Authorization", format!("Bearer {}", token))
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.list.v2+json,\
             application/vnd.docker.distribution.manifest.v2+json",
        )
        .send()
        .await?;

    let bytes = manifest_resp.bytes().await?;

    // Stocker dans tmp/<uuid>/
    let tmp_dir = format!("tmp/{}", uuid);
    if !Path::new(&tmp_dir).exists() {
        create_dir_all(&tmp_dir)?;
    }

    let filename = format!("{}/{}.json", tmp_dir, digest.value);
    if !Path::new(&filename).exists() {
        fs::write(&filename, &bytes)?;
        println!("[STORE] Manifest stocké: {}", filename);
    } else {
        println!("[STORE] Manifest déjà présent: {}", filename);
    }

    Ok(digest)
}
 
pub async fn get_response_from_upstream(
    req: Request<Body>,
    client: Client,
) -> Result<reqwest::Response, Response<Body>> {
    let uri = req.uri().clone();
    let method = req.method().clone();
    let headers = req.headers().clone();

    let upstream_url = format!(
        "{}{}",
        UPSTREAM,
        uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
    );

    let body = to_bytes(req.into_body()).await.unwrap_or_default();

    let mut rb = client.request(method, &upstream_url);
    for (k, v) in headers.iter() {
        if !matches!(k.as_str(), "host" | "connection") {
            rb = rb.header(k, v);
        }
    }
    if !body.is_empty() {
        rb = rb.body(body);
    }

    match rb.send().await {
        Ok(resp) => Ok(resp),
        Err(_) => Err(
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("DockerHub unreachable"))
                .unwrap()
        ),
    }
}



/// Vérifie si le manifest racine est dans la blacklist ou whitelist
/// `mode` = "blacklist" ou "whitelist"
pub async fn check_manifest_in_list(
    context_uuid: Uuid,
    pull_contexts: &Arc<TokioMutex<Vec<PullContext>>>, // OK maintenant
    method: Method,
    mode: &str,
) -> Option<Response<Body>> {

    // 🔹 Récupérer le contexte PullContext
    let ctx_opt = {
        let list = pull_contexts.lock().await;
        list.iter().find(|c| c.uuid == context_uuid).cloned()
    };

    let ctx = match ctx_opt {
        Some(c) => c,
        None => return None, // contexte introuvable
    };

    if let Some(racine_digest) = &ctx.manifest_racine_digest {
        let list_path = match mode {
            "blacklist" => "blacklist.json",
            "whitelist" => "whitelist.json",
            _ => return None,
        };

        if Path::new(list_path).exists() {
            if let Ok(content) = fs::read_to_string(list_path) {
                if let Ok(list_json) = serde_json::from_str::<Vec<PullContext>>(&content) {
                    let is_present = list_json.iter().any(|entry| {
                        if let Some(entry_racine) = &entry.manifest_racine_digest {
                            entry_racine.value == racine_digest.value
                        } else {
                            false
                        }
                    });

                    if is_present {
                        let action = if mode == "blacklist" {
                            "[BLACKLIST CHECK] Manifest racine présent -> pull refusé"
                        } else {
                            "[WHITELIST CHECK] Manifest racine présent -> pull autorisé"
                        };

                        println!("{} | uuid={}", action, context_uuid);

                        // Si blacklist -> cleanup + retirer contexte
                        if mode == "blacklist" {
                            cleanup_tmp_for_uuid(&context_uuid);
                            let mut list = pull_contexts.lock().await;
                            list.retain(|c| c.uuid != context_uuid);
                            println!("[PullContext] Contexte libéré car blacklisté | uuid={}", context_uuid);

                            return Some(
                                Response::builder()
                                    .status(StatusCode::FORBIDDEN)
                                    .body(Body::from("Image présente dans blacklist"))
                                    .unwrap(),
                            );
                        } else if mode == "whitelist" {
                            // whitelist -> on laisse passer
                            return Some(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Body::from("Image présente dans whitelist"))
                                    .unwrap(),
                            );
                        }
                    }
                }
            }
        }
    }

    None // Pas trouvé dans la liste, ou méthode non HEAD
}

/// Ajoute un PullContext dans la blacklist ou la whitelist selon `list_type`.
/// `list_type` doit être "blacklist" ou "whitelist"
pub fn add_context_to_blacklist_or_whitelist(ctx: PullContext, list_type: &str) -> Result<()> {
    // Vérification du paramètre
    let file_path = match list_type {
        "whitelist" => "whitelist.json",
        "blacklist" => "blacklist.json",
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("list_type invalide : '{}', doit être 'whitelist' ou 'blacklist'", list_type),
            ).into());
        }
    };

    // 🔹 Charger la liste existante ou créer une nouvelle
    println!("[DEBUG] Chargement de la {} depuis '{}'", list_type, file_path);

    let mut list: Vec<PullContext> = if Path::new(file_path).exists() {
        match fs::read_to_string(file_path) {
            Ok(s) => match serde_json::from_str::<Vec<PullContext>>(&s) {
                Ok(b) => b,
                Err(_) => Vec::new(),
            },
            Err(_) => Vec::new(),
        }
    } else {
        println!(
            "[DEBUG] {} n'existe pas encore, création d'une nouvelle liste",
            file_path
        );
        Vec::new()
    };

    // 🔹 Vérifier si le contexte existe déjà (via UUID)
    if list.iter().any(|c| c.uuid == ctx.uuid) {
        println!(
            "[DEBUG] Contexte UUID={} déjà présent dans {} – ajout ignoré",
            ctx.uuid, list_type
        );
        return Ok(()); // on ne fait rien si le contexte existe déjà
    }

    // 🔹 Ajouter le contexte courant
    println!("[DEBUG] Ajout du contexte UUID={} à la {}", ctx.uuid, list_type);
    list.push(ctx);

    // 🔹 Écriture dans le fichier
    match serde_json::to_string_pretty(&list) {
        Ok(json) => match fs::write(file_path, json) {
            Ok(_) => println!("[{}] Contexte ajouté dans {}", list_type.to_uppercase(), file_path),
            Err(e) => eprintln!(
                "[{} ERROR] Impossible d'écrire {}: {:?}",
                list_type.to_uppercase(),
                file_path,
                e
            ),
        },
        Err(e) => eprintln!(
            "[{} ERROR] Sérialisation impossible: {:?}",
            list_type.to_uppercase(),
            e
        ),
    }

    Ok(())
}


//Check si aucune requetes envoyé dans le laspe de temps CONTEXT_TIMEOUT
pub fn check_timout(pull_contexts: PullContextList) {

    //tache asyncrone qui s'appelles toutes les secondes 
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(1)).await;

            let mut expired_uuids = Vec::new();

            let mut list = pull_contexts.lock().await;
            let before = list.len();

            //garde 
            list.retain(|ctx| {
                //garde les contextes qui ne depassent pas le timout 
                let alive = ctx.last_activity.elapsed() < CONTEXT_TIMEOUT;
                if !alive {
                    println!(
                        "[Timeout-Reach] Contexte expiré supprimé | uuid={}",
                        ctx.uuid
                    );
                    // 🧹 suppression quarantaine AVANT suppression du ctx
                    remove_ctx_digests_from_quarantine(ctx);
                    expired_uuids.push(ctx.uuid);
                }
                alive
            });

            drop(list); // 🔓 libérer le lock avant l'acces au contexte pour supprimer 

            // 🧹 Suppression des dossiers tmp/<uuid>
            for uuid in expired_uuids 
            {
                cleanup_tmp_for_uuid(&uuid);
            }

            //Si la liste n'a plus la meme taille 
            if before != pull_contexts.lock().await.len() {
                println!(
                    "[Timeout-Reach] Nettoyage effectué: {} → {}",
                    before,
                    pull_contexts.lock().await.len()
                );
            }
        }
    });
}

pub fn cleanup_tmp_for_uuid(uuid: &Uuid) {
    let path = format!("tmp/{}", uuid);

    match fs::remove_dir_all(&path) {
        Ok(_) => {
            println!("[CLEANUP] Dossier tmp supprimé pour uuid={}", uuid);
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "[CLEANUP ERROR] Impossible de supprimer tmp pour uuid={} : {:?}",
                    uuid, e
                );
            }
        }
    }
}

pub async fn get_dockerhub_token(
    client: &Client,
    repository: &str,
) -> Result<String, reqwest::Error> {
    let url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        repository
    );

    let resp: serde_json::Value = client.get(url).send().await?.json().await?;
    Ok(resp["token"].as_str().unwrap().to_string())
}

pub fn remove_ctx_digests_from_quarantine(ctx: &PullContext) {
    let registry = &ctx.registry;
    let repo = &ctx.repository;

    let mut all = Vec::new();
    all.extend(ctx.manifest_digests.iter());
    all.extend(ctx.blob_digests.iter());
    all.extend(ctx.referrers_digests.iter());

    for digest in all {
        let base = format!(
            "quarantaine/{}/{}/",
            registry, repo
        );

        let manifest = format!(
            "{}manifests/sha256/{}.json",
            base, digest.value
        );

        let blob = format!(
            "{}blobs/sha256/{}",
            base, digest.value
        );

        let referrers = format!(
            "{}referrers/sha256/{}.json",
            base, digest.value
        );


        if Path::new(&manifest).exists() {
            if let Err(e) = fs::remove_file(&manifest) {
                eprintln!("[QUARANTINE CLEAN] erreur {}", e);
            } else {
                println!("[QUARANTINE CLEAN] supprimé {}", manifest);
            }
        }

        if Path::new(&blob).exists() {
            if let Err(e) = fs::remove_file(&blob) {
                eprintln!("[QUARANTINE CLEAN] erreur {}", e);
            } else {
                println!("[QUARANTINE CLEAN] supprimé {}", blob);
            }
        }
        
        if Path::new(&referrers).exists() {
            if let Err(e) = fs::remove_file(&referrers) {
                eprintln!("[QUARANTINE CLEAN] erreur {}", e);
            } else {
                println!("[QUARANTINE CLEAN] supprimé {}", referrers);
            }
        }
    }
}


//Cycle de vie des requetes
pub async fn dec_active(pull_contexts: &PullContextList, uuid: Uuid, pull_is_allowed: bool) {

    match pull_contexts.try_lock() {
        Ok(_) => {
            println!("[CTX] dec_active: mutex libre");
            // le guard est droppé immédiatement ici
        }
        Err(_) => {
            println!("[CTX] dec_active: mutex déjà pris -> attente");
        }
    }

    let mut list = pull_contexts.lock().await;
    if let Some(ctx) = list.iter_mut().find(|c| c.uuid == uuid) {
        if ctx.active_requests > 0 {
            ctx.active_requests -= 1;
        }
        println!("[CTX] -1 active_requests={} uuid={}", ctx.active_requests, ctx.uuid);

        if ctx.pull_completed && ctx.active_requests == 0 {

            if pull_is_allowed {
                println!("[SCAN] OK + paramètre → copie vers cache");
                copy_ctx_from_quarantine_to_cache(ctx);
            }
            cleanup_tmp_for_uuid(&ctx.uuid);
            //remove_ctx_digests_from_quarantine(ctx);
            list.retain(|c| c.uuid != uuid);
        }
    }
}


pub fn copy_ctx_from_quarantine_to_cache(ctx: &PullContext) {
    let registry = &ctx.registry;
    let repo = &ctx.repository;

    let base_q = format!("quarantaine/{}/{}/", registry, repo);
    let base_c = format!("cache/{}/{}/", registry, repo);

    // -------- MANIFESTS --------
    for digest in &ctx.manifest_digests {
        let q = format!("{}manifests/sha256/{}.json", base_q, digest.value);
        let c = format!("{}manifests/sha256/{}.json", base_c, digest.value);
        copy_if_exists(&q, &c);
    }

    // -------- BLOBS --------
    for digest in &ctx.blob_digests {
        let q = format!("{}blobs/sha256/{}", base_q, digest.value);
        let c = format!("{}blobs/sha256/{}", base_c, digest.value);
        copy_if_exists(&q, &c);
    }

    // -------- REFERRERS --------
    for digest in &ctx.referrers_digests {
        let q = format!("{}referrers/sha256/{}.json", base_q, digest.value);
        let c = format!("{}referrers/sha256/{}.json", base_c, digest.value);
        copy_if_exists(&q, &c);
    }

    println!(
        "[CACHE COPY] Image copiée quarantaine → cache | {} {}:{}",
        ctx.registry, ctx.repository, ctx.tag
    );
}

fn copy_if_exists(src: &str, dst: &str) {
    let src_path = Path::new(src);
    if !src_path.exists() {
        return;
    }

    let dst_path = Path::new(dst);

    // créer dossier parent
    if let Some(parent) = dst_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("[CACHE COPY] mkdir error {}", e);
            return;
        }
    }

    // skip si déjà en cache
    if dst_path.exists() {
        return;
    }

    match fs::copy(src_path, dst_path) {
        Ok(_) => println!("[CACHE COPY] {}", dst),
        Err(e) => eprintln!("[CACHE COPY] error {} -> {}", src, e),
    }
}

