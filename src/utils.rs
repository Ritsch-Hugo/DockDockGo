// ===== Std =====
use std::fs;
use std::fs::create_dir_all;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

// ===== Tokio =====
use tokio::sync::Mutex as TokioMutex;
use tokio::time::sleep;
use crate::registry_auth::RegistryClient;

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

use std::sync::atomic::{Ordering};


// ===== Crate (TES types / constantes) =====
use crate::{
    CONTEXT_TIMEOUT, Digest, PullContext, PullContextList,
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

    // ===== MANIFEST par tag (cas Podman : /manifests/latest) =====
    if parts[2] == "manifests" && !parts[3].starts_with("sha256:") 
    {
        // Le path contient un tag (ex: "latest") et non un digest
        // On utilise le manifest_racine_digest du contexte pour nommer le fichier
        if let Some(racine) = &ctx.manifest_racine_digest {
            write_digest(
                &base_dir,
                "manifests",
                racine,
                bytes,
                Some("json"),
            );
            println!("Manifest racine (par tag) Ajouté a la quarantaine");
        } else {
            eprintln!("[QUARANTINE] manifest par tag mais manifest_racine_digest absent du ctx");
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

pub fn save_to_cache(
    path: &str,
    bytes: &[u8],
    ctx: &PullContext,
) {
    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();
    if parts.len() < 4 {
        return;
    }

    let base_dir = format!(
        "cache/{}/{}",
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

    // ===== MANIFEST par tag (cas Podman : /manifests/latest) =====
    if parts[2] == "manifests" && !parts[3].starts_with("sha256:") 
    {
        // Le path contient un tag (ex: "latest") et non un digest
        // On utilise le manifest_racine_digest du contexte pour nommer le fichier
        if let Some(racine) = &ctx.manifest_racine_digest {
            write_digest(
                &base_dir,
                "manifests",
                racine,
                bytes,
                Some("json"),
            );
            println!("Manifest racine (par tag) Ajouté a la quarantaine");
        } else {
            eprintln!("[QUARANTINE] manifest par tag mais manifest_racine_digest absent du ctx");
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
        println!("Manifest Ajouté au cache");
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
        println!("Blob Ajouté au cache");
    }

    // ===== REFERRERS =====
    else if parts[2] == "referrers" && parts[3].starts_with("sha256:") {
        let digest_value = parts[3].trim_start_matches("sha256:");
        let digest = Digest {
            algorithm: "sha256".to_string(),
            value: digest_value.to_string(),
        };

        if serde_json::from_slice::<serde_json::Value>(bytes).is_err() {
            println!("Referrer ignoré car non-JSON");
            return;
        }

        write_digest(
            &base_dir,
            "referrers",
            &digest,
            bytes,
            Some("json"),
        );
        println!("Refferer Ajouté au cache");
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

    // ================= MANIFEST par tag (cas Podman) =================
    if parts[2] == "manifests" && !parts[3].starts_with("sha256:") {
        if let Some(racine) = &ctx.manifest_racine_digest {
            let file = format!("{}/manifests/sha256/{}.json", base_dir, racine.value);

            if let Ok(data) = fs::read(&file) {
                if data.len() < 20 {
                    return None;
                }

                // ← Lire le vrai mediaType
                let content_type = serde_json::from_slice::<serde_json::Value>(&data)
                    .ok()
                    .and_then(|v| v.get("mediaType").and_then(|m| m.as_str()).map(|s| s.to_string()))
                    .unwrap_or_else(|| {
                        // Manifest list OCI sans mediaType explicite
                        "application/vnd.oci.image.index.v1+json".to_string()
                    });

                return Some(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Docker-Distribution-API-Version", "registry/2.0")
                        .header("Content-Type", content_type)
                        .header("Docker-Content-Digest", format!("sha256:{}", racine.value))
                        .header("Content-Length", data.len())
                        .body(Body::from(data))
                        .unwrap(),
                );
            }
        }
        return None;
    }

    // ================= MANIFEST =================
    if parts[2] == "manifests" && parts[3].starts_with("sha256:") {
        let digest = parts[3].trim_start_matches("sha256:");
        let file = format!("{}/manifests/sha256/{}.json", base_dir, digest);

        if let Ok(data) = fs::read(&file) {
            if data.len() < 20 {
                return None;
            }

            // ← Lire le vrai mediaType depuis le JSON
            let content_type = serde_json::from_slice::<serde_json::Value>(&data)
                .ok()
                .and_then(|v| v.get("mediaType").and_then(|m| m.as_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| {
                    // Pas de mediaType explicite → OCI manifest
                    "application/vnd.oci.image.manifest.v1+json".to_string()
                });

            let real_digest = sha256_hex(&data);

            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Docker-Distribution-API-Version", "registry/2.0")
                    .header("Content-Type", content_type)
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

            // Décompresser si gzip (magic bytes: 0x1f 0x8b) (pour ghr.io)
            let data = if data.starts_with(&[0x1f, 0x8b]) {
                use std::io::Read;
                let mut decoder = flate2::read::GzDecoder::new(&data[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed).ok()?;
                decompressed
            } else {
                data
            };
            // Vérifier que c'est du JSON valide avant de servir
            if serde_json::from_slice::<serde_json::Value>(&data).is_err() {
                println!("[CACHE] Referrer corrompu ignoré, fallback upstream");
                return None; // ← force le fallback vers upstream
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
    /* 
    let token_url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        repository
    );
    let token_resp = client.get(&token_url).send().await?;
    let token_json: serde_json::Value = token_resp.json().await?;
    let token = token_json.get("token").and_then(|v| v.as_str()).unwrap();
    */

    //Recupèration du token en fonction du registre
    let token = RegistryClient::from_registry(registry)
        .get_token(client, repository)
        .await?;

    let manifest_url = format!("https://{}/v2/{}/manifests/{}", registry, repository, tag);
    let manifest_resp = client
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

    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("registry-1.docker.io")
        .to_string();

    let upstream_url = format!(
        "https://{}{}",
        host,
        uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
    );

    let body = to_bytes(req.into_body()).await.unwrap_or_default();

    let mut rb = client.request(method, &upstream_url);

    for (k, v) in headers.iter() {
        // ← supprimer le token du client + host + connection
        if !matches!(k.as_str(), "host" | "connection" | "authorization") {
            rb = rb.header(k, v);
        }
    }

    // ← injecter un token frais obtenu par le proxy
    let path = uri.path();
    if let Some(repository) = extract_repository_from_path(path) {
        match RegistryClient::from_registry(&host)
            .get_token(&client, &repository)
            .await
        {
            Ok(token) => {
                rb = rb.header("Authorization", format!("Bearer {}", token));
            }
            Err(e) => {
                eprintln!("[AUTH] Impossible d'obtenir un token pour {}: {:?}", repository, e);
                // on continue sans token — Docker Hub répondra 401 mais c'est son problème
            }
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
                .body(Body::from("Registry unreachable"))
                .unwrap()
        ),
    }
}

// ← helper : extrait "library/alpine" depuis "/v2/library/alpine/manifests/latest"
fn extract_repository_from_path(path: &str) -> Option<String> {
    let stripped = path.trim_start_matches("/v2/");
    let parts: Vec<&str> = stripped.split('/').collect();
    let end = parts.iter().position(|p| {
        *p == "manifests" || *p == "blobs" || *p == "referrers"
    })?;
    if end == 0 {
        return None;
    }
    Some(parts[..end].join("/"))
}



/// Vérifie si le manifest racine est dans la blacklist ou whitelist
/// `mode` = "blacklist" ou "whitelist"
/// Actuellement la verif est fait via le manifest racine, pas de differnetiation entre les differnts tags (A modifier) 
pub async fn check_manifest_in_list(
    context_uuid: Uuid,
    pull_contexts: &Arc<TokioMutex<Vec<PullContext>>>,
    _method: Method,
    mode: &str,
    pool: &sqlx::PgPool,
) -> Option<Response<Body>> {

    let ctx_opt = {
        let list = pull_contexts.lock().await;
        list.iter().find(|c| c.uuid == context_uuid).cloned()
    };

    let ctx = match ctx_opt {
        Some(c) => c,
        None => return None,
    };

    let found = crate::db::is_image_in_list(
        pool,
        &ctx.registry,
        &ctx.repository,
        &ctx.tag,
        mode,
    )
    .await
    .unwrap_or(false);

    if !found {
        return None;
    }

    match mode {
        "blacklist" => {
            println!("[BLACKLIST CHECK] {}/{} :{} -> pull refusé", ctx.registry, ctx.repository, ctx.tag);
            Some(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("Image dans la blacklist"))
                    .unwrap(),
            )
        }
        "whitelist" => {
            println!("[WHITELIST CHECK] {}/{} :{} -> pull autorisé", ctx.registry, ctx.repository, ctx.tag);
            Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .unwrap(),
            )
        }
        _ => None,
    }
}

/// Ajoute un PullContext dans la blacklist ou la whitelist selon `list_type`.
/// `list_type` doit être "blacklist" ou "whitelist"
pub async fn add_context_to_blacklist_or_whitelist(
    ctx: PullContext,
    list_type: &str,
    pool: &sqlx::PgPool,
) -> Result<()> {
    crate::db::add_image_to_list(
        pool,
        &ctx.registry,
        &ctx.repository,
        &ctx.tag,
        list_type,
    )
    .await?;

    println!("[{}] {}/{} :{} ajouté", list_type.to_uppercase(), ctx.registry, ctx.repository, ctx.tag);
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
pub async fn dec_active(
    pull_contexts: &PullContextList,
    uuid: Uuid,
) {
    let notify;
    {
        let mut list = pull_contexts.lock().await;
        let ctx = match list.iter_mut().find(|c| c.uuid == uuid) {
            Some(c) => c,
            None => return,
        };

        // décrémente le compteur de requêtes actives
        let prev = ctx.active_requests.fetch_sub(1, Ordering::SeqCst);
        // le compteur est décrémenté, on affiche la nouvelle valeur
        let now = prev - 1;

        println!("[CTX] -1 active_requests={} uuid={}", now, ctx.uuid);

        // clone notify pour l'utiliser hors lock
        notify = ctx.notify_zero.clone();

        if now == 0 {
            println!("[CTX] >>> PLUS AUCUNE REQUETE ACTIVE");
        } else {
            return;
        }
    }

    // 🔔 notifier pour le scan final 
    notify.notify_waiters();
}

pub fn copy_ctx_from_quarantine_to_cache(ctx: &PullContext) {
    let registry = &ctx.registry;
    let repo = &ctx.repository;

    let base_q = format!("quarantaine/{}/{}/", registry, repo);
    let base_c = format!("cache/{}/{}/", registry, repo);

    //println!("LOG -> manifests : {:?}, blobs : {:?}, referrers : {:?}", &ctx.manifest_digests, &ctx.blob_digests, &ctx.referrers_digests);
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
    /* 
    println!(
        "[CACHE COPY] Image copiée quarantaine → cache | {} {}:{}",
        ctx.registry, ctx.repository, ctx.tag
    );*/
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
        Ok(_) => {/*println!("[CACHE COPY] {}", dst)*/},
        Err(e) => eprintln!("[CACHE COPY] error {} -> {}", src, e),
    }
}

pub fn is_registry_allowed(registry: &str) -> bool {
    let file_path = "registry_whitelist.json";

    let content = match fs::read_to_string(file_path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("[REGISTRY] registry_whitelist.json introuvable → tout bloqué");
            return false;
        }
    };

    let list: Vec<String> = match serde_json::from_str(&content) {
        Ok(l) => l,
        Err(_) => {
            eprintln!("[REGISTRY] registry_whitelist.json invalide → tout bloqué");
            return false;
        }
    };

    let allowed = list.iter().any(|r| r == registry);
    if !allowed {
        println!("[REGISTRY] Registre '{}' non autorisé", registry);
    }
    allowed
}

/// Vérifie que le contenu reçu correspond au digest sha256 annoncé dans le path
/// Retourne Ok(()) si le digest est valide, Err(String) sinon
pub fn verify_content_digest(
    path: &str,
    bytes: &[u8],
    docker_content_digest: Option<&str>,
) -> Result<(), String> {
    
    // ← Les referrers utilisent le digest du manifest cible dans l'URL,
    // pas le hash du contenu de la réponse — exclure de la vérification
    if path.contains("/referrers/") {
        return Ok(());
    }
    if path.contains("/manifests/") {
        return Ok(());
    }

    // Cas 1 : digest dans le path (blobs et manifests par digest)
    if path.contains("sha256:") {
        if let Some(pos) = path.find("sha256:") {
            let digest_clean = path[pos..].trim_start_matches("sha256:");
            if digest_clean.len() == 64 && digest_clean.chars().all(|c| c.is_ascii_hexdigit()) {
                let computed = sha256_hex(bytes);
                if computed != digest_clean {
                    return Err(format!(
                        "Digest mismatch | attendu={} calculé={}",
                        digest_clean, computed
                    ));
                }
                println!("[CRYPTO] Digest vérifié OK (path): {}", digest_clean);
                return Ok(());
            }
        }
    }

    // Cas 2 : manifest par tag → vérifier via le header Docker-Content-Digest
    //Cas podman /manifest/latest (manifest list n'est pas demandé par digest)
    if let Some(header_digest) = docker_content_digest {
        let digest_clean = header_digest.trim_start_matches("sha256:");
        if digest_clean.len() == 64 && digest_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            let computed = sha256_hex(bytes);
            if computed != digest_clean {
                return Err(format!(
                    "Digest mismatch (header) | attendu={} calculé={}",
                    digest_clean, computed
                ));
            }
            println!("[CRYPTO] Digest vérifié OK (header): {}", digest_clean);
        }
    }

    Ok(())
}

/// Vérifie que la taille du blob ne dépasse pas la limite autorisée
/// Retourne Ok(()) si la taille est acceptable, Err(String) sinon
pub fn check_blob_size(path: &str, headers: &reqwest::header::HeaderMap) -> Result<(), String> {
    const MAX_BLOB_SIZE: u64 = 2 * 1024 * 1024 * 1024; // 2 GB

    if !path.contains("/blobs/") {
        return Ok(());
    }

    if let Some(content_length) = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if content_length > MAX_BLOB_SIZE {
            return Err(format!(
                "Blob trop volumineux | size={} max={}",
                content_length, MAX_BLOB_SIZE
            ));
        }
    }

    Ok(())
}

