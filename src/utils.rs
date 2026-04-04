// ===== Std =====
use std::fs;
use std::fs::create_dir_all;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use sqlx::PgPool;


// ===== Tokio =====
use tokio::sync::Mutex as TokioMutex;
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
    pool: &sqlx::PgPool,
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

            if let Some(racine) = &ctx.manifest_racine_digest {
                let fp = format!("{}/manifests/sha256/{}.json", base_dir, racine.value);
                let size = bytes.len() as i64;
                let pool2 = pool.clone();
                let registry2 = ctx.registry.clone();
                let repository2 = ctx.repository.clone();
                let digest2 = format!("sha256:{}", racine.value);
                tokio::spawn(async move {
                    let _ = crate::db::upsert_quarantine_file(
                        &pool2, &registry2, &repository2,
                        &digest2, "manifest", "sha256", &fp, size,
                    ).await;
                });
            }
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

        {
            let digest_value = parts[3].trim_start_matches("sha256:");
            let fp = format!("{}/manifests/sha256/{}.json", base_dir, digest_value);
            let size = bytes.len() as i64;
            let pool2 = pool.clone();
            let registry2 = ctx.registry.clone();
            let repository2 = ctx.repository.clone();
            let digest2 = format!("sha256:{}", digest_value);
            tokio::spawn(async move {
                let _ = crate::db::upsert_quarantine_file(
                    &pool2, &registry2, &repository2,
                    &digest2, "manifest", "sha256", &fp, size,
                ).await;
            });
        }
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

        {
            let digest_value = parts[3].trim_start_matches("sha256:");
            let fp = format!("{}/blobs/sha256/{}", base_dir, digest_value);
            let size = bytes.len() as i64;
            let pool2 = pool.clone();
            let registry2 = ctx.registry.clone();
            let repository2 = ctx.repository.clone();
            let digest2 = format!("sha256:{}", digest_value);
            tokio::spawn(async move {
                let _ = crate::db::upsert_quarantine_file(
                    &pool2, &registry2, &repository2,
                    &digest2, "blob", "sha256", &fp, size,
                ).await;
            });
        }
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
        
        {
            let digest_value = parts[3].trim_start_matches("sha256:");
            let fp = format!("{}/referrers/sha256/{}.json", base_dir, digest_value);
            let size = bytes.len() as i64;
            let pool2 = pool.clone();
            let registry2 = ctx.registry.clone();
            let repository2 = ctx.repository.clone();
            let digest2 = format!("sha256:{}", digest_value);
            tokio::spawn(async move {
                let _ = crate::db::upsert_quarantine_file(
                    &pool2, &registry2, &repository2,
                    &digest2, "referrer", "sha256", &fp, size,
                ).await;
            });
        }

    }
}

pub fn save_to_cache(
    path: &str,
    bytes: &[u8],
    ctx: &PullContext,
    pool: &sqlx::PgPool,
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
          
            if let Some(racine) = &ctx.manifest_racine_digest {
                let fp = format!("{}/manifests/sha256/{}.json", base_dir, racine.value);
                let size = bytes.len() as i64;
                let pool2 = pool.clone();
                let registry2 = ctx.registry.clone();
                let repository2 = ctx.repository.clone();
                let digest2 = format!("sha256:{}", racine.value);
                tokio::spawn(async move {
                    let _ = crate::db::upsert_cache_file(
                        &pool2, &registry2, &repository2,
                        &digest2, "manifest", "sha256", &fp, size,
                    ).await;
                });
            }
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

        {
            let digest_value = parts[3].trim_start_matches("sha256:");
            let fp = format!("{}/manifests/sha256/{}.json", base_dir, digest_value);
            let size = bytes.len() as i64;
            let pool2 = pool.clone();
            let registry2 = ctx.registry.clone();
            let repository2 = ctx.repository.clone();
            let digest2 = format!("sha256:{}", digest_value);
            tokio::spawn(async move {
                let _ = crate::db::upsert_cache_file(
                    &pool2, &registry2, &repository2,
                    &digest2, "manifest", "sha256", &fp, size,
                ).await;
            });
        }
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

        {
            let digest_value = parts[3].trim_start_matches("sha256:");
            let fp = format!("{}/blobs/sha256/{}", base_dir, digest_value);
            let size = bytes.len() as i64;
            let pool2 = pool.clone();
            let registry2 = ctx.registry.clone();
            let repository2 = ctx.repository.clone();
            let digest2 = format!("sha256:{}", digest_value);
            tokio::spawn(async move {
                let _ = crate::db::upsert_cache_file(
                    &pool2, &registry2, &repository2,
                    &digest2, "blob", "sha256", &fp, size,
                ).await;
            });
        }
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
        
        {
            let digest_value = parts[3].trim_start_matches("sha256:");
            let fp = format!("{}/referrers/sha256/{}.json", base_dir, digest_value);
            let size = bytes.len() as i64;
            let pool2 = pool.clone();
            let registry2 = ctx.registry.clone();
            let repository2 = ctx.repository.clone();
            let digest2 = format!("sha256:{}", digest_value);
            tokio::spawn(async move {
                let _ = crate::db::upsert_cache_file(
                    &pool2, &registry2, &repository2,
                    &digest2, "referrer", "sha256", &fp, size,
                ).await;
            });
        }
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
pub fn check_timout(pull_contexts: PullContextList, pool: &PgPool) {

    let pool_clone = pool.clone();

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let mut expired_contexts = Vec::new(); // On stocke les objets expirés ici

            let mut list = pull_contexts.lock().await;
            let before = list.len();

            list.retain(|ctx| {
                let alive = ctx.last_activity.elapsed() < CONTEXT_TIMEOUT;
                if !alive {
                    println!("[Timeout-Reach] Contexte expiré détecté | uuid={}", ctx.uuid);
                    expired_contexts.push(ctx.clone()); // On mémorise pour plus tard
                }
                alive
            });

            drop(list); // 🔓 On libère le lock AVANT les appels async


            for ctx in &expired_contexts {
                // L'UPDATE en base de données avec .await
                let _ = sqlx::query("UPDATE pulls SET decision_final = 'TIMEOUT', last_activity = NOW() WHERE uuid = $1::uuid")
                    .bind(ctx.uuid.to_string())
                    .execute(&pool_clone)
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("[DB] Erreur UPDATE pulls timeout: {}", e); 
                        Default::default()
                    });

                remove_ctx_digests_from_quarantine(ctx, &pool_clone);
                cleanup_tmp_for_uuid(&ctx.uuid);
            }

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

pub fn remove_ctx_digests_from_quarantine(ctx: &PullContext, pool: &sqlx::PgPool) {
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

        {
            let pool2 = pool.clone();
            let registry2 = ctx.registry.clone();
            let repository2 = ctx.repository.clone();
            let digest2 = format!("sha256:{}", digest.value);
            tokio::spawn(async move {
                let _ = crate::db::delete_quarantine_file(
                    &pool2, &registry2, &repository2, &digest2, "manifest",
                ).await;
            });
        }

        if Path::new(&blob).exists() {
            if let Err(e) = fs::remove_file(&blob) {
                eprintln!("[QUARANTINE CLEAN] erreur {}", e);
            } else {
                println!("[QUARANTINE CLEAN] supprimé {}", blob);
            }
        }

        {
            let pool2 = pool.clone();
            let registry2 = ctx.registry.clone();
            let repository2 = ctx.repository.clone();
            let digest2 = format!("sha256:{}", digest.value);
            tokio::spawn(async move {
                let _ = crate::db::delete_quarantine_file(
                    &pool2, &registry2, &repository2, &digest2, "blob",
                ).await;
            });
        }
        
        if Path::new(&referrers).exists() {
            if let Err(e) = fs::remove_file(&referrers) {
                eprintln!("[QUARANTINE CLEAN] erreur {}", e);
            } else {
                println!("[QUARANTINE CLEAN] supprimé {}", referrers);
            }
        }

        {
            let pool2 = pool.clone();
            let registry2 = ctx.registry.clone();
            let repository2 = ctx.repository.clone();
            let digest2 = format!("sha256:{}", digest.value);
            tokio::spawn(async move {
                let _ = crate::db::delete_quarantine_file(
                    &pool2, &registry2, &repository2, &digest2, "referrer",
                ).await;
            });
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

pub fn copy_ctx_from_quarantine_to_cache(ctx: &PullContext, pool: &sqlx::PgPool) {
    let registry = &ctx.registry;
    let repo = &ctx.repository;

    let base_q = format!("quarantaine/{}/{}/", registry, repo);
    let base_c = format!("cache/{}/{}/", registry, repo);

    // -------- MANIFESTS --------
    for digest in &ctx.manifest_digests {
        let q = format!("{}manifests/sha256/{}.json", base_q, digest.value);
        let c = format!("{}manifests/sha256/{}.json", base_c, digest.value);
        if copy_if_exists(&q, &c) {
            let pool2 = pool.clone();
            let registry2 = registry.to_string();
            let repository2 = repo.to_string();
            let digest2 = format!("sha256:{}", digest.value);
            let c2 = c.clone();
            let size = std::fs::metadata(&c2).map(|m| m.len() as i64).unwrap_or(0);
            tokio::spawn(async move {
                let _ = crate::db::upsert_cache_file(
                    &pool2, &registry2, &repository2,
                    &digest2, "manifest", "sha256", &c2, size,
                ).await;
            });
        }
    }

    // -------- BLOBS --------
    for digest in &ctx.blob_digests {
        let q = format!("{}blobs/sha256/{}", base_q, digest.value);
        let c = format!("{}blobs/sha256/{}", base_c, digest.value);
        if copy_if_exists(&q, &c) {
            let pool2 = pool.clone();
            let registry2 = registry.to_string();
            let repository2 = repo.to_string();
            let digest2 = format!("sha256:{}", digest.value);
            let c2 = c.clone();
            let size = std::fs::metadata(&c2).map(|m| m.len() as i64).unwrap_or(0);
            tokio::spawn(async move {
                let _ = crate::db::upsert_cache_file(
                    &pool2, &registry2, &repository2,
                    &digest2, "blob", "sha256", &c2, size,
                ).await;
            });
        }
    }

    // -------- REFERRERS --------
    for digest in &ctx.referrers_digests {
        let q = format!("{}referrers/sha256/{}.json", base_q, digest.value);
        let c = format!("{}referrers/sha256/{}.json", base_c, digest.value);
        if copy_if_exists(&q, &c) {
            let pool2 = pool.clone();
            let registry2 = registry.to_string();
            let repository2 = repo.to_string();
            let digest2 = format!("sha256:{}", digest.value);
            let c2 = c.clone();
            let size = std::fs::metadata(&c2).map(|m| m.len() as i64).unwrap_or(0);
            tokio::spawn(async move {
                let _ = crate::db::upsert_cache_file(
                    &pool2, &registry2, &repository2,
                    &digest2, "referrer", "sha256", &c2, size,
                ).await;
            });
        }
    }
}

fn copy_if_exists(src: &str, dst: &str) -> bool {
    let src_path = Path::new(src);
    if !src_path.exists() {
        return false;
    }

    let dst_path = Path::new(dst);

    if let Some(parent) = dst_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("[CACHE COPY] mkdir error {}", e);
            return false;
        }
    }

    if dst_path.exists() {
        return false; // déjà présent, pas besoin de réinsérer en BDD
    }

    match fs::copy(src_path, dst_path) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("[CACHE COPY] error {} -> {}", src, e);
            false
        }
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

/// Télécharge tous les digests attendus (manifests + blobs + referrers) en quarantaine.
/// Appelée après predict_digests, sur le GET du manifest arch-spécifique.
/// Idempotente : skip si le fichier est déjà présent.
pub async fn prefetch_expected_to_quarantine(
    client: &Client,
    ctx: &PullContext,
    pool: &sqlx::PgPool,
) -> Result<(), anyhow::Error> {
    use crate::registry_auth::RegistryClient;

    let token = RegistryClient::from_registry(&ctx.registry)
        .get_token(client, &ctx.repository)
        .await?;

    for digest in &ctx.digests_expected {
        let digest_str = format!("sha256:{}", digest.value);

        // --- Manifests : déjà téléchargés dans tmp/<uuid>/<value>.json par predict_digests ---
        let tmp_manifest = format!("tmp/{}/{}.json", ctx.uuid, digest.value);
        let q_manifest = format!(
            "quarantaine/{}/{}/manifests/sha256/{}.json",
            ctx.registry, ctx.repository, digest.value
        );

        if Path::new(&tmp_manifest).exists() && !Path::new(&q_manifest).exists() {
            match fs::read(&tmp_manifest) {
                Ok(bytes) => {
                    let fake_path = format!("/v2/{}/manifests/{}", ctx.repository, digest_str);
                    save_to_quarantine(&fake_path, &bytes, ctx, pool);
                    println!("[PREFETCH] Manifest copié en quarantaine: {}", digest.value);
                }
                Err(e) => eprintln!("[PREFETCH] Lecture tmp manifest {}: {}", digest.value, e),
            }
            continue;
        }

        if Path::new(&q_manifest).exists() {
            println!("[PREFETCH] Manifest déjà en quarantaine: {}", digest.value);
            continue;
        }

        // --- Blobs : téléchargement upstream ---
        let q_blob = format!(
            "quarantaine/{}/{}/blobs/sha256/{}",
            ctx.registry, ctx.repository, digest.value
        );

        if Path::new(&q_blob).exists() {
            println!("[PREFETCH] Blob déjà en quarantaine: {}", digest.value);
            continue;
        }

        let blob_url = format!(
            "https://{}/v2/{}/blobs/{}",
            ctx.registry, ctx.repository, digest_str
        );

        println!("[PREFETCH] Téléchargement blob: {}", digest.value);

        match client
            .get(&blob_url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                match r.bytes().await {
                    Ok(bytes) => {
                        // Vérification cryptographique avant stockage
                        let computed = sha256_hex(&bytes);
                        if computed != digest.value {
                            eprintln!(
                                "[PREFETCH] Digest mismatch blob {} | calculé={}",
                                digest.value, computed
                            );
                            continue; // on skip ce blob corrompu
                        }
                        let fake_path = format!("/v2/{}/blobs/{}", ctx.repository, digest_str);
                        save_to_quarantine(&fake_path, &bytes, ctx, pool);
                        println!("[PREFETCH] Blob stocké en quarantaine: {}", digest.value);
                    }
                    Err(e) => eprintln!("[PREFETCH] Lecture bytes blob {}: {}", digest.value, e),
                }
            }
            Ok(r) => eprintln!("[PREFETCH] Status {} pour blob {}", r.status(), digest.value),
            Err(e) => eprintln!("[PREFETCH] Erreur réseau blob {}: {}", digest.value, e),
        }
    }

    Ok(())
}

/// Sert un digest depuis la quarantaine, après scan ALLOW.
pub fn serve_from_quarantine(path: &str, ctx: &PullContext) -> Option<Response<Body>> {
    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();
    if parts.len() < 4 {
        return None;
    }

    let base_dir = format!("quarantaine/{}/{}", ctx.registry, ctx.repository);

    // MANIFEST par digest
    if parts[2] == "manifests" && parts[3].starts_with("sha256:") {
        let digest = parts[3].trim_start_matches("sha256:");
        let file = format!("{}/manifests/sha256/{}.json", base_dir, digest);
        if let Ok(data) = fs::read(&file) {
            if data.len() < 20 {
                return None;
            }
            let content_type = serde_json::from_slice::<serde_json::Value>(&data)
                .ok()
                .and_then(|v| {
                    v.get("mediaType")
                        .and_then(|m| m.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| "application/vnd.oci.image.manifest.v1+json".to_string());
            let real_digest = sha256_hex(&data);
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", content_type)
                    .header("Docker-Content-Digest", format!("sha256:{real_digest}"))
                    .header("Content-Length", data.len())
                    .body(Body::from(data))
                    .unwrap(),
            );
        }
    }

    // BLOB
    if parts[2] == "blobs" && parts[3].starts_with("sha256:") {
        let digest = parts[3].trim_start_matches("sha256:");
        let file = format!("{}/blobs/sha256/{}", base_dir, digest);
        if let Ok(data) = fs::read(&file) {
            let real_digest = sha256_hex(&data);
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/octet-stream")
                    .header("Docker-Content-Digest", format!("sha256:{real_digest}"))
                    .header("Content-Length", data.len())
                    .body(Body::from(data))
                    .unwrap(),
            );
        }
    }

    // REFERRERS
    if parts[2] == "referrers" && parts[3].starts_with("sha256:") {
        let digest = parts[3].trim_start_matches("sha256:");
        let file = format!("{}/referrers/sha256/{}.json", base_dir, digest);
        if let Ok(data) = fs::read(&file) {
            if data.len() < 20 {
                return None;
            }
            return Some(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/vnd.oci.image.index.v1+json")
                    .header("Content-Length", data.len())
                    .body(Body::from(data))
                    .unwrap(),
            );
        }
    }

    None
}

/// Valide la conformité structurelle d'une manifest-list OCI/Docker.
/// Vérifie : JSON valide, champ manifests présent, chaque entrée a digest + platform.
pub fn validate_manifest_list(bytes: &[u8]) -> Result<(), String> {
    let v: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| format!("JSON invalide: {}", e))?;

    let manifests = v
        .get("manifests")
        .and_then(|m| m.as_array())
        .ok_or("Champ 'manifests' absent ou invalide")?;

    if manifests.is_empty() {
        return Err("Manifest-list vide".to_string());
    }

    for (i, m) in manifests.iter().enumerate() {
        // digest obligatoire et format sha256:hex64
        let digest = m
            .get("digest")
            .and_then(|d| d.as_str())
            .ok_or_else(|| format!("Entrée {}: digest manquant", i))?;

        if !digest.starts_with("sha256:") || digest.len() != 71 {
            return Err(format!("Entrée {}: digest mal formé: {}", i, digest));
        }

        let hex_part = &digest[7..];
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("Entrée {}: digest non-hexadécimal", i));
        }

        // platform obligatoire
        let platform = m
            .get("platform")
            .ok_or_else(|| format!("Entrée {}: platform manquant", i))?;

        platform
            .get("os")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("Entrée {}: platform.os manquant", i))?;

        platform
            .get("architecture")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("Entrée {}: platform.architecture manquant", i))?;
    }

    Ok(())
}
/// Vérifie que tous les digests attendus (digests_expected) sont présents
/// dans le cache disque avant de servir depuis celui-ci.
/// Retourne true seulement si chaque digest est trouvé (manifest ou blob).
/// Si digests_expected est vide ou contient ≤ 1 élément (pas encore prédit),
/// retourne false pour laisser passer le flux classique.
pub fn all_expected_in_cache(ctx: &PullContext) -> bool {
    if ctx.digests_expected.len() <= 1 {
        return false;
    }

    let base = format!("cache/{}/{}", ctx.registry, ctx.repository);

    for digest in &ctx.digests_expected {
        let manifest_path = format!(
            "{}/manifests/sha256/{}.json",
            base, digest.value
        );
        let blob_path = format!(
            "{}/blobs/sha256/{}",
            base, digest.value
        );

        let in_cache = Path::new(&manifest_path).exists()
            || Path::new(&blob_path).exists();

        if !in_cache {
            println!(
                "[CACHE GUARD] Digest manquant en cache: {} | image incomplète, fallback upstream",
                digest.value
            );
            return false;
        }
    }

    println!(
        "[CACHE GUARD] Tous les {} digests attendus présents en cache",
        ctx.digests_expected.len()
    );
    true
}

