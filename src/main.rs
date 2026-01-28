use std::{convert::Infallible, fs::File, io::BufReader, sync::Arc};

use anyhow::Result;
use hyper::{
    body::to_bytes,
    service::service_fn,
    Body, Method, Request, Response, StatusCode,
};
use hyper::server::conn::Http;
use reqwest::Client;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use std::fs::{self, create_dir_all};
use sha2::{Digest as Sha2Digest, Sha256};


use std::collections::{HashMap, HashSet};
use std::sync::{Mutex};//blocage de concurence -> a changer en mutex tokio
use tokio::sync::Mutex as TokioMutex;

use serde_json::Value;

use std::process::Command;
use std::fs::OpenOptions;
use std::io::Write;

use uuid::Uuid;
use tokio::time::{sleep, Duration};

use serde::{Serialize, Deserialize};

use std::time::Instant;//pour le timeout des pull context 2

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::future::BoxFuture;
use futures::FutureExt; // pour .boxed()





#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Digest {
    algorithm: String, // ex: "sha256"
    value: String,     // hex
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PullContext 
{
    uuid: Uuid,
    ip_client: String,
    registry: String, //ex: "registry-1.docker.io"
    repository: String, //ex: "library/ubuntu"
    tag: String,

    manifest_digests: Vec<Digest>,
    blob_digests: Vec<Digest>,
    referrers_digests: Vec<Digest>,

    manifest_racine_digest: Option<Digest>,
    digests_possible: Vec<Digest>,
    digests_expected: Vec<Digest>,

    os: String,  // ex: "linux"
    arch: String, // ex: "amd64"

    #[serde(skip_serializing, skip_deserializing, default = "Instant::now")]
    last_activity: Instant,
    pull_completed: bool,
}


// Erreurs possibles lors de la récupération du contexte PullContext2
#[derive(Debug)]
enum PullContextError {
    InvalidPath,
    MissingDigestOrTag,
    ContextMismatch,
    DigestNotAllowed,
    BlockingFromTheScanner,
    ExpiredContext,
    StorageError,
}

#[derive(Debug, PartialEq)]
enum DigestVerificationState {
    InProgress,
    Completed,
}



//Structures pour predict_digests

#[derive(Debug, Deserialize)]
struct ManifestList {
    manifests: Vec<ManifestDescriptor>,
}

#[derive(Debug, Deserialize)]
struct ManifestDescriptor {
    digest: String,
    mediaType: String,
    platform: Platform,
    #[serde(default)]
    annotations: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct Platform {
    os: String,
    architecture: String,
}




struct ImageState {
    blobs_expected: HashSet<String>,  // tous les blobs attendus pour l'image
    blobs_downloaded: HashSet<String> // blobs déjà téléchargés
}

type PullContextList = Arc<TokioMutex<Vec<PullContext>>>;

// Définir le timeout désiré (ex : 30 secondes)
const CONTEXT_TIMEOUT: Duration = Duration::from_secs(30);

static UPSTREAM: &str = "https://registry-1.docker.io";

/// 🔍 Analyseur de digest Docker 
/// ex: registery douteux
impl Digest {
    fn as_str(&self) -> String {
        format!("{}:{}", self.algorithm, self.value)
    }
}

impl PullContext {
    fn new(uuid: Uuid, ip_client: String, registry: String, repository: String, tag: String) -> Self {
        Self {
            uuid,
            ip_client,
            registry,
            repository,
            tag,
            manifest_digests: Vec::new(),
            blob_digests: Vec::new(),
            referrers_digests: Vec::new(),
            digests_possible: Vec::new(),
            digests_expected: Vec::new(),
            manifest_racine_digest: None,
            last_activity: Instant::now(),
            os: "unknown".to_string(),
            arch: "unknown".to_string(),
            pull_completed: false,
        }

    }
}


/// 🔐 Politique de sécurité
fn is_allowed() -> bool {
    true
}

/// 🔑 SHA256 réel (Docker compliant)
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// 💾 Sauvegarde en quarantaine
fn save_to_quarantine(
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
    }
}




/// 📦 Sert depuis le cache qui contient les images préalablement scannées
fn try_serve_from_cache(
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


fn manifest_list_has_linux_amd64(bytes: &[u8]) -> bool {
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

/// 🔹 Partie HEAD pour récupérer le manifest et stocker le digest racine
/// 🔹 Récupère uniquement le digest racine d’un tag/manifest, sans stocker le manifest
async fn digest_process_for_head(
    client: &Client,
    registry: &str,
    repository: &str,
    tag: &str,
) -> Result<Digest, anyhow::Error> {
    println!("[HEAD] Récupération du digest racine pour {}/{}", repository, tag);

    // 1️⃣ Récupération du token Docker
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

    println!("[HEAD] Token Docker récupéré");

    // 2️⃣ Télécharger le manifest associé au tag
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

        
    let headers = manifest_resp.headers().clone();

    // 🔍 LOG RATE-LIMIT
    let headers = manifest_resp.headers();

    if let Some(limit) = headers.get("ratelimit-limit") {
        println!(
            "[RATE-LIMIT] limit = {}",
            limit.to_str().unwrap_or("invalid")
        );
    }

    if let Some(remaining) = headers.get("ratelimit-remaining") {
        let remaining_str = remaining.to_str().unwrap_or("invalid");
        println!("[RATE-LIMIT] remaining = {}", remaining_str);

        if remaining_str.starts_with('0') {
            anyhow::bail!("Docker Hub rate-limit atteint (remaining=0)");
        }
    }

    if let Some(src) = headers.get("docker-ratelimit-source") {
        println!(
            "[RATE-LIMIT] source = {}",
            src.to_str().unwrap_or("invalid")
        );
    }


    // 3️⃣ Extraire le digest racine depuis l'en-tête
    // /!\ Attention le Header docker-content-digest n'est pas toujours envoyé /!\
    let manifest_digest = headers
        .get("Docker-Content-Digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("Docker-Content-Digest manquant"))?;

    let digest_clean = manifest_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("Digest inattendu"))?;

    let racine_digest = Digest {
        algorithm: "sha256".to_string(),
        value: digest_clean.to_string(),
    };

    println!("[HEAD] Digest racine prêt: {}", digest_clean);

    Ok(racine_digest)
}

async fn store_digest(
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
fn fetch_and_process_manifest<'a>(
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
            let url = format!("https://{}/v2/{}/manifests/{}", registry, repository, digest);
            let resp = client.get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Accept", "application/vnd.docker.distribution.manifest.v2+json")
                .send()
                .await?;
            let content = resp.bytes().await?;
            fs::write(&path, &content)?;
            println!("[PREDICT] Stored manifest blob: {}", path);
        }

        // Lire le manifest
        let content = fs::read(&path)?;
        let json: serde_json::Value = serde_json::from_slice(&content)?;

        // Ajouter digest du manifest lui-même
        if !digests.iter().any(|d| d.value == digest_clean) {
            digests.push(Digest { algorithm: "sha256".into(), value: digest_clean.into() });
        }

        // Si manifest list → récursion (via BoxFuture)
        if json.get("manifests").is_some() {
            let manifest_list: ManifestList = serde_json::from_value(json)?;
            for m in manifest_list.manifests {
                fetch_and_process_manifest(client, uuid, registry, repository, &m.digest, token, digests).await?;
            }
        } else {
            // Sinon, config + layers
            if let Some(config) = json.get("config").and_then(|c| c.get("digest")).and_then(|d| d.as_str()) {
                let c = config.strip_prefix("sha256:").unwrap_or(config);
                digests.push(Digest { algorithm: "sha256".into(), value: c.into() });
            }
            if let Some(layers) = json.get("layers").and_then(|l| l.as_array()) {
                for layer in layers {
                    if let Some(d) = layer.get("digest").and_then(|v| v.as_str()) {
                        let l = d.strip_prefix("sha256:").unwrap_or(d);
                        digests.push(Digest { algorithm: "sha256".into(), value: l.into() });
                    }
                }
            }
        }

        Ok(())
    }.boxed()
}

async fn predict_digests( //Doit etre appellée lors du HEAD dans get_pull_context
    client: &Client,
    uuid: &Uuid,
    registry: &str,
    repository: &str,
    tag: &str,
    os: &str,
    arch: &str,
    manifest_racine_digest: &Digest,
) -> Result<Vec<Digest>> {


    println!("LOG - MANIFEST RACINE DIGEST : {}", manifest_racine_digest.value);
    println!(
        "[PREDICT] Using provided manifest digest for {}:{}, target={}/{}",
        repository, tag, os, arch
    );

    // ============================
    // 1️⃣ Récupération du token
    // ============================
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

    // ============================
    // 2️⃣ Préparer le stockage temporaire
    // ============================
    let digest_clean = manifest_racine_digest.value.strip_prefix("sha256:")
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
            .header("Accept", "application/vnd.docker.distribution.manifest.list.v2+json,\
                     application/vnd.docker.distribution.manifest.v2+json")
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
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;

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

    if let Some(manifests) = json.get("manifests") {
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

                let digest_clean = m.digest
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
                        registry,
                        repository,
                        m.digest
                    );

                    let resp = client
                        .get(&manifest_url)
                        .header("Authorization", format!("Bearer {}", token))
                        .header(
                            "Accept",
                            "application/vnd.docker.distribution.manifest.v2+json",
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

                            let digest_clean = m.digest
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
                                    registry,
                                    repository,
                                    m.digest
                                );

                                let resp = client
                                    .get(&manifest_url)
                                    .header("Authorization", format!("Bearer {}", token))
                                    .header(
                                        "Accept",
                                        "application/vnd.docker.distribution.manifest.v2+json",
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

    let manifest_list_digest_clean = manifest_racine_digest.value
        .strip_prefix("sha256:")
        .unwrap_or(&manifest_racine_digest.value)
        .to_string();


    // Collecter les digests des manifests téléchargés (arch-specific + unknown)
    let mut manifests_to_process: Vec<String> = digests.iter()
        .filter(|d| d.value != manifest_list_digest_clean) // exclure le manifest list racine
        .map(|d| format!("sha256:{}", d.value))
        .collect();

    // Parcourir chaque manifest pour extraire config + layers
    for digest in manifests_to_process {
        fetch_and_process_manifest(&client, uuid, registry, repository, &digest, token, &mut digests).await?;
    }

    //affiche les digests prédites par predict_digests
    println!("[PREDICT] Collected digests:");
    for d in &digests {
        println!(" - {}:{}", d.algorithm, d.value);
    }


    Ok(digests)

}




/// 🔄 Récupération ou création du contexte PullContext
async fn get_pull_context(
    req: &Request<Body>,
    parts: &[&str],
    client_ip: &str,
    pull_contexts: &PullContextList,
    client: &Client, 
)-> Result<Option<Uuid>, PullContextError> //Retourne soit l'uuid du contexte trouvé (cas success) soit une erreur PullContextError
{

    // 🔹 Construire les variables principales à partir de parts
    let registry = "registry-1.docker.io".to_string(); // Par défaut pour Docker Hub

    // 🔹 Déterminer le type de ressource et son index
    let (resource_type, idx) = if let Some(i) = parts.iter().position(|p| *p == "manifests") {
        ("manifests", i)
    } else if let Some(i) = parts.iter().position(|p| *p == "blobs") {
        ("blobs", i)
    } else if let Some(i) = parts.iter().position(|p| *p == "referrers") {
        ("referrers", i)
    } else {
        println!("[PullContext] Type de ressource inconnu, aucun traitement possible");
        return Err(PullContextError::InvalidPath);
    };

    // 🔹 Vérifier que l'index est valide pour accéder à la valeur suivante (digest ou tag)
    if idx + 1 >= parts.len() {
        println!("[PullContext] Path invalide, digest ou tag manquant");
        return Err(PullContextError::InvalidPath);
    }

    // 🔹 Extraire la valeur (digest ou tag)
    let value = parts[idx + 1];

    /*println!(
        "[PullContext] Resource type={}, index={}, value={}",
        resource_type, idx, value
    );*/


    // Extraire le repository
    let repository = parts[..idx].join("/");

    let tag_ou_digest = parts[parts.len() - 1];
    let ip_client = client_ip.to_string();

    /*println!(
        "[PullContext] registry={}, repository={}, tag/digest={}, client_ip={}\n",
        registry, repository, tag_ou_digest, ip_client
    );*/

    // 🔹 HEAD → création d’un nouveau contexte pour un tag
    if req.method() == Method::HEAD 
    {
        // Récupérer l’index de "manifests"

        // Vérifier que l'index trouvé est valide pour accéder au digest ou tag
        if idx + 1 >= parts.len() {
            println!("[PullContext] Path invalide, digest ou tag manquant");
            return Err(PullContextError::MissingDigestOrTag);
        }

        // Extraire la valeur suivante : digest ou tag selon le type
        let value = parts[idx + 1];
        /*println!(
            "[PullContext] Resource type={}, index={}, value={}",
            resource_type, idx, value
        );*/


        let digest_cmd = format!("{}:{}", repository, tag_ou_digest);
        let mut manifest_racine_digest: Option<String> = None;


        // 🔹 Appeler digest_process_for_head pour récupérer le digest racine

        let manifest_racine_digest = digest_process_for_head(
            client,
            &registry,
            &repository,
            &tag_ou_digest,
        )
        .await
        .map_err(|e| {
            eprintln!("[PullContext] Erreur lors de digest_process_for_head: {:?}", e);
            PullContextError::MissingDigestOrTag
        })?;


        let digest_clean = manifest_racine_digest.value.trim_start_matches("sha256:").to_string();


        println!("[PullContext] Digest racine récupéré: {}", manifest_racine_digest.value);

        // 🔹 Construction de l’UUID déterministe (sans le tag, mais avec digest possible)
        let uuid_input = format!(
            "{}|{}|{}|{}",
            registry,
            repository,
            &manifest_racine_digest.value,
            ip_client
        );

        let uuid = Uuid::new_v5(&Uuid::NAMESPACE_URL, uuid_input.as_bytes());

        // 🔹 Vérifier si l'UUID existe déjà
        let mut list = pull_contexts.lock().await;
        if list.iter().any(|c| c.uuid == uuid) {
            println!("[PullContext] UUID déjà présent, pas de création d'un nouveau contexte");

            //Met a jour l'activité pour le timer
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == uuid) {
                ctx.last_activity = Instant::now();
            }

            return Ok(Some(uuid));//retourner l'uuid existant

        }
    
        // 🔹 Création du contexte PullContext
        let mut ctx = PullContext::new(
            uuid,
            ip_client.clone(),
            registry.clone(),
            repository.clone(),
            tag_ou_digest.to_string(),//ici c'est le tag
        );

        // 🔹 Après création du PullContext et mise à jour du digest racine
        //Si le digest racine n'est pas déjà dans digests_possible, l'ajouter
        ctx.manifest_racine_digest = Some(manifest_racine_digest.clone());
        if !ctx.digests_possible.contains(&manifest_racine_digest) {
            ctx.digests_possible.push(manifest_racine_digest.clone());
        }

        ctx.manifest_racine_digest = Some(manifest_racine_digest.clone());
        if !ctx.digests_expected.contains(&manifest_racine_digest) {
            ctx.digests_expected.push(manifest_racine_digest.clone());
        }

        // 🔹 Stockage du manifest dans tmp/<uuid>/
        let _ = store_digest(client, &registry, &repository, &tag_ou_digest, &uuid)
            .await
            .map_err(|e| {
                eprintln!("[PullContext] Erreur lors de store_digest: {:?}", e);
                PullContextError::StorageError
            })?;

        //Ajout du manifest racine digest au contexte
        ctx.manifest_racine_digest = Some(manifest_racine_digest.clone());



        // 🔹 Récupération de tout les digests pour le manifest list
         
        let token = get_dockerhub_token(&client, &repository)
            .await
            .map_err(|_| PullContextError::MissingDigestOrTag)?;

        let manifest_url = format!(
            "https://registry-1.docker.io/v2/{}/manifests/sha256:{}",
            repository,
            digest_clean
        );

        let resp = client
            .get(&manifest_url)
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.list.v2+json",
            )
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| PullContextError::MissingDigestOrTag)?;

        let manifest_json: serde_json::Value = resp
            .json()
            .await
            .map_err(|_| PullContextError::MissingDigestOrTag)?;

        if let Some(manifests) = manifest_json.get("manifests").and_then(|m| m.as_array()) {
            for m in manifests {
                if let Some(digest) = m.get("digest").and_then(|d| d.as_str()) {
                    let digest = Digest {
                        algorithm: "sha256".to_string(),
                        value: digest.trim_start_matches("sha256:").to_string(),
                    };

                    if !ctx.digests_possible.contains(&digest) {
                        ctx.digests_possible.push(digest);
                    }
                }
            }
        }

        //mise a jour de l'activité pour le timer (nouveau contexte)
        ctx.last_activity = Instant::now();

        list.push(ctx.clone());

        //[Appel API] : déclencher scan de haut niveau

        //Proxy -> API -> Scanner

        //Proxy <- API <- Scanner

        //Si accepté (pour le moment) on retourne l'uuid
        if is_allowed() == true || 1==1
        {
            return Ok(Some(uuid));
        }
        //Si refusé
        else 
        {
            //Ajout a la blacklist
            if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "blacklist") {
                eprintln!("[BLACKLIST ERROR] {}", e);     
            }

            //Supprimer dossier temporaire
            cleanup_tmp_for_uuid(&ctx.uuid);

            // 🔹 Libérer le contexte PullContext
            list.retain(|c| c.uuid != ctx.uuid);

            //Retourne une erreure
            return Err(PullContextError::BlockingFromTheScanner);
        }
        //Gèrer par la suite le cas ou l'orchestre renvoie un ALLOW definitif -> Ajout dans whitelist

    }


    // 🔹 GET → vérifier un digest existant
    else if req.method() == Method::GET 
    {

        // Extraire le digest de la requête
        let digest_str = parts[idx + 1];
        if !digest_str.starts_with("sha256:") {
            return Err(PullContextError::DigestNotAllowed);
        }
        let digest_value = digest_str.trim_start_matches("sha256:").to_string();
        
        // 🔹 Rechercher le contexte correspondant et vérifier le digest
        let mut list = pull_contexts.lock().await;
        for ctx in list.iter_mut() 
        {
            //Verifier si le contexte correspond au client ip, registry, repository et digest possible
            if ctx.ip_client == ip_client
                && ctx.registry == registry
                && ctx.repository == repository
                && (
                    // Tant qu’on n’a qu’un seul digest attendu → mode tolérant
                    (ctx.digests_expected.len() <= 1
                        && ctx.digests_possible.iter().any(|d| d.value == digest_value))
                    ||
                    // Dès qu’on a plusieurs digests attendus → mode strict
                    (ctx.digests_expected.len() > 1
                        && ctx.digests_expected.iter().any(|d| d.value == digest_value))
                )
            {

                println!("[PullContext] Correspondance trouvée pour le digest GET | uuid={}", ctx.uuid);

                //Mise a jour de l'activité pour le timeout
                ctx.last_activity = Instant::now();


                // Déterminer dans quel vecteur stocker le digest selon le type de ressource
                let digest_struct = Digest {
                    algorithm: "sha256".to_string(),
                    value: digest_value.clone(),
                };

                // Ajouter le digest dans le vecteur approprié en garantissant l'unicité
                match resource_type {
                    "manifests" => {
                        if !ctx.manifest_digests.contains(&digest_struct) {
                            ctx.manifest_digests.push(digest_struct.clone());
                            println!("[PullContext] Digest ajouté à manifest_digests: {}", digest_struct.as_str());
                        }
                    }
                    "blobs" => {
                        if !ctx.blob_digests.contains(&digest_struct) {
                            ctx.blob_digests.push(digest_struct.clone());
                            println!("[PullContext] Digest ajouté à blob_digests: {}", digest_struct.as_str());
                        }
                    }
                    "referrers" => {
                        if !ctx.referrers_digests.contains(&digest_struct) {
                            ctx.referrers_digests.push(digest_struct.clone());
                            println!("[PullContext] Digest ajouté à referrers_digests: {}", digest_struct.as_str());
                        }
                    }
                    _ => {
                        println!("[PullContext] Type de ressource inconnu pour stockage des digests");
                    }
                }



                //si le digest racine est defini
                if let Some(racine) = &ctx.manifest_racine_digest
                {
                    //si le digest de la requete n'est pas le digest racine -> ajouter les digests contenus dans le manifest demandé
                    if racine.value != digest_value {

                        let manifest_path = format!(
                            "tmp/{}/{}.json",
                            ctx.uuid,
                            racine.value
                        );

                        
                        let manifest_bytes = std::fs::read(&manifest_path)
                            .map_err(|_| PullContextError::StorageError)?;

                        let manifest_racine_json: serde_json::Value =
                            serde_json::from_slice(&manifest_bytes)
                                .map_err(|_| PullContextError::StorageError)?;

                        // Récupérer OS/ARCH si non défini ou inconnu
                        if ctx.os.is_empty() || ctx.arch.is_empty() || ctx.os == "unknown" || ctx.arch == "unknown" {
                            // Récupérer OS/ARCH pour le digest GET
                            let (os, arch) = get_os_arch_for_digest(&manifest_racine_json, &digest_value);

                            // Stocker dans PullContext
                            ctx.os = os;
                            ctx.arch = arch;

                            println!(
                                "[GET] Digest {} → OS={}, ARCH={}",
                                digest_value, ctx.os, ctx.arch
                            );

                            // Utilisation de predict_digests avec OS/ARCH specifique 
                            let manifest_racine_digest = ctx.manifest_racine_digest.as_ref().unwrap();

                            //On recupère les exacts digests attendus (ni plus ni moin)
                            let predicted_digests = match predict_digests(
                                &client,            // reqwest::Client
                                &ctx.uuid,          // UUID du contexte
                                &registry,          // "registry-1.docker.io"
                                &repository,        // ex: "library/ubuntu"
                                &tag_ou_digest,     // tag ou digest
                                &ctx.os,            // ✅ OS dynamique
                                &ctx.arch,          // ✅ ARCH dynamique
                                manifest_racine_digest,
                            )
                            .await
                            {
                                Ok(d) => d,
                                Err(e) => {
                                    eprintln!("[PullContext] predict_digests failed: {:?}", e);
                                    return Err(PullContextError::StorageError);
                                }
                            };

                            // Mettre à jour les digests attendus
                            ctx.digests_expected = predicted_digests;

                            //println!("[PullContext] Digests expected : {:?}", ctx.digests_expected);
                        }



                    }
                    else {
                        //cas ou le digest GET est le digest racine (normal, ne rien faire)
                        return Ok(Some(ctx.uuid));
                    }   
                } 
                //si le digest racine n'est pas defini  
                else 
                {
                    println!("[PullContext] Aucun digest racine défini pour ce contexte → bloqué");
                    return Err(PullContextError::DigestNotAllowed);
                }

                // Ici tu es sûr :
                // - bon client
                // - bon registry
                // - bon repository
                // - bon digest GET existant
                return Ok(Some(ctx.uuid));
            }
        }
        // Aucun contexte trouvé en parcourant la liste
        println!("[PullContext] Aucun contexte trouvé pour le digest GET demandé");
        return Err(PullContextError::ContextMismatch);
    }

    //Methode ne correspond pas a HEAD ou GET
    return Err(PullContextError::ContextMismatch);
}


fn verify_downloaded_digests(ctx: &PullContext) -> Result<DigestVerificationState, PullContextError> {
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

    // 🔥 CAS 1 — digest inattendu → ERREUR
    let extra: HashSet<_> = downloaded.difference(&expected).collect();
    if !extra.is_empty() {
        eprintln!("[VERIFY] Digest(s) inattendu(s) détecté(s):");
        for d in extra.iter() {
            eprintln!("  - {}", d);
        }
        return Err(PullContextError::DigestNotAllowed);
    }

    // 🔹 CAS 2 — tout est téléchargé → FIN DU PULL
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

    // 🔹 CAS 3 — pull encore en cours (digests manquants)
    let missing: HashSet<_> = expected.difference(&downloaded).collect();
    if !missing.is_empty() {
        println!("[VERIFY] Pull en cours : digests manquants:");
        for d in missing.iter() {
            println!("  - {}", d);
        }
    }

    Ok(DigestVerificationState::InProgress)
}



async fn handle(req: Request<Body>, client: Client, pull_contexts: PullContextList, ) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let headers = req.headers().clone();
    println!("============================================================");
    println!("[REQ] {} {}", method, path);
    // Découper le path pour extraire repo, tag, digest
    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();

    // Ping registry
    if path == "/v2/" {
        return Response::builder().status(StatusCode::OK).body(Body::empty()).unwrap();
    }

    if req.method() == Method::PUT {
        println!("[PUT] Requête PUT non supportée");
    }
    if req.method() == Method::POST {
        println!("[POST] Requête POST non supportée");
    }
    
    //recupère l'ip du client 
    let client_ip = req
    .extensions()
    .get::<std::net::SocketAddr>()
    .unwrap()
    .ip()
    .to_string();

    //recupère le contexte du pull en cours
    //let context = get_pull_context(&req, &parts, &client_ip, &pull_map);
    let context_uuid = match get_pull_context(&req, &parts, &client_ip, &pull_contexts, &client).await {
        Ok(Some(uuid)) => {
            println!("[Main] Contexte trouvé / créé avec UUID: {}", uuid);
            uuid // tu peux continuer à utiliser uuid
        },
        Ok(None) => {
            eprintln!("[Main] Pas d'UUID retourné → pull échoué");
            
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("PullContext non trouvé"))
                .unwrap();
        },
        Err(PullContextError::DigestNotAllowed) => {
            eprintln!("[Main] Digest not allowed");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Erreur PullContext"))
                .unwrap();
        }
        Err(PullContextError::BlockingFromTheScanner) => {
            eprintln!("[Main] Pull bloqué et image blacklisté car scan de haut niveau n'est pas passé");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Erreur PullContext"))
                .unwrap();
        }
        Err(e) => {
            eprintln!("[Main] Erreur lors de la récupération du contexte: {:?}", e);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Erreur PullContext"))
                .unwrap();
        }

        //gèrer l'erreur du cas ou le scan de haut niveau ne passe pas 
        //Renvoyer erreur + blacklist

    };

    //println!("Test1");
     
    //On check whitelist et blacklist qui sur les HEAD
    if req.method() == Method::HEAD
    {  
        // Vérifier la blacklist
        if let Some(resp) = check_manifest_in_list(context_uuid, &pull_contexts, method.clone(), "blacklist").await {
            return resp; // si dans blacklist, on renvoie la réponse FORBIDDEN
        }
        //Verifier dans la whitelist
        if let Some(resp) = check_manifest_in_list(context_uuid, &pull_contexts, method.clone(), "whitelist").await {
            return resp; // si dans whitelist, on renvoie OK 
        }
    }

    // Vérifier le cache avant d'aller en upstream
    //si le digest est present dans le cache on retourne la réponse a partir du cache
    {
        if req.method() == Method::GET 
        {
            let list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                if let Some(resp) = try_serve_from_cache(&req, ctx) {//Si le digest est dans le cache on retourne a partir du digest stocké
                    println!("[CACHE] Digest trouvé en cache");

                    //Appeler la fonction verify_downloaded_digests pour libèrer le contexte au bon moment 

                    return resp;
                }
                else 
                {
                    println!("[CACHE] Digest pas trouvée dans le cache -> GET upstream -> quarantine ->  Scan");
                }

            }
        }
    }


    // Construire l'URL upstream
    let upstream_url = format!(
        "{}{}",
        UPSTREAM,
        uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
    );
    //println!("[UPSTREAM FETCH FOR CACHE] → {}", upstream_url);

    // Lire le corps de la requête
    let body = to_bytes(req.into_body()).await.unwrap_or_default();

    // Préparer la requête vers l'upstream
    let mut rb = client.request(method.clone(), &upstream_url);
    for (k, v) in headers.iter() {
        if !matches!(k.as_str(), "host" | "connection") {
            rb = rb.header(k, v);
        }
    }
    if !body.is_empty() {
        rb = rb.body(body);
    }

    // Envoyer la requête upstream
    let upstream = match rb.send().await {
        Ok(r) => r,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("DockerHub unreachable"))
                .unwrap();
        }
    };

    // Extraire status et headers avant de consommer le body
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let bytes = upstream.bytes().await.unwrap_or_default(); // consomme `upstream`

    // Vérification architecture
    //On regarde si l'architecture linux/amd64 est présente dans la manifest list
    if method == Method::GET
        && path.contains("/manifests/")
        && !bytes.is_empty()
    {
        // Si c'est une manifest list (présence du champ "manifests")
        let is_manifest_list = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("manifests").cloned())
            .is_some();

        //blocage si linux/amd64 pas présent
        if is_manifest_list && !manifest_list_has_linux_amd64(&bytes) 
        {
            //println!("[ARCH CHECK] Manifest list incompatible linux/amd64");

            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from(
                    "No matching manifest for linux/amd64"
                ))
                .unwrap();
        }
    }



    // 🔹 Sauvegarde en quarantaine pour analyse
    if method == Method::GET && !bytes.is_empty() 
    {
        if path.contains("/manifests/")
            || path.contains("/blobs/")
            || path.contains("/referrers/")
        {
            let list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                save_to_quarantine(&path, &bytes, ctx);
            }
        }
    }



    // 🔹 Vérification finale des digests téléchargés
    if method == Method::GET
    {
        let mut list = pull_contexts.lock().await;
        if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {

            // On ne déclenche le "Pull COMPLET" que si la requête est un GET pour laisser passer les HEAD
            // et que digests_expected contient plus d'un élément
            if method == Method::GET && ctx.digests_expected.len() > 1{

                //On compare les digests expected et ceux réellement téléchargés
                match verify_downloaded_digests(ctx) {
                    Ok(DigestVerificationState::InProgress) => {
                        // pull normal, on laisse continuer
                    }
                    Ok(DigestVerificationState::Completed) => 
                    {
                        println!("[PullContext] Pull COMPLET pour uuid={}", ctx.uuid);
                        //Mettre la variable scan_completed a true
                        ctx.pull_completed = true;


                        //[Appel API] : déclencher scan final avec tout les digests 

                        //Proxy -> API -> Scanner

                        //Proxy <- API <- Scanner

                        //Si Image OK 
                        if is_allowed() == true
                        {
                            //Ajout de l'image a la whitelist
                            if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "whitelist") {
                                eprintln!("[WHITELIST ERROR] {}", e);
                                
                            }

                            //return reponse client 
                            let mut resp = Response::builder().status(status);
                            for (k, v) in headers.iter() {
                                resp = resp.header(k, v);
                            }

                            return resp.body(Body::from(bytes)).unwrap();

                            //nettoyer contexte
                            cleanup_tmp_for_uuid(&ctx.uuid);
                        }
                        //Si Image refusée 
                        else
                        {
                            //Ajout a la blacklist
                            if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "blacklist") {
                                eprintln!("[BLACKLIST ERROR] {}", e);
                                
                            }

                            //Supprimer dossier temporaire
                            cleanup_tmp_for_uuid(&ctx.uuid);

                            // 🔹 Libérer le contexte PullContext
                            list.retain(|c| c.uuid != context_uuid);

                            //affichage de la liste de contexte restante :    
                            println!("========== PULL CONTEXT 2 LIST ==========");
                            for (i, c) in list.iter().enumerate() {
                                println!(
                                    "[{}]\n\
                                    uuid={}\n\
                                    ip={}\n\
                                    registry={}\n\
                                    repository={}\n\
                                    tag={}\n\
                                    manifest_racine_digests={:?}\n\
                                    blob_digests={:?}\n\
                                    referrers_digests={:?}\n\
                                    digests_possible={:?}\n
                                    digests_expected={:?}\n
                                    os={}, arch={}\n",
                                    i, c.uuid, c.ip_client, c.registry, c.repository, c.tag,
                                    c.manifest_racine_digest, c.blob_digests, c.referrers_digests, c.digests_possible, c.digests_expected, c.os, c.arch
                                );
                            }
                            //retourner une erreure 
                            println!("========================================="); 
                                return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Image refused by security scan"))
                                .unwrap();
                        }     
                    }
                    Err(_) => {
                        eprintln!("[PullContext] Pull invalide");
                        // Libérer le contexte si nécessaire
                        list.retain(|c| c.uuid != context_uuid);
                        return Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from("Digest mismatch detected"))
                            .unwrap();
                    }
                }
            } else {
                // Si ce n'est pas un GET ou digests_expected <= 1, on ne fait rien
            }
        }


        //[Appel API] -> pour envoyer les données au scan de sécurité

        //Proxy -> API -> Scanner
        //Proxy <- API <- Scanner

        // On continue ou on stop le pull en fonction du scan de sécurité
        if method == Method::GET && !is_allowed() {
            println!("[SECURITY CHECK] Image non conforme -> bloquage du pull");

            //libèrer le mutex
            drop(list);

            // 🔹 Récupérer le contexte courant
            //println!("[DEBUG] Tentative de récupérer le contexte UUID={}", context_uuid);
            match pull_contexts.try_lock() {
                Ok(mut list) => {
                    if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid).cloned() {
                        println!("[DEBUG] Contexte trouvé pour UUID={}", context_uuid);
                    } else {
                        println!("[DEBUG] Aucun contexte trouvé pour UUID={}", context_uuid);
                    }
                }
                Err(_) => {
                    println!("[DEBUG] Impossible de prendre le lock, il est déjà verrouillé !");
                }
            }

            //Recupèrer le contexte bloqué
            let blocked_context = {
                let list = pull_contexts.lock().await;
                list.iter()
                    .find(|c| c.uuid == context_uuid)
                    .cloned()
            };

            if blocked_context.is_none() 
            {
                println!("[DEBUG] Aucun contexte trouvé pour UUID={}", context_uuid);
            } 
            else 
            {
                println!("[DEBUG] Contexte trouvé pour UUID={}", context_uuid);
            }

            //Ajout de l'image refusée dans la blacklist
            if let Some(ctx) = blocked_context 
            {
                if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "blacklist") {
                    eprintln!("[BLACKLIST ERROR] {}", e);
                }

            } 
            else 
            {
                //println!("[DEBUG] Aucun contexte à ajouter à la blacklist");
            }

            //On supprime le dossier temporaire
            cleanup_tmp_for_uuid(&context_uuid);

            // 🔹 Libérer le contexte PullContext
            {
                let mut list = pull_contexts.lock().await;
                list.retain(|c| c.uuid != context_uuid);
                println!(
                    "[PullContext] Contexte libéré après scan non conforme | uuid={}",
                    context_uuid
                );
            }

            //Cas ou l'image est refusé par le scan de securité 
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Image refusée par le scan de sécurité"))
                .unwrap();
        }
    }


    //Si image pas dans le cache mais scan OK -> on laisse passer la réponse upstream
    // Construire la réponse finale pour le client
    let mut resp = Response::builder().status(status);
    for (k, v) in headers.iter() {
        resp = resp.header(k, v);
    }

    resp.body(Body::from(bytes)).unwrap()

}


#[tokio::main]
async fn main() -> Result<()> {
    let certs = load_certs("certs-mitm/registry-1.docker.io.crt")?;
    let key = load_private_key("certs-mitm/registry-1.docker.io.key")?;

    let tls = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let listener = TcpListener::bind(("0.0.0.0", 443)).await?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let client = Client::builder().use_rustls_tls().build()?;

    // State partagé pour la liste de contexte pour chaques pull
    let pull_context: PullContextList = Arc::new(TokioMutex::new(Vec::new()));

    //Ajout de la fonction de timout 
    check_timout(pull_context.clone());


    println!("✅ MITM Docker registry en écoute sur https://registry-1.docker.io:443");

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let client = client.clone();
        let pull_contexts = pull_context.clone();

        
        tokio::spawn(async move {
            println!("[CONN] Client {:?}", addr);
            if let Ok(tls) = acceptor.accept(stream).await 
            {
                
                let client = client.clone();
                let pull_contexts = pull_contexts.clone();


                let service = service_fn(move |mut req| 
                    {
                        let client = client.clone();
                        let addr = addr; // passer addr
                        let pull_contexts = pull_contexts.clone();
                        async move 
                        { 
                            // stocker addr dans la requête pour handle
                            req.extensions_mut().insert(addr);
                            Ok::<_, Infallible>(handle(req, client,pull_contexts).await) 
                        }
                    });
                let _ = Http::new().serve_connection(tls, service).await;
            }
        });
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
    if method != Method::HEAD {
        return None; // on ne traite que HEAD ici
    }

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
fn add_context_to_blacklist_or_whitelist(ctx: PullContext, list_type: &str) -> Result<()> {
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



/// 🔑 Chargement des certificats TLS
fn load_certs(path: &str) -> Result<Vec<Certificate>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    let certs = certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

/// 🔑 Chargement de la clé privée TLS
fn load_private_key(path: &str) -> Result<PrivateKey> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);

    let keys = pkcs8_private_keys(&mut reader)?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].clone()));
    }

    let mut reader = BufReader::new(File::open(path)?);
    let keys = rsa_private_keys(&mut reader)?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].clone()));
    }

    Err(anyhow::anyhow!("No private keys found in {}", path))
}

//Check si aucune requetes envoyé dans le laspe de temps CONTEXT_TIMEOUT
fn check_timout(pull_contexts: PullContextList) {

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

fn cleanup_tmp_for_uuid(uuid: &Uuid) {
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

async fn get_dockerhub_token(
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
