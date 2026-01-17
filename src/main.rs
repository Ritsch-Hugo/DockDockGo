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

use std::time::Instant;//pour le timeout des pull context 2

#[derive(Clone)]
struct PullContext 
{
    client_ip: String, // IP du client
    client_id: Uuid,
    repo: String,
    tag: Option<String>,

}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Digest {
    algorithm: String, // ex: "sha256"
    value: String,     // hex
}

#[derive(Debug, Clone)]
struct PullContext2 {
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

    last_activity: Instant,

}


// Erreurs possibles lors de la récupération du contexte PullContext2
#[derive(Debug)]
enum PullContextError {
    InvalidPath,
    MissingDigestOrTag,
    ContextMismatch,
    DigestNotAllowed,
    ExpiredContext,
}

struct ImageState {
    blobs_expected: HashSet<String>,  // tous les blobs attendus pour l'image
    blobs_downloaded: HashSet<String> // blobs déjà téléchargés
}

#[derive(Debug)]
enum DigestOrTag {
    Digest(String), // GET → sha256:...
    Tag(String),    // HEAD → tag
}

type SharedState = Arc<Mutex<HashMap<String, ImageState>>>;
type PullMap = Arc<Mutex<HashMap<String, PullContext>>>;
type PullContext2List = Arc<TokioMutex<Vec<PullContext2>>>;

// Définir le timeout désiré (ex : 30 secondes)
const CONTEXT_TIMEOUT: Duration = Duration::from_secs(15);

static UPSTREAM: &str = "https://registry-1.docker.io";

/// 🔍 Analyseur de digest Docker 
/// ex: registery douteux
impl Digest {
    fn parse(input: &str) -> Option<Self> {
        let mut parts = input.splitn(2, ':');
        let algorithm = parts.next()?;
        let value = parts.next()?;

        if algorithm.is_empty() || value.is_empty() {
            return None;
        }

        // Vérification hex
        if !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        Some(Digest {
            algorithm: algorithm.to_string(),
            value: value.to_string(),
        })
    }

    fn as_str(&self) -> String {
        format!("{}:{}", self.algorithm, self.value)
    }
}

impl PullContext2 {
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
            manifest_racine_digest: None,
            last_activity: Instant::now(),
        }
    }

    fn push_unique(vec: &mut Vec<Digest>, digest: Digest) {
        if !vec.contains(&digest) {
            vec.push(digest);
        }
    }

    fn add_manifest_digest(&mut self, digest: Digest) {
        Self::push_unique(&mut self.manifest_digests, digest);
    }

    fn add_blob_digest(&mut self, digest: Digest) {
        Self::push_unique(&mut self.blob_digests, digest);
    }

    fn add_referrer_digest(&mut self, digest: Digest) {
        Self::push_unique(&mut self.referrers_digests, digest);
    }
}


/// 🔐 Politique de sécurité
fn is_allowed(path: &str, body: &[u8]) -> bool {
    //println!("[POLICY] Analyse de {}", path);

    // Toujours autoriser le ping registry
    if path == "/v2/" {
        return true;
    }

    // Toujours autoriser les blobs
    if path.contains("/blobs/") {
        return true;
    }

    // Toujours autoriser les manifests déjà stockés
    if path.contains("/manifests/") && !body.is_empty() {
        return true;
    }

    // 🔒 Exemple : bloquer tout le reste
    true
}

/// last_request: retourne true si la requête courante est la dernière à traiter pour l'image
fn last_request(path: &str, bytes: &[u8], state: &SharedState) -> bool {
    use serde_json::Value;


    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();
    if parts.len() < 4 {
        return false; // path invalide, impossible de savoir
    }

    let repo = format!("{}/{}", parts[0], parts[1]);

    //println!("[LAST_REQUEST LOG] path: {}, parts: {:?}, repo: {}", path, parts, repo);

    // ----- Cas manifest -----
    if parts[2] == "manifests" && !bytes.is_empty() {
        if let Ok(manifest_json) = serde_json::from_slice::<Value>(bytes) {
            let mut blobs = HashSet::new();
            if let Some(layers) = manifest_json.get("layers").and_then(|l| l.as_array()) {
                for layer in layers {
                    if let Some(digest) = layer.get("digest").and_then(|d| d.as_str()) {
                        blobs.insert(digest.to_string());
                    }
                }
            }
            //println!("[LAST_REQUEST] blobs_expected for {}: {:?}", repo, blobs);

            let mut state_lock = state.lock().unwrap();
            state_lock.insert(repo.clone(), ImageState {
                blobs_expected: blobs,
                blobs_downloaded: HashSet::new(),
            });
        }
        return false; // manifest n'est jamais "dernier"
    }

    // ----- Cas blobs -----
    if parts[2] == "blobs" && parts[3].starts_with("sha256:") {
        let digest = parts[3].to_string(); // garder "sha256:..."
        let mut state_lock = state.lock().unwrap();

        if let Some(image_state) = state_lock.get_mut(&repo) {
            image_state.blobs_downloaded.insert(digest.clone());
            //println!("[LAST_REQUEST] blobs_downloaded: {:?}", image_state.blobs_downloaded);
            //println!("[LAST_REQUEST] blobs_expected: {:?}", image_state.blobs_expected);

            if image_state.blobs_expected.is_subset(&image_state.blobs_downloaded) {
                println!("[LAST_REQUEST] All expected blobs downloaded for {}", repo);
                return true;
            }

        }
    }


    false
}

/// 🔑 SHA256 réel (Docker compliant)
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// 💾 Sauvegarde en quarantaine
fn save_to_quarantine(path: &str, bytes: &[u8], context: &PullContext) {
    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();
    if parts.len() < 4 {
        return;
    }

    let tag = context.tag.as_deref().unwrap_or("unknown");
    println!("[CACHE] Tag : {}", tag);
    let repo = format!("{}/{}", parts[0], parts[1]);

    // MANIFEST
    if parts[2] == "manifests" {
        let name = parts[3].trim_start_matches("sha256:");
        let dir = format!("quarantaine/{}/{}/manifests", repo, tag);
        create_dir_all(&dir).ok();
        fs::write(format!("{}/{}.json", dir, name), bytes).ok();
    }

    // BLOB
    if parts[2] == "blobs" && parts[3].starts_with("sha256:") {
        let digest = parts[3].trim_start_matches("sha256:");
        let dir = format!("quarantaine/{}/{}/blobs/sha256", repo, tag);
        create_dir_all(&dir).ok();
        fs::write(format!("{}/{}", dir, digest), bytes).ok();
    }
    // REFERRERS
    if parts[2] == "referrers" && parts[3].starts_with("sha256:") {
        let digest = parts[3].trim_start_matches("sha256:");
        let dir = format!("quarantaine/{}/{}/referrers", repo, tag);
        create_dir_all(&dir).ok();
        fs::write(format!("{}/{}.json", dir, digest), bytes).ok();
    }
}

/// 📦 Sert depuis le cache qui contient les images préalablement scannées
fn try_serve_from_cache(req: &Request<Body>, context: &PullContext) -> Option<Response<Body>> {
    let path = req.uri().path();
    let is_head = req.method() == Method::HEAD;

    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();
    if parts.len() < 4 {
        return None;
    }

    //decapsuler le tag du contexte
    let tag = context.tag.as_deref().unwrap_or("unknown");
    //println!("[CACHE] Tag : {}", tag);

    let repo = format!("{}/{}", parts[0], parts[1]);

    //println!("[CACHE] Recherche de {} dans {}", path, repo);

    //On doit laisser passer les requetues GET a chaques fois jusqu'au dernier blob meme si l'image n'est pas en cache
    if req.method() == Method::GET
    {
        // ===== MANIFEST =====
        if parts[2] == "manifests" 
        {
            let name = parts[3].trim_start_matches("sha256:");
            let file = format!("cache/{}/{}/manifests/{}.json", repo, tag, name);
            //si le fichier demandé par la requete existe et a pu etre lu
            if let Ok(data) = fs::read(&file) 
            {
                println!("data: {}", String::from_utf8_lossy(&data));
                if data.len() < 20 {
                    return None;
                }
                
                let digest = sha256_hex(&data);//calcul du digest sha256 du manifest

                //construction de la reponse HTTP conforme au standard Docker Registry v2
                return Some(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Docker-Distribution-API-Version", "registry/2.0")
                        .header(
                            "Content-Type",
                            "application/vnd.docker.distribution.manifest.v2+json",
                        )
                        .header("Docker-Content-Digest", format!("sha256:{digest}"))
                        .header("Content-Length", data.len())
                        .body(if is_head { Body::empty() } else { Body::from(data) })
                        .unwrap(),
                );
            
            }
        }

        // ===== BLOB =====
        if parts[2] == "blobs" && parts[3].starts_with("sha256:") {
            let digest = parts[3].trim_start_matches("sha256:");
            let file = format!("cache/{}/{}/blobs/sha256/{}", repo, tag, digest);

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
        
        if parts[2] == "referrers" && parts[3].starts_with("sha256:") 
        {
            let digest = parts[3].trim_start_matches("sha256:");
            let file = format!("cache/{}/{}/referrers/{}.json", repo, tag, digest);

            if let Ok(data) = fs::read(&file) {
                // Sécurité minimale : referrers non vide et JSON plausible
                if data.len() < 20 {
                    return None; // image incomplète → blocage
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



fn get_pull_context(req: &Request<Body>, parts: &[&str], client_ip: &str, pull_map: &PullMap) -> PullContext 
{
    // Sécurité minimale
    if parts.len() < 2 {
        return PullContext {
            client_ip: client_ip.to_string(),
            client_id: Uuid::new_v4(),
            repo: "unknown".to_string(),
            tag: None,
        };
    }

    let repo = format!("{}/{}", parts[0], parts[1]);
    let key = format!("{}|{}", client_ip, repo);

    let mut map = pull_map.lock().unwrap();
    // Récupération ou création du contexte PullContext
    let entry = map.entry(key).or_insert_with(|| PullContext {
        client_ip: client_ip.to_string(),
        client_id: Uuid::new_v4(),
        repo: repo.clone(),
        tag: None,
    });

    // Mise à jour du tag UNIQUEMENT sur HEAD manifest tag
    if req.method() == Method::HEAD
        && parts.len() > 3
        && !parts[3].starts_with("sha256:")
    {
        entry.tag = Some(parts[3].to_string());
    }

    entry.clone()
}

async fn get_pull_context2(
    req: &Request<Body>,
    parts: &[&str],
    client_ip: &str,
    pull_contexts: &PullContext2List,
)-> Result<Option<Uuid>, PullContextError> //Retourne soit l'uuid du contexte trouvé (cas success) soit une erreur PullContextError
{
    // 🔹 Nettoyer les contextes expirés avec timeout
    {
        let mut list = pull_contexts.lock().await;
        list.retain(|ctx| {
            let alive = ctx.last_activity.elapsed() < CONTEXT_TIMEOUT;
            if !alive {
                println!("[PullContext2] Contexte expiré supprimé | uuid={}", ctx.uuid);
            }
            alive
        });
    } // ⬅️ le lock est relâché automatiquement ici

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
        println!("[PullContext2] Type de ressource inconnu, aucun traitement possible");
        return Err(PullContextError::InvalidPath);
    };

    // 🔹 Vérifier que l'index est valide pour accéder à la valeur suivante (digest ou tag)
    if idx + 1 >= parts.len() {
        println!("[PullContext2] Path invalide, digest ou tag manquant");
        return Err(PullContextError::InvalidPath);
    }

    // 🔹 Extraire la valeur (digest ou tag)
    let value = parts[idx + 1];

    println!(
        "[PullContext2] Resource type={}, index={}, value={}",
        resource_type, idx, value
    );


    // Extraire le repository
    let repository = parts[..idx].join("/");

    let tag_ou_digest = parts[parts.len() - 1];
    let ip_client = client_ip.to_string();

    println!(
        "[PullContext2] registry={}, repository={}, tag/digest={}, client_ip={}\n",
        registry, repository, tag_ou_digest, ip_client
    );

    // 🔹 HEAD → création d’un nouveau contexte pour un tag
    if req.method() == Method::HEAD {
        // Récupérer l’index de "manifests"

        // Vérifier que l'index trouvé est valide pour accéder au digest ou tag
        if idx + 1 >= parts.len() {
            println!("[PullContext2] Path invalide, digest ou tag manquant");
            return Err(PullContextError::MissingDigestOrTag);
        }

        // Extraire la valeur suivante : digest ou tag selon le type
        let value = parts[idx + 1];
        println!(
            "[PullContext2] Resource type={}, index={}, value={}",
            resource_type, idx, value
        );


        // 🔹 Récupération du digest racine via docker buildx imagetools inspect
        let digest_cmd = format!("{}:{}", repository, tag_ou_digest);
        let mut manifest_racine_digest: Option<String> = None;
        if let Ok(output) = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "docker buildx imagetools inspect {} | grep 'Digest:' | head -n1 | awk '{{print $2}}'",
                digest_cmd
            ))
            .output()
        {
            if output.status.success() 
            {
                let d = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !d.is_empty() {
                    manifest_racine_digest = Some(d);
                }
            }
            else 
            {
                eprintln!("[PullContext2] Échec de la commande docker buildx imagetools inspect");
                return Err(PullContextError::MissingDigestOrTag);
            }
        }

        // 🔹 Construction de l’UUID déterministe (sans le tag, mais avec digest possible)
        let uuid_input = format!(
            "{}|{}|{}|{}",
            registry,
            repository,
            manifest_racine_digest.as_deref().unwrap_or("no-digest"),
            ip_client
        );
        let uuid = Uuid::new_v5(&Uuid::NAMESPACE_URL, uuid_input.as_bytes());

        // 🔹 Vérifier si l'UUID existe déjà
        let mut list = pull_contexts.lock().await;
        if list.iter().any(|c| c.uuid == uuid) {
            println!("[PullContext2] UUID déjà présent, pas de création d'un nouveau contexte");
            return Ok(Some(uuid));//retourner l'uuid existant
        }
        




        // 🔹 Création du contexte PullContext2
        let mut ctx = PullContext2::new(
            uuid,
            ip_client.clone(),
            registry.clone(),
            repository.clone(),
            tag_ou_digest.to_string(),//ici c'est le tag
        );

        ctx.last_activity = Instant::now();//initialisation du timer d'activité

        // 🔹 Ajouter les digests possibles dans le champ digests_possible et dans le champ manifest_digests + manifest_racine_digest
        if let Some(d) = manifest_racine_digest //si le digest racine a été récupéré
        {
            let digest_clean = d.trim_start_matches("sha256:").to_string();
            let digest_struct = Digest {
                algorithm: "sha256".to_string(),
                value: digest_clean.clone(),
            };

            // Ajouter dans digests_possible uniquement s'il n'est pas déjà présent
            if !ctx.digests_possible.contains(&digest_struct) {
                ctx.digests_possible.push(digest_struct.clone());
            }


            // Ajouter dans manifest_racine_digest 
            ctx.manifest_racine_digest = Some(digest_struct);

            // 🔹 Extraire tous les digests du manifest depuis DockerHub
            let cmd = format!(
                "TOKEN=$(curl -s \"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull\" | jq -r .token) && \
                curl -s -H \"Authorization: Bearer $TOKEN\" \
                    -H \"Accept: application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json\" \
                    https://registry-1.docker.io/v2/{repo}/manifests/sha256:{digest} \
                | jq -r 'if has(\"manifests\") then .manifests[].digest elif has(\"config\") then .config.digest, (.layers[].digest // empty) else empty end'",
                repo = repository,
                digest = digest_clean
            );

            if let Ok(output) = Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .output()
            {
                //si la commande shell a réussi
                if output.status.success() 
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        let line_clean = line.trim_start_matches("sha256:").to_string();
                        if !line_clean.is_empty() {//si la ligne n'est pas vide
                            let digest = Digest {
                                algorithm: "sha256".to_string(),
                                value: line_clean,
                            };
                            // Ajouter uniquement si pas déjà présent
                            if !ctx.digests_possible.contains(&digest) {
                                ctx.digests_possible.push(digest);
                            }
                        }
                    }
                } 
                else 
                {
                    eprintln!("[PullContext2] Échec de la commande curl/jq pour récupérer les digests");
                    return Err(PullContextError::MissingDigestOrTag);
                }
            }
        }
        else
        {
            eprintln!("[PullContext2] Aucun digest racine récupéré, impossible de créer le contexte");
            return Err(PullContextError::MissingDigestOrTag);
        }




        // 🔹 Ajouter le contexte à la liste partagée
        list.push(ctx);

        // 🔎 Affichage de toute la liste
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
                 digests_possible={:?}\n",
                i, c.uuid, c.ip_client, c.registry, c.repository, c.tag,
                c.manifest_racine_digest, c.blob_digests, c.referrers_digests, c.digests_possible
            );
        }
        println!("=========================================");

        return Ok(Some(uuid));
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
        //Verifier si l'uuid existe dans la liste 
        let mut list = pull_contexts.lock().await;
        for ctx in list.iter_mut() 
        {
            //Verifier si le contexte correspond au client ip, registry, repository et digest possible
            if ctx.ip_client == ip_client
                && ctx.registry == registry
                && ctx.repository == repository
                && ctx.digests_possible.iter().any(|d| d.value == digest_value)
            {
                ctx.last_activity = Instant::now(); // Mettre à jour l'activité pour le timeout

                println!("[PullContext2] Correspondance trouvée pour le digest GET | uuid={}", ctx.uuid);
                //Verifier si le digest actuel correspond au digest racine
                if let Some(racine) = &ctx.manifest_racine_digest //si le digest racine est defini
                {
                //si le digest de la requete n'est pas le digest racine -> ajouter les digests contenus dans le manifest demandé
                    if racine.value != digest_value 
                    {
                        //On ajoute les digests contenus dans le manifest courant qui a été demandé
                        println!("[PullContext2] Digest du GET différent du digest racine → récupération des digests du manifest demandé");

                        // Construire la commande TOKEN + curl
                        let repo = &ctx.repository;
                        let digest = digest_value.clone(); // digest actuel GET

                        let cmd = format!(
                            r#"TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull" | jq -r .token) && \
                            curl -s -H "Authorization: Bearer $TOKEN" \
                                -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json" \
                                https://registry-1.docker.io/v2/{repo}/manifests/sha256:{digest} \
                            | jq -r 'if has("manifests") then .manifests[].digest elif has("config") then .config.digest, (.layers[].digest // empty) else empty end'"#,
                            repo = repo,
                            digest = digest
                        );

                        // Exécuter la commande shell
                        if let Ok(output) = Command::new("sh")
                            .arg("-c")
                            .arg(cmd)
                            .output()
                        {
                            if output.status.success() 
                            {
                                let stdout = String::from_utf8_lossy(&output.stdout);
                                for line in stdout.lines() {
                                    let line_clean = line.trim_start_matches("sha256:").to_string();
                                    if !line_clean.is_empty() {
                                        let digest_struct = Digest {
                                            algorithm: "sha256".to_string(),
                                            value: line_clean,
                                        };
                                        // Ajouter uniquement si pas déjà présent
                                        if !ctx.digests_possible.contains(&digest_struct) 
                                        {
                                            ctx.digests_possible.push(digest_struct.clone());
                                            println!("[PullContext2] Nouveau digest ajouté: {}", digest_struct.as_str());

                                        }
                                    }
                                }
                            } 
                            else 
                            {
                                eprintln!("[PullContext2] Échec de la récupération des digests via curl");
                                return Err(PullContextError::DigestNotAllowed);
                            }
                        } 
                        else 
                        {
                            eprintln!("[PullContext2] Impossible d'exécuter la commande shell");
                            return Err(PullContextError::DigestNotAllowed);
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
                    println!("[PullContext2] Aucun digest racine défini pour ce contexte → bloqué");
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
        println!("[PullContext2] Aucun contexte trouvé pour le digest GET demandé");
        return Err(PullContextError::ContextMismatch);
    }

    //Methode ne correspond pas a HEAD ou GET
    return Err(PullContextError::ContextMismatch);
}






async fn handle(req: Request<Body>, client: Client, state: SharedState, pull_map: PullMap, pull_contexts2: PullContext2List, ) -> Response<Body> {
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
    /*if req.method() == Method::GET && parts.len() > 3 && parts[3].starts_with("sha256:") {
        parse_digest(
            DigestOrTag::Digest(parts[3].to_string()),
            &req,
        );
    }
    if req.method() == Method::HEAD && parts.len() > 3 && !parts[3].starts_with("sha256:") {
        parse_digest(
            DigestOrTag::Tag(parts[3].to_string()),
            &req,
        );
    }*/

    
    //recupère l'ip du client 
    let client_ip = req
    .extensions()
    .get::<std::net::SocketAddr>()
    .unwrap()
    .ip()
    .to_string();

    /*if parts.len() > 3 {
    println!("Requête HEAD sur tag : {}", parts[3]);
    }*/

    //recupère le contexte du pull en cours

    //let context = get_pull_context(&req, &parts, &client_ip, &pull_map);
    let context2 = match get_pull_context2(&req, &parts, &client_ip, &pull_contexts2).await {
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
        Err(PullContextError::ExpiredContext) => {
            eprintln!("[Main] Pull bloqué car déjà en cours pour la même image dans les 15s");
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Body::from("Pull récent pour la même image, attendre 15 secondes"))
                .unwrap();
        },
        Err(e) => {
            eprintln!("[Main] Erreur lors de la récupération du contexte: {:?}", e);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Erreur PullContext"))
                .unwrap();
        }

    };

    //log
    /*println!(
        "[PULL CONTEXT] client={} uuid={} repo={} tag={:?} client_ip={}",
        client_ip,
        context.client_id,
        context.repo,
        context.tag,
        context.client_ip
    );*/

    /* 
    // Affichage de TOUTE la liste des PullContext2
    let list = pull_contexts2.lock().unwrap().clone();
    println!("========== PULL CONTEXT 2 LIST ==========");
    for (i, c) in list.iter().enumerate() {
        println!(
            "[{}]\n\
            uuid={}\n\
            ip={}\n\
            registry={}\n\
            repository={}\n\
            image={}\n\
            tag={}\n\
            manifest_digests={:?}\n\
            blob_digests={:?}\n\
            referrers_digests={:?}\n",
            i,
            c.uuid,
            c.ip_client,
            c.registry,
            c.repository,
            c.image,
            c.tag,
            c.manifest_digests,
            c.blob_digests,
            c.referrers_digests,
        );
    }
    println!("=========================================");
    */


    //sleep(Duration::from_secs(1000)).await; 

    let context = get_pull_context(&req, &parts, &client_ip, &pull_map);
    let requested_repo = format!("{}/{}", parts[0], parts[1]);

    //Verification du contexte de requete
    // /!\Produit une erreure si differents pulls sont mélangés 
    // Solution -> Utiliser un Uuid de session de pull commun a chaques requetes d'un meme pull
    if client_ip != context.client_ip || requested_repo != context.repo{
        println!("[ERROR] IP du client ne correspond pas au contexte PullContext");
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("IP du client ne correspond pas au contexte PullContext"))
            .unwrap();
    }
    // Tenter de servir depuis le cache local
    //Si la fonction try_serve_from_cache retourne une reponse (Some)
    if let Some(resp) = try_serve_from_cache(&req, &context) {
        //println!("[LOCAL REGISTRY] {}", path);
        return resp;
    }
    else if req.method() == Method::GET
    {
        println!("Image pas trouvée dans le cache | Bloquage");
        /*loop 
        {

        }*/
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

    // Vérification architecture UNIQUEMENT sur GET manifest
    if method == Method::GET
        && path.contains("/manifests/")
        && !bytes.is_empty()
    {
        // Si c'est une manifest list (présence du champ "manifests")
        let is_manifest_list = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v.get("manifests").cloned())
            .is_some();

        if is_manifest_list && !manifest_list_has_linux_amd64(&bytes) {
            //println!("[ARCH CHECK] Manifest list incompatible linux/amd64");

            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from(
                    "No matching manifest for linux/amd64"
                ))
                .unwrap();
        }
    }


    // === POLICY CHECK ===
    if !is_allowed(&path, &bytes) {
        save_to_quarantine(&path, &bytes, &context); // stocke la ressource dans la quarantaine
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Image mise en quarantaine"))
            .unwrap();
    }

    // Sauvegarder les manifests et blobs GET valides dans la quarantaine
    if method == Method::GET && !bytes.is_empty() {
        if path.contains("/manifests/") || path.contains("/blobs/") || path.contains("/referrers/") {
            save_to_quarantine(&path, &bytes, &context);
        }
    }
    // Vérifier si c'est la dernière requête à traiter pour cette image
    // /!\Attention /!\ L'erreure est gènérée lors du dernier blob téléchargé donc les autres blobs et manifests sont bien téléchargés
    //Il faudra changer la logique pour intercepter uniquement les premiers HEAD pour conniatre l'image ciblé, 
    //bloquer le pull et faire la requete docker pull depuis le server proxy pour mettre en cache
    if last_request(&path, &bytes, &state) == true {
        println!("Dernière requête pour cette image traitée.");
        return Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from("Image mise en quarantaine"))
        .unwrap();
    }

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

    // State partagé pour suivre les pulls en cours
    let pull_map: PullMap = Arc::new(Mutex::new(HashMap::new()));

    // State partagé pour suivre les blobs/manifests
    let state: SharedState = Arc::new(Mutex::new(HashMap::new()));
    let pull_contexts2: PullContext2List = Arc::new(TokioMutex::new(Vec::new()));


    println!("✅ MITM Docker registry en écoute sur https://registry-1.docker.io:443");

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let client = client.clone();
        let state = state.clone(); // Arc<Mutex<SharedState>>
        let pull_map = pull_map.clone(); // <-- clone pour cette itération
        let pull_contexts2 = pull_contexts2.clone();

        
        tokio::spawn(async move {
            println!("[CONN] Client {:?}", addr);
            if let Ok(tls) = acceptor.accept(stream).await 
            {
                
                let client = client.clone();
                let state = state.clone();
                let pull_map = pull_map.clone(); // <-- clone pour service_fn
                let pull_contexts2 = pull_contexts2.clone();


                let service = service_fn(move |mut req| 
                    {
                        let client = client.clone();
                        let state = state.clone();
                        let pull_map = pull_map.clone(); // clone pour handle
                        let addr = addr; // passer addr
                        let pull_contexts2 = pull_contexts2.clone();
                        async move 
                        { 
                            // stocker addr dans la requête pour handle
                            req.extensions_mut().insert(addr);
                            Ok::<_, Infallible>(handle(req, client, state, pull_map, pull_contexts2).await) 
                        }
                    });
                let _ = Http::new().serve_connection(tls, service).await;
            }
        });
    }
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