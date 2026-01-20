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
struct PullContext {
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

    #[serde(skip_serializing, skip_deserializing, default = "Instant::now")]
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

    // Base dir conforme à la nouvelle arborescence
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


/// 🔄 Récupération ou création du contexte PullContext
async fn get_pull_context(
    req: &Request<Body>,
    parts: &[&str],
    client_ip: &str,
    pull_contexts: &PullContextList,
    client: &Client, 
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
                eprintln!("[PullContext] Échec de la commande docker buildx imagetools inspect");
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
            println!("[PullContext] UUID déjà présent, pas de création d'un nouveau contexte");
            return Ok(Some(uuid));//retourner l'uuid existant
        }




        //Appeller ici la fonction predict_digests    

        // 🔹 Prédiction des digests à partir du tag
        let predicted_digests = match predict_digests(
            &client,                    // reqwest::Client
            &uuid,                      // UUID du contexte
            &registry,                  // "registry-1.docker.io"
            &repository,                // ex: "library/ubuntu"
            &tag_ou_digest,             // ex: "latest"
            "linux",                    // OS (actuellement forcé)
            "amd64",                    // Arch (actuellement forcé)
        ).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[PullContext] predict_digests failed: {:?}", e);
                return Err(PullContextError::MissingDigestOrTag);
            }
        };
    




        // 🔹 Création du contexte PullContext
        let mut ctx = PullContext::new(
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
        /*println!("========== PULL CONTEXT 2 LIST ==========");
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
        println!("=========================================");*/

        //Ici Appel API pour envoyer données de contexte HEAD au scan haut niveau 

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
                println!("[PullContext] Correspondance trouvée pour le digest GET | uuid={}", ctx.uuid);


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



                //Verifier si le digest actuel correspond au digest racine
                if let Some(racine) = &ctx.manifest_racine_digest //si le digest racine est defini
                {
                    //si le digest de la requete n'est pas le digest racine -> ajouter les digests contenus dans le manifest demandé
                    if racine.value != digest_value 
                    {
                        //On ajoute les digests contenus dans le manifest courant qui a été demandé
                        println!("[PullContext] Digest du GET différent du digest racine → récupération des digests du manifest demandé");

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
                                            println!("[PullContext] Nouveau digest ajouté: {}", digest_struct.as_str());

                                        }
                                    }
                                }
                            } 
                            else 
                            {
                                eprintln!("[PullContext] Échec de la récupération des digests via curl");
                                return Err(PullContextError::DigestNotAllowed);
                            }
                        } 
                        else 
                        {
                            eprintln!("[PullContext] Impossible d'exécuter la commande shell");
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
                let c = config.strip_prefix("sha256").unwrap_or(config);
                digests.push(Digest { algorithm: "sha256".into(), value: c.into() });
            }
            if let Some(layers) = json.get("layers").and_then(|l| l.as_array()) {
                for layer in layers {
                    if let Some(d) = layer.get("digest").and_then(|v| v.as_str()) {
                        let l = d.strip_prefix("sha256").unwrap_or(d);
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
) -> Result<Vec<Digest>> {

    //Trouver le manifest list pour le repository:tag

    println!(
        "[PREDICT] Fetch manifest for {}:{}, target={}/{}",
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
    // Récupération du manifest (tag)
    // ============================
    let manifest_url = format!(
        "https://{}/v2/{}/manifests/{}",
        registry,
        repository,
        tag
    );

    let manifest_resp = client
        .get(&manifest_url)
        .header("Authorization", format!("Bearer {}", token))
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.list.v2+json,\
             application/vnd.docker.distribution.manifest.v2+json"
        )
        .send()
        .await?;

    let status = manifest_resp.status();
    let headers = manifest_resp.headers().clone();
    let bytes = manifest_resp.bytes().await?;


    // ============================
    // — Stockage temporaire du manifest
    // ============================

    // 1️⃣ Récupération du digest du manifest (header HTTP)
    let manifest_digest = headers
        .get("Docker-Content-Digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("Docker-Content-Digest manquant"))?
        .to_string();

    // Nettoyage "sha256:..."
    let digest_clean = manifest_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("Digest inattendu"))?;

    // 2️⃣ Création du dossier tmp/<uuid>/
    let tmp_dir = format!("tmp/{}", uuid);

    if !Path::new(&tmp_dir).exists() {
        create_dir_all(&tmp_dir)?;
    }

    // 3️⃣ Fichier = digest.json
    let filename = format!("{}/{}.json", tmp_dir, digest_clean);

    // 4️⃣ Écriture idempotente
    if !Path::new(&filename).exists() {
        fs::write(&filename, &bytes)?;
        println!(
            "[PREDICT] Manifest stored: {} ({} bytes)",
            filename,
            bytes.len()
        );
    } else {
        println!(
            "[PREDICT] Manifest already exists: {}",
            filename
        );
    }






    println!("[PREDICT] Manifest HTTP status: {}", status);
    println!("[PREDICT] Manifest size: {} bytes", bytes.len());

    // ============================
    // Détection du type
    // ============================
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        if v.get("manifests").is_some() {
            println!("[PREDICT] Manifest type: MANIFEST LIST (multi-arch)");
        } else if v.get("config").is_some() {
            println!("[PREDICT] Manifest type: SINGLE MANIFEST");
        } else {
            println!("[PREDICT] Manifest type: UNKNOWN JSON STRUCTURE");
        }
    } else {
        println!("[PREDICT] Manifest is NOT valid JSON");
    }
    let mut digests = Vec::new();


    // On ajoute toujours le manifest racine
    let digest_clean = manifest_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("Digest inattendu"))?
        .to_string();

    digests.push(Digest {
        algorithm: "sha256".to_string(),
        value: digest_clean,
    });


    // ============================
    // Parsing MANIFEST LIST
    // ============================
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;

    if let Some(manifests) = json.get("manifests") {
        println!("[PREDICT] Parsing manifest list");

        let manifest_list: ManifestList = serde_json::from_value(json)?;

        // 1️⃣ D'abord, récupérer le manifest correspondant à notre OS/ARCH
        let mut main_manifest_digest: Option<String> = None;

        for m in &manifest_list.manifests {
            if m.platform.os == os && m.platform.architecture == arch {
                println!(
                    "[PREDICT] Selected manifest {} for {}/{}",
                    m.digest, os, arch
                );

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

                    println!(
                        "[PREDICT] Stored arch-specific manifest: {}",
                        manifest_path
                    );
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
                            println!(
                                "[PREDICT] Including unknown manifest {} linked to main manifest",
                                m.digest
                            );

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

    let manifest_list_digest_clean = manifest_digest
    .strip_prefix("sha256:")
    .unwrap_or(&manifest_digest)
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


    println!("[PREDICT] Collected digests:");
    for d in &digests {
        println!(" - {}:{}", d.algorithm, d.value);
    }


    Ok(digests)

} //etape suivante est de faire la fonction last_request qui predit le dernier digest pull en fonction des digests préalablement pull






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


    // Vérifier si le manifest racine est dans la blacklist
    {
        if method == Method::HEAD 
        {
            let list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                if let Some(racine_digest) = &ctx.manifest_racine_digest {
                    let blacklist_path = "blacklist.json";
                    if std::path::Path::new(blacklist_path).exists() {
                        if let Ok(content) = std::fs::read_to_string(blacklist_path) {
                            if let Ok(blacklist) = serde_json::from_str::<Vec<PullContext>>(&content) {
                                if blacklist.iter().any(|b| {
                                    if let Some(b_racine) = &b.manifest_racine_digest {
                                        b_racine.value == racine_digest.value
                                    } else {
                                        false
                                    }
                                }) {
                                    println!(
                                        "[BLACKLIST CHECK] Manifest racine {} présent dans blacklist -> pull refusé",
                                        racine_digest.value
                                    );

                                    // 🔹 Libérer le contexte
                                    drop(list); // libérer le lock
                                    let mut list = pull_contexts.lock().await;
                                    list.retain(|c| c.uuid != context_uuid);
                                    println!(
                                        "[PullContext] Contexte libéré car blacklisté | uuid={}",
                                        context_uuid
                                    );

                                    // 🔹 Retourner FORBIDDEN
                                    return Response::builder()
                                        .status(StatusCode::FORBIDDEN)
                                        .body(Body::from("Image présente dans blacklist"))
                                        .unwrap();
                                }
                            }
                        }
                    }
                }
            }
        }
    }


    // Vérifier le cache avant d'aller en upstream
    {
        if req.method() == Method::GET 
        {
            let list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                if let Some(resp) = try_serve_from_cache(&req, ctx) {//Si le digest est dans le cache on retourne a partir du digest stocké
                    return resp;
                }
                else 
                {
                    println!("Image pas trouvée dans le cache -> GET upstream -> quarantine ->  Scan");
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

    // Vérification architecture UNIQUEMENT sur GET manifest
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



    // Sauvegarde en quarantaine pour analyse
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

    //Appeler ici l'API pour envoyer les données au scan de sécurité

    // On continue ou on stop le pull en fonction du scan de sécurité
    if method == Method::GET && !is_allowed() //On laisse passer tout les HEAD et bloque les GET non conformes
    {
        println!("[SECURITY CHECK] Image non conforme -> bloquage du pull");


        // Ajouter le contexte dans la blacklist.json

        // 🔹 Récupérer le contexte courant
        let blocked_context = {
            let list = pull_contexts.lock().await;
            list.iter()
                .find(|c| c.uuid == context_uuid)
                .cloned()
        };

        if let Some(ctx) = blocked_context 
        {
            use serde::{Serialize, Deserialize};
            use std::fs;
            use std::path::Path;

            let blacklist_path = "blacklist.json";

            // 🔹 Charger la blacklist existante ou créer une nouvelle liste
            let mut blacklist: Vec<PullContext> = if Path::new(blacklist_path).exists() {
                fs::read_to_string(blacklist_path)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            // 🔹 Ajouter le contexte courant
            blacklist.push(ctx);

            // 🔹 Écriture dans le fichier
            if let Ok(json) = serde_json::to_string_pretty(&blacklist) {
                let _ = fs::write(blacklist_path, json);
                println!("[BLACKLIST] Contexte ajouté dans blacklist.json");
            }
        }



        // 🔹 Libérer le contexte PullContext
        {
            let mut list = pull_contexts.lock().await;
            list.retain(|c| c.uuid != context_uuid);
            println!(
                "[PullContext] Contexte libéré après scan non conforme | uuid={}",
                context_uuid
            );
        }

        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Image refusée par le scan de sécurité"))
            .unwrap();
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
    let certs = load_certs("certs-mitm2/registry-1.docker.io.crt")?;
    let key = load_private_key("certs-mitm2/registry-1.docker.io.key")?;

    let tls = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let listener = TcpListener::bind(("0.0.0.0", 443)).await?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let client = Client::builder().use_rustls_tls().build()?;

    // State partagé pour suivre les blobs/manifests
    let pull_context: PullContextList = Arc::new(TokioMutex::new(Vec::new()));


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