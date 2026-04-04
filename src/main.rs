use std::{convert::Infallible, fs::File, io::BufReader, sync::Arc};

use anyhow::Result;
use hyper::{
    service::service_fn,
    Body, Method, Request, Response, StatusCode,
};
use hyper::server::conn::Http;
use reqwest::Client;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use std::collections::{HashMap};
use tokio::sync::Mutex as TokioMutex;


use uuid::Uuid;
use tokio::time::{Duration};

use serde::{Serialize, Deserialize};

use std::time::Instant;//pour le timeout des pull context 2

use reqwest::multipart;

use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

use rustls::sign::any_supported_type;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use std::path::Path;



mod pull_context;
mod db;
use pull_context::{
    get_pull_context, 
    digest_process_for_head,
};


// Déclare le module
mod predict_digests_utils;
mod registry_auth;
mod validation;

// Puis importe les fonctions dont tu as besoin
use predict_digests_utils::{
    get_os_arch_for_digest,
    //fetch_and_process_manifest,
    predict_digests_docker,
    predict_digests_podman,
    verify_downloaded_digests,
};

mod utils;
use utils::{
    save_to_quarantine,
    save_to_cache,
    try_serve_from_cache,
    manifest_list_has_linux_amd64,
    store_digest,
    get_response_from_upstream,
    check_manifest_in_list,
    add_context_to_blacklist_or_whitelist,
    check_timout,
    cleanup_tmp_for_uuid,
    remove_ctx_digests_from_quarantine,
    dec_active,
    copy_ctx_from_quarantine_to_cache,
    is_registry_allowed,
    verify_content_digest,
    check_blob_size,
    prefetch_expected_to_quarantine,
    serve_from_quarantine,
    validate_manifest_list,
};



#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Digest {
    algorithm: String, // ex: "sha256"
    value: String,     // hex
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PullContext 
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
    scan_final_done: bool,
    in_whitelist: Option<bool>,
    in_blacklist: Option<bool>,
    in_cache: Option<bool>,
    check_if_verify_digest_completed: bool,

    pub scan_status: Option<String>, // "ALLOW", "PENDING", "DENY" ou None si pas encore de scan

    pub active_requests: AtomicUsize,

    pub client_type: String, //podman ou docker

    #[serde(skip_serializing, skip_deserializing)]
    pub notify_zero: Arc<Notify>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanDecision {
    PENDING,
    ALLOW,
    DENY,
}

// Erreurs possibles lors de la récupération du contexte PullContext2
#[derive(Debug)]
enum PullContextError {
    InvalidPath,
    MissingDigestOrTag,
    ContextMismatch,
    DigestNotAllowed,
    BlockingFromTheScanner,
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
    platform: Platform,
    #[serde(default)]
    annotations: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct Platform {
    os: String,
    architecture: String,
}



//Structure pour la gestion multi certificats 
struct MultiCertResolver {
    certs: HashMap<String, Arc<CertifiedKey>>,
}

/// Entrée pour une IP : nombre de requêtes et début de la fenêtre
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

pub struct RateLimiter {
    entries: Arc<TokioMutex<HashMap<String, RateLimitEntry>>>,
    max_requests: u32,   // nombre max de requêtes par fenêtre
    window: Duration,    // durée de la fenêtre
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            entries: Arc::new(TokioMutex::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    /// Retourne true si la requête est autorisée, false si le rate limit est atteint
    pub async fn check(&self, ip: &str) -> bool {
        let mut map = self.entries.lock().await;
        let now = Instant::now();

        match map.get_mut(ip) {
            Some(entry) => {
                // Si la fenêtre est expirée, on remet à zéro
                if now.duration_since(entry.window_start) > self.window {
                    entry.count = 1;
                    entry.window_start = now;
                    true
                } else if entry.count >= self.max_requests {
                    // Fenêtre active et limite atteinte
                    false
                } else {
                    entry.count += 1;
                    true
                }
            }
            None => {
                // Première requête de cette IP
                map.insert(ip.to_string(), RateLimitEntry {
                    count: 1,
                    window_start: now,
                });
                true
            }
        }
    }

    //Nettoyage périodique des entrées expirées pour éviter la fuite mémoire
    
    pub fn start_cleanup(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let mut map = self.entries.lock().await;
                let now = Instant::now();
                let before = map.len();
                map.retain(|_, entry| {
                    now.duration_since(entry.window_start) <= self.window
                });
                let removed = before - map.len();
                if removed > 0 {
                    println!("[RATE-LIMIT] Nettoyage effectué, {} IPs supprimées ({} restantes)", removed, map.len());
                }
            }
        });
    }
}

impl MultiCertResolver {
    fn new() -> Self {
        Self {
            certs: HashMap::new(),
        }
    }

    fn add(&mut self, domain: &str) -> Result<()> {
        let crt_path = format!("certs-mitm/{}.crt", domain);
        let key_path = format!("certs-mitm/{}.key", domain);

        if !Path::new(&crt_path).exists() || !Path::new(&key_path).exists() {
            eprintln!("[TLS] Certificat manquant pour {}", domain);
            return Ok(());
        }

        let certs = load_certs(&crt_path)?;
        let key = load_private_key(&key_path)?;
        let signing_key = any_supported_type(&key)?;
        let certified = Arc::new(CertifiedKey::new(certs, signing_key));
        self.certs.insert(domain.to_string(), certified);
        println!("[TLS] Certificat chargé pour {}", domain);
        Ok(())
    }
}

impl ResolvesServerCert for MultiCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?;
        self.certs.get(name).cloned()
    }
}

type PullContextList = Arc<TokioMutex<Vec<PullContext>>>;

// Définir le timeout désiré (ex : 30 secondes)
const CONTEXT_TIMEOUT: Duration = Duration::from_secs(200000);

//static UPSTREAM: &str = "https://registry-1.docker.io";


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
            scan_final_done: false,
            in_blacklist: None,
            in_whitelist: None,
            in_cache: None,
            check_if_verify_digest_completed: false,
            scan_status: Some("PENDING".to_string()),
            active_requests: AtomicUsize::new(0),
            client_type: "unknown".to_string(),
            notify_zero: Arc::new(Notify::new()),

        }

    }
}
impl Clone for PullContext {
    fn clone(&self) -> Self {
        Self {
            uuid: self.uuid,
            ip_client: self.ip_client.clone(),
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            tag: self.tag.clone(),
            manifest_digests: self.manifest_digests.clone(),
            blob_digests: self.blob_digests.clone(),
            referrers_digests: self.referrers_digests.clone(),
            manifest_racine_digest: self.manifest_racine_digest.clone(),
            digests_possible: self.digests_possible.clone(),
            digests_expected: self.digests_expected.clone(),
            os: self.os.clone(),
            arch: self.arch.clone(),
            last_activity: self.last_activity,
            pull_completed: self.pull_completed,
            scan_final_done: self.scan_final_done,
            in_whitelist: self.in_whitelist,
            in_blacklist: self.in_blacklist,
            in_cache: self.in_cache,
            check_if_verify_digest_completed: self.check_if_verify_digest_completed,
            scan_status: self.scan_status.clone(),
            active_requests: AtomicUsize::new(self.active_requests.load(Ordering::SeqCst)),
            client_type: self.client_type.clone(),
            notify_zero: self.notify_zero.clone(),
        }
    }
}

/// 🔐 Politique de sécurité (async)
/// ALLOW ou PENDING => true (on continue)
/// DENY => false (on bloque direct)
pub async fn launch_final_scan(
    pull_contexts: &PullContextList,
    uuid: Uuid,
    path: &str,
    pool: &sqlx::PgPool,
) -> Option<ScanDecision>
{

    // 1️⃣ récupérer le contexte
    let mut ctx_clone;
    {
        let mut list = pull_contexts.lock().await;
        let ctx = list.iter_mut().find(|c| c.uuid == uuid)?;

        // sécurité : scan déjà lancé ?
        if ctx.scan_final_done {
            return None;
        }

        ctx.scan_final_done = true;
        ctx_clone = ctx.clone();
    }
    // 🔴 on sort du mutex ici

    println!("[SCAN FINAL] lancement pour uuid={}", uuid);

    // 2️⃣ appel scanner
    let state = match is_allowed(&mut ctx_clone, path, "scan_final").await {
        Err(e) => {
            eprintln!("[ORCH ERROR] {}", e);
            return None; // ← fail closed
        }
        Ok(s) => s,
    };



    let mut list = pull_contexts.lock().await;
    let ctx = list.iter_mut().find(|c| c.uuid == uuid)?;

    if state == "ALLOW"
    {
        return Some(ScanDecision::ALLOW);
    }
     
    if state == "PENDING" 
    {
        return Some(ScanDecision::PENDING);
    }
    
    if state == "DENY" 
    {
        return Some(ScanDecision::DENY);
    }

    println!("[SCAN FINAL] état inconnu");
    None
}

async fn is_allowed(ctx: &mut PullContext, path: &str, flag: &str) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct OrchestratorResp {
        pull_id: uuid::Uuid,
        state: String, // "PENDING" | "ALLOW" | "DENY"
    }

    println!("flag : {}", flag);
    const ORCH_URL: &str = "http://127.0.0.1:3000/v1/decision";

    println!("============================== APPEL ORCHESTRATEUR ==============================");
    println!("uuid={} repo={}:{}", ctx.uuid, ctx.repository, ctx.tag);

    // 1) context inchangé
    let mut form = multipart::Form::new()
        .text("context", serde_json::to_string(ctx).unwrap_or_else(|_| "{}".to_string()));

async fn add_file_if_exists(
    form: multipart::Form,
    field_name: &'static str,
    filename: String,
    path: String,
) -> multipart::Form {
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            if bytes.is_empty() {
                println!("[ORCH WARN] fichier vide: {}", path);
                return form;
            }

            println!("[ORCH INFO] ajout fichier: {}", path);

            let mime = if path.contains("/manifests/") || path.contains("/referrers/") {
                "application/json"
            } else {
                "application/octet-stream"
            };

            // Renommer le fichier pour éviter les ':' dans le nom
            let safe_filename = filename.replace(":", "_");

            let part = multipart::Part::bytes(bytes)
                .file_name(safe_filename)
                .mime_str(mime)
                .unwrap();

            form.part(field_name, part)
        }
        Err(e) => {
            println!("[ORCH WARN] fichier introuvable: {} ({})", path, e);
            form
        }
    }
}

    let base_dir = format!("quarantaine/{}/{}", ctx.registry, ctx.repository);

    // =====================================================================
    // SCAN FINAL → envoyer TOUS les digests de l'image
    // =====================================================================
    println!("flag : {} : ", flag);

    if flag == "scan_final" 
    {
        println!("[ORCH] SCAN FINAL -> envoi de tous les digests de l'image");

        // ---------------- manifests ----------------
        for d in &ctx.manifest_digests {
            let digest = d.as_str();
            let parts: Vec<&str> = digest.split(':').collect();
            if parts.len() == 2 {
                let algo = parts[0];
                let value = parts[1];

                let filename = digest.clone();
                let file_path = format!("{}/manifests/{}/{}.json", base_dir, algo, value);

                form = add_file_if_exists(form, "manifests", filename, file_path).await;
            }
        }

        // ---------------- blobs ----------------
        for d in &ctx.blob_digests {
            let digest = d.as_str();
            let parts: Vec<&str> = digest.split(':').collect();
            if parts.len() == 2 {
                let algo = parts[0];
                let value = parts[1];

                let filename = digest.clone();
                let file_path = format!("{}/blobs/{}/{}", base_dir, algo, value);

                form = add_file_if_exists(form, "blobs", filename, file_path).await;
            }
        }

        // ---------------- referrers ----------------
        for d in &ctx.referrers_digests {
            let digest = d.as_str();
            let parts: Vec<&str> = digest.split(':').collect();
            if parts.len() == 2 {
                let algo = parts[0];
                let value = parts[1];

                let filename = digest.clone();
                let file_path = format!("{}/referrers/{}/{}.json", base_dir, algo, value);

                form = add_file_if_exists(form, "referrers", filename, file_path).await;
            }
        }

        println!("[ORCH] SCAN FINAL -> tous les fichiers ajoutés au multipart");
    }

    //Cas scan haut niveau podman (sur le GET /manifest/<tag>)
    else if path.contains("/manifests/") && !path.contains("sha256:") 
    {
        if flag != "scan_haut_niveau" {  // ← ne pas joindre le manifest pour le premier call
            if let Some(racine) = &ctx.manifest_racine_digest {
                let digest = racine.as_str();
                let parts: Vec<&str> = digest.split(':').collect();
                if parts.len() == 2 {
                    let algo = parts[0];
                    let value = parts[1];
                    let file_path = format!("{}/manifests/{}/{}.json", base_dir, algo, value);
                    println!("[ORCH] manifest racine (par tag) détecté: {}", file_path);
                    form = add_file_if_exists(form, "manifests", digest.clone(), file_path).await;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // On envoie uniquement le digest demandé dans l'URL
    // ------------------------------------------------------------------
    else 
    {

        if let Some(pos) = path.find("sha256:") 
        {
            let digest = &path[pos..];
            println!("[ORCH] digest courant détecté: {}", digest);

            if path.contains("/manifests/") {
                let parts: Vec<&str> = digest.split(':').collect();
                if parts.len() == 2 {
                    let algo = parts[0];
                    let value = parts[1];

                    let filename = digest.to_string();
                    let file_path = format!("{}/manifests/{}/{}.json", base_dir, algo, value);

                    form = add_file_if_exists(form, "manifests", filename, file_path).await;
                }
                
            } else if path.contains("/blobs/") {
                let parts: Vec<&str> = digest.split(':').collect();
                if parts.len() == 2 {
                    let algo = parts[0];
                    let value = parts[1];

                    let filename = digest.to_string();
                    let file_path = format!("{}/blobs/{}/{}", base_dir, algo, value);

                    println!("[ORCH] fichier blob attendu: {}", file_path);

                    form = add_file_if_exists(form, "blobs", filename, file_path).await;
                }
            } else if path.contains("/referrers/") {
                let parts: Vec<&str> = digest.split(':').collect();
                if parts.len() == 2 {
                    let algo = parts[0];
                    let value = parts[1];

                    let filename = digest.to_string();
                    let file_path = format!("{}/referrers/{}/{}.json", base_dir, algo, value);

                    form = add_file_if_exists(form, "referrers", filename, file_path).await;
                }
            }
        }
            
        // ← CAS PODMAN : path par tag, pas de sha256: dans le path
        else if path.contains("/manifests/") && !path.contains("sha256:") && flag != "scan_haut_niveau" {
            // Utiliser le manifest_racine_digest du contexte
            if let Some(racine) = &ctx.manifest_racine_digest {
                let digest = racine.as_str(); // "sha256:d1e2e92c..."
                let parts: Vec<&str> = digest.split(':').collect();
                if parts.len() == 2 {
                    let algo = parts[0];
                    let value = parts[1];

                    let filename = digest.clone();
                    let file_path = format!("{}/manifests/{}/{}.json", base_dir, algo, value);

                    println!("[ORCH] manifest racine (par tag) détecté: {}", file_path);
                    form = add_file_if_exists(form, "manifests", filename, file_path).await;
                }
            }
        }
    }

    println!("file_path : {}", base_dir);


    // 5) POST multipart 
    let client = reqwest::Client::new();

    let state: Result<String, String> = match tokio::time::timeout(
        Duration::from_secs(30),
        client.post(ORCH_URL).multipart(form).send()
    ).await {
        Err(_) => {
            // ← Err du timeout (elapsed)
            eprintln!("[ORCH TIMEOUT] Orchestrateur ne répond pas");
            return Err("Timeout orchestrateur".to_string());
        }
        Ok(Err(e)) => {
            // ← Err réseau
            eprintln!("[ORCH CALL] request error: {:?}", e);
            return Err(format!("Erreur réseau: {}", e));
        }
        Ok(Ok(r)) => {
            let status = r.status();
            println!("[ORCH CALL] status={}", status);
            let text = r.text().await.unwrap_or_default();
            println!("[ORCH RAW RESP] {}", text);

            if !status.is_success() {
                println!("[ORCH ERROR] orchestrateur a renvoyé non-200");
                return Ok("PENDING".to_string());
            }

            match serde_json::from_str::<OrchestratorResp>(&text) {
                Ok(body) => {
                    println!("[ORCH RESP] pull_id={} state={}", body.pull_id, body.state);
                    Ok(body.state.trim().to_uppercase())
                }
                Err(e) => {
                    println!("[ORCH PARSE ERROR] {:?}", e);
                    Ok("PENDING".to_string())
                }
            }
        }
    };


    println!("==================================================================================");

    let state_str = match state {
        Ok(ref s) => s.clone(),
        Err(ref e) => return Err(e.clone()),
    };

    match state_str.as_str() {
        "ALLOW" => {
            println!("Pull autorisé par l'orchestrateur");
            ctx.scan_status = Some("ALLOW".to_string());
        }
        "PENDING" => {
            println!("Pull en attente, décision non finale");
            ctx.scan_status = Some("PENDING".to_string());
        }
        "DENY" => {
            println!("Pull refusé par l'orchestrateur");
            ctx.scan_status = Some("DENY".to_string());
        }
        other => {
            println!("[WARNING] État inattendu reçu: {}", other);
        }
    }

    Ok(state_str)
}



async fn handle(req: Request<Body>, client: Client, pull_contexts: PullContextList, pool: sqlx::PgPool, rate_limiter: Arc<RateLimiter>) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    //let headers = req.headers().clone();

    // Normaliser sha256- → sha256: pour les registres OCI
    let path = path.replace("sha256-", "sha256:");
    println!("============================================================");
    println!("[REQ] {} {}", method, path);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    println!("[UA] {}", user_agent);

    // Découper le path pour extraire repo, tag, digest
    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();

    // ✅ VALIDATION HEADERS — avant tout, y compris /v2/
    if let Err(e) = validation::validate_headers(&req) {
        let client_ip = req.extensions()
            .get::<std::net::SocketAddr>()
            .map(|a| a.to_string())
            .unwrap_or_default();
        eprintln!("[SECURITY] Headers invalides | ip={} err={}", client_ip, e);
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Requête invalide"))
            .unwrap();
    }

    // ✅ RATE LIMITING
    let client_ip_for_rate = req.extensions()
        .get::<std::net::SocketAddr>()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();

    if !rate_limiter.check(&client_ip_for_rate).await {
        eprintln!("[RATE-LIMIT] Limite atteinte | ip={}", client_ip_for_rate);
        return Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .body(Body::from("Rate-limit : Trop de requêtes"))
            .unwrap();
    }

    // Ping registry
    if path == "/v2/" {
        if req.method() != Method::GET {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::empty())
                .unwrap();
        }
        return Response::builder().status(StatusCode::OK).body(Body::empty()).unwrap();
    }

    if req.method() != Method::GET && req.method() != Method::HEAD {
        eprintln!("[SECURITY] Méthode non autorisée: {} {}", method, path);
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Méthode non autorisée"))
            .unwrap();
    }

    // Redirection des requêtes /token vers le vrai registre
    if path.starts_with("/token") {
        let upstream = match get_response_from_upstream(req, client).await {
            Ok(resp) => resp,
            Err(resp) => return resp,
        };
        let status = upstream.status();
        let headers = upstream.headers().clone();
        let bytes = upstream.bytes().await.unwrap_or_default();
        let mut resp = Response::builder().status(status);
        for (k, v) in headers.iter() {
            resp = resp.header(k, v);
        }
        return resp.body(Body::from(bytes)).unwrap();
    }
        
    //recupère l'ip du client 
    let client_ip = req
    .extensions()
    .get::<std::net::SocketAddr>()
    .unwrap()
    .ip()
    .to_string();

    //exctation de l'host depuis la requete 
    let host = req.headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Vérifier si le registre est autorisé
    if !is_registry_allowed(&host) {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Registre non autorisé"))
            .unwrap();
    }

    // ✅ VÉRIFICATION IP — l'IP doit être connue dans la table users du dashboard
    if !db::is_ip_allowed(&pool, &client_ip).await {
        eprintln!("[SECURITY] Pull refusé — IP non autorisee : {}", client_ip);
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Acces refuse : IP non autorisee"))
            .unwrap();
    }

    // ✅ VALIDATION DES INPUTS
    if path.contains("..") || path.contains('\\') {
        eprintln!("[SECURITY] Path traversal détecté: {}", path);
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Requête invalide"))
            .unwrap();
    }

    // Extraire repository et tag/digest depuis parts pour valider
    let repo_and_tag_valid = (|| -> Result<(), &'static str> {
        // Trouver l'index de "manifests", "blobs" ou "referrers"
        let idx = parts.iter().position(|p| {
            *p == "manifests" || *p == "blobs" || *p == "referrers"
        }).ok_or("resource type manquant")?;

        if idx + 1 >= parts.len() {
            return Err("tag ou digest manquant");
        }

        let repository = parts[..idx].join("/");
        let tag_or_digest = parts[parts.len() - 1];

        //appel de la fonction de validation
        validation::validate_request_components(&host, &repository, tag_or_digest)
            .map_err(|_| "composants invalides")?;

        Ok(())
    })();

    //Si validation echoue
    if let Err(e) = repo_and_tag_valid {
        eprintln!("[SECURITY] Validation échouée: {}", e);
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Requête invalide"))
            .unwrap();
    }


    let client_type = detect_client_type(&req);
    println!("[CLIENT] type détecté: {}", client_type); 

    //recupère le contexte du pull en cours
    let context_uuid = match get_pull_context(&req, &parts, &client_ip, &pull_contexts, &client, &path, client_type, &pool).await {
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
            eprintln!("[Main] Accès refusé au registre");
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Accès refusé : image privée ou credentials manquants"))
                .unwrap();
        }
        Err(PullContextError::MissingDigestOrTag) => {  // ← ajouter ce cas
            eprintln!("[Main] L'image n'existe pas dans le registre ou est privée");
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Image inexistante ou privée"))
                .unwrap();
        }
        Err(PullContextError::BlockingFromTheScanner) => {
            eprintln!("[Main] Pull bloqué et image blacklisté car scan de haut niveau n'est pas passé");
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Image refusée par le scan de sécurité"))
                .unwrap();
        }
        Err(e) => {
            eprintln!("[Main] Erreur lors de la récupération du contexte: {:?}", e);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Erreur PullContext"))
                .unwrap();
        }

    };

    //Ajoute la requete courrante au context dans active_request 
    {
        let mut list = pull_contexts.lock().await;
        if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
            // Incrémente atomiquement
            let _atomic_count_request: usize = ctx.active_requests.fetch_add(1, Ordering::SeqCst) + 1;

            println!(
                "[CTX] +1 active_requests={:?} uuid={}",
                ctx.active_requests.load(Ordering::SeqCst),
                ctx.uuid
            );
        }

    }
   

    // Vérifier le cache avant d'aller en upstream
    //si le digest est present dans le cache on retourne la réponse a partir du cache
    {
        if req.method() == Method::GET 
        {
            let mut list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
                if let Some(resp) = try_serve_from_cache(&req, ctx) {//Si le digest est dans le cache on retourne a partir du digest stocké
                    
                    ctx.in_cache = Some(true);

                    println!("[CACHE] Digest trouvé en cache");

                    //Appeler la fonction verify_downloaded_digests pour libèrer le contexte au bon moment 

                    // On ne déclenche le "Pull COMPLET" que si la requête est un GET pour laisser passer les HEAD
                    // et que digests_expected contient plus d'un élément
                    let mut should_cleanup = false;
                    if ctx.digests_expected.len() > 1
                    {

                        //On compare les digests expected et ceux réellement téléchargés

                        match verify_downloaded_digests(ctx) 
                        {
                            Ok(DigestVerificationState::InProgress) => {
                                // pull normal, on laisse continuer
                            }
                            Ok(DigestVerificationState::Completed) => 
                            {
                                println!("[PullContext] Pull COMPLET pour uuid={}", ctx.uuid);
                                //Mettre la variable scan_completed a true
                                ctx.pull_completed = true;

                                sqlx::query("UPDATE pulls SET scan_completed = true, decision_final = 'ALLOW', last_activity = NOW() WHERE uuid = $1::uuid")
                                    .bind(context_uuid.to_string())
                                    .execute(&pool)
                                    .await
                                    .unwrap_or_else(|e| { eprintln!("[DB] Erreur UPDATE pulls cache: {}", e); Default::default() });

                                cleanup_tmp_for_uuid(&ctx.uuid);
                                remove_ctx_digests_from_quarantine(ctx, &pool);

                                should_cleanup = true;

                            }
                            Err(_) => {
                                eprintln!("[PullContext] Pull invalide");
                                //
                                cleanup_tmp_for_uuid(&ctx.uuid);
                                remove_ctx_digests_from_quarantine(ctx, &pool);
                                drop(list);
                                dec_active(&pull_contexts, context_uuid).await;

                                let mut list = pull_contexts.lock().await;
                                list.retain(|c| c.uuid != context_uuid);
                                return Response::builder()
                                    .status(StatusCode::FORBIDDEN)
                                    .body(Body::from("Digest mismatch detected"))
                                    .unwrap();
                            }
                        }

                    }

                    //On clone le notify AVANT de sortir du lock
                    let notify = {
                        if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                            ctx.notify_zero.clone()
                        } else {
                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Digest mismatch detected"))
                                .unwrap();
                        }
                    };

                    drop(list);
                    // Décrémenter le compteur AVANT de retirer le contexte
                    dec_active(&pull_contexts, context_uuid).await;

                    if should_cleanup {
                        // 🔴 CHECK IMMÉDIAT
                        let zero = {
                            let list = pull_contexts.lock().await;
                            if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                                ctx.active_requests.load(Ordering::SeqCst) == 0
                            } else {
                                true
                            }
                        };

                        if !zero {
                            notify.notified().await;
                        }

                        let mut list = pull_contexts.lock().await;
                        list.retain(|c| c.uuid != context_uuid);
                    }


                    return resp;
                }
                else 
                {
                    println!("[CACHE] Digest pas trouvée dans le cache -> GET upstream -> quarantine ->  Scan");
                }

            }
        }
    }

    //Pas sur d'etre necessaire
    //A ce moment on sait que le digest n'est pas dans le cache
    {
        let mut list = pull_contexts.lock().await;
        if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) 
        {
            ctx.in_cache = Some(false);
        }
    }




     
    //On check blacklist 
    if req.method() == Method::HEAD || req.method() == Method::GET
    {  
        // Vérifier la blacklist
        if let Some(resp) = check_manifest_in_list(context_uuid, &pull_contexts, method.clone(), "blacklist", &pool).await {
            println!("Image dans blacklist");
            {
                let mut list = pull_contexts.lock().await;
                if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) 
                {
                    ctx.in_blacklist = Some(true);
                }
            }
            //Les digests deja stockés en quarantaine ne sont pas supprimés 
            dec_active(&pull_contexts, context_uuid).await;

            let mut list = pull_contexts.lock().await;
            list.retain(|c| c.uuid != context_uuid);
            return resp; // si dans blacklist, on renvoie la réponse FORBIDDEN
        }
    }
    else 
    {
        //A ce moment on sait que le digest n'est pas en blacklist
        {
            let mut list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) 
            {
                ctx.in_blacklist = Some(false);
            }
        }
    }
    //Verifier dans la whitelist
    if let Some(_) = check_manifest_in_list(context_uuid, &pull_contexts, method.clone(), "whitelist", &pool).await 
    {
        println!("Image dans whitelist");

        {
            let mut list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) 
            {
                ctx.in_whitelist = Some(true);
            }
        }

        //On redirige la requete vers le repo upstream
        let upstream = match get_response_from_upstream(req, client).await {
            Ok(resp) => resp,  // upstream ok
            Err(resp) => 
            {
                dec_active(&pull_contexts, context_uuid).await;
                return resp;
            } // upstream KO → renvoyer directement la réponse
        };

        //On extrait la reponse upstream
        let status = upstream.status();
        let headers = upstream.headers().clone();

        // ✅ LIMITE TAILLE DES BLOBS
        if let Err(e) = check_blob_size(&path, &headers) {
            eprintln!("[SECURITY] {} | ip={} path={}", e, client_ip, path);
            dec_active(&pull_contexts, context_uuid).await;
            let mut list = pull_contexts.lock().await;
            list.retain(|c| c.uuid != context_uuid);
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from("Blob trop volumineux"))
                .unwrap();
        }
        let bytes = upstream.bytes().await.unwrap_or_default(); // consomme `upstream`

        // ✅ VÉRIFICATION CRYPTOGRAPHIQUE
        let docker_content_digest = headers
            .get("Docker-Content-Digest")
            .and_then(|v| v.to_str().ok());

        if method == Method::GET {
            if let Err(e) = verify_content_digest(&path, &bytes, docker_content_digest) {
                eprintln!("[SECURITY] {} | ip={} path={}", e, client_ip, path);
                dec_active(&pull_contexts, context_uuid).await;
                let mut list = pull_contexts.lock().await;
                list.retain(|c| c.uuid != context_uuid);
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("Digest mismatch"))
                    .unwrap();
            }
        }
        //On laisse tout passer
        let mut resp = Response::builder().status(status);
        for (k, v) in headers.iter() {
            resp = resp.header(k, v);
        }

        //Check si dernière requete 
        let mut list = pull_contexts.lock().await;

        let mut should_cleanup = false;

        if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) 
        {
            if ctx.digests_expected.len() > 1
            {
                //On compare les digests expected et ceux réellement téléchargés
                match verify_downloaded_digests(ctx) {
                    Ok(DigestVerificationState::InProgress) => {
                        // pull normal, on laisse continuer
                        //println!("Pull en cours ");
                    }
                    Ok(DigestVerificationState::Completed) => 
                    {
                        println!("[PullContext] Pull COMPLET pour uuid={}", ctx.uuid);

                        sqlx::query("UPDATE pulls SET scan_completed = true, decision_final = 'ALLOW', last_activity = NOW() WHERE uuid = $1::uuid")
                            .bind(context_uuid.to_string())
                            .execute(&pool)
                            .await
                            .unwrap_or_else(|e| { eprintln!("[DB] Erreur UPDATE pulls cache: {}", e); Default::default() });

                        //Mettre la variable scan_completed a true
                        ctx.pull_completed = true;

                        should_cleanup = true;

                        cleanup_tmp_for_uuid(&ctx.uuid);

                    }
                    Err(_) => {
                        eprintln!("[PullContext] Pull invalide");
                        // Libérer le contexte si nécessaire
                        drop(list);
                        dec_active(&pull_contexts, context_uuid).await;

                        let mut list = pull_contexts.lock().await;
                        list.retain(|c| c.uuid != context_uuid);

                        return Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from("Digest mismatch detected"))
                            .unwrap();
                    }
                }
            }
            //Sauvegarde en cache
            if method == Method::GET 
            {
                if path.contains("/manifests/")
                    || path.contains("/blobs/")
                    || path.contains("/referrers/")
                {
                    println!("Ecriture des fichiers en cache");
                    save_to_cache(&path, &bytes, ctx, &pool);
                }
            }
        } 

        //On clone le notify AVANT de sortir du lock
        let notify = {
            if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                ctx.notify_zero.clone()
            } else {
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("Digest mismatch detected"))
                    .unwrap();
            }
        };

        drop(list);
        dec_active(&pull_contexts, context_uuid).await;

        if should_cleanup {
            // 🔴 CHECK IMMÉDIAT
            let zero = {
                let list = pull_contexts.lock().await;
                if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                    ctx.active_requests.load(Ordering::SeqCst) == 0
                } else {
                    true
                }
            };

            if !zero {
                notify.notified().await;
            }

            let mut list = pull_contexts.lock().await;
            list.retain(|c| c.uuid != context_uuid);
        }
        return resp.body(Body::from(bytes)).unwrap();
    }
    else 
    {
        //A ce moment on sait que le digest n'est pas en whitelist
        {
            let mut list = pull_contexts.lock().await;
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) 
            {
                ctx.in_whitelist = Some(false);
            }
        }
    }



    //-------------Cas ou le fichier n'est ni en cache, ni en whitelist, ni en blacklist-------------

    //On redirige la requete vers le repo upstream
    let upstream = match get_response_from_upstream(req, client.clone()).await {
        Ok(resp) => resp,  // upstream ok
        Err(resp) =>
        { 
            //drop(list);
            dec_active(&pull_contexts, context_uuid).await;
            return resp;// upstream KO → renvoyer directement la réponse
        }
    };

    //On extrait la reponse upstream
    let status = upstream.status();
    let headers = upstream.headers().clone();

    // ✅ LIMITE TAILLE DES BLOBS
    if let Err(e) = check_blob_size(&path, &headers) {
        eprintln!("[SECURITY] {} | ip={} path={}", e, client_ip, path);
        dec_active(&pull_contexts, context_uuid).await;
        let mut list = pull_contexts.lock().await;
        list.retain(|c| c.uuid != context_uuid);
        return Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(Body::from("Blob trop volumineux"))
            .unwrap();
    }
    let bytes = upstream.bytes().await.unwrap_or_default(); // consomme `upstream`


    // ✅ VÉRIFICATION CRYPTOGRAPHIQUE DU DIGEST
    let docker_content_digest = headers
        .get("Docker-Content-Digest")
        .and_then(|v| v.to_str().ok());

    if method == Method::GET {
        if let Err(e) = verify_content_digest(&path, &bytes, docker_content_digest) {
            eprintln!("[SECURITY] {} | ip={} path={}", e, client_ip, path);
            dec_active(&pull_contexts, context_uuid).await;
            let mut list = pull_contexts.lock().await;
            list.retain(|c| c.uuid != context_uuid);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Digest mismatch"))
                .unwrap();
        }
    }

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

        if is_manifest_list {
            if let Err(reason) = validate_manifest_list(&bytes) {
                eprintln!("[MANIFEST VALIDATION] Manifest-list invalide: {} | path={}", reason, path);
                dec_active(&pull_contexts, context_uuid).await;
                let mut list = pull_contexts.lock().await;
                list.retain(|c| c.uuid != context_uuid);
                return Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("Manifest-list non conforme"))
                    .unwrap();
            }
            println!("[MANIFEST VALIDATION] Manifest-list conforme: {}", path);
        }
    }







    // ═══════════════════════════════════════════════════════════════
    // POINT DE BLOCAGE : GET manifest arch-spécifique
    // À ce stade : os/arch connus, manifest-list déjà passé, 
    // digests_expected vient d'être rempli dans get_pull_context.
    // On préfetch tout + scan final avant de répondre au client.
    // ═══════════════════════════════════════════════════════════════
    let scan_already_done = {
        let list = pull_contexts.lock().await;
        list.iter()
            .find(|c| c.uuid == context_uuid)
            .map(|c| c.scan_final_done)
            .unwrap_or(true)
    };

    if method == Method::GET && path.contains("/manifests/") && path.contains("sha256:") && !scan_already_done
    {
        // Vérifier qu'on est sur le manifest arch-spécifique :
        // digests_expected > 1 signifie que predict_digests vient de tourner
        // (rempli dans get_pull_context au GET du manifest arch-spécifique)
        let is_arch_manifest = {
            let list = pull_contexts.lock().await;
            list.iter()
                .find(|c| c.uuid == context_uuid)
                .map(|ctx| {
                    ctx.digests_expected.len() > 1
                        && ctx.os != "unknown"
                        && ctx.arch != "unknown"
                        && !ctx.check_if_verify_digest_completed
                })
                .unwrap_or(false)
        };

        if is_arch_manifest {
            println!(
                "[PREFETCH] Manifest arch-spécifique détecté — prefetch + scan final | uuid={}",
                context_uuid
            );

            // 1. Cloner le contexte pour le prefetch (hors lock)
            let ctx_for_prefetch = {
                let list = pull_contexts.lock().await;
                list.iter().find(|c| c.uuid == context_uuid).cloned()
            };

            if let Some(ctx_snapshot) = ctx_for_prefetch {
                // 2. Prefetch tous les artefacts en quarantaine
                if let Err(e) =
                    prefetch_expected_to_quarantine(&client, &ctx_snapshot, &pool).await
                {
                    eprintln!("[PREFETCH] Erreur: {} | uuid={}", e, context_uuid);
                    dec_active(&pull_contexts, context_uuid).await;
                    let mut list = pull_contexts.lock().await;
                    list.retain(|c| c.uuid != context_uuid);
                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Erreur préchargement quarantaine"))
                        .unwrap();
                }

                // 3. Marquer tous les digests expected comme téléchargés dans le contexte
                //    (manifest_digests + blob_digests) pour que verify_downloaded_digests
                //    retourne Completed immédiatement après
                {
                    let mut list = pull_contexts.lock().await;
                    if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
                        for d in ctx.digests_expected.clone() {
                            // On détermine le type via la présence du fichier en quarantaine
                            let q_manifest = format!(
                                "quarantaine/{}/{}/manifests/sha256/{}.json",
                                ctx.registry, ctx.repository, d.value
                            );
                            let q_blob = format!(
                                "quarantaine/{}/{}/blobs/sha256/{}",
                                ctx.registry, ctx.repository, d.value
                            );
                            if Path::new(&q_manifest).exists() {
                                if !ctx.manifest_digests.contains(&d) {
                                    ctx.manifest_digests.push(d.clone());
                                }
                            } else if Path::new(&q_blob).exists() {
                                if !ctx.blob_digests.contains(&d) {
                                    ctx.blob_digests.push(d.clone());
                                }
                            }
                        }
                        ctx.check_if_verify_digest_completed = true;
                    }
                }
                let ctx_snapshot = {
                    let list = pull_contexts.lock().await;
                    list.iter().find(|c| c.uuid == context_uuid).cloned()
                };

                let Some(ctx_snapshot) = ctx_snapshot else {
                    dec_active(&pull_contexts, context_uuid).await;
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from("Contexte introuvable"))
                        .unwrap();
                };

                // 4. Attendre que active_requests == 0 (pas d'autres requêtes en cours)
                //    puis lancer le scan final — même pattern que l'existant
                let notify = {
                    let list = pull_contexts.lock().await;
                    list.iter()
                        .find(|c| c.uuid == context_uuid)
                        .map(|c| c.notify_zero.clone())
                };

                if let Some(notify) = notify 
                {
                    dec_active(&pull_contexts, context_uuid).await;

                    let already_zero = {
                        let list = pull_contexts.lock().await;
                        list.iter()
                            .find(|c| c.uuid == context_uuid)
                            .map(|c| c.active_requests.load(Ordering::SeqCst) == 0)
                            .unwrap_or(true)
                    };

                    if !already_zero {
                        notify.notified().await;
                    }

                    // 5. Scan final
                    let scan_result =
                        launch_final_scan(&pull_contexts, context_uuid, &path, &pool).await;

                    match scan_result {
                        Some(ScanDecision::ALLOW) => {
                            println!("[SECURITY CHECK] Image conforme -> autorisation du pull");

                            sqlx::query("UPDATE pulls SET decision_final = 'ALLOW', last_activity = NOW() WHERE uuid = $1::uuid")
                            .bind(context_uuid.to_string())
                            .execute(&pool)
                            .await
                            .unwrap_or_else(|e| { eprintln!("[DB] Erreur UPDATE pulls cache: {}", e); Default::default() });

                            {
                                let mut list = pull_contexts.lock().await;
                                if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
                                    ctx.scan_status = Some("ALLOW".to_string());
                                    ctx.pull_completed = false;
                                    ctx.check_if_verify_digest_completed = false;
                                    //ctx.manifest_digests.clear();
                                    ctx.blob_digests.clear();
                                    ctx.referrers_digests.clear();
                                }
                            }


                            //Ajouter a whitelist 
                            if let Err(e) = add_context_to_blacklist_or_whitelist(ctx_snapshot.clone(), "whitelist", &pool).await{
                                eprintln!("[WHITELIST ERROR] {}", e);
                            }

                            // Servir le manifest courant arch-spécifique depuis la quarantaine
                            let response = match serve_from_quarantine(&path, &ctx_snapshot) 
                            {
                                Some(r) => r,
                                None => {
                                    eprintln!("[PREFETCH SCAN] serve_from_quarantine vide — fallback bytes upstream");
                                    let mut resp = Response::builder().status(status);
                                    for (k, v) in headers.iter() {
                                        resp = resp.header(k, v);
                                    }
                                    resp.body(Body::from(bytes)).unwrap()
                                }
                            };
                            //remove_ctx_digests_from_quarantine(&ctx_snapshot, &pool);
                            copy_ctx_from_quarantine_to_cache(&ctx_snapshot, &pool);
                            remove_ctx_digests_from_quarantine(&ctx_snapshot, &pool);
                            cleanup_tmp_for_uuid(&ctx_snapshot.uuid);
                            return response;

                        }
                        Some(ScanDecision::DENY) => 
                        {      
                            println!("[SECURITY CHECK] Image non conforme -> bloquage du pull");
                            sqlx::query("UPDATE pulls SET scan_completed = true, decision_final = 'DENY', last_activity = NOW() WHERE uuid = $1::uuid")
                            .bind(context_uuid.to_string())
                            .execute(&pool)
                            .await
                            .unwrap_or_else(|e| { eprintln!("[DB] Erreur UPDATE pulls cache: {}", e); Default::default() });


                            //Ajouter a blacklist
                            if let Err(e) = add_context_to_blacklist_or_whitelist(ctx_snapshot.clone(), "blacklist", &pool).await {
                                eprintln!("[BLACKLIST ERROR] {}", e);
                            }
                            cleanup_tmp_for_uuid(&ctx_snapshot.uuid);
                            remove_ctx_digests_from_quarantine(&ctx_snapshot, &pool);

                            {
                                let mut list = pull_contexts.lock().await;
                                list.retain(|c| c.uuid != context_uuid);
                            }

                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Image refused by security scan"))
                                .unwrap();
                        }
                        /* 
                        Some(ScanDecision::PENDING) => {
                            println!("[SECURITY CHECK] Image conforme -> autorisation du pull");

                            sqlx::query("UPDATE pulls SET decision_final = 'ALLOW', last_activity = NOW() WHERE uuid = $1::uuid")
                            .bind(context_uuid.to_string())
                            .execute(&pool)
                            .await
                            .unwrap_or_else(|e| { eprintln!("[DB] Erreur UPDATE pulls cache: {}", e); Default::default() });

                            {
                                let mut list = pull_contexts.lock().await;
                                if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
                                    ctx.scan_status = Some("ALLOW".to_string());
                                    ctx.pull_completed = false;
                                    ctx.check_if_verify_digest_completed = false;
                                    //ctx.manifest_digests.clear();
                                    ctx.blob_digests.clear();
                                    ctx.referrers_digests.clear();
                                }
                            }


                            //Ajouter a whitelist 
                            if let Err(e) = add_context_to_blacklist_or_whitelist(ctx_snapshot.clone(), "whitelist", &pool).await{
                                eprintln!("[WHITELIST ERROR] {}", e);
                            }

                            // Servir le manifest courant arch-spécifique depuis la quarantaine
                            let response = match serve_from_quarantine(&path, &ctx_snapshot) 
                            {
                                Some(r) => r,
                                None => {
                                    eprintln!("[PREFETCH SCAN] serve_from_quarantine vide — fallback bytes upstream");
                                    let mut resp = Response::builder().status(status);
                                    for (k, v) in headers.iter() {
                                        resp = resp.header(k, v);
                                    }
                                    resp.body(Body::from(bytes)).unwrap()
                                }
                            };
                            copy_ctx_from_quarantine_to_cache(&ctx_snapshot, &pool);
                            remove_ctx_digests_from_quarantine(&ctx_snapshot, &pool);
                            cleanup_tmp_for_uuid(&ctx_snapshot.uuid);
                            return response;

                        }*/

                         
                        Some(ScanDecision::PENDING) => {

                            cleanup_tmp_for_uuid(&ctx_snapshot.uuid);

                            //Image continue d'etre scanné puis est soit ajouté a la blacklist / whitelist ( + cache) coté orchestrateur   
                            //Notify dashboard user quand image prete   

                            println!("[SCAN FINAL] PENDING -> Scan en cours");
                            
                            let mut list = pull_contexts.lock().await;
                            list.retain(|c| c.uuid != context_uuid);
                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Image en cours de scan"))
                                .unwrap();
                        }
                        
                        
                        None => {
                            println!("[SECURITY CHECK]- Race condition détectée ou erreur lors du scan final");

                            {
                                let mut list = pull_contexts.lock().await;
                                list.retain(|c| c.uuid != context_uuid);
                            }
                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Image refused by security scan"))
                                .unwrap();
                        }
                    }

                }
            }
        }
    }



    //------------- Cas HEAD et Manifest List -------------
    dec_active(&pull_contexts, context_uuid).await; //Appel is_allowed ici

    // Construire la réponse finale pour le client -> 200 OK
    let mut resp = Response::builder().status(status);
    for (k, v) in headers.iter() {
        resp = resp.header(k, v);
    }

    //LOG
    /* 
    println!("[RESP] status={} headers:", status);
    for (k, v) in headers.iter() {
        println!("  {}: {}", k, v.to_str().unwrap_or("?"));
    }*/

    resp.body(Body::from(bytes)).unwrap()

}


#[tokio::main]
async fn main() -> Result<()> {

    //Gestion Multi-Certificats
    let content = std::fs::read_to_string("registry_whitelist.json")
        .expect("[TLS] registry_whitelist.json introuvable");
    let registries: Vec<String> = serde_json::from_str(&content)
        .expect("[TLS] registry_whitelist.json invalide");

    let mut resolver = MultiCertResolver::new();
    for registry in &registries {
        resolver.add(registry)?;
    }

    let tls = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));


    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://docdockgo_admin:docdockgo@localhost:5432/docdockgo".to_string());

    let pool = db::init_pool(&database_url).await?;

        
    let listener = TcpListener::bind(("0.0.0.0", 443)).await?;

    //[HANDSHAKE]
    // 1 - Le client initie la connexion TLS 
    // 2 - Le proxy envoie le certificat server (du bon registre)
    // 3 - Si le certificat est signé par la CA, le certificat est accepté car la CA du proxy est trust par le client
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let client = Client::builder().use_rustls_tls().build()?;

    // State partagé pour la liste de contexte pour chaques pull
    let pull_context: PullContextList = Arc::new(TokioMutex::new(Vec::new()));

    //Ajout de la fonction de timout 
    check_timout(pull_context.clone(), &pool);


    println!("✅ MITM Docker registry en écoute sur https://registry-1.docker.io:443");

    let rate_limiter = Arc::new(RateLimiter::new(100, 60));
    rate_limiter.clone().start_cleanup();

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let client = client.clone();
        let pull_contexts = pull_context.clone();
        let pool = pool.clone();
        let rate_limiter = rate_limiter.clone();

        
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
                        let pool = pool.clone();
                        let rate_limiter = rate_limiter.clone();
                        async move 
                        { 
                            // stocker addr dans la requête pour handle
                            req.extensions_mut().insert(addr);
                            Ok::<_, Infallible>(handle(req, client,pull_contexts, pool, rate_limiter).await) 
                        }
                    });
                let _ = Http::new()
                .max_buf_size(16 * 1024)        // 16 KB max buffer
                .serve_connection(tls, service)
                .await;
            }
        });
    }
}


/// 🔑 Chargement des certificats TLS
fn load_certs(path: &str) -> Result<Vec<Certificate>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    let certs = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|c| Certificate(c.to_vec()))
        .collect();
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKey> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);

    let keys: Vec<_> = pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].secret_pkcs8_der().to_vec()));
    }

    let mut reader = BufReader::new(File::open(path)?);
    let keys: Vec<_> = rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    if !keys.is_empty() {
        return Ok(PrivateKey(keys[0].secret_pkcs1_der().to_vec()));
    }

    Err(anyhow::anyhow!("No private keys found in {}", path))
}

pub fn detect_client_type(req: &Request<Body>) -> &'static str {
    let ua = req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if ua.contains("containers/") {
        "podman"
    } else if ua.to_lowercase().contains("docker") {
        "docker"
    } else {
        "unknown"
    }
}
