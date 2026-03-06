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
use pull_context::{
    get_pull_context, 
    digest_process_for_head,
};


// Déclare le module
mod predict_digests_utils;

mod registry_auth;

// Puis importe les fonctions dont tu as besoin
use predict_digests_utils::{
    get_os_arch_for_digest,
    //fetch_and_process_manifest,
    predict_digests,
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
    get_dockerhub_token,
    remove_ctx_digests_from_quarantine,
    dec_active,
    copy_ctx_from_quarantine_to_cache,
    is_registry_allowed,
};



#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Digest {
    algorithm: String, // ex: "sha256"
    value: String,     // hex
}

#[derive(Debug, Serialize, Deserialize)]
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
    scan_final_done: bool,
    in_whitelist: Option<bool>,
    in_blacklist: Option<bool>,
    in_cache: Option<bool>,
    check_if_verify_digest_completed: bool,

    pub scan_status: Option<String>, // "ALLOW", "PENDING", "DENY" ou None si pas encore de scan

    pub active_requests: AtomicUsize,

    #[serde(skip_serializing, skip_deserializing)]
    pub notify_zero: Arc<Notify>,
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
const CONTEXT_TIMEOUT: Duration = Duration::from_secs(200);

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
) -> Option<bool> {

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
    let state = is_allowed(&mut ctx_clone, path, "scan_final").await;



    let mut list = pull_contexts.lock().await;
    let ctx = list.iter_mut().find(|c| c.uuid == uuid)?;

    if state == "ALLOW" || state == "PENDING" {
        println!("[SCAN FINAL] OK → cache");

        //Ajouter a whitelist 
        if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "whitelist") {
            eprintln!("[WHITELIST ERROR] {}", e);
        }
        copy_ctx_from_quarantine_to_cache(ctx);
        cleanup_tmp_for_uuid(&ctx.uuid);
        remove_ctx_digests_from_quarantine(ctx);

        list.retain(|c| c.uuid != uuid);
        return Some(true);
    }

    if state == "DENY" {
        println!("[SCAN FINAL] REFUSÉ");

        //Ajouter a blacklist
        if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "blacklist") {
            eprintln!("[BLACKLIST ERROR] {}", e);
        }

        cleanup_tmp_for_uuid(&ctx.uuid);
        remove_ctx_digests_from_quarantine(ctx);
        list.retain(|c| c.uuid != uuid);
        return Some(false);
    }

    println!("[SCAN FINAL] état inconnu");
    None
}

async fn is_allowed(ctx: &mut PullContext, path: &str, flag: &str) -> String {
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

    // ------------------------------------------------------------------
    // On envoie uniquement le digest demandé dans l'URL
    // ------------------------------------------------------------------
    else 
    {

        if let Some(pos) = path.find("sha256:") {
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
    }

    println!("file_path : {}", base_dir);
    // 5) POST multipart (inchangé)
    let client = reqwest::Client::new();
    let resp = client.post(ORCH_URL).multipart(form).send().await;

    let state = match resp {
        Ok(r) => {
            let status = r.status();
            println!("[ORCH CALL] status={}", status);

            // 🔴 lire TOUJOURS la réponse en texte brut
            let text = r.text().await.unwrap_or_default();
            println!("[ORCH RAW RESP] {}", text);

            if !status.is_success() {
                println!("[ORCH ERROR] orchestrateur a renvoyé non-200");
                return "PENDING".to_string();
            }

            match serde_json::from_str::<OrchestratorResp>(&text) {
                Ok(body) => {
                    println!(
                        "[ORCH RESP] pull_id={} state={}",
                        body.pull_id, body.state
                    );
                    body.state.trim().to_uppercase()
                }
                Err(e) => {
                    println!("[ORCH PARSE ERROR] {:?}", e);
                    "PENDING".to_string()
                }
            }
        }
        Err(e) => {
            println!("[ORCH CALL] request error: {:?}", e);
            "PENDING".to_string()
        }
    };


    println!("==================================================================================");

    match state.as_str() {
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

    state
}



async fn handle(req: Request<Body>, client: Client, pull_contexts: PullContextList, ) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    //let headers = req.headers().clone();

    // Normaliser sha256- → sha256: pour les registres OCI
    let path = path.replace("sha256-", "sha256:");
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


    let mut pull_completed = false;
    //recupère le contexte du pull en cours
    // /!\ Attention : Scan de haut niveau appelé dans tout les cas meme si le pull est déjà dans la whitelist ou blacklist, ou même dans le cache (pour le moment) /!\
    let context_uuid = match get_pull_context(&req, &parts, &client_ip, &pull_contexts, &client, &path).await {
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

    };

    //Ajoute la requete courrante au context dans active_request 
    {
        let mut list = pull_contexts.lock().await;
        if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
            // Incrémente atomiquement
            let atomic_count_request = ctx.active_requests.fetch_add(1, Ordering::SeqCst) + 1;

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

                                //Ajouter a whitelist
                                if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "whitelist") {
                                    eprintln!("[WHITELIST ERROR] {}", e);
                                }
                                cleanup_tmp_for_uuid(&ctx.uuid);
                                remove_ctx_digests_from_quarantine(&ctx);

                                should_cleanup = true;

                            }
                            Err(_) => {
                                eprintln!("[PullContext] Pull invalide");
                                //
                                cleanup_tmp_for_uuid(&ctx.uuid);
                                remove_ctx_digests_from_quarantine(&ctx);
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




     
    //On check blacklist que sur les HEAD 
    if req.method() == Method::HEAD
    {  
        // Vérifier la blacklist
        if let Some(resp) = check_manifest_in_list(context_uuid, &pull_contexts, method.clone(), "blacklist").await {
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
    if let Some(response) = check_manifest_in_list(context_uuid, &pull_contexts, method.clone(), "whitelist").await 
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
        let bytes = upstream.bytes().await.unwrap_or_default(); // consomme `upstream`

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
            // 🔹 Sauvegarde en cache
            if method == Method::GET 
            {
                if path.contains("/manifests/")
                    || path.contains("/blobs/")
                    || path.contains("/referrers/")
                {
                    println!("Ecriture des fichiers en cache");
                    save_to_cache(&path, &bytes, ctx);
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
    let upstream = match get_response_from_upstream(req, client).await {
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
    if method == Method::GET 
    {
        if path.contains("/manifests/")
            || path.contains("/blobs/")
            || path.contains("/referrers/")
        {
            println!("Ecriture des fichiers en quarantaine");
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
        if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) 
        {

        // On ne déclenche le "Pull COMPLET" que si la requête est un GET pour laisser passer les HEAD
        // et que digests_expected contient plus d'un élément
            if ctx.digests_expected.len() > 1
            {

                if ctx.check_if_verify_digest_completed == false
                {
                    //On compare les digests expected et ceux réellement téléchargés
                    match verify_downloaded_digests(ctx) {
                        Ok(DigestVerificationState::InProgress) => {
                            // pull normal, on laisse continuer
                        }
                        Ok(DigestVerificationState::Completed) => 
                        {

                            ctx.check_if_verify_digest_completed = true;

                            println!("[PullContext] Pull COMPLET pour uuid={}", ctx.uuid);

                            pull_completed = true;

                            println!("[HANDLE] - Call API pour scan Final");

                            // on clone le notify AVANT de sortir du lock
                            let notify = ctx.notify_zero.clone();
                            let ctx_clone = ctx.clone();

                            // ⚠️ IMPORTANT : on sort du mutex AVANT d'attendre
                            drop(list);

                            // 1️⃣ on décrémente CETTE requête
                            dec_active(&pull_contexts, context_uuid).await;


                            // 2️⃣ Vérifier d'abord si déjà à 0 avant d'attendre
                            // 🔔 Ce pattern permet d'éviter un blocage infini si la notification a déjà été émise avant qu'on commence à l'écouter.
                            let already_zero = {
                                let list = pull_contexts.lock().await;
                                if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid) {
                                    ctx.active_requests.load(Ordering::SeqCst) == 0
                                } else {
                                    true
                                }
                            };

                            // 3️⃣ N'attendre que si pas encore à 0
                            if !already_zero {
                                notify.notified().await;
                            }

                            // 3️⃣ maintenant scan final
                            let status_scan_final =
                                launch_final_scan(&pull_contexts, context_uuid, &path).await;

                            match status_scan_final {
                                Some(true) => {
                                    println!("[SECURITY CHECK] Image conforme -> ajout whitelist");

                                    //Ajouter a whitelist
                                    if let Err(e) = add_context_to_blacklist_or_whitelist(ctx_clone.clone(), "whitelist") {
                                        eprintln!("[WHITELIST ERROR] {}", e);
                                    }

                                    cleanup_tmp_for_uuid(&ctx_clone.uuid);
                                    remove_ctx_digests_from_quarantine(&ctx_clone);


                                    let mut list = pull_contexts.lock().await;
                                    list.retain(|c| c.uuid != context_uuid);

                                    let mut resp = Response::builder().status(status);
                                    for (k, v) in headers.iter() {
                                        resp = resp.header(k, v);
                                    }
                                    return resp.body(Body::from(bytes)).unwrap();
                                }
                                Some(false) => {

                                    //Ajouter a whitelist
                                    if let Err(e) = add_context_to_blacklist_or_whitelist(ctx_clone.clone(), "whitelist") {
                                        eprintln!("[WHITELIST ERROR] {}", e);
                                    }
                                    cleanup_tmp_for_uuid(&ctx_clone.uuid);
                                    remove_ctx_digests_from_quarantine(&ctx_clone);

                                    println!("[SECURITY CHECK] Image non conforme -> bloquage du pull");

                                    let mut list = pull_contexts.lock().await;
                                    list.retain(|c| c.uuid != context_uuid);
                                    return Response::builder()
                                        .status(StatusCode::FORBIDDEN)
                                        .body(Body::from("Image refused by security scan"))
                                        .unwrap();
                                }
                                None => {
                                    println!("[SECURITY CHECK]- Race condition détectée ou erreur lors du scan final");

                                    let mut list = pull_contexts.lock().await;
                                    list.retain(|c| c.uuid != context_uuid);
                                    return Response::builder()
                                        .status(StatusCode::FORBIDDEN)
                                        .body(Body::from("Image refused by security scan"))
                                        .unwrap();
                                }
                            }
                        }

                        Err(_) => {
                            eprintln!("[PullContext] Pull invalide");

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
            }
        } 
        else {
            // Si ce n'est pas un GET ou digests_expected <= 1, on ne fait rien
        }



        //-------------Cas ou le fichier n'est ni en cache, ni en whitelist, ni en blacklist et on ets pas a la dernière requete -------------
        // -> Cas ou on scan les digests un par un 

        //[Appel API] -> pour envoyer les données au scan de sécurité

        //Proxy -> API -> Scanner
        //Proxy <- API <- Scanner

        if method == Method::GET 
        {
            if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) 
            {
                //Scan chaques digests uniquement si le scan d'avant est en PENDING
                if ctx.scan_status.as_deref() == Some("PENDING")
                {
                    // On continue ou on stop le pull en fonction du scan de sécurité
                    println!("[GetPullContext] - Call API pour scan par digest");
                    match is_allowed(ctx, &path, "flagg").await.as_str() 
                    {
                        "DENY" => 
                        {
                            //
                            //------------- Cas ou le fichier est refusé par le scan de sécurité -------------
                            println!("[SCAN BY DIGEST] Digest DENY -> bloquage du pull + ajout image en blacklist");

                            if let Some(ctx) = list.iter().find(|c| c.uuid == context_uuid).cloned() 
                            {
                                println!("[DEBUG] Contexte trouvé pour UUID={}", context_uuid);

                                // blacklist
                                if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "blacklist") {
                                    eprintln!("[BLACKLIST ERROR] {}", e);
                                }

                                cleanup_tmp_for_uuid(&ctx.uuid);
                                remove_ctx_digests_from_quarantine(&ctx);


                            }
                            else 
                            {
                                println!("[DEBUG] Aucun contexte trouvé pour UUID={}", context_uuid);
                            }

                            drop(list);
                            dec_active(&pull_contexts, context_uuid).await;

                            let mut list = pull_contexts.lock().await;
                            list.retain(|c| c.uuid != context_uuid);
                            //Cas ou l'image est refusé par le scan de securité 
                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Image refusée par le scan de sécurité"))
                                .unwrap();
                        }
                        "ALLOW" => 
                        {
                            println!("[SCAN BY DIGEST] Digest ALLOW -> continuation du pull + ajout image en whitelist");
                            //Ajout a la whitelist
                            if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "whitelist") {
                                eprintln!("[WHITELIST ERROR] {}", e);   
                            
                            }
                        }
                        "PENDING" => 
                        {
                            println!("[SCAN BY DIGEST] Digest PENDING -> continuation du pull");
                        }
                        other => 
                        {
                            eprintln!("[WARNING] État inattendu de l'orchestrateur: {}", other);
                            //par défaut on considère comme PENDING
                        }
                    }
                }
            }
        }
    }

    //------------- Cas ou le digest est accepté par le scan de sécurité -------------


    //Appeller la fonction qui va supprimer le digest de la quarantaine et le mettre en cache 
    

    dec_active(&pull_contexts, context_uuid).await; //Appel is_allowed ici


    // Construire la réponse finale pour le client -> 200 OK
    let mut resp = Response::builder().status(status);
    for (k, v) in headers.iter() {
        resp = resp.header(k, v);
    }

    resp.body(Body::from(bytes)).unwrap()

}


#[tokio::main]
async fn main() -> Result<()> {
    
    
    /*let certs = load_certs("certs-mitm/registry-1.docker.io.crt")?;
    let key = load_private_key("certs-mitm/registry-1.docker.io.key")?;

    let tls = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    */

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
