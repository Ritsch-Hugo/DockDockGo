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

use std::fs;
use std::path::Path;
use sha2::{Digest as Sha2Digest};

use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex as TokioMutex;


use uuid::Uuid;
use tokio::time::{Duration};

use serde::{Serialize, Deserialize};

use std::time::Instant;//pour le timeout des pull context 2

use reqwest::multipart;

mod pull_context;
use pull_context::{
    get_pull_context, 
    digest_process_for_head,
};


// Déclare le module
mod predict_digests_utils;

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
};



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
    scan_final_done: bool,
    in_whitelist: Option<bool>,
    in_blacklist: Option<bool>,
    in_cache: Option<bool>,

    pub scan_status: Option<String>, // "ALLOW", "PENDING", "DENY" ou None si pas encore de scan

    pub active_requests: usize,
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
const CONTEXT_TIMEOUT: Duration = Duration::from_secs(60);

static UPSTREAM: &str = "https://registry-1.docker.io";



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
            scan_status: Some("PENDING".to_string()),
            active_requests: 0,

        }

    }
}


/// 🔐 Politique de sécurité
/*fn is_allowed() -> bool {
    false
}*/

/// 🔐 Politique de sécurité (async)
/// ALLOW ou PENDING => true (on continue)
/// DENY => false (on bloque direct)

async fn is_allowed(ctx: &mut PullContext) -> String {
    #[derive(serde::Deserialize)]
    struct OrchestratorResp {
        pull_id: uuid::Uuid,
        state: String, // "PENDING" | "ALLOW" | "DENY"
    }

    const ORCH_URL: &str = "http://127.0.0.1:3000/v1/decision";

    println!("============================== APPEL ORCHESTRATEUR ==============================");
    println!("uuid={} repo={}:{}", ctx.uuid, ctx.repository, ctx.tag);

    // 1) champ context (inchangé, juste emballé en texte multipart)
    let mut form = multipart::Form::new()
        .text("context", serde_json::to_string(ctx).unwrap_or_else(|_| "{}".to_string()));

    // Helper: ajoute un fichier s'il existe, sinon skip (pas bloquant pour le MVP)
    async fn add_file_if_exists(
        form: multipart::Form,
        field_name: &'static str,
        filename: String,
        path: String,
    ) -> multipart::Form {
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let part = multipart::Part::bytes(bytes).file_name(filename);
                form.part(field_name, part)
            }
            Err(_) => form, // pas trouvé => on ignore
        }
    }

    // Base dir (même logique que save_to_quarantine)
    let base_dir = format!("quarantaine/{}/{}", ctx.registry, ctx.repository);

    // 2) manifests
    for d in &ctx.manifest_digests {
        let filename = format!("{}:{}", d.algorithm, d.value);
        let path = format!("{}/manifests/{}/{}.json", base_dir, d.algorithm, d.value);
        form = add_file_if_exists(form, "manifests", filename, path).await;
    }

    // 3) blobs
    for d in &ctx.blob_digests {
        let filename = format!("{}:{}", d.algorithm, d.value);
        let path = format!("{}/blobs/{}/{}", base_dir, d.algorithm, d.value);
        form = add_file_if_exists(form, "blobs", filename, path).await;
    }

    // 4) referrers
    for d in &ctx.referrers_digests {
        let filename = format!("{}:{}", d.algorithm, d.value);
        let path = format!("{}/referrers/{}/{}.json", base_dir, d.algorithm, d.value);
        form = add_file_if_exists(form, "referrers", filename, path).await;
    }

    // 5) POST multipart
    let client = reqwest::Client::new();
    let resp = client.post(ORCH_URL).multipart(form).send().await;

    //Traietement de la réponse de l'orchestrateur
    let state = match resp {
        Ok(r) => {
            println!("[ORCH CALL] status={}", r.status());
            match r.json::<OrchestratorResp>().await {
                Ok(body) => {
                    println!("[ORCH RESP] body={{ pull_id={}, state={} }}", body.pull_id, body.state);
                    body.state.trim().to_uppercase()
                }
                Err(e) => {
                    println!("[ORCH CALL] parse error: {:?}", e);
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

    match state.as_str() 
    {
        "ALLOW" => {
            println!("Pull autorisé par l'orchestrateur");
            ctx.scan_status = Some("ALLOW".to_string());
            // continuer le pull normalement
        },
        "PENDING" => {
            println!("Pull en attente, décision non finale");
            ctx.scan_status = Some("PENDING".to_string());
            // éventuellement laisser passer mais marquer en attente
        },
        "DENY" => {
            println!("Pull refusé par l'orchestrateur");
            ctx.scan_status = Some("DENY".to_string());
            // bloquer le pull, blacklist si nécessaire
        },
        other => {
            println!("[WARNING] État inattendu reçu: {}", other);
            // par défaut on peut considérer comme "PENDING"
        }
    }

    state // retourne directement "ALLOW", "PENDING" ou "DENY"
}


async fn handle(req: Request<Body>, client: Client, pull_contexts: PullContextList, ) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    //let headers = req.headers().clone();
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
    // /!\ Attention : Scan de haut niveau appelé dans tout les cas meme si le pull est déjà dans la whitelist ou blacklist, ou même dans le cache (pour le moment) /!\
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

    };

    //Ajoute la requete courrante au context dans active_request 
    {
        let mut list = pull_contexts.lock().await;
        if let Some(ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {
            ctx.active_requests += 1;
            println!(
                "[CTX] +1 active_requests={} uuid={}",
                ctx.active_requests, ctx.uuid
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
                            }
                            Err(_) => {
                                eprintln!("[PullContext] Pull invalide");
                                // Libérer le contexte si nécessaire
                                drop(list);
                                dec_active(&pull_contexts, context_uuid, false).await;
                                //list.retain(|c| c.uuid != context_uuid);
                                return Response::builder()
                                    .status(StatusCode::FORBIDDEN)
                                    .body(Body::from("Digest mismatch detected"))
                                    .unwrap();
                            }
                        }

                    }

                    drop(list);
                    dec_active(&pull_contexts, context_uuid, false).await;
                    return resp;
                }
                else 
                {
                    println!("[CACHE] Digest pas trouvée dans le cache -> GET upstream -> quarantine ->  Scan");
                }

            }
        }
    }

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
            //drop(list);
            dec_active(&pull_contexts, context_uuid, false).await;
            return resp; // si dans blacklist, on renvoie la réponse FORBIDDEN
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
                //drop(list);
                dec_active(&pull_contexts, context_uuid, false).await;
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

                    }
                    Err(_) => {
                        eprintln!("[PullContext] Pull invalide");
                        // Libérer le contexte si nécessaire
                        drop(list);
                        dec_active(&pull_contexts, context_uuid, false).await;

                        return Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from("Digest mismatch detected"))
                            .unwrap();
                    }
                }
            }
        } 


        drop(list);
        dec_active(&pull_contexts, context_uuid, false).await;

        return resp.body(Body::from(bytes)).unwrap();
    }



    //-------------Cas ou le fichier n'est ni en cache, ni en whitelist, ni en blacklist-------------

    //On redirige la requete vers le repo upstream
    let upstream = match get_response_from_upstream(req, client).await {
        Ok(resp) => resp,  // upstream ok
        Err(resp) =>
        { 
            //drop(list);
            dec_active(&pull_contexts, context_uuid, false).await;
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
    if method == Method::GET //&& !bytes.is_empty() 
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
        if let Some(mut ctx) = list.iter_mut().find(|c| c.uuid == context_uuid) {

            // On ne déclenche le "Pull COMPLET" que si la requête est un GET pour laisser passer les HEAD
            // et que digests_expected contient plus d'un élément
            if ctx.digests_expected.len() > 1{

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
                         println!("test");

                        //[Appel API] : déclencher scan final avec tout les digests 

                        //Proxy -> API -> Scanner

                        //Proxy <- API <- Scanner

                        //Si Image OK 
                        println!("[HANDLE] - Call API pour scan Final");
                        //appel is _allow
                         
                        match is_allowed(&mut ctx).await.as_str() 
                        {
                            "ALLOW" | "PENDING" => 
                            {
                                println!("[SECURITY CHECK] Image conforme ou en attente -> continuation du pull + ajout whitelist");
                                //Ajout de l'image a la whitelist
                                if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "whitelist") {
                                    eprintln!("[WHITELIST ERROR] {}", e);
                                    
                                }

                                drop(list);
                                dec_active(&pull_contexts, context_uuid, false).await;
                                //return reponse client 
                                let mut resp = Response::builder().status(status);
                                for (k, v) in headers.iter() {
                                    resp = resp.header(k, v);
                                }

                                return resp.body(Body::from(bytes)).unwrap();
                            }
                            //Si Image refusée 
                            "DENY" => 
                            {
                                //Ajout a la blacklist
                                if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "blacklist") {
                                    eprintln!("[BLACKLIST ERROR] {}", e);
                                    
                                }

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

                                drop(list);
                                dec_active(&pull_contexts, context_uuid, false).await;

                                return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Image refused by security scan"))
                                .unwrap();
                            }
                            other => 
                            {
                                eprintln!("[WARNING] État inattendu de l'orchestrateur: {}", other);
                            }
                            
                        }     
                    }
                    Err(_) => {
                        eprintln!("[PullContext] Pull invalide");
                        // Libérer le contexte si nécessaire
                        drop(list);
                        dec_active(&pull_contexts, context_uuid, false).await;
                        //list.retain(|c| c.uuid != context_uuid);
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
                    match is_allowed(ctx).await.as_str() 
                    {
                        "DENY" => 
                        {
                            //
                            //------------- Cas ou le fichier est refusé par le scan de sécurité -------------
                            println!("[SECURITY CHECK] Image non conforme -> bloquage du pull");

                            if let Some(mut ctx) = list.iter().find(|c| c.uuid == context_uuid).cloned() 
                            {

                                println!("[DEBUG] Contexte trouvé pour UUID={}", context_uuid);

                                // blacklist
                                if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "blacklist") {
                                    eprintln!("[BLACKLIST ERROR] {}", e);
                                }


                                //Check si on peut suppr le context
                                println!("activ_request : {}", ctx.active_requests);

                                cleanup_tmp_for_uuid(&ctx.uuid);
                            }
                            else 
                            {
                                println!("[DEBUG] Aucun contexte trouvé pour UUID={}", context_uuid);
                            }

                            drop(list);
                            dec_active(&pull_contexts, context_uuid, false).await;
                            //Cas ou l'image est refusé par le scan de securité 
                            return Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("Image refusée par le scan de sécurité"))
                                .unwrap();
                        }
                        "ALLOW" => 
                        {
                            println!("[SECURITY CHECK] Image conforme -> continuation du pull + ajout whitelist");
                            //Ajout a la whitelist
                            if let Err(e) = add_context_to_blacklist_or_whitelist(ctx.clone(), "whitelist") {
                                eprintln!("[WHITELIST ERROR] {}", e);   
                            
                            }
                        }
                        "PENDING" => 
                        {
                            //println!("[SECURITY CHECK] Image en attente de validation -> continuation du pull en mode PENDING");
                            //On laisse continuer le pull mais on reste en attente pour les prochains digests
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


    //drop(list);
    dec_active(&pull_contexts, context_uuid, false).await;

    // Construire la réponse finale pour le client -> 200 OK
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
