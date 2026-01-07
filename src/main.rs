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
use sha2::{Digest, Sha256};

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex};

use serde_json::Value;

use uuid::Uuid;

#[derive(Clone)]
struct PullContext 
{
    client_ip: String, // IP du client
    client_id: Uuid,
    repo: String,
    tag: Option<String>,

}
struct ImageState {
    blobs_expected: HashSet<String>,  // tous les blobs attendus pour l'image
    blobs_downloaded: HashSet<String> // blobs déjà téléchargés
}

type SharedState = Arc<Mutex<HashMap<String, ImageState>>>;
type PullMap = Arc<Mutex<HashMap<String, PullContext>>>;

static UPSTREAM: &str = "https://registry-1.docker.io";

/// 🔐 Politique de sécurité
fn is_allowed(path: &str, body: &[u8]) -> bool {
    println!("[POLICY] Analyse de {}", path);

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

    println!("[LAST_REQUEST LOG] path: {}, parts: {:?}, repo: {}", path, parts, repo);

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
            println!("[LAST_REQUEST] blobs_expected for {}: {:?}", repo, blobs);

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
            println!("[LAST_REQUEST] blobs_downloaded: {:?}", image_state.blobs_downloaded);
            println!("[LAST_REQUEST] blobs_expected: {:?}", image_state.blobs_expected);

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
    println!("[CACHE] Tag : {}", tag);

    let repo = format!("{}/{}", parts[0], parts[1]);

    println!("[CACHE] Recherche de {} dans {}", path, repo);

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

async fn handle(req: Request<Body>, client: Client, state: SharedState, pull_map: PullMap) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let headers = req.headers().clone();
    println!("============================================================");
    println!("[REQ] {} {}", method, path);

    // Ping registry
    if path == "/v2/" {
        return Response::builder().status(StatusCode::OK).body(Body::empty()).unwrap();
    }


    // Découper le path pour extraire repo, tag, digest
    let parts: Vec<&str> = path.trim_start_matches("/v2/").split('/').collect();

    
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
    let context = get_pull_context(&req, &parts, &client_ip, &pull_map);

    //log
    println!(
        "[PULL CONTEXT] client={} uuid={} repo={} tag={:?} client_ip={}",
        client_ip,
        context.client_id,
        context.repo,
        context.tag,
        context.client_ip
    );


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
        println!("[LOCAL REGISTRY] {}", path);
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
    println!("[UPSTREAM FETCH FOR CACHE] → {}", upstream_url);

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
            println!("[ARCH CHECK] Manifest list incompatible linux/amd64");

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
    let certs = load_certs("registry-1.docker.io.crt")?;
    let key = load_private_key("registry-1.docker.io.key")?;

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

    println!("✅ MITM Docker registry en écoute sur https://registry-1.docker.io:443");

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let client = client.clone();
        let state = state.clone(); // Arc<Mutex<SharedState>>
        let pull_map = pull_map.clone(); // <-- clone pour cette itération
        
        tokio::spawn(async move {
            println!("[CONN] Client {:?}", addr);
            if let Ok(tls) = acceptor.accept(stream).await 
            {
                
                let client = client.clone();
                let state = state.clone();
                let pull_map = pull_map.clone(); // <-- clone pour service_fn

                let service = service_fn(move |mut req| 
                    {
                        let client = client.clone();
                        let state = state.clone();
                        let pull_map = pull_map.clone(); // clone pour handle
                        let addr = addr; // passer addr
                        async move 
                        { 
                            // stocker addr dans la requête pour handle
                            req.extensions_mut().insert(addr);
                            Ok::<_, Infallible>(handle(req, client, state, pull_map).await) 
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