//Ce code ne gère pas les tunels HTTPS : CONNECT

// Import des modules nécessaires
use std::convert::Infallible; // Pour gérer les erreurs impossibles dans Hyper
use std::path::Path;           // Gestion des chemins de fichiers
use tokio::fs;                  // Accès aux fichiers de manière asynchrone
use hyper::{Body, Request, Response, Server, StatusCode}; // Serveur et types HTTP
use hyper::header::{CONTENT_TYPE};
use hyper::service::{make_service_fn, service_fn};        // Création de services Hyper
use reqwest::Client;            // Client HTTP pour appeler Docker Hub
use anyhow::Result;             // Gestion simplifiée des erreurs
use serde::Deserialize;         // Pour désérialiser du JSON

// URL du registre Docker officiel
static UPSTREAM: &str = "https://registry-1.docker.io";

struct Scan_images_struct {
    image: String,
    scan_is_done: bool,
}
fn is_scanned(repo: &str) -> bool {
    // TODO: Remplacer par vrai contrôle du scan
    true 
}

// Fonction pour générer un chemin de fichier de cache à partir d'une URL
fn cache_path(path: &str) -> String {
    // Supprime le '/' initial et remplace tous les '/' par '_'
    // Exemple: /v2/library/hello-world → cache/v2_library_hello-world
    format!("cache/{}", path.trim_start_matches('/').replace("/", "_"))
}

fn quarantaine_path(path: &str) -> String {
    // Supprime le '/' initial et remplace tous les '/' par '_'
    // Exemple: /v2/library/hello-world → quarantaine/v2_library_hello-world
    format!("quarantaine/{}", path.trim_start_matches('/').replace("/", "_"))
}

// Structure pour désérialiser la réponse JSON du token Docker
#[derive(Deserialize)]
struct TokenResponse {
    token: String, // Le token JWT retourné par Docker
}

// Fonction asynchrone pour récupérer un token Docker Hub pour un repo spécifique
async fn get_docker_token(client: &Client, repo: &str) -> Result<String> {
    // Construction de l'URL d'authentification Docker
    let url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        repo
    );

    // Requête GET vers Docker Auth et conversion JSON en TokenResponse
    let resp: TokenResponse = client.get(&url).send().await?.json().await?;
    Ok(resp.token) // Retour du token
}

// Fonction asynchrone qui gère une requête entrante et agit comme un proxy

pub async fn proxy(req: Request<Body>, client: Client) -> Result<Response<Body>> {

    
    let path = req.uri().path();
    let cache_file = cache_path(path);
    let quarantaine_file = quarantaine_path(path);

    // 1️⃣ Si l'image est en cache, on renvoie directement
    if fs::metadata(&cache_file).await.is_ok() {
        let data = fs::read(&cache_file).await?;
        return Ok(Response::new(Body::from(data)));
    }

    // 2️⃣ Extraction du repository (ex: library/hello-world)
    let repo = path
        .trim_start_matches("/v2/")
        .split('/')
        .take(2)
        .collect::<Vec<_>>()
        .join("/");

    println!("Repository demandé : {}", repo);

    // 3️⃣ Vérifie si l'image a été scannée
    if path.contains("/manifests/") || path.contains("/blobs/") || path.contains("/tags/list") || path.contains("/v2/")
    {

        if !is_scanned(&repo) {
            println!("L'image {} n'a pas encore été scannée.", repo);

            // Crée le dossier quarantaine si inexistant et y écrit le nom de l'image
            fs::create_dir_all("quarantaine").await.ok();
            fs::write(&quarantaine_file, repo.as_bytes()).await?;
            println!("L'image {} a été placée en quarantaine.", repo);

            // Retour immédiat au client Docker
            let resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Image en quarantaine, en attente de scan"))
                .unwrap();


            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"errors":[{"code":"FORBIDDEN","message":"Image en quarantaine, pull impossible"}]}"#))
                .unwrap());

        }
    }

    // 4️⃣ Si scan terminé, on récupère le manifest ou blob depuis Docker Hub
    let token = get_docker_token(&client, &repo).await?;
    let url = format!("{}{}", UPSTREAM, path);
    let resp = client.get(&url).bearer_auth(token).send().await?;
    let bytes = resp.bytes().await?;

    // 5️⃣ Mise en cache si ce n'est pas une erreur
    if !bytes.starts_with(b"{\"errors\"") {
        fs::create_dir_all("cache").await.ok();
        fs::write(&cache_file, &bytes).await?;
    }

    Ok(Response::new(Body::from(bytes)))
}




// Fonction principale qui lance le serveur Hyper asynchrone
#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new(); // Création d'un client HTTP réutilisable

    // Création du service pour chaque connexion entrante
    let make_svc = make_service_fn(move |_| {
        let client = client.clone(); // Clone du client pour chaque service
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let client = client.clone();
                async move {
                    // Appelle la fonction proxy pour gérer la requête
                    //println!("Connexion entrante | req : {:?}", req);


                    println!("--- Nouvelle requête ---\n");

                    println!("Method       : {:?}", req.method());
                    println!("URI          : {:?}", req.uri());
                    println!("client addr : {:?}", req.extensions().get::<hyper::server::conn::AddrStream>());
                    println!("Version      : {:?}", req.version()); // HTTP/1.1, HTTP/2
                    println!("Headers      : {:?}", req.headers()); // tous les headers
                    println!("Host         : {:?}", req.headers().get("host"));
                    println!("Content-Type : {:?}", req.headers().get("content-type"));
                    println!("User-Agent   : {:?}", req.headers().get("user-agent"));
                    println!("Authorization: {:?}", req.headers().get("authorization"));
                    println!("Cookies      : {:?}", req.headers().get("cookie"));


                    match proxy(req, client).await {
                        Ok(resp) => Ok::<_, Infallible>(resp), // Renvoie la réponse si succès
                        Err(e) => {                            // Gestion d'erreurs
                            eprintln!("Erreur: {}", e);        // Affiche l'erreur dans la console
                            Ok(Response::builder()             // Retourne un HTTP 500 au client
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from("Erreur serveur"))
                                .unwrap())
                        }
                    }
                }
            }))
        }
    });

    let addr = ([0, 0, 0, 0], 5000).into(); // Adresse d'écoute : port 5000 sur toutes les interfaces
    println!("✅ Proxy Docker AVEC authentification sur http://{}", addr);

    Server::bind(&addr).serve(make_svc).await?; // Démarre le serveur Hyper
    Ok(())
}
