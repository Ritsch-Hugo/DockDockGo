// Import des modules nécessaires
use std::convert::Infallible; // Pour gérer les erreurs impossibles dans Hyper
//use std::path::Path;           // Gestion des chemins de fichiers
use tokio::fs;                  // Accès aux fichiers de manière asynchrone
use hyper::{Body, Request, Response, Server, StatusCode}; // Serveur et types HTTP
use hyper::service::{make_service_fn, service_fn};        // Création de services Hyper
use reqwest::Client;            // Client HTTP pour appeler Docker Hub
use anyhow::Result;             // Gestion simplifiée des erreurs
use serde::Deserialize;         // Pour désérialiser du JSON

// URL du registre Docker officiel
static UPSTREAM: &str = "https://registry-1.docker.io";

// Fonction pour générer un chemin de fichier de cache à partir d'une URL
fn cache_path(path: &str) -> String {
    // Supprime le '/' initial et remplace tous les '/' par '_'
    // Exemple: /v2/library/hello-world → cache/v2_library_hello-world
    format!("cache/{}", path.trim_start_matches('/').replace("/", "_"))
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
async fn proxy(req: Request<Body>, client: Client) -> Result<Response<Body>> {
    let path = req.uri().path();           // Récupère le chemin demandé par le client
    let cache_file = cache_path(path);     // Génère le chemin de fichier de cache

    // Vérifie si le fichier existe déjà en cache
    if fs::metadata(&cache_file).await.is_ok() {
        let data = fs::read(&cache_file).await?;   // Lecture du cache
        println!("En Cache");
        return Ok(Response::new(Body::from(data))); // Renvoie directement au client
    }

    // Extraction du repository depuis l'URL
    let repo = path
        .trim_start_matches("/v2/")          // Supprime le préfixe "/v2/"
        .split('/')                          // Sépare par '/'
        .take(2)                             // Prend les deux premiers segments (ex: library/hello-world)
        .collect::<Vec<_>>()
        .join("/");

    // Récupération du token Docker pour ce repository
    let token = get_docker_token(&client, &repo).await?;

    // Construction de l'URL complète vers Docker Hub
    let url = format!("{}{}", UPSTREAM, path);
    println!("Proxy vers : {}", url);        // Affiche la redirection dans la console

    // Appel HTTP vers Docker Hub avec authentification Bearer
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await?;

    let bytes = resp.bytes().await?; // Lecture des données brutes

    // Mise en cache seulement si ce n'est pas une réponse d'erreur JSON
    if !bytes.starts_with(b"{\"errors\"") {
        fs::create_dir_all("cache").await.ok();  // Crée le dossier cache si inexistant
        fs::write(&cache_file, &bytes).await?;   // Écrit le fichier dans le cache
    }

    Ok(Response::new(Body::from(bytes)))        // Retourne la réponse au client
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
