//Importe  les modules 
use std::convert::Infallible;// gestion des erreures impossible dans Hyper
use tokio::fs; //acces au fichier de manière asyncrones
use hyper::{Body, Request, Response, Server, StatusCode, Method};//Server et type HTTP
use hyper::header::CONTENT_TYPE;
use hyper::service::{make_service_fn, service_fn};//creation du service HTTP Hyper
use reqwest::Client;//Client HTTP pour dokcerHub
use anyhow::Result;//gestion des erreurs
use serde::Deserialize;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::io::copy_bidirectional;//Tunel securisé bidirectionnel

//registre visé par le docker pull
static UPSTREAM: &str = "https://registry-1.docker.io";

// 🔹 Bloquer ou laisser passer les pulls
const ALLOW_PULL: bool = true;

//renvoie le chemin du fichier des infos de l'image a stocker dans le cache ( a partir de l'URL)
fn cache_path(path: &str) -> String { 
    format!("cache/{}", path.trim_start_matches('/').replace("/", "_"))
}

//Cree le chemin du dossier de quarantaine a partir d'une URL
fn quarantaine_path(path: &str) -> String {
    format!("quarantaine/{}", path.trim_start_matches('/').replace("/", "_"))
}

//Structure pour deserialiser la reponse JSON du token Docker
#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

//Fonction pour recuperer le token DockerHub
async fn get_docker_token(client: &Client, repo: &str) -> Result<String> {
    //constructioin de l'url en fonction du depot ciblé 
    let url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        repo
    );
    //GET vers Docker Auth et conversion de la reponse 
    let resp: TokenResponse = client.get(&url).send().await?.json().await?;
    Ok(resp.token)
}

// 🔹 Tunnel TCP bidirectionnel pour CONNECT
async fn handle_connect(mut client: hyper::upgrade::Upgraded, host: String) -> Result<()> {
    if !ALLOW_PULL {
        // Si on bloque, on ferme simplement la connexion
        return Ok(());
    }

    // Connexion au serveur Docker Hub
    let mut server = TokioTcpStream::connect(host).await?;
    // Copie bidirectionnelle entre client et serveur
    //etablis une connection securisé entre le proxy et le server, Tunel TCP
    copy_bidirectional(&mut client, &mut server).await?;
    Ok(())
}


async fn proxy(req: Request<Body>, client: Client) -> Result<Response<Body>> {
    


    //Interception de la requette CONNECT (https) Pour etablir un tunnel TLS avec docker hub
    if req.method() == Method::CONNECT {
        let host = req.uri().authority().map(|a| a.as_str().to_string()).unwrap_or_default();
        println!("host = {}", host);

        if !ALLOW_PULL {
            println!("❌ Docker pull bloqué vers {}", host);
            //Retour d'une erreure FORBIDDEN
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"errors":[{"code":"FORBIDDEN","message":"Pull bloqué"}]}"#))
                .unwrap());
        }

        println!("🔗 Tunnel vers {}", host);

        // Upgrade la connexion HTTP vers TCP pour le CONNECT
        tokio::spawn(async move {
            if let Ok(upgraded) = hyper::upgrade::on(req).await {
                if let Err(e) = handle_connect(upgraded, host).await {
                    eprintln!("Erreur tunnel CONNECT: {}", e);
                }
            }
        });

        // On renvoie 200 au client pour valider le CONNECT
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap());
    }

    // ---------------- HTTP classique (cache / quarantaine) ----------------
    let path = req.uri().path();
    let cache_file = cache_path(path);
    let quarantaine_file = quarantaine_path(path);

    //si l'image est en cache ou la renvoie direcetement
    if fs::metadata(&cache_file).await.is_ok() {
        let data = fs::read(&cache_file).await?;
        return Ok(Response::new(Body::from(data)));
    }

    //extraction du nom de repository (ex: libray/hello-world)
    let repo = path
        .trim_start_matches("/v2/")
        .split('/')
        .take(2)
        .collect::<Vec<_>>()
        .join("/");

    println!("Repository demandé : {}", repo);

    //verifie si image scannée
    if path.contains("/manifests/") || path.contains("/blobs/") || path.contains("/tags/list") || path.contains("/v2/") {
        // Ici tu peux ajouter ton vrai scan
        if false {
            fs::create_dir_all("quarantaine").await.ok();
            fs::write(&quarantaine_file, repo.as_bytes()).await?;
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"errors":[{"code":"FORBIDDEN","message":"Image en quarantaine, pull impossible"}]}"#))
                .unwrap());
        }
    }

    // Récupération manifest/blobs depuis Docker Hub
    let token = get_docker_token(&client, &repo).await?;
    let url = format!("{}{}", UPSTREAM, path);
    let resp = client.get(&url).bearer_auth(token).send().await?;
    let bytes = resp.bytes().await?;

    if !bytes.starts_with(b"{\"errors\"") {
        fs::create_dir_all("cache").await.ok();
        fs::write(&cache_file, &bytes).await?;
    }

    Ok(Response::new(Body::from(bytes)))
}

//Fonction principale qui lance le server Hyper Async
#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new(); //Creation d'un client HTTP reutilisable

    //Creation du service pour chaque connexion entrante 
    let make_svc = make_service_fn(move |_| {
        let client = client.clone();//Clone du client pour chaque service
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let client = client.clone();
                async move {
                    //Appel de la fonction prxoy pour gèrer chaques requetes
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
                        Ok(resp) => Ok::<_, Infallible>(resp),
                        Err(e) => {
                            eprintln!("Erreur: {}", e);
                            Ok(Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Body::from("Erreur serveur"))
                                .unwrap())
                        }
                    }
                }
            }))
        }
    });

    let addr = ([0, 0, 0, 0], 5000).into();
    println!("✅ Proxy Docker avec blocage ALLOW_PULL={} sur http://{}", ALLOW_PULL, addr);

    Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}
