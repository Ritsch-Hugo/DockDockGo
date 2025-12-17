use std::{convert::Infallible, fs::File, io::BufReader, sync::Arc};//import de bibliotheque standard

use std::path::Path;
use hyper::header::{CONTENT_TYPE};
use tokio::fs;//gestion async des fichiers
use anyhow::Result;//gestion des erreurs
use hyper::{ //librairie HTTP bas niveau
    body::to_bytes,
    service::service_fn,
    Body, Method, Request, Response, StatusCode,
};
use hyper::server::conn::Http;//servir les connexions HTTP
use reqwest::Client; //Librairie pour requetes HTTP / HTTPS (gère connexion TCP, TLS, headers, coookies...)
use rustls::{Certificate, PrivateKey, ServerConfig}; //TLS moderne pour serv HTTPS MITM Import des types des clés et CA
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};//parser les fichiers PEM
use tokio::net::TcpListener; //gestion des taches asyncrones 
use tokio_rustls::TlsAcceptor;// Negociation TLS avec client 

// URL réel du registry Docker
static UPSTREAM: &str = "https://registry-1.docker.io";

//crée le chemin du fichier en param dans le cache ex: image.json -> cache/image.json
fn cache_path(path: &str) -> String {
    format!("cache{}", path) // => cache/v2/library/alpine/...
}

//créer le chemin du dossier de quarantaine 
fn quarantaine_path(path: &str) -> String {
    let p = format!("quarantaine/{}", path.trim_start_matches('/').replace('/', "_"));
    println!("[LOG] Quarantaine path = {}", p);
    p
}

pub async fn list_files_in_dir(dir_path: &str) -> std::io::Result<()> {
    let mut entries = fs::read_dir(dir_path).await?;

    println!("Contenu du dossier '{}':", dir_path);

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            println!("Fichier: {}", path.display());
        } else if path.is_dir() {
            println!("Dossier: {}", path.display());
        }
    }

    Ok(())
}

/// Décision de sécurité sur la réponse upstream (manifest/blobs)
fn is_allowed(path: &str, body: &[u8]) -> bool {
    println!("[POLICY] Analyse de {}", path);

    // Exemple 1 : bloquer TOUT pour test
    // return false;

    // Exemple 2 : bloquer tout sauf alpine
    // if !path.contains("library/alpine") {
    //     return false;
    // }

    // TODO: ici tu peux parser le manifest, regarder les couches, etc.
    let _ = body; // pour éviter le warning pour l'instant

    true
}

/// Charge un certificat X.509 (PEM)
fn load_certs(path: &str) -> Result<Vec<Certificate>> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);//mise en tampon
    let certs = certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

/// Charge une clé privée (PKCS8 ou RSA PEM)
fn load_private_key(path: &str) -> Result<PrivateKey> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);

    // On essaie d'abord PKCS8
    if let Ok(keys) = pkcs8_private_keys(&mut reader) {
        if let Some(k) = keys.into_iter().next() {
            return Ok(PrivateKey(k));
        }
    }

    // On réouvre pour RSA
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);
    if let Ok(keys) = rsa_private_keys(&mut reader) {
        if let Some(k) = keys.into_iter().next() {
            return Ok(PrivateKey(k));
        }
    }

    anyhow::bail!("Impossible de charger une clé privée depuis {}", path);//aucune clé trouvée
}
//Gestion des chaques requetes (fonction Proxy)
/// Handler d'une requête HTTP décodée par TLS
async fn handle(req: Request<Body>, client: Client) -> Response<Body> {
    //clone des info car utilisés ensuite 
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    //
    let path = uri.path().to_string();
    println!("[REQ] {} {}", method, path);

    //filtrage des requetes 
    // On ne traite que /v2/... pour l'instant, le reste passe tel quel
    if !path.starts_with("/v2/") {
        println!("[INFO] Chemin hors /v2/, on passe tel quel");
    }
    
    // Construction de l'URL complète vers le vrai registry
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    //construction de l'url upstream
    let upstream_url = format!("{}{}", UPSTREAM, path_and_query);

    // Récupérer le body client (rarement utilisé par Docker en GET)
    let body_bytes = match to_bytes(req.into_body()).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ERR] Lecture body client: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Erreur lecture body client"))
                .unwrap();
        }
    };
         
    //variable contenant le chemin de l'image qui doit ou pas etre contenu dans le cache 
    //log les chemins des dossiers cache et quarantaine
    let cache_file = cache_path(&path); 
    //let cache_file = "cache/v2_library_hello-world_manifests_sha256:f7931603f70e13dbd844253370742c4fc4202d290c80442b2e68706d8f33ce26";
    let quarantaine_file = quarantaine_path(&path);

    println!("cache_file = {}", cache_file);  

    //list_files_in_dir("cache").await;

    //loop {

  //  }
    //si l'image est trouvée dans le cache 
    if fs::metadata(&cache_file).await.is_ok() {
        let data = match fs::read(&cache_file).await {
            Ok(d) => {
                println!("Image trouvée dans le cache, pull de l'image...");
                
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/vnd.docker.distribution.manifest.v2+json")
                    .body(Body::from(d))
                    .unwrap();
            },
            Err(e) => {
                eprintln!("[ERR] Lecture cache: {}", e);
                return Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Erreur lecture cache"))
                    .unwrap();
            }
        };
    }
    //le cas ou l'image n'est pas dans le cache
    else 
    {
        //On doit aller chercher l'image dans DockerHub et la placer dans le dossier quarantaine
        println!("[ALERTE] L'image n'est pas presente dans notre depot securisé - Elle doit etre scanner d'etre poussée en production");
        //loop {

        //}

        // Construire requête upstream avec reqwest
        let mut rb = client.request(method.clone(), &upstream_url);

        for (name, value) in headers.iter() {
            // On filtre quelques headers de connexion
            if name.as_str().eq_ignore_ascii_case("host")
                || name.as_str().eq_ignore_ascii_case("connection")
                || name.as_str().eq_ignore_ascii_case("proxy-connection")
            {
                continue;
            }
            rb = rb.header(name, value);
        }
        //ajout du body si non vide 
        if !body_bytes.is_empty() 
        {
            rb = rb.body(body_bytes);
        }

        println!("[UP] → {}", upstream_url);

        //Redirection de la requete client vers DockerHub
        //Reqwest gère le chiffrement vers dockerhub et le dechiffrement de la reponse
        //la methode send retourne la reponse 
        let upstream_resp = match rb.send().await {
            Ok(r) => r,
            Err(e) => {//erreure dans la requete proxy -> registry distant 
                eprintln!("[ERR] requête upstream: {}", e);
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Erreur requête vers registry-1.docker.io"))
                    .unwrap();
            }
        };

        //recupère le status de la requete de reponse de dockerhub
        let status = upstream_resp.status();
        //recupère les headers
        let upstream_headers = upstream_resp.headers().clone();

        //recupère le body de retour 
        let bytes = match upstream_resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[ERR] lecture body upstream: {}", e);
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("Erreur lecture réponse registry"))
                    .unwrap();
            }
        };
        println!("[DEBUG] Taille body = {}", bytes.len());


        //Décision sécurité ici : on a le path + les octets de la réponse
        // if !is_allowed(&path, &bytes) 
        // {
        // println!("[POLICY] ❌ BLOQUÉ {}", path);
        // return Response::builder()
        //    .status(StatusCode::FORBIDDEN)
        //    .body(Body::from("Image / ressource bloquée par la politique MITM"))
        //    .unwrap();
        // }

        //On propage status + body + TOUS les headers utiles
        
        
        /*let mut builder = Response::builder().status(status);

        // Propager tous les headers upstream, sauf quelques hop-by-hop
        for (name, value) in upstream_headers.iter() {
            if name == hyper::header::CONNECTION
                || name == hyper::header::TRANSFER_ENCODING
                || name.as_str().eq_ignore_ascii_case("keep-alive")
                || name.as_str().eq_ignore_ascii_case("proxy-authenticate")
                || name.as_str().eq_ignore_ascii_case("proxy-authorization")
                || name.as_str().eq_ignore_ascii_case("te")
                || name.as_str().eq_ignore_ascii_case("trailers")
                || name.as_str().eq_ignore_ascii_case("upgrade")
            {
                continue;
            }
            //mis a jour des headers a retourner au client 
            builder = builder.header(name, value);
        }*/

        //println!("[POLICY] ✅ AUTORISÉ {}", path);

        //crée le dossier quarantaine si il n'existe pas
        fs::create_dir_all("quarantaine").await.ok();

        // if bytes.is_empty() {
        //     println!("Methode : {} - On ne met pas en quarantaine les body vides", method);

        //     // Retourner au client le status et headers du upstream, body vide
        //     let mut builder = Response::builder().status(status);
        //     for (name, value) in upstream_headers.iter() {
        //         // Ignorer les headers hop-by-hop
        //         if name == hyper::header::CONNECTION
        //             || name == hyper::header::TRANSFER_ENCODING
        //             || name.as_str().eq_ignore_ascii_case("keep-alive")
        //             || name.as_str().eq_ignore_ascii_case("proxy-authenticate")
        //             || name.as_str().eq_ignore_ascii_case("proxy-authorization")
        //             || name.as_str().eq_ignore_ascii_case("te")
        //             || name.as_str().eq_ignore_ascii_case("trailers")
        //             || name.as_str().eq_ignore_ascii_case("upgrade")
        //         {
        //             continue;
        //         }
        //         builder = builder.header(name, value);
        //     }

        //     return builder.body(Body::empty()).unwrap();
        // }

        //else {
        //on change le type de bytes pour pouvoir l'ecrire avec write
        let body_vec = bytes.to_vec();

        println!("[DEBUG] Taille body = {}", bytes.len());

        if let Err(e) = fs::write(&quarantaine_file, &body_vec).await {
            eprintln!("[ERR] Impossible d'écrire en quarantaine : {}", e);
        }

        //Envoie message au client
        return Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::from("[ERROR] L'image n'a jamais été scannée par DockDockGo, l'image a été pull dans le dossier quarantaine"))
        .unwrap();
        //}

                
    }
}

#[tokio::main]//indique a rust d'utiliser main dans un runtime tokio 
async fn main() -> Result<()> {//renvoie Ok ou Err
    //chargements des clés publique et privé du server MITM TLS 
    let certs = load_certs("registry-1.docker.io.crt")?;
    let key = load_private_key("registry-1.docker.io.key")?;

    //creation d'un builder de configuration TLS pour un server 
    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;//utilisation du certificat et la clé priv

    let tls_config = Arc::new(tls_config);//pointeur partagé 

    //Server ecoute sur toutes les interfaces sur le port HTTPS standard
    let listener = TcpListener::bind(("0.0.0.0", 443)).await?;

    //acceptator gère le handshake et transforme une connexion TCP en TLS
    let acceptor = TlsAcceptor::from(tls_config);

    println!("✅ MITM Docker registry en écoute sur https://registry-1.docker.io:443");

    // client HTTPS vers le vrai registry
    let client = Client::builder()
        .use_rustls_tls()
        .build()?;

    //Server tourne toujours et attend les requetes
    loop {
        //accepte chaques requetes
        let (stream, addr) = listener.accept().await?;
        //clonage des objets 
        let acceptor = acceptor.clone();
        let client = client.clone();

        //creation d'une tache asyncrone
        tokio::spawn(async move {
            println!("[CONN] Client {:?}", addr);
            //lance le handshake et transforme TCP en TLS 
            //dechiffrement ce passe ici 
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[ERR] handshake TLS: {}", e);
                    return;
                }
            };

            //construction du service hyper
            let service = service_fn(move |req| {
                let client = client.clone();
                //appel asyncrones de la fonction handle du proxy (gestion de chaques requetes)
                async move { Ok::<_, Infallible>(handle(req, client).await) }
            });

            if let Err(e) = Http::new()
                .serve_connection(tls_stream, service)
                .await
            {
                eprintln!("[ERR] serve_connection: {}", e);
            }
        });
    }
}
