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

// URL réel du registry Docker
static UPSTREAM: &str = "https://registry-1.docker.io";

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
    let mut reader = BufReader::new(certfile);
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

    anyhow::bail!("Impossible de charger une clé privée depuis {}", path);
}

/// Handler d'une requête HTTP décodée par TLS
async fn handle(req: Request<Body>, client: Client) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let path = uri.path().to_string();
    println!("[REQ] {} {}", method, path);

    // On ne traite que /v2/... pour l'instant, le reste passe tel quel
    if !path.starts_with("/v2/") {
        println!("[INFO] Chemin hors /v2/, on passe tel quel");
    }

    // Construction de l'URL complète vers le vrai registry
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

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

    if !body_bytes.is_empty() {
        rb = rb.body(body_bytes);
    }

    println!("[UP] → {}", upstream_url);

    let upstream_resp = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ERR] requête upstream: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Erreur requête vers registry-1.docker.io"))
                .unwrap();
        }
    };

    let status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();

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

    // Décision sécurité ici : on a le path + les octets de la réponse
    if !is_allowed(&path, &bytes) {
        println!("[POLICY] ❌ BLOQUÉ {}", path);
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("Image / ressource bloquée par la politique MITM"))
            .unwrap();
    }

    // Si autorisé : on propage status + body + TOUS les headers utiles
    let mut builder = Response::builder().status(status);

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

        builder = builder.header(name, value);
    }

    println!("[POLICY] ✅ AUTORISÉ {}", path);

    builder.body(Body::from(bytes)).unwrap()
}

#[tokio::main]
async fn main() -> Result<()> {
    // ⚠️ adapte les chemins vers tes fichiers
    let certs = load_certs("registry-1.docker.io.crt")?;
    let key = load_private_key("registry-1.docker.io.key")?;

    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let tls_config = Arc::new(tls_config);
    let acceptor = TlsAcceptor::from(tls_config);

    let listener = TcpListener::bind(("0.0.0.0", 443)).await?;
    println!("✅ MITM Docker registry en écoute sur https://registry-1.docker.io:443");

    // client HTTPS vers le vrai registry
    let client = Client::builder()
        .use_rustls_tls()
        .build()?;

    loop {
        let (stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let client = client.clone();

        tokio::spawn(async move {
            println!("[CONN] Client {:?}", addr);
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[ERR] handshake TLS: {}", e);
                    return;
                }
            };

            let service = service_fn(move |req| {
                let client = client.clone();
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
