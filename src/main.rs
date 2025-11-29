use std::convert::Infallible;

use anyhow::Result;
use hyper::{
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Method, Request, Response, Server, StatusCode,
};
use reqwest::Client;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Décide si on autorise un CONNECT vers host:port
fn is_allowed_connect(authority: &str) -> bool {
    println!("[POLICY] CONNECT vers {}", authority);

    // Bloquer Docker Hub
    if authority.starts_with("registry-1.docker.io:443")
        || authority.starts_with("index.docker.io:443")
        || authority.starts_with("auth.docker.io:443")
    {
        println!("[POLICY] BLOQUÉ {}", authority);
        return false;
    }

    true
}


/// Tunnel TCP bidirectionnel pour CONNECT
async fn tunnel(mut upgraded: Upgraded, addr: String) -> io::Result<()> {
    let mut server = TcpStream::connect(&addr).await?;

    let (mut client_read, mut client_write) = tokio::io::split(upgraded);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let client_to_server = tokio::spawn(async move {
        io::copy(&mut client_read, &mut server_write).await?;
        server_write.shutdown().await
    });

    let server_to_client = tokio::spawn(async move {
        io::copy(&mut server_read, &mut client_write).await?;
        client_write.shutdown().await
    });

    let _ = tokio::try_join!(client_to_server, server_to_client);
    Ok(())
}

/// Forward d'une requête HTTP "normale" (non CONNECT)
async fn forward_http(req: Request<Body>, client: Client) -> Response<Body> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Construire l'URL complète pour reqwest
    let url = if uri.scheme().is_some() && uri.authority().is_some() {
        // Forme absolue déjà (proxy-style): http://example.com/path?query
        uri.to_string()
    } else {
        // Forme origin: /path?query + Host: header
        let host = match headers.get("host") {
            Some(h) => match h.to_str() {
                Ok(s) => s,
                Err(_) => {
                    return Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Invalid Host header"))
                        .unwrap()
                }
            },
            None => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Missing Host header"))
                    .unwrap()
            }
        };

        let path_and_query = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        format!("http://{}{}", host, path_and_query)
    };

    println!("[HTTP] {} {}", method, url);

    // Récupérer le body de la requête
    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[HTTP] Erreur lecture body client: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Erreur lecture body client"))
                .unwrap();
        }
    };

    // Construire la requête reqwest
    let mut rb = client.request(method.clone(), &url);

    for (name, value) in headers.iter() {
        // On évite de relayer certains headers de connexion
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

    // Envoyer la requête upstream
    let upstream_resp = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[HTTP] Erreur requête upstream: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Erreur requête upstream"))
                .unwrap();
        }
    };

    let status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();

    let bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[HTTP] Erreur lecture body upstream: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Erreur lecture réponse upstream"))
                .unwrap();
        }
    };

    // Construire la réponse pour le client
    let mut builder = Response::builder().status(status);

    // On propage quelques headers intéressants
    if let Some(ct) = upstream_headers.get("content-type") {
        builder = builder.header("content-type", ct);
    }
    if let Some(cl) = upstream_headers.get("content-length") {
        builder = builder.header("content-length", cl);
    }

    builder.body(Body::from(bytes)).unwrap()
}

async fn handle(req: Request<Body>, client: Client) -> Response<Body> {
    let method = req.method().clone();

    // 1) Gestion du CONNECT (HTTPS, typiquement Docker -> registry-1.docker.io:443)
    if method == Method::CONNECT {
        let authority = match req.uri().authority() {
            Some(a) => a.as_str().to_string(),
            None => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("CONNECT sans authority host:port"))
                    .unwrap();
            }
        };

        println!("[CONNECT] {}", authority);

        // Vérifier la politique
        if !is_allowed_connect(&authority) {
            println!("[CONNECT] BLOQUÉ {}", authority);
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Connect bloqué par la politique"))
                .unwrap();
        }

        // On démarre le tunnel dans une tâche séparée
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = tunnel(upgraded, authority).await {
                        eprintln!("[CONNECT] Erreur tunnel: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("[CONNECT] Erreur upgrade: {}", e);
                }
            }
        });

        // Réponse 200 Connection Established
        return Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap();
    }

    // 2) Autres méthodes HTTP (GET/POST...) → forward HTTP
    forward_http(req, client).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new();

    let make_svc = make_service_fn(move |_| {
        let client = client.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let client = client.clone();
                async move { Ok::<_, Infallible>(handle(req, client).await) }
            }))
        }
    });

    let addr = ([0, 0, 0, 0], 5000).into();
    println!("✅ Proxy HTTP(S) en écoute sur http://{}", addr);

    Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}
