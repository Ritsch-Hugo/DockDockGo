use std::{convert::Infallible, sync::Arc};
use tokio::fs;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream as TokioTcpStream;

use hyper::{Body, Request, Response, Server, Method, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::header::CONTENT_TYPE;

use reqwest::Client;
use anyhow::Result;

use rcgen::{CertificateParams, DistinguishedName, Certificate as RcCert, KeyPair};
use rustls::{Certificate as RustlsCert, PrivateKey, ServerConfig, server::AllowAnyAnonymousOrAuthenticatedClient};
use tokio_rustls::{TlsAcceptor, rustls};

use serde::Deserialize;
use rustls_pemfile::{certs, pkcs8_private_keys};

use rcgen::{IsCa, BasicConstraints, DnType};


static UPSTREAM: &str = "https://registry-1.docker.io";
const ALLOW_PULL: bool = true;
const ENABLE_QUARANTINE: bool = true;

fn cache_path(path: &str) -> String {
    format!("cache/{}", path.trim_start_matches('/').replace('/', "_"))
}

fn quarantine_path(path: &str) -> String {
    format!("quarantine/{}", path.trim_start_matches('/').replace('/', "_"))
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

async fn get_docker_token(client: &Client, repo: &str) -> Result<String> {
    let url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        repo
    );
    let resp: TokenResponse = client.get(&url).send().await?.json().await?;
    Ok(resp.token)
}

//
// 🔥 Correction : génération MITM sans from_ca_cert_pem()
//

// Charge CA/ca.crt + CA/ca.key en Rustls cert + key
fn load_ca() -> Result<(RustlsCert, PrivateKey, RcCert)> {
    let ca_cert_pem = std::fs::read("CA/ca.crt")?;
    let ca_key_pem = std::fs::read("CA/ca.key")?;

    let mut cert_reader = &ca_cert_pem[..];
    let mut key_reader = &ca_key_pem[..];

    let cert_chain = certs(&mut cert_reader)?
        .into_iter()
        .map(RustlsCert)
        .next()
        .unwrap();

    let key_bytes = pkcs8_private_keys(&mut key_reader)?
        .into_iter()
        .next()
        .unwrap();

    let key = PrivateKey(key_bytes.clone());
    let keypair = KeyPair::from_pem(std::str::from_utf8(&ca_key_pem)?)?;

    // Construire un KeyPair rcgen à partir de la clé privée PEM
    let ca_keypair = KeyPair::from_pem(std::str::from_utf8(&ca_key_pem)?)?;

    // Construire des params pour la CA (is_ca = true) et injecter la clé privée
    let mut ca_params = CertificateParams::new(vec![]);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "DockDockGo Root CA");
    ca_params.key_pair = Some(ca_keypair);

    // Créer la représentation rcgen de la CA (utilisée pour signer)
    let rc_ca_cert = RcCert::from_params(ca_params)?;


    Ok((cert_chain, PrivateKey(key_bytes), rc_ca_cert))
}

async fn generate_cert_for_host(host: &str) -> Result<(Vec<RustlsCert>, PrivateKey)> {
    let (_, _, ca_rc) = load_ca()?;

    let mut params = CertificateParams::new(vec![host.to_string()]);
    params.distinguished_name = DistinguishedName::new();

    let cert = RcCert::from_params(params)?;
    let cert_pem = cert.serialize_pem_with_signer(&ca_rc)?;
    let key_pem = cert.serialize_private_key_pem();

    Ok((
        vec![RustlsCert(cert_pem.into_bytes())],
        PrivateKey(key_pem.into_bytes()),
    ))
}

//
// 🔥 Correction du TLS
//
async fn mitm_tls(upgraded: Upgraded, host: String) -> Result<()> {
    let (cert_chain, priv_key) = generate_cert_for_host(&host).await?;

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let tls_stream = acceptor.accept(upgraded).await?;
    let mut server = TokioTcpStream::connect(&host).await?;

    // Important : ne pas mettre &mut &tls_stream
    let mut tls_stream = tls_stream;

    copy_bidirectional(&mut tls_stream, &mut server).await?;
    Ok(())
}

//
// Proxy classique HTTP + logique MITM
//
async fn proxy(req: Request<Body>, client: Client) -> Result<Response<Body>> {
    if req.method() == Method::CONNECT {
        let host = req.uri().authority().unwrap().as_str().to_string();

        if !ALLOW_PULL {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Pull bloqué"))
                .unwrap());
        }

        tokio::spawn(async move {
            if let Ok(up) = hyper::upgrade::on(req).await {
                if let Err(e) = mitm_tls(up, host).await {
                    eprintln!("MITM TLS error: {}", e);
                }
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap());
    }

    let path = req.uri().path();
    let cache_file = cache_path(path);
    let quarantine_file = quarantine_path(path);

    // Cache local
    if fs::metadata(&cache_file).await.is_ok() {
        let data = fs::read(&cache_file).await?;
        return Ok(Response::new(Body::from(data)));
    }

    let repo = path.trim_start_matches("/v2/").split('/').take(2).collect::<Vec<_>>().join("/");

    // Quarantine
    if ENABLE_QUARANTINE && (path.contains("/manifests/") || path.contains("/blobs/")) {
        fs::create_dir_all("quarantine").await.ok();
        fs::write(&quarantine_file, repo.as_bytes()).await?;

        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"errors":[{"code":"FORBIDDEN","message":"Image en quarantaine"}]}"#))
            .unwrap());
    }

    // Normal upstream pull
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

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new();

    let make_svc = make_service_fn(move |_| {
        let client = client.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| proxy(req, client.clone())))
        }
    });

    let addr = ([0, 0, 0, 0], 5000).into();
    println!("MITM Docker Proxy — actif sur : http://{}", addr);

    Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}
