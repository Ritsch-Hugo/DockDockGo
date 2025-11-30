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
use rustls::{Certificate as RustlsCert, PrivateKey, ServerConfig};
use tokio_rustls::{TlsAcceptor, rustls};

use serde::Deserialize;
use rustls_pemfile::{certs, pkcs8_private_keys};

use rcgen::{IsCa, BasicConstraints, DnType};

use rcgen::SanType;


static UPSTREAM: &str = "https://registry-1.docker.io";
const ALLOW_PULL: bool = true;
const ENABLE_QUARANTINE: bool = true;

fn cache_path(path: &str) -> String {
    let p = format!("cache/{}", path.trim_start_matches('/').replace('/', "_"));
    println!("[LOG] Cache path = {}", p);
    p
}

fn quarantine_path(path: &str) -> String {
    let p = format!("quarantine/{}", path.trim_start_matches('/').replace('/', "_"));
    println!("[LOG] Quarantine path = {}", p);
    p
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

async fn get_docker_token(client: &Client, repo: &str) -> Result<String> {
    println!("[LOG] Requesting Docker token for repo: {}", repo);

    let url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
        repo
    );

    let resp: TokenResponse = client.get(&url).send().await?.json().await?;
    
    println!("[LOG] Received Docker token (len={})", resp.token.len());

    Ok(resp.token)
}
fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    let mut r = &pem[..];
    let der = rustls_pemfile::certs(&mut r)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no cert in PEM"))?;
    Ok(der)
}


// Load CA
fn load_ca() -> Result<(RustlsCert, PrivateKey, RcCert)> {
    println!("[LOG] Loading CA certificate and key...");

    // Charger CA depuis fichiers
    let ca_cert_pem = std::fs::read("CA/ca.crt")?;
    let ca_key_pem = std::fs::read("CA/ca_pkcs8.key")?;

    // Convertir cert PEM → DER
    let ca_der = pem_to_der(&ca_cert_pem)?;
    let ca_rustls_cert = RustlsCert(ca_der.clone());

    // Charger private key
    let mut key_reader = &ca_key_pem[..];
    let key_bytes = pkcs8_private_keys(&mut key_reader)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("CA key not pkcs8"))?;

    let key = PrivateKey(key_bytes);

    // rcgen CA (même clé, même cert)
    let ca_keypair = KeyPair::from_pem(std::str::from_utf8(&ca_key_pem)?)?;

    let mut params = CertificateParams::new(vec![]);
    params.alg = &rcgen::PKCS_RSA_SHA256;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, "DockDockGo Root CA");
    params.key_pair = Some(ca_keypair);

    let rc_ca_cert = RcCert::from_params(params)?;

    println!("[LOG] CA loaded OK.");

    Ok((ca_rustls_cert, key, rc_ca_cert))
}


async fn generate_cert_for_host(host: &str) -> Result<(Vec<RustlsCert>, PrivateKey)> {
    println!("[LOG] Generating certificate for host: {}", host);

    // Nettoyage : extraire host SANS port
    let host_only = host.split(':').next().unwrap().to_string();

    let (ca_rustls_cert, _, ca_rc) = load_ca()?;

    // SANs compatibles Docker / Go / Rust / Chrome
    let mut params = CertificateParams::new(vec![
        host_only.clone(),             // DNS:registry-1.docker.io
        format!("*.{}", host_only),    // DNS:*.registry-1.docker.io
    ]);

    // Ajoute la version AVEC port — Docker client l’exige parfois
    params.subject_alt_names.push(
        rcgen::SanType::DnsName(format!("{}:443", host_only))
    );

    // Algorithme elliptique recommandé
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;

    let cert = RcCert::from_params(params)?;

    println!("[LOG] Signing certificate with CA...");
    let cert_der = cert.serialize_der_with_signer(&ca_rc)?;
    let key_der = cert.serialize_private_key_der();

    // Chaîne = leaf + CA
    let chain = vec![RustlsCert(cert_der.clone()), ca_rustls_cert];
    let priv_key = PrivateKey(key_der);

    Ok((chain, priv_key))
}





async fn mitm_tls(upgraded: Upgraded, host: String) -> Result<()> {
    println!("[LOG] Starting TLS MITM on host: {}", host);

    let (cert_chain, priv_key) = generate_cert_for_host(&host).await?;

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    println!("[LOG] Accepting client TLS...");
    let tls_stream = acceptor.accept(upgraded).await?;

    println!("[LOG] Connecting to upstream TLS server: {}", host);
    let mut server = TokioTcpStream::connect(&host).await?;

    let mut tls_stream = tls_stream;

    println!("[LOG] Starting bidirectional TLS relay...");
    let res = copy_bidirectional(&mut tls_stream, &mut server).await;
    println!("[LOG] TLS relay ended: {:?}", res);

    Ok(())
}

async fn proxy(req: Request<Body>, client: Client) -> Result<Response<Body>> {
    println!("\n[LOG] New request: {} {}", req.method(), req.uri());

    if req.method() == Method::CONNECT {
        let host = req.uri().authority().unwrap().as_str().to_string();

        println!("[LOG] CONNECT request → TLS MITM on {}", host);

        tokio::spawn(async move {
            println!("[LOG] (spawned) Upgrading connection for MITM…");
            if let Ok(up) = hyper::upgrade::on(req).await {
                if let Err(e) = mitm_tls(up, host).await {
                    eprintln!("[LOG] MITM TLS error: {}", e);
                }
            } else {
                eprintln!("[LOG] Failed to upgrade CONNECT request.");
            }
        });

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap());
    }

    let path = req.uri().path();
    println!("[LOG] Handling normal HTTP path: {}", path);

    let cache_file = cache_path(path);

    if fs::metadata(&cache_file).await.is_ok() {
        println!("[LOG] Cache hit! Returning local file.");

        let data = fs::read(&cache_file).await?;
        return Ok(Response::new(Body::from(data)));
    }

    println!("[LOG] No cache. Determining repo...");
    let repo = path.trim_start_matches("/v2/")
                   .split('/')
                   .take(2)
                   .collect::<Vec<_>>()
                   .join("/");

    println!("[LOG] Repo detected: {}", repo);

    if ENABLE_QUARANTINE && (path.contains("/manifests/") || path.contains("/blobs/")) {
        let quarantine_file = quarantine_path(path);

        println!("[LOG] Quarantine mode ON → blocking {}", path);

        fs::create_dir_all("quarantine").await.ok();
        fs::write(&quarantine_file, repo.as_bytes()).await?;

        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"errors":[{"code":"FORBIDDEN","message":"Image en quarantaine"}]}"#
            ))
            .unwrap());
    }

    println!("[LOG] Fetching Docker token...");
    let token = get_docker_token(&client, &repo).await?;

    println!("[LOG] Pulling from upstream...");
    let url = format!("{}{}", UPSTREAM, path);

    let resp = client.get(&url).bearer_auth(&token).send().await?;
    let bytes = resp.bytes().await?;

    println!("[LOG] Upstream response size = {} bytes", bytes.len());

    if !bytes.starts_with(b"{\"errors\"") {
        println!("[LOG] Saving to cache: {}", cache_file);
        fs::create_dir_all("cache").await.ok();
        fs::write(&cache_file, &bytes).await?;
    } else {
        println!("[LOG] Upstream returned an error JSON, not caching.");
    }

    Ok(Response::new(Body::from(bytes)))
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new();

    let make_svc = make_service_fn(move |_| {
        let client = client.clone();
        async move {
            println!("[LOG] New connection handled by service_fn");
            Ok::<_, Infallible>(service_fn(move |req| proxy(req, client.clone())))
        }
    });

    let addr = ([0, 0, 0, 0], 5000).into();
    println!("\nMITM Docker Proxy — listening on http://{}", addr);

    Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}
