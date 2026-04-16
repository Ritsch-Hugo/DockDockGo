use axum::extract::DefaultBodyLimit;
use axum::{
    extract::Multipart,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
mod auth;
mod dashboard;

use bytes::Bytes;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use rand::{seq::SliceRandom, thread_rng};
use reqwest;
use reqwest::multipart;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::net::SocketAddr;
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;
use crate::auth::{AppState, OidcState};

#[derive(Deserialize)]
struct HighLevelResp {
    pull_id: Uuid,
    opinion: String,
}

const HL_URL: &str = "http://127.0.0.1:4000/v1/high-level";
static COMPLIANCE_URL: &str = "http://127.0.0.1:3001/v1/scan-upload";
static STATIC_SCAN_URL: &str = "http://127.0.0.1:3002/v1/scan-upload";

static MANIFESTS: Lazy<DashMap<Uuid, Bytes>> = Lazy::new(DashMap::new);
static PENDING_BLOBS: Lazy<DashMap<Uuid, Vec<Bytes>>> = Lazy::new(DashMap::new);

static STATIC_MANIFESTS: Lazy<DashMap<Uuid, Bytes>> = Lazy::new(DashMap::new);
static STATIC_PENDING_BLOBS: Lazy<DashMap<Uuid, Vec<Bytes>>> = Lazy::new(DashMap::new);

// ===================
// PullContext INCHANGÉ
// ===================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Digest {
    algorithm: String,
    value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PullContext {
    uuid: Uuid,
    ip_client: String,
    registry: String,
    repository: String,
    tag: String,

    manifest_digests: Vec<Digest>,
    blob_digests: Vec<Digest>,
    referrers_digests: Vec<Digest>,

    manifest_racine_digest: Option<Digest>,
    digests_possible: Vec<Digest>,
    digests_expected: Vec<Digest>,

    os: String,
    arch: String,
    pull_completed: bool,
}

// ===================

#[derive(Serialize)]
struct DecisionResp {
    pull_id: Uuid,
    state: &'static str, // "PENDING" | "ALLOW" | "DENY"
}

fn extract_result_score(opinion: &str) -> Option<u8> {
    let last = opinion.lines().rev().find(|l| !l.trim().is_empty())?.trim();
    let rest = last.strip_prefix("Resultat :")?.trim();
    let n: u16 = rest.parse().ok()?;
    if n <= 100 {
        Some(n as u8)
    } else {
        None
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

async fn send_manifest_blob_to_service(
    service_name: &str,
    service_url: &str,
    manifest: Bytes,
    blob: Bytes,
) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();

    let form = multipart::Form::new()
        .part(
            "manifest",
            multipart::Part::bytes(manifest.to_vec())
                .file_name("manifest.json")
                .mime_str("application/json")
                .map_err(|e| e.to_string())?,
        )
        .part(
            "blob",
            multipart::Part::bytes(blob.to_vec())
                .file_name("blob.bin")
                .mime_str("application/octet-stream")
                .map_err(|e| e.to_string())?,
        );

    let resp = client
        .post(service_url)
        .multipart(form)
        .send()
        .await
        .map_err(|e| format!("{service_name} unreachable: {e}"))?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| e.to_string())?;

    if !status.is_success() {
        return Err(format!("{service_name} http {status}: {text}"));
    }

    serde_json::from_str(&text).map_err(|e| format!("bad json from {service_name}: {e}"))
}

// ---------------------------
// Agent + dispatch (nouveau)
// ---------------------------

#[derive(Debug, Clone, Copy)]
enum ScanType {
    Compliance,
    Sbom,
    Statique,
    Dynamique,
}

impl ScanType {
    fn as_str(&self) -> &'static str {
        match self {
            ScanType::Compliance => "COMPLIANCE",
            ScanType::Sbom => "SBOM",
            ScanType::Statique => "STATIQUE",
            ScanType::Dynamique => "DYNAMIQUE",
        }
    }
}

// Stub “IA agentique”: choix aléatoire pour l’instant
fn agent_choose_scan(_ctx: &PullContext, kind: &str, digest: &str) -> ScanType {
    let choices = [
        // ScanType::Compliance,
        //   ScanType::Sbom,
        ScanType::Statique,
        //     ScanType::Dynamique,
    ];
    let mut rng = thread_rng();
    let pick = *choices.choose(&mut rng).unwrap();

    println!(
        "[ORCH][AGENT] decision scan={} for kind={} digest={}",
        pick.as_str(),
        kind,
        digest
    );

    pick
}

// Dispatcher stub (tu brancheras tes vrais scanners ici)
async fn dispatch_to_scanner(
    scan: ScanType,
    kind: &str,
    bytes: Bytes,
    digest: &str,
    ctx: &PullContext,
) {
    match scan {
        ScanType::Compliance => {
            if kind == "manifest" {
                MANIFESTS.insert(ctx.uuid, bytes.clone());
                println!(
                    "[ORCH][COMPLIANCE] manifest stored pull_id={} digest={}",
                    ctx.uuid, digest
                );

                // flush blobs reçus avant le manifest
                if let Some((_k, mut pending)) = PENDING_BLOBS.remove(&ctx.uuid) {
                    if let Some(man) = MANIFESTS.get(&ctx.uuid).map(|v| v.value().clone()) {
                        for b in pending.drain(..) {
                            match send_manifest_blob_to_service(
                                "compliance",
                                COMPLIANCE_URL,
                                man.clone(),
                                b,
                            )
                            .await
                            {
                                Ok(v) => println!(
                                    "[ORCH][COMPLIANCE] ok pull_id={} resp={}",
                                    ctx.uuid, v
                                ),
                                Err(e) => println!(
                                    "[ORCH][COMPLIANCE] error pull_id={} err={}",
                                    ctx.uuid, e
                                ),
                            }
                        }
                    }
                }
                return;
            }

            if kind == "blob" {
                if let Some(man) = MANIFESTS.get(&ctx.uuid).map(|v| v.value().clone()) {
                    println!(
                        "[ORCH][COMPLIANCE] forwarding blob pull_id={} digest={} size={}",
                        ctx.uuid,
                        digest,
                        bytes.len()
                    );
                    match send_manifest_blob_to_service("compliance", COMPLIANCE_URL, man, bytes)
                        .await
                    {
                        Ok(v) => println!("[ORCH][COMPLIANCE] ok pull_id={} resp={}", ctx.uuid, v),
                        Err(e) => {
                            println!("[ORCH][COMPLIANCE] error pull_id={} err={}", ctx.uuid, e)
                        }
                    }
                } else {
                    println!(
                        "[ORCH][COMPLIANCE] blob buffered (manifest missing) pull_id={} digest={}",
                        ctx.uuid, digest
                    );
                    PENDING_BLOBS.entry(ctx.uuid).or_default().push(bytes);
                }
                return;
            }

            println!("[ORCH][COMPLIANCE] ignoring kind={}", kind);
        }
        ScanType::Sbom => {
            println!(
                "[ORCH][SCAN][SBOM] pull_id={} kind={} digest={} size={}",
                ctx.uuid,
                kind,
                digest,
                bytes.len()
            );
            // sbom_scan(bytes, digest, ctx).await;
        }
        ScanType::Statique => {
            if kind == "manifest" {
                STATIC_MANIFESTS.insert(ctx.uuid, bytes.clone());
                println!(
                    "[ORCH][STATIQUE] manifest stored pull_id={} digest={}",
                    ctx.uuid, digest
                );

                if let Some((_k, mut pending)) = STATIC_PENDING_BLOBS.remove(&ctx.uuid) {
                    if let Some(man) = STATIC_MANIFESTS.get(&ctx.uuid).map(|v| v.value().clone()) {
                        for b in pending.drain(..) {
                            match send_manifest_blob_to_service(
                                "statique",
                                STATIC_SCAN_URL,
                                man.clone(),
                                b,
                            )
                            .await
                            {
                                Ok(v) => {
                                    println!("[ORCH][STATIQUE] ok pull_id={} resp={}", ctx.uuid, v)
                                }
                                Err(e) => println!(
                                    "[ORCH][STATIQUE] error pull_id={} err={}",
                                    ctx.uuid, e
                                ),
                            }
                        }
                    }
                }
                return;
            }

            if kind == "blob" {
                if let Some(man) = STATIC_MANIFESTS.get(&ctx.uuid).map(|v| v.value().clone()) {
                    println!(
                        "[ORCH][STATIQUE] forwarding blob pull_id={} digest={} size={}",
                        ctx.uuid,
                        digest,
                        bytes.len()
                    );
                    match send_manifest_blob_to_service("statique", STATIC_SCAN_URL, man, bytes)
                        .await
                    {
                        Ok(v) => println!("[ORCH][STATIQUE] ok pull_id={} resp={}", ctx.uuid, v),
                        Err(e) => {
                            println!("[ORCH][STATIQUE] error pull_id={} err={}", ctx.uuid, e)
                        }
                    }
                } else {
                    println!(
                        "[ORCH][STATIQUE] blob buffered (manifest missing) pull_id={} digest={}",
                        ctx.uuid, digest
                    );
                    STATIC_PENDING_BLOBS
                        .entry(ctx.uuid)
                        .or_default()
                        .push(bytes);
                }
                return;
            }

            println!("[ORCH][STATIQUE] ignoring kind={}", kind);
        }
        ScanType::Dynamique => {
            println!(
                "[ORCH][SCAN][DYNAMIQUE] pull_id={} kind={} digest={} size={}",
                ctx.uuid,
                kind,
                digest,
                bytes.len()
            );
            // dynamic_scan(bytes, digest, ctx).await;
        }
    }
}

// Buffer pour gérer l’ordre arbitraire des champs multipart
struct ReceivedFile {
    kind: String, // "manifest" | "blob" | "referrer"
    bytes: Bytes,
    digest: String,
    filename: Option<String>,
}

async fn decide(mut mp: Multipart) -> impl IntoResponse {
    let mut decision_state: &'static str = "PENDING";
    let mut ctx: Option<PullContext> = None;

    let mut files_received = false;
    let mut file_buf: Vec<ReceivedFile> = Vec::new();

    while let Some(field) = match mp.next_field().await {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("multipart read error: {e}"),
            )
                .into_response()
        }
    } {
        let name = field.name().unwrap_or("").to_string();
        let filename = field.file_name().map(|s| s.to_string());

        // -------- context --------
        if name == "context" {
            let text = match field.text().await {
                Ok(t) => t,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("context read error: {e}"))
                        .into_response()
                }
            };

            match serde_json::from_str::<PullContext>(&text) {
                Ok(parsed) => ctx = Some(parsed),
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("context json invalid: {e}"),
                    )
                        .into_response()
                }
            }

            continue;
        }

        // -------- fichiers --------
        let kind = match name.as_str() {
            "manifests" | "manifest" => Some("manifest"),
            "blobs" | "blob" => Some("blob"),
            "referrers" | "referrer" => Some("referrer"),
            _ => None,
        };

        if let Some(kind) = kind {
            let bytes: Bytes = match field.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("file read error: {e}"))
                        .into_response()
                }
            };

            files_received = true;
            let digest = sha256_digest(&bytes);

            println!(
                "[ORCH] file received | kind={} digest={} size={} filename={:?}",
                kind,
                digest,
                bytes.len(),
                filename
            );

            // Bufferise pour traiter après avoir ctx garanti
            file_buf.push(ReceivedFile {
                kind: kind.to_string(),
                bytes,
                digest,
                filename,
            });
        }
    }

    let ctx = match ctx {
        Some(c) => c,
        None => {
            return (StatusCode::BAD_REQUEST, "missing multipart field 'context'").into_response()
        }
    };

    // -------- LOG GLOBAL --------
    println!(
        "[ORCH] pull_id={} image={}/{}:{} completed={}",
        ctx.uuid, ctx.registry, ctx.repository, ctx.tag, ctx.pull_completed
    );

    // Cas 1: il y a des fichiers => appel agent + dispatch scanners
    if files_received {
        println!("[ORCH] files detected => agentic routing");

        for f in file_buf {
            let scan = agent_choose_scan(&ctx, &f.kind, &f.digest);
            dispatch_to_scanner(scan, &f.kind, f.bytes, &f.digest, &ctx).await;
        }

        // Pour l’instant: tu peux choisir une policy simple
        decision_state = "PENDING"; // ou "ALLOW" si tu veux laisser passer pendant les scans async
    } else {
        // Cas 2: pas de fichiers => HEAD => high-level
        println!("[ORCH] HEAD détecté, analyse de haut niveau");

        let http = reqwest::Client::new();

        match http.post(HL_URL).json(&ctx).send().await {
            Ok(r) => {
                println!("[ORCH][HIGH] status={}", r.status());

                match r.json::<HighLevelResp>().await {
                    Ok(body) => {
                        println!("[ORCH][HIGH] pull_id={}", body.pull_id);
                        println!("[ORCH][HIGH] opinion:\n{}", body.opinion);

                        match extract_result_score(&body.opinion) {
                            Some(score) => {
                                println!("[ORCH][HIGH] parsed score={}", score);
                                decision_state = if score > 75 { "PENDING" } else { "DENY" };
                                println!("[ORCH][HIGH] decision={}", decision_state);
                            }
                            None => {
                                println!("[ORCH][HIGH] score missing/invalid -> DENY");
                                decision_state = "DENY";
                            }
                        }
                    }
                    Err(e) => {
                        println!("[ORCH][HIGH] json parse error: {e}");
                        decision_state = "DENY";
                    }
                }
            }
            Err(e) => {
                println!("[ORCH][HIGH] scanner unreachable: {e}");
                decision_state = "DENY";
            }
        }
    }

    (
        StatusCode::OK,
        Json(DecisionResp {
            pull_id: ctx.uuid,
            state: decision_state,
        }),
    )
        .into_response()
}

#[tokio::main]
async fn main() {

    dotenvy::dotenv().ok();

    // 1. Initialiser la DB (comme dans ton Proxy)
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL doit être défini dans le .env");
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("Echec de connexion à la DB");

    // 2. Créer l'état global
    let state = AppState {
        oidc_ctx: OidcState::default(),
        db: pool,
    };
 
    let app = Router::new()
        // ─── API proxy ───────────────────────────────────────────────────
        .route("/v1/decision", post(decide))
 
        // ─── Auth OIDC ───────────────────────────────────────────────────
        .route("/", get(auth::login_handler))
        .route("/callback", get(auth::callback_handler))

        .route("/logout", get(auth::logout))
        .route("/logged-out", get(auth::logged_out_handler))
 
        // ─── Dashboard ───────────────────────────────────────────────────
        .nest("/dashboard", dashboard::router())
 
        // ─── State partagé (OIDC) ────────────────────────────────────────
        .with_state(state)
 
        // ─── Limites ─────────────────────────────────────────────────────
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024));
 
    let addr: SocketAddr = "0.0.0.0:3010".parse().unwrap();
    println!("Orchestrateur listening on http://{addr}");
 
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}
