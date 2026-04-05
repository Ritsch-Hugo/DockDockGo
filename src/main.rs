use axum::extract::DefaultBodyLimit;
use axum::{
    extract::Multipart,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
mod auth;
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

#[derive(Deserialize)]
struct HighLevelResp {
    pull_id: Uuid,
    opinion: String,
}

const HL_URL: &str = "http://127.0.0.1:4000/v1/high-level";
static COMPLIANCE_URL: &str = "http://127.0.0.1:3001/v1/scan-upload";
static STATIC_SCAN_URL: &str = "http://127.0.0.1:3002/v1/scan-upload";

// ===================
// Types de scan
// ===================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

// ===================
// Storage par scan_type
// Chaque ScanType a ses propres maps manifest/blob.
// On indexe par (pull_id, scan_type) => les deux maps globales
// suffisent car un pull n'a qu'un seul scan_type à la fois.
// Quand l'IA pourra choisir plusieurs scanners, il faudra
// composer la clé en (pull_id, scan_type).
// ===================

#[derive(Clone)]
struct StoredManifest {
    digest: String,
    bytes: Bytes,
}

#[derive(Clone)]
struct PendingBlob {
    digest: String,
    bytes: Bytes,
}

// Clé composite : (pull_id, scan_type_str) pour isoler les données
// par pull ET par type de scan — prêt pour le multi-scan futur.
type ScanKey = (Uuid, &'static str);

static MANIFESTS: Lazy<DashMap<ScanKey, Vec<StoredManifest>>> = Lazy::new(DashMap::new);
static PENDING_BLOBS: Lazy<DashMap<ScanKey, Vec<PendingBlob>>> = Lazy::new(DashMap::new);

// ===================
// Décision de scan par pull_id
// Mémorisée dès le premier fichier reçu pour ce pull.
// Tous les fichiers du même pull utilisent le même scanner.
// ===================
static PULL_SCAN_DECISION: Lazy<DashMap<Uuid, ScanType>> = Lazy::new(DashMap::new);

// ===================
// PullContext
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
    if n <= 100 { Some(n as u8) } else { None }
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

// ===================
// Agent : décision de scan
// Appelé UNE SEULE FOIS par pull_id, résultat mémorisé dans PULL_SCAN_DECISION.
// Quand l'IA supportera le multi-scan, cette fonction retournera Vec<ScanType>.
// ===================

fn agent_choose_scan(ctx: &PullContext) -> ScanType {
    let choices = [
        // ScanType::Compliance,
        // ScanType::Sbom,
        ScanType::Statique,
        // ScanType::Dynamique,
    ];
    let mut rng = thread_rng();
    let pick = *choices.choose(&mut rng).unwrap();

    println!(
        "[ORCH][AGENT] pull_id={} => scan={}",
        ctx.uuid,
        pick.as_str()
    );

    pick
}

/// Retourne le ScanType associé à ce pull_id.
/// Si c'est la première fois qu'on voit ce pull, on appelle l'agent et on mémorise.
fn get_or_decide_scan(ctx: &PullContext) -> ScanType {
    if let Some(existing) = PULL_SCAN_DECISION.get(&ctx.uuid) {
        return *existing;
    }
    let scan = agent_choose_scan(ctx);
    PULL_SCAN_DECISION.insert(ctx.uuid, scan);
    scan
}

// ===================
// Helpers manifest/blob
// ===================

fn manifest_references_digest(manifest_bytes: &[u8], wanted_digest: &str) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(manifest_bytes) else {
        return false;
    };

    fn value_contains_digest(v: &serde_json::Value, wanted: &str) -> bool {
        match v {
            serde_json::Value::Object(map) => {
                if let Some(d) = map.get("digest").and_then(|x| x.as_str()) {
                    if d == wanted { return true; }
                }
                map.values().any(|child| value_contains_digest(child, wanted))
            }
            serde_json::Value::Array(arr) => {
                arr.iter().any(|child| value_contains_digest(child, wanted))
            }
            _ => false,
        }
    }

    value_contains_digest(&v, wanted_digest)
}

fn find_matching_manifest(manifests: &[StoredManifest], blob_digest: &str) -> Option<StoredManifest> {
    manifests
        .iter()
        .find(|m| manifest_references_digest(&m.bytes, blob_digest))
        .cloned()
}

fn scanner_url(scan: ScanType) -> Option<&'static str> {
    match scan {
        ScanType::Compliance => Some(COMPLIANCE_URL),
        ScanType::Statique   => Some(STATIC_SCAN_URL),
        ScanType::Sbom       => None, // pas encore d'endpoint
        ScanType::Dynamique  => None,
    }
}

// ===================
// Dispatch unifié
// Utilise la clé (pull_id, scan_type) pour toutes les maps.
// ===================

async fn dispatch_to_scanner(scan: ScanType, kind: &str, bytes: Bytes, digest: &str, ctx: &PullContext) {
    let tag = scan.as_str();
    let key: ScanKey = (ctx.uuid, tag);

    match kind {
        "manifest" => {
            MANIFESTS.entry(key).or_default().push(StoredManifest {
                digest: digest.to_string(),
                bytes: bytes.clone(),
            });

            println!(
                "[ORCH][{}] manifest stocké pull_id={} digest={}",
                tag, ctx.uuid, digest
            );

            // Tenter de flusher les blobs en attente maintenant qu'on a un manifest de plus
            flush_pending(scan, ctx).await;
        }

        "blob" => {
            let manifests = MANIFESTS
                .get(&key)
                .map(|v| v.value().clone())
                .unwrap_or_default();

            if let Some(man) = find_matching_manifest(&manifests, digest) {
                println!(
                    "[ORCH][{}] envoi blob pull_id={} blob_digest={} manifest_digest={} size={}",
                    tag, ctx.uuid, digest, man.digest, bytes.len()
                );
                forward_to_scanner(scan, tag, man.bytes, bytes, ctx.uuid).await;
            } else {
                println!(
                    "[ORCH][{}] blob bufferisé pull_id={} blob_digest={} (pas encore de manifest)",
                    tag, ctx.uuid, digest
                );
                PENDING_BLOBS.entry(key).or_default().push(PendingBlob {
                    digest: digest.to_string(),
                    bytes,
                });
            }
        }

        other => {
            println!("[ORCH][{}] kind ignoré: {}", tag, other);
        }
    }
}

async fn flush_pending(scan: ScanType, ctx: &PullContext) {
    let tag = scan.as_str();
    let key: ScanKey = (ctx.uuid, tag);

    let manifests = MANIFESTS
        .get(&key)
        .map(|v| v.value().clone())
        .unwrap_or_default();

    if manifests.is_empty() { return; }

    let Some((_k, pending)) = PENDING_BLOBS.remove(&key) else { return };

    let mut still_pending = Vec::new();

    for pb in pending {
        if let Some(man) = find_matching_manifest(&manifests, &pb.digest) {
            println!(
                "[ORCH][{}] flush blob pull_id={} blob_digest={} manifest_digest={}",
                tag, ctx.uuid, pb.digest, man.digest
            );
            forward_to_scanner(scan, tag, man.bytes, pb.bytes, ctx.uuid).await;
        } else {
            println!(
                "[ORCH][{}] blob toujours en attente pull_id={} blob_digest={}",
                tag, ctx.uuid, pb.digest
            );
            still_pending.push(pb);
        }
    }

    if !still_pending.is_empty() {
        PENDING_BLOBS.insert(key, still_pending);
    }
}

async fn forward_to_scanner(scan: ScanType, tag: &str, manifest: Bytes, blob: Bytes, pull_id: Uuid) {
    let Some(url) = scanner_url(scan) else {
        println!("[ORCH][{}] pas d'endpoint configuré, envoi ignoré", tag);
        return;
    };

    match send_manifest_blob_to_service(tag, url, manifest, blob).await {
        Ok(v)  => println!("[ORCH][{}] ok pull_id={} resp={}", tag, pull_id, v),
        Err(e) => println!("[ORCH][{}] erreur pull_id={} err={}", tag, pull_id, e),
    }
}

// ===================
// Buffer multipart
// ===================

struct ReceivedFile {
    kind: String,
    bytes: Bytes,
    digest: String,
    filename: Option<String>,
}

// ===================
// Handler principal
// ===================

async fn decide(mut mp: Multipart) -> impl IntoResponse {
    let mut decision_state: &'static str = "PENDING";
    let mut ctx: Option<PullContext> = None;
    let mut files_received = false;
    let mut file_buf: Vec<ReceivedFile> = Vec::new();

    while let Some(field) = match mp.next_field().await {
        Ok(f) => f,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("multipart read error: {e}")).into_response();
        }
    } {
        let name = field.name().unwrap_or("").to_string();
        let filename = field.file_name().map(|s| s.to_string());

        if name == "context" {
            let text = match field.text().await {
                Ok(t) => t,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("context read error: {e}")).into_response();
                }
            };
            match serde_json::from_str::<PullContext>(&text) {
                Ok(parsed) => ctx = Some(parsed),
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("context json invalid: {e}")).into_response();
                }
            }
            continue;
        }

        let kind = match name.as_str() {
            "manifests" | "manifest" => Some("manifest"),
            "blobs"     | "blob"     => Some("blob"),
            "referrers" | "referrer" => Some("referrer"),
            _                        => None,
        };

        if let Some(kind) = kind {
            let bytes: Bytes = match field.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("file read error: {e}")).into_response();
                }
            };

            files_received = true;
            let digest = sha256_digest(&bytes);

            println!(
                "[ORCH] fichier reçu | kind={} digest={} size={} filename={:?}",
                kind, digest, bytes.len(), filename
            );

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
            return (StatusCode::BAD_REQUEST, "champ multipart 'context' manquant").into_response();
        }
    };

    println!(
        "[ORCH] pull_id={} image={}/{}:{} completed={}",
        ctx.uuid, ctx.registry, ctx.repository, ctx.tag, ctx.pull_completed
    );

    if files_received {
        println!("[ORCH] fichiers détectés => routage agentique");

        // Décision unique pour tout le pull — mémorisée si déjà connue
        let scan = get_or_decide_scan(&ctx);

        println!(
            "[ORCH] pull_id={} scan={} => {} fichier(s) à dispatcher",
            ctx.uuid, scan.as_str(), file_buf.len()
        );

        for f in file_buf {
            println!(
                "[ORCH] dispatch kind={} digest={} filename={:?}",
                f.kind, f.digest, f.filename
            );
            dispatch_to_scanner(scan, &f.kind, f.bytes, &f.digest, &ctx).await;
        }

        decision_state = "PENDING";

    } else {
        println!("[ORCH] HEAD détecté => analyse haut niveau");

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
                                println!("[ORCH][HIGH] score={}", score);
                                decision_state = if score > 75 { "PENDING" } else { "DENY" };
                                println!("[ORCH][HIGH] decision={}", decision_state);
                            }
                            None => {
                                println!("[ORCH][HIGH] score absent/invalide => DENY");
                                decision_state = "DENY";
                            }
                        }
                    }
                    Err(e) => {
                        println!("[ORCH][HIGH] erreur json: {e}");
                        decision_state = "DENY";
                    }
                }
            }
            Err(e) => {
                println!("[ORCH][HIGH] scanner injoignable: {e}");
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
    let app = Router::new()
        .route("/v1/decision", post(decide))
        .route("/", get(auth::login_page))
        .route("/login", post(auth::login_submit))
        .route("/dashboard/dev", get(auth::dev_dashboard))
        .route("/dashboard/rssi", get(auth::rssi_dashboard))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024)); // 1 GB

    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    println!("Orchestrateur listening on http://{addr}");

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}