use axum::{
    extract::Multipart, http::StatusCode, response::IntoResponse, routing::post, Json, Router,
};
use bytes::Bytes;
use rand::{seq::SliceRandom, thread_rng};
use reqwest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::net::SocketAddr;
use uuid::Uuid;
use axum::extract::DefaultBodyLimit;
use tower_http::limit::RequestBodyLimitLayer;


#[derive(Deserialize)]
struct HighLevelResp {
    pull_id: Uuid,
    opinion: String,
}

const HL_URL: &str = "http://127.0.0.1:4000/v1/high-level";

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
        ScanType::Compliance,
        ScanType::Sbom,
        ScanType::Statique,
        ScanType::Dynamique,
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
            println!(
                "[ORCH][SCAN][COMPLIANCE] pull_id={} kind={} digest={} size={}",
                ctx.uuid,
                kind,
                digest,
                bytes.len()
            );
            // compliance_scan(bytes, digest, ctx).await;
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
            println!(
                "[ORCH][SCAN][STATIQUE] pull_id={} kind={} digest={} size={}",
                ctx.uuid,
                kind,
                digest,
                bytes.len()
            );
            // static_scan(bytes, digest, ctx).await;
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
    let app = Router::new()
        .route("/v1/decision", post(decide))
        // Axum : désactive la limite par défaut (souvent ~2MB selon version/config)
        .layer(DefaultBodyLimit::disable())
        // Tower : fixe ta limite réelle (mets une valeur réaliste, pas forcément MAX)
        .layer(RequestBodyLimitLayer::new(1024 * 1024 * 1024)); // ex: 1GB

    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    println!("Orchestrateur listening on http://{addr}");

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

