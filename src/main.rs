use axum::{
    extract::Multipart,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::net::SocketAddr;
use uuid::Uuid;

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

// Pour tester
const MANUAL_STATE: &str = "ALLOW";

fn sha256_digest(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

async fn decide(mut mp: Multipart) -> impl IntoResponse {
    let mut ctx: Option<PullContext> = None;
    let mut files_received = false;

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
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("context read error: {e}"),
                    )
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
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("file read error: {e}"),
                    )
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

            // 👉 ici tu dispatcheras vers le bon scanner
            // send_to_scanner(kind, bytes, digest, &ctx)
        }
    }

    let ctx = match ctx {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "missing multipart field 'context'",
            )
                .into_response()
        }
    };

    // -------- LOG GLOBAL --------
    println!(
        "[ORCH] pull_id={} image={}/{}:{} completed={}",
        ctx.uuid, ctx.registry, ctx.repository, ctx.tag, ctx.pull_completed
    );

    if !files_received {
        println!("[ORCH] HEAD détecté, analyse de haut niveau");
    }

    (
        StatusCode::OK,
        Json(DecisionResp {
            pull_id: ctx.uuid,
            state: MANUAL_STATE,
        }),
    )
        .into_response()
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/v1/decision", post(decide));

    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    println!("Orchestrateur listening on http://{addr}");

    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}
