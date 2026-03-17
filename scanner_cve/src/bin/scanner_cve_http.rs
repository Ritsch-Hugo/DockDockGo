use axum::{
    extract::{DefaultBodyLimit, Multipart},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use serde_json::{json, Value};
use uuid::Uuid;

use std::{fs, net::SocketAddr, path::PathBuf};

use scanner_cve::engine::pipeline;
use scanner_cve::models::{ScanRequest, ScanResponse, ScanStatus};

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/scan-upload", post(scan_upload))
        .layer(DefaultBodyLimit::max(1024 * 1024 * 1024)); // 1GB

    let addr = SocketAddr::from(([127, 0, 0, 1], 3002));
    println!("🚀 CVE Scanner listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    axum::serve(listener, app)
        .await
        .expect("axum server failed");
}

async fn health() -> &'static str {
    "ok"
}

async fn scan_upload(mut multipart: Multipart) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let base = PathBuf::from(format!("/tmp/dockdockgo-cve-{}", request_id));
    let blobs_dir = base.join("blobs").join("sha256");

    if let Err(e) = fs::create_dir_all(&blobs_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_response(
                Some(request_id),
                &format!("failed to create workspace: {e}"),
            )),
        )
            .into_response();
    }

    let cleanup_guard = CleanupGuard { path: base.clone() };

    let mut manifest_path: Option<PathBuf> = None;
    let mut config_path: Option<PathBuf> = None;
    let mut pull_context_raw: Option<Vec<u8>> = None;

    loop {
        let next = match multipart.next_field().await {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(error_response(
                        Some(request_id.clone()),
                        &format!("multipart error: {e}"),
                    )),
                )
                    .into_response();
            }
        };

        let Some(field) = next else { break };

        let name = field.name().unwrap_or("").to_string();
        let filename = field.file_name().unwrap_or("blob").to_string();

        let data = match field.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(error_response(
                        Some(request_id.clone()),
                        &format!("failed reading field bytes: {e}"),
                    )),
                )
                    .into_response();
            }
        };

        match name.as_str() {
            "manifest" => {
                let path = base.join("manifest.json");
                if let Err(e) = fs::write(&path, &data) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(error_response(
                            Some(request_id.clone()),
                            &format!("failed writing manifest: {e}"),
                        )),
                    )
                        .into_response();
                }
                manifest_path = Some(path);
            }

            "config" => {
                let path = base.join("config.json");
                if let Err(e) = fs::write(&path, &data) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(error_response(
                            Some(request_id.clone()),
                            &format!("failed writing config: {e}"),
                        )),
                    )
                        .into_response();
                }
                config_path = Some(path);
            }

            "pull_context" | "pullContext" => {
                pull_context_raw = Some(data.to_vec());
            }

            "blob" => {
                let path = blobs_dir.join(filename);
                if let Err(e) = fs::write(&path, &data) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(error_response(
                            Some(request_id.clone()),
                            &format!("failed writing blob: {e}"),
                        )),
                    )
                        .into_response();
                }
            }

            _ => {
                // champ inconnu ignoré
            }
        }
    }

    let manifest_path = match manifest_path {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(error_response(
                    Some(request_id.clone()),
                    "missing manifest field (name=manifest)",
                )),
            )
                .into_response();
        }
    };

    let pull_meta: Value = match pull_context_raw {
        None => json!({}),
        Some(raw) => match serde_json::from_slice::<Value>(&raw) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(error_response(
                        Some(request_id.clone()),
                        &format!("invalid pull_context json: {e}"),
                    )),
                )
                    .into_response();
            }
        },
    };

    let req = ScanRequest {
        request_id: Some(request_id.clone()),
        manifest_path: manifest_path.to_string_lossy().to_string(),
        config_path: config_path.map(|p| p.to_string_lossy().to_string()),
        blob_store_dir: base.join("blobs").to_string_lossy().to_string(),
        meta: json!({
            "source": "upload",
            "pull_context": pull_meta
        }),
    };

    let scan_res = match pipeline::run(&req) {
        Ok(r) => r,
        Err(e) => {
            let err = ScanResponse {
                request_id: req.request_id.clone(),
                status: ScanStatus::Error,
                missing_layers: vec![],
                message: Some(format!("scan failed: {e}")),
                summary: None,
                findings: vec![],
                raw_trivy_json: None,
                meta: req.meta.clone(),
            };
            return (StatusCode::OK, Json(err)).into_response();
        }
    };

    drop(cleanup_guard);

    (StatusCode::OK, Json(scan_res)).into_response()
}

fn error_response(request_id: Option<String>, msg: &str) -> ScanResponse {
    ScanResponse {
        request_id,
        status: ScanStatus::Error,
        missing_layers: vec![],
        message: Some(msg.to_string()),
        summary: None,
        findings: vec![],
        raw_trivy_json: None,
        meta: json!({}),
    }
}

struct CleanupGuard {
    path: PathBuf,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}