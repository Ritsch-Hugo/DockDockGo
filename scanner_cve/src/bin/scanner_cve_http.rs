use axum::{
    extract::{DefaultBodyLimit, Multipart},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

use serde_json::{json, Value};
use uuid::Uuid;

use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use scanner_cve::engine::pipeline;
use scanner_cve::models::{ScanRequest, ScanResponse, ScanStatus};

const MAX_BODY_SIZE: usize = 1024 * 1024 * 1024; // 1 GB
const MAX_MANIFEST_SIZE: usize = 5 * 1024 * 1024; // 5 MB
const MAX_CONFIG_SIZE: usize = 10 * 1024 * 1024; // 10 MB
const MAX_PULL_CONTEXT_SIZE: usize = 2 * 1024 * 1024; // 2 MB
const MAX_BLOB_SIZE: usize = 200 * 1024 * 1024; // 200 MB
const MAX_BLOBS: usize = 128;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/scan-upload", post(scan_upload))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3002));
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

    let mut seen_blob_names = HashSet::new();
    let mut blob_count = 0usize;
    let mut seen_manifest = false;
    let mut seen_config = false;
    let mut seen_pull_context = false;

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

        match name.as_str() {
            "manifest" => {
                if seen_manifest {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            "duplicate manifest field",
                        )),
                    )
                        .into_response();
                }
                seen_manifest = true;

                let data = match field.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(error_response(
                                Some(request_id.clone()),
                                &format!("failed reading manifest: {e}"),
                            )),
                        )
                            .into_response();
                    }
                };

                if data.len() > MAX_MANIFEST_SIZE {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            "manifest too large",
                        )),
                    )
                        .into_response();
                }

                if let Err(e) = serde_json::from_slice::<Value>(&data) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            &format!("invalid manifest json: {e}"),
                        )),
                    )
                        .into_response();
                }

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
                if seen_config {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            "duplicate config field",
                        )),
                    )
                        .into_response();
                }
                seen_config = true;

                let data = match field.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(error_response(
                                Some(request_id.clone()),
                                &format!("failed reading config: {e}"),
                            )),
                        )
                            .into_response();
                    }
                };

                if data.len() > MAX_CONFIG_SIZE {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            "config too large",
                        )),
                    )
                        .into_response();
                }

                if let Err(e) = serde_json::from_slice::<Value>(&data) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            &format!("invalid config json: {e}"),
                        )),
                    )
                        .into_response();
                }

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
                if seen_pull_context {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            "duplicate pull_context field",
                        )),
                    )
                        .into_response();
                }
                seen_pull_context = true;

                let data = match field.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(error_response(
                                Some(request_id.clone()),
                                &format!("failed reading pull_context: {e}"),
                            )),
                        )
                            .into_response();
                    }
                };

                if data.len() > MAX_PULL_CONTEXT_SIZE {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            "pull_context too large",
                        )),
                    )
                        .into_response();
                }

                if let Err(e) = serde_json::from_slice::<Value>(&data) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            &format!("invalid pull_context json: {e}"),
                        )),
                    )
                        .into_response();
                }

                pull_context_raw = Some(data.to_vec());
            }

            "blob" => {
                blob_count += 1;

                if blob_count > MAX_BLOBS {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            "too many blobs",
                        )),
                    )
                        .into_response();
                }

                let raw_filename = field.file_name().unwrap_or("").to_string();

                let safe_blob_name = match sanitize_blob_filename(&raw_filename) {
                    Ok(v) => v,
                    Err(msg) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(error_response(Some(request_id.clone()), &msg)),
                        )
                            .into_response();
                    }
                };

                if !seen_blob_names.insert(safe_blob_name.clone()) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            &format!("duplicate blob filename: {}", safe_blob_name),
                        )),
                    )
                        .into_response();
                }

                let data = match field.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(error_response(
                                Some(request_id.clone()),
                                &format!("failed reading blob: {e}"),
                            )),
                        )
                            .into_response();
                    }
                };

                if data.len() > MAX_BLOB_SIZE {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            &format!("blob too large: {}", safe_blob_name),
                        )),
                    )
                        .into_response();
                }

                let path = blobs_dir.join(&safe_blob_name);

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
                return (
                    StatusCode::BAD_REQUEST,
                    Json(error_response(
                        Some(request_id.clone()),
                        &format!("unexpected multipart field: {}", name),
                    )),
                )
                    .into_response();
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

fn sanitize_blob_filename(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("blob filename is missing".to_string());
    }

    let filename = Path::new(raw)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "invalid blob filename".to_string())?;

    if filename != raw {
        return Err("blob filename must not contain path separators".to_string());
    }

    if filename.len() != 64 {
        return Err("blob filename must be a 64-char sha256 hex digest".to_string());
    }

    if !filename.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("blob filename must contain only hex characters".to_string());
    }

    Ok(filename.to_ascii_lowercase())
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