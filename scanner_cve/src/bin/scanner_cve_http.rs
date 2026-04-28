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
    time::Instant,
};

use tokio::io::AsyncWriteExt;

use tracing::{error, info, warn};

use scanner_cve::engine::pipeline;
use scanner_cve::models::{ScanRequest, ScanResponse, ScanStatus};

const MAX_BODY_SIZE: usize = 10 * 1024 * 1024 * 1024; // 10 GB
const MAX_MANIFEST_SIZE: usize = 1024 * 1024; // 1 MB
const MAX_CONFIG_SIZE: usize = 5 * 1024 * 1024; // 5 MB
const MAX_PULL_CONTEXT_SIZE: usize = 2 * 1024 * 1024; // 2 MB
const MAX_BLOB_SIZE: usize = 2 * 1024 * 1024 * 1024; // 2 GB
const MAX_BLOBS: usize = 128;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/scan-upload", post(scan_upload))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3002));
    info!(address = %addr, "CVE scanner listening");

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
    let start = Instant::now();
    let base = PathBuf::from(format!("/tmp/dockdockgo-cve-{}", request_id));
    let blobs_dir = base.join("blobs").join("sha256");

    info!(request_id = %request_id, "scan request received");

    if let Err(e) = fs::create_dir_all(&blobs_dir) {
        error!(request_id = %request_id, error = %e, "failed to create workspace");
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
                warn!(request_id = %request_id, reason = "multipart error", error = %e, "input rejected");
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

        let Some(mut field) = next else { break };

        let name = field.name().unwrap_or("").to_string();

        match name.as_str() {
            "manifest" => {
                if seen_manifest {
                    warn!(request_id = %request_id, reason = "duplicate manifest field", "input rejected");
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
                        warn!(request_id = %request_id, reason = "failed reading manifest", error = %e, "input rejected");
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
                    warn!(request_id = %request_id, reason = "manifest too large", size = data.len(), "input rejected");
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
                    warn!(request_id = %request_id, reason = "invalid manifest json", error = %e, "input rejected");
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
                    error!(request_id = %request_id, error = %e, "failed writing manifest");
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
                    warn!(request_id = %request_id, reason = "duplicate config field", "input rejected");
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
                        warn!(request_id = %request_id, reason = "failed reading config", error = %e, "input rejected");
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
                    warn!(request_id = %request_id, reason = "config too large", size = data.len(), "input rejected");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(Some(request_id.clone()), "config too large")),
                    )
                        .into_response();
                }

                if let Err(e) = serde_json::from_slice::<Value>(&data) {
                    warn!(request_id = %request_id, reason = "invalid config json", error = %e, "input rejected");
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
                    error!(request_id = %request_id, error = %e, "failed writing config");
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
                    warn!(request_id = %request_id, reason = "duplicate pull_context field", "input rejected");
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
                        warn!(request_id = %request_id, reason = "failed reading pull_context", error = %e, "input rejected");
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
                    warn!(request_id = %request_id, reason = "pull_context too large", size = data.len(), "input rejected");
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
                    warn!(request_id = %request_id, reason = "invalid pull_context json", error = %e, "input rejected");
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
                    warn!(request_id = %request_id, reason = "too many blobs", count = blob_count, "input rejected");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(Some(request_id.clone()), "too many blobs")),
                    )
                        .into_response();
                }

                let raw_filename = field.file_name().unwrap_or("").to_string();

                let safe_blob_name = match sanitize_blob_filename(&raw_filename) {
                    Ok(v) => v,
                    Err(msg) => {
                        warn!(request_id = %request_id, reason = "invalid blob filename", filename = %raw_filename, "input rejected");
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(error_response(Some(request_id.clone()), &msg)),
                        )
                            .into_response();
                    }
                };

                if !seen_blob_names.insert(safe_blob_name.clone()) {
                    warn!(request_id = %request_id, reason = "duplicate blob filename", filename = %safe_blob_name, "input rejected");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(error_response(
                            Some(request_id.clone()),
                            &format!("duplicate blob filename: {}", safe_blob_name),
                        )),
                    )
                        .into_response();
                }

                let path = blobs_dir.join(&safe_blob_name);

                let mut file = match tokio::fs::File::create(&path).await {
                    Ok(f) => f,
                    Err(e) => {
                        error!(request_id = %request_id, error = %e, "failed creating blob file");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(error_response(
                                Some(request_id.clone()),
                                "failed creating blob file",
                            )),
                        )
                            .into_response();
                    }
                };

                let mut written = 0usize;
                loop {
                    let chunk = match field.chunk().await {
                        Ok(Some(c)) => c,
                        Ok(None) => break,
                        Err(e) => {
                            warn!(request_id = %request_id, reason = "failed reading blob chunk", error = %e, "input rejected");
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

                    written = match written.checked_add(chunk.len()) {
                        Some(v) => v,
                        None => {
                            warn!(request_id = %request_id, reason = "blob size overflow", filename = %safe_blob_name, "input rejected");
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(error_response(
                                    Some(request_id.clone()),
                                    &format!("blob too large: {}", safe_blob_name),
                                )),
                            )
                                .into_response();
                        }
                    };

                    if written > MAX_BLOB_SIZE {
                        warn!(request_id = %request_id, reason = "blob too large", filename = %safe_blob_name, size = written, "input rejected");
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(error_response(
                                Some(request_id.clone()),
                                &format!("blob too large: {}", safe_blob_name),
                            )),
                        )
                            .into_response();
                    }

                    if let Err(e) = file.write_all(&chunk).await {
                        error!(request_id = %request_id, error = %e, "failed writing blob chunk");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(error_response(
                                Some(request_id.clone()),
                                "failed writing blob",
                            )),
                        )
                            .into_response();
                    }
                }
            }

            _ => {
                warn!(request_id = %request_id, reason = "unexpected multipart field", field = %name, "input rejected");
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
            warn!(request_id = %request_id, reason = "missing manifest field", "input rejected");
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
                warn!(request_id = %request_id, reason = "invalid pull_context json", error = %e, "input rejected");
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

    info!(request_id = %request_id, blobs = blob_count, "starting scan pipeline");

    let scan_res = match pipeline::run(&req).await {
        Ok(r) => r,
        Err(e) => {
            error!(request_id = %request_id, error = %e, duration_ms = start.elapsed().as_millis(), "scan pipeline failed");
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

    if let Some(ref summary) = scan_res.summary {
        info!(
            request_id = %request_id,
            status = "complete",
            total = summary.vulnerabilities_total,
            critical = summary.severity_count.critical,
            high = summary.severity_count.high,
            medium = summary.severity_count.medium,
            low = summary.severity_count.low,
            duration_ms = start.elapsed().as_millis(),
            "scan complete"
        );
    } else {
        info!(request_id = %request_id, status = ?scan_res.status, duration_ms = start.elapsed().as_millis(), "scan complete");
    }

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
