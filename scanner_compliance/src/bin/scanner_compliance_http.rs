use axum::{
    extract::{DefaultBodyLimit, Multipart},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use scanner_compliance::models::{RawBlob, ScanRequest, Stage};
use scanner_compliance::pipeline;
use scanner_compliance::security::check_json_depth;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use uuid::Uuid;

/// Maximum total HTTP body size (10 GB).
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024 * 1024;

/// Maximum size of a single blob received via multipart (2 GB).
const MAX_BLOB_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Maximum size of manifest_raw (1 MB).
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// Computes the hex-encoded SHA256 of the given bytes.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Sanitizes a multipart file_name to a safe basename.
///
/// Accepts only the last path component and rejects anything that could
/// escape the workspace: separators, `..`, empty names, or names starting
/// with `.` (hidden files are not expected in this context).
///
/// Returns `None` if the name is unsafe or unusable.
fn sanitize_file_name(raw: &str) -> Option<String> {
    // Extract only the final component (drops any directory prefix)
    let base = Path::new(raw).file_name()?.to_str()?;

    // Reject empty, current-dir marker, or names containing separators
    if base.is_empty() || base == "." || base.contains('/') || base.contains('\\') {
        return None;
    }

    // Reject explicit traversal (redundant after file_name() but kept as defence-in-depth)
    if base == ".." || base.contains("..") {
        return None;
    }

    Some(base.to_string())
}

/// RAII guard for a temporary workspace directory.
///
/// Creates the directory on construction and removes it automatically on drop,
/// regardless of whether the owning function returns normally or via an early
/// return / panic.  The resolved path is verified to stay under `/tmp/scans/`
/// as a defence-in-depth measure.
struct WorkspaceGuard {
    path: PathBuf,
}

impl WorkspaceGuard {
    /// Creates `/tmp/scans/{id}`, verifies the canonical path prefix, and
    /// returns a guard that will clean up the directory on drop.
    fn create(id: &str) -> Result<Self, String> {
        let path = PathBuf::from(format!("/tmp/scans/{}", id));

        fs::create_dir_all(&path).map_err(|e| format!("Failed to create workspace: {}", e))?;

        // Resolve symlinks / `.` / `..` and assert we are still under /tmp/scans/
        let canonical = fs::canonicalize(&path)
            .map_err(|e| format!("Failed to canonicalize workspace path: {}", e))?;

        if !canonical.starts_with("/tmp/scans/") {
            // Remove the directory we just created before returning the error.
            let _ = fs::remove_dir_all(&path);
            return Err(format!(
                "Workspace path escapes /tmp/scans/: {:?}",
                canonical
            ));
        }

        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for WorkspaceGuard {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.path) {
            eprintln!("[workspace] cleanup error for {:?}: {}", self.path, e);
        }
    }
}

/// Waits for SIGTERM or SIGINT and returns, triggering axum's graceful shutdown.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => println!("[shutdown] SIGTERM received"),
        _ = sigint.recv()  => println!("[shutdown] SIGINT received"),
    }
}

/// Reads rate-limit settings from environment variables, with safe defaults.
///
/// - `RATE_LIMIT_PER_SECOND`  : replenish 1 token every N seconds (default: 1 → 1 req/s)
/// - `RATE_LIMIT_BURST`       : maximum burst size (default: 10)
fn rate_limit_config() -> (u64, u32) {
    let per_second = std::env::var("RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1);
    let burst = std::env::var("RATE_LIMIT_BURST")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(10);
    (per_second, burst)
}

#[tokio::main]
async fn main() {
    let (per_second, burst) = rate_limit_config();
    println!("Rate limit: 1 req / {}s, burst {}", per_second, burst);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3001);

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(per_second)
            .burst_size(burst)
            .finish()
            .expect("Invalid rate-limit configuration"),
    );

    // Routes soumises au rate limiting
    let scanned = Router::new()
        .route("/v1/scan", post(scan_handler))
        .route("/v1/scan-upload", post(upload_handler))
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    // /health exclue du rate limiting (sondes Kubernetes)
    let app = Router::new()
        .route("/health", get(health_handler))
        .merge(scanned);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    println!("Scanner HTTP listening on http://{}", addr);

    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind address");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("Server error");
}

/* ---------------- HEALTH ---------------- */

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/* ---------------- JSON ENDPOINT ---------------- */

async fn scan_handler(Json(req): Json<ScanRequest>) -> impl IntoResponse {
    let request_id = Uuid::new_v4().to_string();
    eprintln!("[req:{}] scan_handler start", request_id);

    if req.manifest_raw.len() > MAX_MANIFEST_BYTES {
        eprintln!(
            "[req:{}] rejected: manifest_raw too large ({} bytes)",
            request_id,
            req.manifest_raw.len()
        );
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "manifest_raw too large: {} bytes (max 1 MB)",
                req.manifest_raw.len()
            ),
        )
            .into_response();
    }

    if let Err(e) = check_json_depth(&req.manifest_raw) {
        eprintln!("[req:{}] rejected: {}", request_id, e);
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    let image = match pipeline::image_from_scan_request(req) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("[req:{}] pipeline error: {}", request_id, e);
            return (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)).into_response();
        }
    };

    let report = pipeline::scan_image(&image);
    eprintln!(
        "[req:{}] scan complete, {} findings",
        request_id,
        report.findings.len()
    );

    (StatusCode::OK, Json(report)).into_response()
}

/* ---------------- MULTIPART ENDPOINT ---------------- */

async fn upload_handler(mut multipart: Multipart) -> impl IntoResponse {
    // Create workspace under /tmp/scans/<uuid> (absolute path).
    // The guard removes the directory automatically when it goes out of scope,
    // covering both normal returns and every early-return error path.
    let request_id = Uuid::new_v4().to_string();
    eprintln!("[req:{}] upload_handler start", request_id);

    let workspace = match WorkspaceGuard::create(&request_id) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("[req:{}] workspace creation failed: {}", request_id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
        }
    };

    eprintln!(
        "[req:{}] workspace created: {:?}",
        request_id,
        workspace.path()
    );

    let mut manifest_path: Option<PathBuf> = None;
    let mut blobs: Vec<RawBlob> = Vec::new();

    // Lecture multipart (SAFE)
    while let Some(field) = match multipart.next_field().await {
        Ok(f) => f,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Multipart error: {}", e)).into_response();
        }
    } {
        let field_name = field.name().unwrap_or("").to_string();
        let raw_file_name = field.file_name().unwrap_or("unknown").to_string();

        let safe_name = match sanitize_file_name(&raw_file_name) {
            Some(n) => n,
            None => {
                eprintln!(
                    "[req:{}] rejected unsafe file_name: {:?}",
                    request_id, raw_file_name
                );
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Rejected unsafe file_name: {:?}", raw_file_name),
                )
                    .into_response();
            }
        };

        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("Read error: {}", e)).into_response();
            }
        };

        if data.len() > MAX_BLOB_BYTES {
            eprintln!(
                "[req:{}] rejected blob '{}': {} bytes exceeds max {} bytes",
                request_id,
                safe_name,
                data.len(),
                MAX_BLOB_BYTES
            );
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "Blob '{}' too large: {} bytes (max {} bytes)",
                    safe_name,
                    data.len(),
                    MAX_BLOB_BYTES
                ),
            )
                .into_response();
        }

        // safe_name is a guaranteed pure basename (no separators, no `..`)
        let file_path = workspace.path().join(&safe_name);

        let mut file = match fs::File::create(&file_path) {
            Ok(f) => f,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("File create error: {}", e),
                )
                    .into_response();
            }
        };

        if let Err(e) = file.write_all(&data) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Write error: {}", e),
            )
                .into_response();
        }

        eprintln!(
            "[req:{}] received field '{}' ({} bytes) -> {:?}",
            request_id,
            field_name,
            data.len(),
            file_path
        );

        if field_name == "manifest" {
            manifest_path = Some(file_path.clone());
        }

        if field_name == "blob" {
            let declared = safe_name.as_str();
            let computed = sha256_hex(&data);

            if computed != declared {
                eprintln!(
                    "[req:{}] digest mismatch for blob '{}': declared sha256:{}, computed sha256:{}",
                    request_id, safe_name, declared, computed
                );
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Digest mismatch for blob '{}': declared sha256:{}, computed sha256:{}",
                        safe_name, declared, computed
                    ),
                )
                    .into_response();
            }
            eprintln!("[req:{}] blob '{}' digest OK", request_id, safe_name);

            blobs.push(RawBlob {
                digest: format!("sha256:{}", safe_name),
                media_type: None,
                size: None,
                path: Some(file_path.to_string_lossy().into_owned()),
                bytes_b64: None,
            });
        }
    }

    // Vérification manifest
    let manifest_path = match manifest_path {
        Some(p) => p,
        None => {
            eprintln!("[req:{}] rejected: no manifest provided", request_id);
            return (StatusCode::BAD_REQUEST, "No manifest provided").into_response();
        }
    };

    // Lire manifest
    let manifest_raw = match fs::read_to_string(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to read manifest: {}", e),
            )
                .into_response();
        }
    };

    if let Err(e) = check_json_depth(&manifest_raw) {
        eprintln!("[req:{}] rejected: {}", request_id, e);
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    // Construire ScanRequest
    let req = ScanRequest {
        image_ref: Some("upload".into()),
        manifest_raw,
        blobs,
        stage: Stage::Final,
    };

    // Pipeline
    let image = match pipeline::image_from_scan_request(req) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("[req:{}] pipeline error: {}", request_id, e);
            return (StatusCode::BAD_REQUEST, format!("ScanRequest error: {}", e)).into_response();
        }
    };

    let report = pipeline::scan_image(&image);
    eprintln!(
        "[req:{}] scan complete, {} findings",
        request_id,
        report.findings.len()
    );

    // workspace drops here → Drop::drop() removes /tmp/scans/<uuid> automatically
    eprintln!("[req:{}] workspace cleanup triggered", request_id);
    (StatusCode::OK, Json(report)).into_response()
}
