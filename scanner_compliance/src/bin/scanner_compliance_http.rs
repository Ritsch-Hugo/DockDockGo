use axum::{
    extract::{DefaultBodyLimit, Multipart},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use scanner_compliance::models::{RawBlob, ScanRequest, Stage};
use scanner_compliance::pipeline;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::TcpListener;
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

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/v1/scan", post(scan_handler))
        .route("/v1/scan-upload", post(upload_handler))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));

    println!("🚀 Scanner HTTP listening on http://{}", addr);

    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind address");

    axum::serve(listener, app).await.expect("Server error");
}

/* ---------------- JSON ENDPOINT ---------------- */

async fn scan_handler(Json(req): Json<ScanRequest>) -> impl IntoResponse {
    if req.manifest_raw.len() > MAX_MANIFEST_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            format!("manifest_raw too large: {} bytes (max 1 MB)", req.manifest_raw.len()),
        )
            .into_response();
    }

    let image = match pipeline::image_from_scan_request(req) {
        Ok(img) => img,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid request: {}", e)).into_response();
        }
    };

    let report = pipeline::scan_image(&image);

    (StatusCode::OK, Json(report)).into_response()
}

/* ---------------- MULTIPART ENDPOINT ---------------- */

async fn upload_handler(mut multipart: Multipart) -> impl IntoResponse {
    // Workspace
    let request_id = Uuid::new_v4().to_string();
    let workspace_path = format!("./tmp/scans/{}", request_id);

    if let Err(e) = fs::create_dir_all(&workspace_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create workspace: {}", e),
        )
            .into_response();
    }

    println!("📂 Workspace created: {}", workspace_path);

    let mut manifest_path: Option<String> = None;
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
                let _ = fs::remove_dir_all(&workspace_path);
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
            let _ = fs::remove_dir_all(&workspace_path);
            return (
                StatusCode::BAD_REQUEST,
                format!("Blob '{}' too large: {} bytes (max {} bytes)", safe_name, data.len(), MAX_BLOB_BYTES),
            )
                .into_response();
        }

        // safe_name is a guaranteed pure basename (no separators, no `..`)
        let file_path = format!("{}/{}", workspace_path, safe_name);

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

        println!("📥 Received '{}' -> {}", field_name, file_path);

        if field_name == "manifest" {
            manifest_path = Some(file_path.clone());
        }

        if field_name == "blob" {
            let declared = safe_name.as_str();
            let computed = sha256_hex(&data);

            if computed != declared {
                let _ = fs::remove_dir_all(&workspace_path);
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "Digest mismatch for blob '{}': declared sha256:{}, computed sha256:{}",
                        safe_name, declared, computed
                    ),
                )
                    .into_response();
            }

            blobs.push(RawBlob {
                digest: format!("sha256:{}", safe_name),
                media_type: None,
                size: None,
                path: Some(file_path.clone()),
                bytes_b64: None,
            });
        }
    }

    // Vérification manifest
    let manifest_path = match manifest_path {
        Some(p) => p,
        None => {
            let _ = fs::remove_dir_all(&workspace_path);
            return (StatusCode::BAD_REQUEST, "No manifest provided").into_response();
        }
    };

    // Lire manifest
    let manifest_raw = match fs::read_to_string(&manifest_path) {
        Ok(m) => m,
        Err(e) => {
            let _ = fs::remove_dir_all(&workspace_path);
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to read manifest: {}", e),
            )
                .into_response();
        }
    };

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
            let _ = fs::remove_dir_all(&workspace_path);
            return (StatusCode::BAD_REQUEST, format!("ScanRequest error: {}", e)).into_response();
        }
    };

    let report = pipeline::scan_image(&image);

    // Cleanup
    if let Err(e) = fs::remove_dir_all(&workspace_path) {
        eprintln!("Cleanup error: {}", e);
    }

    (StatusCode::OK, Json(report)).into_response()
}
