use axum::{
    extract::Multipart, http::StatusCode, response::IntoResponse, routing::post, Json, Router,
};
use scanner_compliance::models::{RawBlob, ScanRequest, Stage};
use scanner_compliance::pipeline;

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;

use tokio::net::TcpListener;
use uuid::Uuid;

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
        .route("/v1/scan-upload", post(upload_handler));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));

    println!("🚀 Scanner HTTP listening on http://{}", addr);

    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind address");

    axum::serve(listener, app).await.expect("Server error");
}

/* ---------------- JSON ENDPOINT ---------------- */

async fn scan_handler(Json(req): Json<ScanRequest>) -> impl IntoResponse {
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
            let digest = format!("sha256:{}", safe_name);

            blobs.push(RawBlob {
                digest,
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
