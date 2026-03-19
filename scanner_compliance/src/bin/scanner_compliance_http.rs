use axum::{
    extract::Multipart, http::StatusCode, response::IntoResponse, routing::post, Json, Router,
};
use scanner_compliance::models::{RawBlob, ScanRequest, Stage};
use scanner_compliance::pipeline;

use std::fs;
use std::io::Write;
use std::net::SocketAddr;

use tokio::net::TcpListener;
use uuid::Uuid;

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
        let file_name = field.file_name().unwrap_or("unknown").to_string();

        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("Read error: {}", e)).into_response();
            }
        };

        let file_path = format!("{}/{}", workspace_path, file_name);

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
            let digest = format!("sha256:{}", file_name);

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
