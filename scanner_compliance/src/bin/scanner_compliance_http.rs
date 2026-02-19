use axum::{
    routing::post,
    Router,
    Json,
    http::StatusCode,
    response::IntoResponse,
    extract::Multipart,
};
use scanner_compliance::models::ScanRequest;
use scanner_compliance::pipeline;
use tokio::net::TcpListener;
use uuid::Uuid;
use std::fs;
use std::io::Write;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/v1/scan", post(scan_handler)) // JSON endpoint existant
        .route("/v1/scan-upload", post(upload_handler)); // NOUVEAU multipart

    let addr = "127.0.0.1:3001";

    println!("🚀 Scanner HTTP listening on http://{}", addr);

    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind address");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

/* ---------------- JSON EXISTANT ---------------- */

async fn scan_handler(
    Json(req): Json<ScanRequest>,
) -> impl IntoResponse {

    let image = match pipeline::image_from_scan_request(req) {
        Ok(img) => img,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid request: {}", e),
            )
                .into_response();
        }
    };

    let report = pipeline::scan_image(&image);

    (StatusCode::OK, Json(report)).into_response()
}

/* ---------------- MULTIPART TEST ---------------- */

async fn upload_handler(
    mut multipart: Multipart,
) -> impl IntoResponse {

    // 1️⃣ Workspace
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

    let mut manifest_received = false;
    let mut blobs_count = 0;

    // 2️⃣ Lecture multipart
    while let Some(field) = multipart.next_field().await.unwrap() {

        let field_name = field.name().unwrap_or("").to_string();
        let file_name = field.file_name().unwrap_or("unknown").to_string();

        let data = field.bytes().await.unwrap();

        let file_path = format!("{}/{}", workspace_path, file_name);

        let mut file = fs::File::create(&file_path)
            .expect("Failed to create file");

        file.write_all(&data)
            .expect("Failed to write file");

        println!("📥 Received field '{}' -> {}", field_name, file_path);

        if field_name == "manifest" {
            manifest_received = true;
        }

        if field_name == "blob" {
            blobs_count += 1;
        }
    }

    // 3️⃣ Cleanup (on garde pour l’instant pour test visuel)
    println!("🧹 Cleaning workspace...");
    if let Err(e) = fs::remove_dir_all(&workspace_path) {
        eprintln!("Cleanup error: {}", e);
    }

    if !manifest_received {
        return (
            StatusCode::BAD_REQUEST,
            "No manifest provided",
        )
            .into_response();
    }

    (
        StatusCode::OK,
        format!("Upload OK ({} blobs)", blobs_count),
    )
        .into_response()
}
