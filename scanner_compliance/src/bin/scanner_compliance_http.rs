use axum::{
    routing::post,
    Router,
    Json,
    http::StatusCode,
    response::IntoResponse,
};
use scanner_compliance::models::ScanRequest;
use scanner_compliance::pipeline;
use tokio::net::TcpListener;
use uuid::Uuid;
use std::fs;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/v1/scan", post(scan_handler));

    let addr = "127.0.0.1:3001";

    println!("🚀 Scanner HTTP listening on http://{}", addr);

    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind address");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

async fn scan_handler(
    Json(req): Json<ScanRequest>,
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

    // 2️⃣ Scan
    let response = {
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
    };

    // 3️⃣ Cleanup
    if let Err(e) = fs::remove_dir_all(&workspace_path) {
        eprintln!("Failed to cleanup workspace {}: {}", workspace_path, e);
    } else {
        println!("🧹 Workspace deleted: {}", workspace_path);
    }

    response
}
