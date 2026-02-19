use axum::{
    routing::post,
    Json,
    Router,
    http::StatusCode,
    response::IntoResponse,
};
use scanner_compliance::models::ScanRequest;
use scanner_compliance::pipeline;
use tokio::net::TcpListener;

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

    // 1️⃣ Convertir ScanRequest -> ImageData
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

    // 2️⃣ Exécuter le scan
    let report = pipeline::scan_image(&image);

    // 3️⃣ Retourner JSON
    (StatusCode::OK, Json(report)).into_response()
}
