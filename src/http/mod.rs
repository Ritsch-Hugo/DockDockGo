use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::notifier::NotificationStore;
use crate::sbom::{generate_and_store, SbomStore};
use crate::store::WhitelistStore;

#[derive(Clone)]
struct AppState {
    whitelist: Arc<WhitelistStore>,
    notifications: NotificationStore,
    sbom_store: Arc<SbomStore>,
    syft_bin: String,
}

pub fn router(
    whitelist: Arc<WhitelistStore>,
    notifications: NotificationStore,
    sbom_store: Arc<SbomStore>,
    syft_bin: String,
) -> Router {
    let state = AppState {
        whitelist,
        notifications,
        sbom_store,
        syft_bin,
    };

    Router::new()
        // Core
        .route("/health", get(health))
        .route("/images", get(get_images))
        .route("/notifications", get(get_notifications))
        // Whitelist management
        .route("/whitelist/reload", post(reload_whitelist))
        // SBOM management
        .route("/sbom", get(list_sboms))
        .route("/sbom", delete(delete_sbom))
        .route("/sbom/refresh", post(refresh_sbom))
        .layer(RequestBodyLimitLayer::new(16 * 1024))
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .with_state(state)
}

// ── Core handlers ─────────────────────────────────────────────────────────────

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn get_images(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(state.whitelist.images()))
}

async fn get_notifications(State(state): State<AppState>) -> Json<serde_json::Value> {
    let n = state.notifications.lock().unwrap();
    Json(serde_json::json!(*n))
}

// ── SBOM handlers ─────────────────────────────────────────────────────────────

/// GET /sbom — list all stored SBOMs
async fn list_sboms(State(state): State<AppState>) -> Json<serde_json::Value> {
    let sboms = state.sbom_store.list();
    Json(serde_json::json!(sboms))
}

#[derive(Deserialize)]
struct ImageQuery {
    /// Full image reference, e.g. ?image=nginx:1.25
    image: String,
}

/// DELETE /sbom?image=<ref> — remove a stored SBOM
async fn delete_sbom(
    State(state): State<AppState>,
    Query(q): Query<ImageQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let existed = state.sbom_store.delete(&q.image).await;
    if existed {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "deleted": q.image })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no SBOM found for this image" })),
        )
    }
}

/// POST /sbom/refresh?image=<ref>
/// Trigger an immediate Syft scan for the given image (or all whitelisted images
/// if the query param is omitted).
async fn refresh_sbom(
    State(state): State<AppState>,
    query: Option<Query<ImageQuery>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let images: Vec<String> = match query {
        // Specific image
        Some(Query(q)) => vec![q.image],
        // All whitelisted images
        None => state
            .whitelist
            .images()
            .iter()
            .map(|i| i.name.clone())
            .collect(),
    };

    let mut results = serde_json::Map::new();
    for image in &images {
        match generate_and_store(&state.sbom_store, image, &state.syft_bin).await {
            Ok(sbom) => {
                results.insert(
                    image.clone(),
                    serde_json::json!({
                        "status": "ok",
                        "packages": sbom.packages.len(),
                        "generated_at": sbom.generated_at,
                    }),
                );
            }
            Err(e) => {
                results.insert(
                    image.clone(),
                    serde_json::json!({ "status": "error", "error": e.to_string() }),
                );
            }
        }
    }

    (StatusCode::OK, Json(serde_json::Value::Object(results)))
}

// ── Whitelist handlers ────────────────────────────────────────────────────────

/// POST /whitelist/reload
///
/// Re-reads `whitelist.toml` from disk, adds any new images to the live list,
/// and immediately generates a Syft SBOM for each new image.
/// Already-whitelisted images are untouched — no duplicate SBOMs.
///
/// Response:
/// ```json
/// {
///   "added": ["alpine:3.20"],
///   "already_present": 3,
///   "sboms": {
///     "alpine:3.20": { "status": "ok", "packages": 42 }
///   }
/// }
/// ```
async fn reload_whitelist(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let new_images = match state.whitelist.reload() {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            );
        }
    };

    let already_present = state.whitelist.images().len() - new_images.len();

    let mut sboms = serde_json::Map::new();
    for image in &new_images {
        let entry = match generate_and_store(&state.sbom_store, image, &state.syft_bin).await {
            Ok(sbom) => serde_json::json!({
                "status": "ok",
                "packages": sbom.packages.len(),
            }),
            Err(e) => serde_json::json!({ "status": "error", "error": e.to_string() }),
        };
        sboms.insert(image.clone(), entry);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "added": new_images,
            "already_present": already_present,
            "sboms": sboms,
        })),
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_router() -> Router {
        let whitelist = Arc::new(crate::store::WhitelistStore::from_images(vec![]));
        let notifications = crate::notifier::new_store();
        let sbom_store = SbomStore::open(
            &std::env::temp_dir()
                .join(format!("cdv_test_{}", std::process::id()))
                .to_string_lossy()
                .to_string(),
        )
        .expect("test sbom store");
        router(whitelist, notifications, sbom_store, "syft".to_owned())
    }

    async fn get(router: Router, uri: &str) -> axum::response::Response {
        router
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn health_ok() {
        let resp = get(test_router(), "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn images_array() {
        let resp = get(test_router(), "/images").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
    }

    #[tokio::test]
    async fn notifications_empty() {
        let resp = get(test_router(), "/notifications").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!([]));
    }

    #[tokio::test]
    async fn sbom_list_empty() {
        let resp = get(test_router(), "/sbom").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
    }

    #[tokio::test]
    async fn unknown_route_404() {
        let resp = get(test_router(), "/unknown").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
