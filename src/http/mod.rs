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

#[derive(Clone)]
struct AppState {
    notifications: NotificationStore,
    sbom_store: Arc<SbomStore>,
    syft_bin: String,
}

pub fn router(
    notifications: NotificationStore,
    sbom_store: Arc<SbomStore>,
    syft_bin: String,
) -> Router {
    let state = AppState {
        notifications,
        sbom_store,
        syft_bin,
    };

    Router::new()
        .route("/health", get(health))
        .route("/notifications", get(get_notifications))
        // SBOM management — POST /sbom/refresh is called by the orchestrator
        // when a new image is added to the whitelist
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

async fn get_notifications(State(state): State<AppState>) -> Json<serde_json::Value> {
    let n = state.notifications.lock().unwrap();
    Json(serde_json::json!(*n))
}

// ── SBOM handlers ─────────────────────────────────────────────────────────────

async fn list_sboms(State(state): State<AppState>) -> Json<serde_json::Value> {
    let sboms = state.sbom_store.list();
    Json(serde_json::json!(sboms))
}

#[derive(Deserialize)]
struct ImageQuery {
    image: String,
}

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
///
/// Called by the orchestrator when a new image is added to the whitelist.
/// Spawns a background Syft scan and returns 202 Accepted immediately —
/// Syft can take tens of seconds; the caller should not block on this.
///
/// Without `?image=`, refreshes all images that already have a stored SBOM.
async fn refresh_sbom(
    State(state): State<AppState>,
    query: Option<Query<ImageQuery>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let images: Vec<String> = match query {
        Some(Query(q)) => vec![q.image],
        None => state
            .sbom_store
            .list()
            .into_iter()
            .map(|s| s.image)
            .collect(),
    };

    for image in &images {
        let store = Arc::clone(&state.sbom_store);
        let syft = state.syft_bin.clone();
        let img = image.clone();
        tokio::spawn(async move {
            match generate_and_store(&store, &img, &syft).await {
                Ok(s) => {
                    tracing::info!(image = %img, packages = s.packages.len(), "SBOM refreshed")
                }
                Err(e) => tracing::warn!(image = %img, error = %e, "SBOM refresh failed"),
            }
        });
    }

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "accepted",
            "queued": images,
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
        let notifications = crate::notifier::new_store();
        let sbom_store = SbomStore::open(
            &std::env::temp_dir()
                .join(format!("cdv_test_{}", std::process::id()))
                .to_string_lossy()
                .to_string(),
        )
        .expect("test sbom store");
        router(notifications, sbom_store, "syft".to_owned())
    }

    async fn get_req(router: Router, uri: &str) -> axum::response::Response {
        router
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn health_ok() {
        let resp = get_req(test_router(), "/health").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn notifications_empty() {
        let resp = get_req(test_router(), "/notifications").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!([]));
    }

    #[tokio::test]
    async fn sbom_list_empty() {
        let resp = get_req(test_router(), "/sbom").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
    }

    #[tokio::test]
    async fn unknown_route_404() {
        let resp = get_req(test_router(), "/unknown").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
