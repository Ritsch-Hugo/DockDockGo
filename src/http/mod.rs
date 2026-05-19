use axum::{
    extract::State,
    routing::get,
    Json, Router,
};
use std::sync::Arc;
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use crate::notifier::NotificationStore;
use crate::store::WhitelistStore;

#[derive(Clone)]
struct AppState {
    whitelist: Arc<WhitelistStore>,
    notifications: NotificationStore,
}

pub fn router(whitelist: Arc<WhitelistStore>, notifications: NotificationStore) -> Router {
    let state = AppState { whitelist, notifications };

    Router::new()
        .route("/health", get(health))
        .route("/images", get(get_images))
        .route("/notifications", get(get_notifications))
        .layer(RequestBodyLimitLayer::new(16 * 1024)) // 16 KB max body
        .layer(TimeoutLayer::new(Duration::from_secs(10)))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn get_images(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(state.whitelist.images()))
}

async fn get_notifications(State(state): State<AppState>) -> Json<serde_json::Value> {
    let notifications = state.notifications.lock().unwrap();
    Json(serde_json::json!(*notifications))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_router() -> Router {
        let whitelist = Arc::new(crate::store::WhitelistStore::from_images(vec![]));
        let notifications = crate::notifier::new_store();
        router(whitelist, notifications)
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let resp = test_router()
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn images_returns_json_array() {
        let resp = test_router()
            .oneshot(Request::builder().uri("/images").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.is_array());
    }

    #[tokio::test]
    async fn notifications_empty_on_start() {
        let resp = test_router()
            .oneshot(Request::builder().uri("/notifications").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!([]));
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let resp = test_router()
            .oneshot(Request::builder().uri("/unknown").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
