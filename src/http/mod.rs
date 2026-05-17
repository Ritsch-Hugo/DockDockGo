use axum::{
    extract::State,
    routing::get,
    Json, Router,
};
use std::sync::Arc;

use crate::notifier::NotificationStore;
use crate::store::WhitelistStore;

#[derive(Clone)]
struct AppState {
    whitelist: Arc<WhitelistStore>,
    notifications: NotificationStore,
}

pub fn router(whitelist: Arc<WhitelistStore>, notifications: NotificationStore) -> Router {
    let state = AppState {
        whitelist,
        notifications,
    };

    Router::new()
        .route("/health", get(health))
        .route("/images", get(get_images))
        .route("/notifications", get(get_notifications))
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
