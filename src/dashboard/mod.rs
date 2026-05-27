pub mod handlers;
pub mod store;

use crate::auth::AppState;
use axum::{routing::{get, post, delete}, Router};

pub fn router() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/dev",    get(handlers::dev_dashboard))
        .route("/rssi",   get(handlers::rssi_dashboard))
        .route("/events", get(handlers::dashboard_events_stream))
        .route("/pull/:uuid", get(handlers::pull_detail))
        .route("/api/search", get(handlers::search_pulls))
        .route("/api/whitelist", post(handlers::api_add_whitelist))
        .route("/api/whitelist/:id", delete(handlers::api_remove_whitelist))
        .route("/api/blacklist", post(handlers::api_add_blacklist))
        .route("/api/blacklist/:id", delete(handlers::api_remove_blacklist))
        .route("/api/cache/:id", delete(handlers::api_delete_cache))
        .route("/api/search/dev", get(handlers::search_pulls_dev))
        .route("/logo.png", get(handlers::serve_logo))
}