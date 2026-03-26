pub mod handlers;
pub mod store;

use axum::{routing::get, Router};

pub fn router() -> Router {
    Router::new()
        // Ces routes seront préfixées par /dashboard (grâce au .nest)
        .route("/dev", get(handlers::dev_dashboard))
        .route("/rssi", get(handlers::rssi_dashboard))
}