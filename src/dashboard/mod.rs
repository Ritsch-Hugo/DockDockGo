pub mod handlers;
pub mod store;

use axum::{routing::get, Router};
use crate::auth::OidcState;

pub fn router() -> Router<OidcState> {
    Router::new()
        .route("/dev", get(handlers::dev_dashboard))
        .route("/rssi", get(handlers::rssi_dashboard))
}