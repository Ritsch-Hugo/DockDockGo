pub mod handlers;
pub mod store;

use crate::auth::AppState; // Importe bien AppState
use axum::{routing::get, Router};

pub fn router() -> Router<AppState> {
    // On précise explicitement le type lors de la création
    Router::<AppState>::new() 
        .route("/dev", get(handlers::dev_dashboard))
        .route("/rssi", get(handlers::rssi_dashboard))
}