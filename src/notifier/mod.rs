use crate::db;
use crate::models::{MatchResult, Notification};
use chrono::Utc;
use reqwest::Client;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

pub type NotificationStore = Arc<Mutex<Vec<Notification>>>;

pub fn new_store() -> NotificationStore {
    Arc::new(Mutex::new(Vec::new()))
}

pub async fn run(
    mut match_rx: mpsc::Receiver<MatchResult>,
    store: NotificationStore,
    dashboard_url: Option<String>,
    db_pool: Option<PgPool>,
) {
    let client = Client::new();

    while let Some(result) = match_rx.recv().await {
        // Persist to DB (deduplication via ON CONFLICT DO NOTHING)
        if let Some(ref pool) = db_pool {
            let published_at = result.published_at;
            if let Err(e) = db::record_cve_alert(pool, &result, published_at).await {
                warn!(error = %e, cve_id = %result.cve_id, "Failed to persist CVE alert to DB");
            }
        }

        let notification = Notification {
            id: Uuid::new_v4(),
            cve_id: result.cve_id.clone(),
            image_name: result.image_name.clone(),
            matched_packages: result.matched_packages.clone(),
            sent_at: Utc::now(),
        };

        info!(
            notification_id = %notification.id,
            cve_id = %notification.cve_id,
            image = %notification.image_name,
            packages = ?notification.matched_packages,
            "Notification sent"
        );

        if let Some(ref url) = dashboard_url {
            match client.post(url).json(&notification).send().await {
                Ok(resp) => info!(status = %resp.status(), "Dashboard notified"),
                Err(e) => warn!(error = %e, "Failed to reach dashboard"),
            }
        }

        store.lock().unwrap().push(notification);
    }
}
