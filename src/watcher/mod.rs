use crate::sbom::{generate_and_store, SbomStore};
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Listens on the PostgreSQL channel `whitelist_new`.
///
/// The DB trigger `trg_whitelist_new` fires `pg_notify('whitelist_new', ...)`
/// after every INSERT on the `whitelist` table.  This task picks up those
/// notifications and runs Syft to generate (or refresh) the SBOM for the
/// newly whitelisted image, regardless of which service performed the INSERT.
pub async fn run(pool: PgPool, sbom_store: Arc<SbomStore>, syft_bin: String) {
    let mut listener = match PgListener::connect_with(&pool).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, "Failed to create PgListener — whitelist watcher disabled");
            return;
        }
    };

    if let Err(e) = listener.listen("whitelist_new").await {
        error!(error = %e, "Failed to LISTEN on 'whitelist_new' — whitelist watcher disabled");
        return;
    }

    info!("Watching PostgreSQL channel 'whitelist_new' for new images");

    loop {
        match listener.recv().await {
            Ok(notification) => {
                let payload = notification.payload().to_owned();
                let store = Arc::clone(&sbom_store);
                let syft = syft_bin.clone();

                tokio::spawn(async move {
                    match serde_json::from_str::<serde_json::Value>(&payload) {
                        Ok(json) => {
                            let registry = json["registry"].as_str().unwrap_or("");
                            let repository = json["repository"].as_str().unwrap_or("");
                            let tag = json["tag"].as_str();

                            let image_ref = match tag {
                                Some(t) if !t.is_empty() => {
                                    format!("{}/{}:{}", registry, repository, t)
                                }
                                _ => format!("{}/{}", registry, repository),
                            };

                            info!(image = %image_ref, "New whitelist entry — generating SBOM");
                            match generate_and_store(&store, &image_ref, &syft).await {
                                Ok(s) => info!(
                                    image = %image_ref,
                                    packages = s.packages.len(),
                                    "SBOM generated from whitelist notify"
                                ),
                                Err(e) => {
                                    warn!(image = %image_ref, error = %e, "SBOM generation failed")
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, payload = %payload, "Failed to parse whitelist_new payload")
                        }
                    }
                });
            }
            // sqlx PgListener reconnects automatically on transient connection errors
            Err(e) => error!(error = %e, "PgListener recv error"),
        }
    }
}
