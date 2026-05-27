use anyhow::Result;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

use crate::sbom::StoredSbom;

// ── Pool ──────────────────────────────────────────────────────────────────────

pub async fn connect(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    Ok(pool)
}

// ── SBOM helpers ──────────────────────────────────────────────────────────────

/// Load all SBOMs stored in the database. Called once at startup to
/// pre-populate the in-memory cache — Syft does not need to re-run.
pub async fn load_all_sboms(pool: &PgPool) -> Result<Vec<StoredSbom>> {
    let rows = sqlx::query(
        "SELECT image_name, image_digest, source, packages, generated_at FROM sboms",
    )
    .fetch_all(pool)
    .await?;

    let sboms = rows
        .into_iter()
        .filter_map(|r| {
            let packages_val: serde_json::Value = r.try_get("packages").ok()?;
            let packages = serde_json::from_value(packages_val).ok()?;
            Some(StoredSbom {
                image: r.try_get("image_name").ok()?,
                generated_at: r.try_get("generated_at").ok()?,
                image_digest: r.try_get("image_digest").ok(),
                source: r
                    .try_get::<Option<String>, _>("source")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "syft".to_string()),
                packages,
            })
        })
        .collect();

    Ok(sboms)
}

/// Insert or update a SBOM. Uses UPSERT on image_name so re-generating
/// a SBOM for the same image simply overwrites the previous row.
pub async fn upsert_sbom(pool: &PgPool, sbom: &StoredSbom) -> Result<()> {
    let packages_json = serde_json::to_value(&sbom.packages)?;

    sqlx::query(
        r#"
        INSERT INTO sboms (image_name, image_digest, source, packages, generated_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (image_name) DO UPDATE SET
            image_digest = EXCLUDED.image_digest,
            source       = EXCLUDED.source,
            packages     = EXCLUDED.packages,
            generated_at = EXCLUDED.generated_at
        "#,
    )
    .bind(&sbom.image)
    .bind(&sbom.image_digest)
    .bind(&sbom.source)
    .bind(packages_json)
    .bind(sbom.generated_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete the SBOM for `image_name`. Returns `true` if a row was deleted.
pub async fn delete_sbom(pool: &PgPool, image: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM sboms WHERE image_name = $1")
        .bind(image)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
