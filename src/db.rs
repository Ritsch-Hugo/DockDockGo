use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::collections::HashSet;

use crate::models::{MatchResult, Severity};

// ── Pool ──────────────────────────────────────────────────────────────────────

pub async fn connect(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    Ok(pool)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Load all CVE IDs already present in `cve_alerts`.
/// Called once at poller startup to pre-populate the `seen` set, so CVEs
/// already processed before a restart are not re-notified.
pub async fn load_seen_cve_ids(pool: &PgPool) -> Result<HashSet<String>> {
    let rows = sqlx::query_scalar::<_, String>("SELECT DISTINCT cve_id FROM cve_alerts")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().collect())
}

/// Persist one CVE alert for a (cve_id, image_name) pair.
/// ON CONFLICT DO NOTHING — idempotent, safe to call multiple times.
pub async fn record_cve_alert(
    pool: &PgPool,
    result: &MatchResult,
    published_at: DateTime<Utc>,
) -> Result<()> {
    let severity_str = match result.severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
    };
    let packages_json = serde_json::to_value(&result.matched_packages)?;

    sqlx::query(
        r#"
        INSERT INTO cve_alerts
            (cve_id, image_name, severity, description, affected_packages, published_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (cve_id, image_name) DO NOTHING
        "#,
    )
    .bind(&result.cve_id)
    .bind(&result.image_name)
    .bind(severity_str)
    .bind(&result.description)
    .bind(packages_json)
    .bind(published_at)
    .execute(pool)
    .await?;

    Ok(())
}
