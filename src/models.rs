use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Package {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub ecosystem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cve {
    pub id: String,
    pub description: String,
    pub severity: Severity,
    pub affected_packages: Vec<Package>,
    pub published_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Sbom {
    /// Fallback packages defined in whitelist.toml.
    /// Used only when no Syft-generated SBOM exists for this image.
    #[serde(default)]
    pub packages: Vec<Package>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistedImage {
    pub name: String,
    /// Static SBOM from whitelist.toml (fallback when Syft hasn't run yet).
    #[serde(default)]
    pub sbom: Sbom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub cve_id: String,
    pub image_name: String,
    pub matched_packages: Vec<Package>,
    /// Carried from the source CVE so the notifier can persist it without
    /// needing a separate lookup.
    pub severity: Severity,
    pub description: String,
    pub published_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: Uuid,
    pub cve_id: String,
    pub image_name: String,
    pub matched_packages: Vec<Package>,
    pub sent_at: DateTime<Utc>,
}
