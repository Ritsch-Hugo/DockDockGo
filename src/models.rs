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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub packages: Vec<Package>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistedImage {
    pub name: String,
    pub sbom: Sbom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub cve_id: String,
    pub image_name: String,
    pub matched_packages: Vec<Package>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: Uuid,
    pub cve_id: String,
    pub image_name: String,
    pub matched_packages: Vec<Package>,
    pub sent_at: DateTime<Utc>,
}
