//! SBOM generation (via Syft) and storage.
//!
//! `SbomStore` keeps an in-memory cache of all SBOMs for fast read access.
//! When a `PgPool` is provided the store is backed by PostgreSQL — SBOMs
//! survive service restarts without re-running Syft.
//! Without a pool the store falls back to local JSON files (used in tests
//! and when `DATABASE_URL` is not set).

use crate::db;
use crate::models::Package;
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

// ── Stored SBOM ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSbom {
    /// Full image reference, e.g. "nginx:1.25" or "ghcr.io/org/img:sha-abc"
    pub image: String,
    pub generated_at: DateTime<Utc>,
    /// Digest of the image at scan time (filled by Syft via metadata)
    #[serde(default)]
    pub image_digest: Option<String>,
    /// Tool that produced this SBOM ("syft" | "manual")
    #[serde(default = "default_source")]
    pub source: String,
    pub packages: Vec<Package>,
}

fn default_source() -> String {
    "syft".to_string()
}

// ── CycloneDX JSON (Syft output, minimal subset) ─────────────────────────────

#[derive(Deserialize, Default)]
struct CycloneDxBom {
    #[serde(default)]
    metadata: CdxMetadata,
    #[serde(default)]
    components: Vec<CdxComponent>,
}

#[derive(Deserialize, Default)]
struct CdxMetadata {
    #[serde(default)]
    component: Option<CdxMetaComponent>,
}

#[derive(Deserialize)]
struct CdxMetaComponent {
    #[serde(rename = "type", default)]
    _kind: String,
    /// Image digest reported by Syft in the BOM metadata
    #[serde(default)]
    version: String,
}

#[derive(Deserialize)]
struct CdxComponent {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: Option<String>,
    /// Package URL — used to derive the OSV ecosystem.
    /// Format: pkg:<type>/<namespace>/<name>@<version>
    #[serde(default)]
    purl: Option<String>,
}

/// Map a PURL type to an OSV-compatible ecosystem string.
/// <https://osv.dev/docs/#section/Requesting-information/Package-filter>
fn purl_type_to_ecosystem(t: &str) -> Option<&'static str> {
    match t {
        "apk" => Some("Alpine"),
        "deb" => Some("Debian"),
        "rpm" => Some("Red Hat"),
        "pypi" => Some("PyPI"),
        "npm" => Some("npm"),
        "gem" => Some("RubyGems"),
        "golang" => Some("Go"),
        "cargo" => Some("crates.io"),
        "maven" => Some("Maven"),
        "nuget" => Some("NuGet"),
        _ => None,
    }
}

fn parse_purl_type(purl: &str) -> Option<&str> {
    purl.strip_prefix("pkg:").and_then(|s| s.split('/').next())
}

fn cdx_to_packages(bom: CycloneDxBom) -> Vec<Package> {
    bom.components
        .into_iter()
        .filter_map(|c| {
            if c.name.is_empty() {
                return None;
            }
            let version = c.version.filter(|v| !v.is_empty())?;
            let ecosystem = c
                .purl
                .as_deref()
                .and_then(parse_purl_type)
                .and_then(purl_type_to_ecosystem)
                .map(str::to_owned);
            Some(Package {
                name: c.name,
                version,
                ecosystem,
            })
        })
        .collect()
}

// ── SbomStore ─────────────────────────────────────────────────────────────────

/// Thread-safe store with an in-memory cache.
///
/// - **DB mode** (`pool` is `Some`): SBOMs are loaded from PostgreSQL at
///   startup and persisted on every write. Survives restarts.
/// - **File mode** (`pool` is `None`): SBOMs are read/written as JSON files
///   under `dir`. Used in tests and when `DATABASE_URL` is not set.
pub struct SbomStore {
    pool: Option<PgPool>,
    dir: PathBuf,
    cache: RwLock<HashMap<String, StoredSbom>>,
}

impl SbomStore {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// DB-backed store. Loads all existing SBOMs from PostgreSQL into the
    /// cache — Syft will only be called for images with no stored SBOM.
    pub async fn open_with_db(pool: PgPool) -> anyhow::Result<Arc<Self>> {
        let store = Arc::new(Self {
            pool: Some(pool.clone()),
            dir: PathBuf::new(), // unused in DB mode
            cache: RwLock::new(HashMap::new()),
        });

        match db::load_all_sboms(&pool).await {
            Ok(sboms) => {
                let mut cache = store.cache.write().expect("sbom cache poisoned");
                let count = sboms.len();
                for sbom in sboms {
                    cache.insert(sbom.image.clone(), sbom);
                }
                info!(count, "SBOMs loaded from database");
            }
            Err(e) => warn!(error = %e, "Failed to load SBOMs from DB — starting with empty cache"),
        }

        Ok(store)
    }

    /// File-backed store (fallback / tests). Opens or creates `dir`.
    pub fn open(dir: &str) -> anyhow::Result<Arc<Self>> {
        let path = PathBuf::from(dir);
        std::fs::create_dir_all(&path)
            .with_context(|| format!("cannot create SBOM dir '{dir}'"))?;

        let store = Arc::new(Self {
            pool: None,
            dir: path,
            cache: RwLock::new(HashMap::new()),
        });
        store.reload_from_files();
        Ok(store)
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    pub fn list(&self) -> Vec<StoredSbom> {
        self.cache
            .read()
            .expect("sbom cache poisoned")
            .values()
            .cloned()
            .collect()
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Persist a SBOM (DB upsert or file write) and update the in-memory cache.
    pub async fn save(&self, sbom: StoredSbom) -> anyhow::Result<()> {
        if let Some(ref pool) = self.pool {
            db::upsert_sbom(pool, &sbom).await?;
            info!(image = %sbom.image, packages = sbom.packages.len(), "SBOM saved to database");
        } else {
            let path = self.file_path(&sbom.image);
            let json = serde_json::to_string_pretty(&sbom)?;
            std::fs::write(&path, &json)
                .with_context(|| format!("cannot write SBOM to '{}'", path.display()))?;
            info!(image = %sbom.image, packages = sbom.packages.len(), path = %path.display(), "SBOM saved to file");
        }

        self.cache
            .write()
            .expect("sbom cache poisoned")
            .insert(sbom.image.clone(), sbom);
        Ok(())
    }

    /// Delete a SBOM (DB or file) and remove it from the cache.
    /// Returns `true` if it existed.
    pub async fn delete(&self, image: &str) -> bool {
        if let Some(ref pool) = self.pool {
            match db::delete_sbom(pool, image).await {
                Ok(existed) => {
                    self.cache
                        .write()
                        .expect("sbom cache poisoned")
                        .remove(image);
                    existed
                }
                Err(e) => {
                    warn!(error = %e, image, "Failed to delete SBOM from DB");
                    false
                }
            }
        } else {
            let path = self.file_path(image);
            let existed = path.exists();
            if existed {
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!(error = %e, "Failed to delete SBOM file");
                }
            }
            self.cache
                .write()
                .expect("sbom cache poisoned")
                .remove(image);
            existed
        }
    }

    // ── File-mode internals ───────────────────────────────────────────────────

    fn stem(image: &str) -> String {
        image
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn file_path(&self, image: &str) -> PathBuf {
        self.dir.join(format!("{}.json", Self::stem(image)))
    }

    fn reload_from_files(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut cache = self.cache.write().expect("sbom cache poisoned");
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|e| e == "json") {
                match std::fs::read_to_string(&p)
                    .ok()
                    .and_then(|s| serde_json::from_str::<StoredSbom>(&s).ok())
                {
                    Some(sbom) => {
                        debug!(image = %sbom.image, path = %p.display(), "SBOM loaded");
                        cache.insert(sbom.image.clone(), sbom);
                    }
                    None => warn!(path = %p.display(), "Malformed SBOM file — skipping"),
                }
            }
        }
        info!(count = cache.len(), "SBOMs loaded from files");
    }
}

// ── Syft integration ──────────────────────────────────────────────────────────

/// Call Syft to generate a fresh SBOM for `image`, store it, and return it.
///
/// Uses the `registry:<image>` scheme so Syft pulls directly from the
/// registry — no Docker daemon or mounted socket required.
pub async fn generate_and_store(
    store: &SbomStore,
    image: &str,
    syft_bin: &str,
) -> anyhow::Result<StoredSbom> {
    info!(image, syft = syft_bin, "Generating SBOM");

    let image_ref = if image.starts_with("registry:") || image.contains("://") {
        image.to_owned()
    } else {
        format!("registry:{image}")
    };

    let output = tokio::process::Command::new(syft_bin)
        .args([&image_ref, "--output", "cyclonedx-json", "--quiet"])
        .output()
        .await
        .with_context(|| format!("failed to spawn Syft ('{syft_bin}')"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Syft exited {}: {stderr}", output.status);
    }

    let bom: CycloneDxBom = serde_json::from_slice(&output.stdout)
        .context("failed to parse Syft CycloneDX JSON output")?;

    let digest = bom
        .metadata
        .component
        .as_ref()
        .map(|c| c.version.clone())
        .filter(|v| !v.is_empty());

    let packages = cdx_to_packages(bom);
    info!(image, count = packages.len(), "SBOM packages extracted");

    let sbom = StoredSbom {
        image: image.to_owned(),
        generated_at: Utc::now(),
        image_digest: digest,
        source: "syft".to_owned(),
        packages,
    };
    store.save(sbom.clone()).await?;
    Ok(sbom)
}
