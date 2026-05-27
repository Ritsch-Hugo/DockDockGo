//! SBOM generation (via Syft) and file-based storage.
//!
//! Each whitelisted image gets one JSON file: `SBOM_DIR/<safe_name>.json`.
//! The store is kept in memory (loaded at startup, refreshed on write) so the
//! poller never touches the filesystem on the hot path.

use crate::models::Package;
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
        "apk"    => Some("Alpine"),
        "deb"    => Some("Debian"),
        "rpm"    => Some("Red Hat"),
        "pypi"   => Some("PyPI"),
        "npm"    => Some("npm"),
        "gem"    => Some("RubyGems"),
        "golang" => Some("Go"),
        "cargo"  => Some("crates.io"),
        "maven"  => Some("Maven"),
        "nuget"  => Some("NuGet"),
        _        => None,
    }
}

fn parse_purl_type(purl: &str) -> Option<&str> {
    // pkg:<type>/... → extract <type>
    purl.strip_prefix("pkg:")
        .and_then(|s| s.split('/').next())
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

/// Thread-safe, file-backed store.
/// One `<stem>.json` file per image under `dir/`.
pub struct SbomStore {
    dir: PathBuf,
    cache: RwLock<HashMap<String, StoredSbom>>,
}

impl SbomStore {
    /// Open (or create) the store at `dir`, loading any existing files.
    pub fn open(dir: &str) -> anyhow::Result<Arc<Self>> {
        let path = PathBuf::from(dir);
        std::fs::create_dir_all(&path)
            .with_context(|| format!("cannot create SBOM dir '{dir}'"))?;

        let store = Arc::new(Self {
            dir: path,
            cache: RwLock::new(HashMap::new()),
        });
        store.reload_all();
        Ok(store)
    }

    /// Sanitise an image reference into a safe filename stem.
    /// "ghcr.io/org/img:sha-abc" → "ghcr_io_org_img_sha_abc"
    fn stem(image: &str) -> String {
        image
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
            .collect()
    }

    fn file_path(&self, image: &str) -> PathBuf {
        self.dir.join(format!("{}.json", Self::stem(image)))
    }

    fn reload_all(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut cache = self.cache.write().expect("sbom cache poisoned");
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().map_or(false, |e| e == "json") {
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
        info!(count = cache.len(), "SBOMs loaded from disk");
    }

    pub fn get(&self, image: &str) -> Option<StoredSbom> {
        self.cache
            .read()
            .expect("sbom cache poisoned")
            .get(image)
            .cloned()
    }

    pub fn list(&self) -> Vec<StoredSbom> {
        self.cache
            .read()
            .expect("sbom cache poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Persist a SBOM to disk and update the in-memory cache.
    pub fn save(&self, sbom: StoredSbom) -> anyhow::Result<()> {
        let path = self.file_path(&sbom.image);
        let json = serde_json::to_string_pretty(&sbom)?;
        std::fs::write(&path, &json)
            .with_context(|| format!("cannot write SBOM to '{}'", path.display()))?;
        info!(
            image = %sbom.image,
            packages = sbom.packages.len(),
            path = %path.display(),
            "SBOM saved"
        );
        self.cache
            .write()
            .expect("sbom cache poisoned")
            .insert(sbom.image.clone(), sbom);
        Ok(())
    }

    /// Delete the SBOM for `image` (disk + cache).  Returns `true` if it existed.
    pub fn delete(&self, image: &str) -> bool {
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

// ── Syft integration ──────────────────────────────────────────────────────────

/// Call Syft to generate a fresh SBOM for `image`, store it, and return it.
///
/// Uses the `registry:<image>` scheme so Syft pulls directly from the
/// registry — no Docker daemon or mounted socket required.
///
/// `syft_bin` is the executable name/path (default: `"syft"`).
pub async fn generate_and_store(
    store: &SbomStore,
    image: &str,
    syft_bin: &str,
) -> anyhow::Result<StoredSbom> {
    info!(image, syft = syft_bin, "Generating SBOM");

    // Prefer registry: scheme to avoid needing Docker socket
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
    store.save(sbom.clone())?;
    Ok(sbom)
}
