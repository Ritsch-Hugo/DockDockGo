use crate::models::WhitelistedImage;
use anyhow::Context;
use serde::Deserialize;
use std::sync::RwLock;

#[derive(Debug, Deserialize)]
struct StoreConfig {
    images: Vec<WhitelistedImage>,
}

pub struct WhitelistStore {
    /// Path passed to the config loader (without extension).
    path: String,
    /// Dynamic list — updated by reload() without restarting the service.
    images: RwLock<Vec<WhitelistedImage>>,
}

impl WhitelistStore {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let images = Self::read_images(path)?;
        Ok(Self {
            path: path.to_string(),
            images: RwLock::new(images),
        })
    }

    /// Returns a snapshot of the current image list.
    pub fn images(&self) -> Vec<WhitelistedImage> {
        self.images.read().expect("whitelist poisoned").clone()
    }

    /// Re-read the TOML file, add any new images, and return their names.
    /// Images already in the list are left untouched (no duplicate SBOMs).
    pub fn reload(&self) -> anyhow::Result<Vec<String>> {
        let fresh = Self::read_images(&self.path)?;
        let mut list = self.images.write().expect("whitelist poisoned");

        let existing: std::collections::HashSet<&str> =
            list.iter().map(|i| i.name.as_str()).collect();

        let added: Vec<WhitelistedImage> = fresh
            .into_iter()
            .filter(|i| !existing.contains(i.name.as_str()))
            .collect();

        let new_names: Vec<String> = added.iter().map(|i| i.name.clone()).collect();
        list.extend(added);
        Ok(new_names)
    }

    fn read_images(path: &str) -> anyhow::Result<Vec<WhitelistedImage>> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name(path))
            .build()
            .context("failed to read whitelist config")?;

        let store_config: StoreConfig = cfg
            .try_deserialize()
            .context("invalid whitelist config format")?;

        Ok(store_config.images)
    }
}

#[cfg(test)]
impl WhitelistStore {
    pub fn from_images(images: Vec<WhitelistedImage>) -> Self {
        Self {
            path: String::new(),
            images: RwLock::new(images),
        }
    }
}
