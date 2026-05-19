use crate::models::WhitelistedImage;
use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct StoreConfig {
    images: Vec<WhitelistedImage>,
}

pub struct WhitelistStore {
    images: Vec<WhitelistedImage>,
}

impl WhitelistStore {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::File::with_name(path))
            .build()
            .context("failed to read whitelist config")?;

        let store_config: StoreConfig = cfg
            .try_deserialize()
            .context("invalid whitelist config format")?;

        Ok(Self {
            images: store_config.images,
        })
    }

    pub fn images(&self) -> &[WhitelistedImage] {
        &self.images
    }
}

#[cfg(test)]
impl WhitelistStore {
    pub fn from_images(images: Vec<WhitelistedImage>) -> Self {
        Self { images }
    }
}
