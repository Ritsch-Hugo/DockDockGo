use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

pub struct Workspace {
    pub root: PathBuf,
    pub rootfs: PathBuf,
}

impl Workspace {
    pub fn new() -> Result<Self> {
        let id = Uuid::new_v4().to_string();

        let root = std::env::temp_dir().join(format!("dockdockgo-cve-{}", id));

        let rootfs = root.join("rootfs");

        fs::create_dir_all(&rootfs).with_context(|| "failed to create workspace")?;

        Ok(Self { root, rootfs })
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
