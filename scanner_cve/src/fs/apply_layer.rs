use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use tar::Archive;

pub fn apply_layer(blob_store: &str, digest: &str, rootfs: &Path) -> Result<()> {
    let parts: Vec<&str> = digest.split(':').collect();

    if parts.len() != 2 {
        anyhow::bail!("invalid digest {}", digest);
    }

    let algo = parts[0];
    let hash = parts[1];

    let layer_path = PathBuf::from(blob_store).join(algo).join(hash);

    if !layer_path.exists() {
        anyhow::bail!("layer not found {:?}", layer_path);
    }

    let file = File::open(&layer_path).with_context(|| "failed to open layer")?;

    // reader polymorphe
    let reader: Box<dyn Read> = if layer_path.extension().map(|e| e == "gz").unwrap_or(false) {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };

    let mut archive = Archive::new(reader);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();

        // gestion des whiteouts
        if let Some(name) = path.file_name() {
            let name = name.to_string_lossy();

            if name.starts_with(".wh.") {
                let target = name.trim_start_matches(".wh.");

                let mut remove_path = rootfs.join(path.parent().unwrap_or(Path::new("")));

                remove_path.push(target);

                if remove_path.exists() {
                    if remove_path.is_dir() {
                        fs::remove_dir_all(remove_path)?;
                    } else {
                        fs::remove_file(remove_path)?;
                    }
                }

                continue;
            }
        }

        let dest = rootfs.join(&path);

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        entry.unpack(&dest)?;
    }

    Ok(())
}
