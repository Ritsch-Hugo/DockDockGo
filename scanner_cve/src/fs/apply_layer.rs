use std::fs::{self, File};
use std::io::BufRead;
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use tar::{Archive, EntryType};

const MAX_ENTRIES: usize = 100_000;
const MAX_FILE_SIZE: u64 = 200 * 1024 * 1024; // 200 MB
const MAX_TOTAL_UNPACKED: u64 = 2 * 1024 * 1024 * 1024; // 2 GB

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

    let file = File::open(&layer_path)
        .with_context(|| format!("failed to open layer {:?}", layer_path))?;

    let reader = open_layer_reader(file).context("failed to prepare layer reader")?;
    let mut archive = Archive::new(reader);

    let mut entry_count = 0usize;
    let mut total_unpacked = 0u64;

    for entry_res in archive.entries().context("cannot list tar entries")? {
        let mut entry = entry_res.context("cannot read tar entry")?;
        entry_count += 1;

        if entry_count > MAX_ENTRIES {
            anyhow::bail!("too many entries in layer {}", digest);
        }

        let raw_path = entry
            .path()
            .context("cannot read tar entry path")?
            .to_path_buf();

        let rel_path = sanitize_relative_path(&raw_path)
            .with_context(|| format!("invalid archive path: {}", raw_path.display()))?;

        // Whiteouts OCI
        if is_opaque_whiteout(&rel_path) {
            let parent = rel_path.parent().unwrap_or(Path::new(""));
            clear_directory_contents_in_rootfs(rootfs, parent).with_context(|| {
                format!("failed to apply opaque whiteout for {}", rel_path.display())
            })?;
            continue;
        }

        if let Some(target) = whiteout_target(&rel_path) {
            safe_remove_in_rootfs(rootfs, &target)
                .with_context(|| format!("failed to apply whiteout for {}", rel_path.display()))?;
            continue;
        }

        let dest = ensure_within_rootfs(rootfs, &rel_path)
            .with_context(|| format!("path escapes rootfs: {}", rel_path.display()))?;

        match entry.header().entry_type() {
            EntryType::Directory => {
                reject_if_symlink_in_path(rootfs, &dest)?;
                fs::create_dir_all(&dest)
                    .with_context(|| format!("failed to create dir {}", dest.display()))?;
            }

            EntryType::Regular => {
                if let Some(parent) = dest.parent() {
                    reject_if_symlink_in_path(rootfs, parent)?;
                    fs::create_dir_all(parent).with_context(|| {
                        format!("failed to create parent dir {}", parent.display())
                    })?;
                }

                reject_if_symlink_in_path(rootfs, &dest)?;

                let mut outfile = File::create(&dest)
                    .with_context(|| format!("failed to create file {}", dest.display()))?;

                total_unpacked = copy_bounded(&mut entry, &mut outfile, &rel_path, total_unpacked)?;
            }

            EntryType::Symlink => {
                anyhow::bail!("symlinks are forbidden in layer: {}", rel_path.display());
            }

            EntryType::Link => {
                anyhow::bail!("hardlinks are forbidden in layer: {}", rel_path.display());
            }

            other => {
                anyhow::bail!(
                    "unsupported tar entry type for {}: {:?}",
                    rel_path.display(),
                    other
                );
            }
        }
    }

    Ok(())
}

fn open_layer_reader(file: File) -> Result<Box<dyn Read>> {
    let mut reader = BufReader::new(file);
    let peek = reader.fill_buf().context("failed to peek layer header")?;

    let is_gzip = peek.len() >= 2 && peek[0] == 0x1f && peek[1] == 0x8b;

    if is_gzip {
        Ok(Box::new(GzDecoder::new(reader)))
    } else {
        Ok(Box::new(reader))
    }
}

fn sanitize_relative_path(path: &Path) -> Result<PathBuf> {
    let mut clean = PathBuf::new();

    for comp in path.components() {
        match comp {
            Component::Normal(part) => {
                if part.is_empty() {
                    anyhow::bail!("empty path component");
                }
                clean.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                anyhow::bail!("parent dir '..' forbidden: {}", path.display());
            }
            Component::RootDir => {
                anyhow::bail!("absolute path forbidden: {}", path.display());
            }
            Component::Prefix(_) => {
                anyhow::bail!("path prefix forbidden: {}", path.display());
            }
        }
    }

    if clean.as_os_str().is_empty() {
        anyhow::bail!("empty resulting path: {}", path.display());
    }

    Ok(clean)
}

fn ensure_within_rootfs(rootfs: &Path, rel: &Path) -> Result<PathBuf> {
    let dest = rootfs.join(rel);

    if !dest.starts_with(rootfs) {
        anyhow::bail!("path escapes rootfs: {}", dest.display());
    }

    Ok(dest)
}

fn reject_if_symlink_in_path(rootfs: &Path, dest: &Path) -> Result<()> {
    let rel = dest
        .strip_prefix(rootfs)
        .map_err(|_| anyhow::anyhow!("destination is not under rootfs"))?;

    let mut current = rootfs.to_path_buf();

    for comp in rel.components() {
        current.push(comp.as_os_str());

        if current.exists() {
            let meta = fs::symlink_metadata(&current)
                .with_context(|| format!("failed to read metadata for {}", current.display()))?;

            if meta.file_type().is_symlink() {
                anyhow::bail!("symlink found in destination path: {}", current.display());
            }
        }
    }

    Ok(())
}

/// Copie `src` vers `dst` chunk par chunk en comptant les octets réellement écrits.
/// Vérifie MAX_FILE_SIZE (par fichier) et MAX_TOTAL_UNPACKED (cumulé sur le layer).
/// Retourne le nouveau total cumulé.
fn copy_bounded<R: Read>(
    src: &mut R,
    dst: &mut File,
    rel_path: &Path,
    mut total: u64,
) -> Result<u64> {
    let mut buf = [0u8; 64 * 1024]; // 64 KB par chunk
    let mut file_written: u64 = 0;

    loop {
        let n = src.read(&mut buf).context("read error during extraction")?;
        if n == 0 {
            break;
        }

        file_written = file_written
            .checked_add(n as u64)
            .context("file size overflow")?;

        if file_written > MAX_FILE_SIZE {
            anyhow::bail!(
                "file too large in layer: {} ({} bytes written, limit {} bytes)",
                rel_path.display(),
                file_written,
                MAX_FILE_SIZE
            );
        }

        total = total
            .checked_add(n as u64)
            .context("total unpacked size overflow")?;

        if total > MAX_TOTAL_UNPACKED {
            anyhow::bail!("layer unpacked size limit exceeded");
        }

        dst.write_all(&buf[..n])
            .context("write error during extraction")?;
    }

    Ok(total)
}

fn is_opaque_whiteout(rel_path: &Path) -> bool {
    rel_path.file_name().and_then(|n| n.to_str()) == Some(".wh..wh..opq")
}

fn whiteout_target(rel_path: &Path) -> Option<PathBuf> {
    let file_name = rel_path.file_name()?.to_str()?;
    let stripped = file_name.strip_prefix(".wh.")?;

    if stripped == ".wh..opq" {
        return None;
    }

    let mut target = rel_path.parent().unwrap_or(Path::new("")).to_path_buf();
    target.push(stripped);
    Some(target)
}

fn safe_remove_in_rootfs(rootfs: &Path, rel_target: &Path) -> Result<()> {
    let clean_target = sanitize_relative_path(rel_target)?;
    let abs_target = ensure_within_rootfs(rootfs, &clean_target)?;

    reject_if_symlink_in_path(rootfs, &abs_target)?;

    if abs_target.is_dir() {
        fs::remove_dir_all(&abs_target)
            .with_context(|| format!("failed to remove dir {}", abs_target.display()))?;
    } else if abs_target.exists() {
        fs::remove_file(&abs_target)
            .with_context(|| format!("failed to remove file {}", abs_target.display()))?;
    }

    Ok(())
}

fn clear_directory_contents_in_rootfs(rootfs: &Path, rel_dir: &Path) -> Result<()> {
    let clean_dir = sanitize_relative_path(rel_dir)?;
    let abs_dir = ensure_within_rootfs(rootfs, &clean_dir)?;

    reject_if_symlink_in_path(rootfs, &abs_dir)?;

    if !abs_dir.exists() {
        return Ok(());
    }

    if !abs_dir.is_dir() {
        anyhow::bail!(
            "opaque whiteout target is not a directory: {}",
            abs_dir.display()
        );
    }

    for entry_res in fs::read_dir(&abs_dir)
        .with_context(|| format!("failed to read dir {}", abs_dir.display()))?
    {
        let entry = entry_res?;
        let path = entry.path();

        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to read metadata for {}", path.display()))?;

        if meta.file_type().is_symlink() || meta.is_file() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove file {}", path.display()))?;
        } else if meta.is_dir() {
            fs::remove_dir_all(&path)
                .with_context(|| format!("failed to remove dir {}", path.display()))?;
        } else {
            anyhow::bail!(
                "unsupported entry while clearing opaque whiteout: {}",
                path.display()
            );
        }
    }

    Ok(())
}
