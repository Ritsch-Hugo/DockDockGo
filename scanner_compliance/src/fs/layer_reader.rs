use crate::models::FsEntry;
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use tar::Archive;
use tar::EntryType;

/// Maximum decompressed bytes allowed per layer (4 GB).
const MAX_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Maximum number of entries allowed per tar layer.
const MAX_TAR_ENTRIES: usize = 1_000_000;

/// Maximum allowed length for a tar entry path (in bytes).
const MAX_PATH_LEN: usize = 4096;

/// Wraps a `Read` and returns an error if more than `limit` bytes are read.
struct LimitedReader<R: Read> {
    inner: R,
    remaining: u64,
}

impl<R: Read> LimitedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self { inner, remaining: limit }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "decompressed layer exceeds size limit",
            ));
        }

        let max = buf.len().min(self.remaining as usize);
        let n = self.inner.read(&mut buf[..max])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn normalize_path(p: &str) -> Option<String> {
    // tar entries can be like "./etc/passwd"
    let mut s = p.trim().to_string();

    // remove leading "./"
    while s.starts_with("./") {
        s = s[2..].to_string();
    }

    // strip leading '/' (we keep paths relative)
    while s.starts_with('/') {
        s = s[1..].to_string();
    }

    if s.is_empty() {
        return None;
    }

    // very defensive: avoid traversal
    if s.contains("..") {
        return None;
    }

    Some(s)
}

fn is_gzip(path: &Path) -> io::Result<bool> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 2];
    let n = f.read(&mut magic)?;
    Ok(n == 2 && magic == [0x1f, 0x8b])
}

pub fn read_layer_entries(layer_path: &str) -> Result<Vec<FsEntry>, String> {
    let p = Path::new(layer_path);

    let gz = is_gzip(p).map_err(|e| format!("failed to probe gzip magic: {e}"))?;

    let file = File::open(p).map_err(|e| format!("failed to open layer blob {layer_path}: {e}"))?;
    let buf = BufReader::new(file);

    // stream reader with decompression bomb protection
    let reader: Box<dyn Read> = if gz {
        Box::new(LimitedReader::new(GzDecoder::new(buf), MAX_DECOMPRESSED_BYTES))
    } else {
        Box::new(LimitedReader::new(buf, MAX_DECOMPRESSED_BYTES))
    };

    let mut ar = Archive::new(reader);
    let mut out: Vec<FsEntry> = Vec::new();
    let mut entry_count = 0usize;

    let entries = match ar.entries() {
        Ok(e) => e,
        Err(e) => {
            // not a tar layer (could be attestation/SBOM/other blob)
            eprintln!("layer is not a tar archive, skipping: {e}");
            return Ok(Vec::new());
        }
    };

    for e in entries {
        entry_count += 1;
        if entry_count > MAX_TAR_ENTRIES {
            eprintln!("layer exceeds max entry count ({MAX_TAR_ENTRIES}), skipping rest");
            break;
        }

        let entry = match e {
            Ok(en) => en,
            Err(e) => {
                eprintln!("layer tar entry read failed, skipping whole layer: {e}");
                return Ok(Vec::new());
            }
        };

        let entry_path = match entry.path() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("tar: invalid path, skipping entry: {e}");
                continue;
            }
        };

        let path_str = match entry_path.to_str() {
            Some(s) => s,
            _ => continue,
        };

        if path_str.len() > MAX_PATH_LEN {
            eprintln!("tar: path too long ({} bytes), skipping entry", path_str.len());
            continue;
        }

        let norm = match normalize_path(path_str) {
            Some(s) => s,
            _ => continue,
        };

        let mode = entry.header().mode().ok().map(|m| m as u32);

        let kind = match entry.header().entry_type() {
            EntryType::Directory => "dir",
            EntryType::Regular => "file",
            EntryType::Symlink => "symlink",
            _ => "other",
        }
        .to_string();

        out.push(FsEntry {
            path: norm,
            mode,
            kind: Some(kind),
        });
    }

    Ok(out)
}
