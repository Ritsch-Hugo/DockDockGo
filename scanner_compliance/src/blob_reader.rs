use crate::models::RawBlob;
use std::fs;

pub fn blob_bytes(blob: &RawBlob) -> Result<Vec<u8>, String> {
    if let Some(p) = &blob.path {
        return fs::read(p).map_err(|e| format!("failed to read blob path {}: {}", p, e));
    }
    Err("blob has no content: provide 'path' in RawBlob".to_string())
}
