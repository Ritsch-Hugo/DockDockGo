use std::path::Path;

pub fn check_layers(
    blob_store: &str,
    layers: &[String],
) -> (bool, Vec<String>) {

    let mut missing = Vec::new();

    for digest in layers {
        let parts: Vec<&str> = digest.split(':').collect();

        if parts.len() != 2 {
            missing.push(digest.clone());
            continue;
        }

        let algo = parts[0];
        let hash = parts[1];

        let path = format!("{}/{}/{}", blob_store, algo, hash);

        if !Path::new(&path).exists() {
            missing.push(digest.clone());
        }
    }

    let complete = missing.is_empty();

    (complete, missing)
}