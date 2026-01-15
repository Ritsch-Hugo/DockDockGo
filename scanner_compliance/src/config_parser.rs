use crate::models::ImageConfig;
use serde_json::Value;
use std::collections::HashMap;

pub fn parse_oci_config_json(bytes: &[u8]) -> Result<ImageConfig, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("invalid config JSON: {e}"))?;
    let cfg = v.get("config").unwrap_or(&Value::Null);

    let user = cfg.get("User").and_then(|x| x.as_str()).map(|s| s.to_string());

    // Env: ["K=V", ...]
    let mut env: HashMap<String, String> = HashMap::new();
    if let Some(arr) = cfg.get("Env").and_then(|x| x.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                if let Some((k, val)) = s.split_once('=') {
                    env.insert(k.to_string(), val.to_string());
                }
            }
        }
    }

    // Labels: {k:v}
    let mut labels: HashMap<String, String> = HashMap::new();
    if let Some(obj) = cfg.get("Labels").and_then(|x| x.as_object()) {
        for (k, vv) in obj.iter() {
            if let Some(s) = vv.as_str() {
                labels.insert(k.clone(), s.to_string());
            } else {
                labels.insert(k.clone(), vv.to_string());
            }
        }
    }

    let entrypoint = cfg
        .get("Entrypoint")
        .and_then(|x| x.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(Vec::new);

    let cmd = cfg
        .get("Cmd")
        .and_then(|x| x.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_else(Vec::new);

    let working_dir = cfg.get("WorkingDir").and_then(|x| x.as_str()).map(|s| s.to_string());

    let exposed_ports = cfg
        .get("ExposedPorts")
        .and_then(|x| x.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_else(Vec::new);

    let volumes = cfg
        .get("Volumes")
        .and_then(|x| x.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_else(Vec::new);

    Ok(ImageConfig {
        user,
        env,
        labels,
        entrypoint,
        cmd,
        working_dir,
        exposed_ports,
        volumes,
    })
}
