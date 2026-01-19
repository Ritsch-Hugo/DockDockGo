use crate::models::ImageConfig;
use serde_json::Value;
use std::collections::HashMap;

/// Parse OCI image config (best-effort) depuis bytes.
/// IMPORTANT (4.1): un OCI config peut être valide même si `.config` est vide.
/// - Ok(ImageConfig) si le JSON contient bien un champ `"config"` de type objet
/// - Err si JSON invalide ou si ce n'est pas un OCI config
pub fn parse_oci_config_json(bytes: &[u8]) -> Result<ImageConfig, String> {
    let v: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid config JSON: {e}"))?;

    let cfg_obj = v
        .get("config")
        .and_then(|x| x.as_object())
        .ok_or_else(|| "not an OCI image config: missing `.config` object".to_string())?;

    // user
    let user = cfg_obj
        .get("User")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    // working dir
    let working_dir = cfg_obj
        .get("WorkingDir")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    // env: ["K=V", ...]
    let mut env: HashMap<String, String> = HashMap::new();
    if let Some(arr) = cfg_obj.get("Env").and_then(|x| x.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                if let Some((k, v)) = s.split_once('=') {
                    env.insert(k.to_string(), v.to_string());
                }
            }
        }
    }

    // labels: map
    let mut labels: HashMap<String, String> = HashMap::new();
    if let Some(obj) = cfg_obj.get("Labels").and_then(|x| x.as_object()) {
        for (k, vv) in obj.iter() {
            if let Some(s) = vv.as_str() {
                labels.insert(k.clone(), s.to_string());
            } else {
                labels.insert(k.clone(), vv.to_string());
            }
        }
    }

    // entrypoint/cmd: arrays
    let mut entrypoint: Vec<String> = Vec::new();
    if let Some(arr) = cfg_obj.get("Entrypoint").and_then(|x| x.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                entrypoint.push(s.to_string());
            }
        }
    }

    let mut cmd: Vec<String> = Vec::new();
    if let Some(arr) = cfg_obj.get("Cmd").and_then(|x| x.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                cmd.push(s.to_string());
            }
        }
    }

    // exposed ports: keys of map
    let mut exposed_ports: Vec<String> = Vec::new();
    if let Some(obj) = cfg_obj.get("ExposedPorts").and_then(|x| x.as_object()) {
        for k in obj.keys() {
            exposed_ports.push(k.to_string());
        }
    }

    // volumes: keys of map
    let mut volumes: Vec<String> = Vec::new();
    if let Some(obj) = cfg_obj.get("Volumes").and_then(|x| x.as_object()) {
        for k in obj.keys() {
            volumes.push(k.to_string());
        }
    }

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
