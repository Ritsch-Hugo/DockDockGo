use crate::models::*;
use std::collections::HashMap;

/// Une règle de compliance : prend une ImageData et retourne un Finding.
pub trait Rule {
    fn id(&self) -> &'static str;
    fn evaluate(&self, image: &ImageData) -> Finding;
}

/// Exécute toutes les règles et construit le Report (findings + summary).
pub fn run_rules(image: &ImageData, rules: &[Box<dyn Rule>]) -> Report {
    let mut findings: Vec<Finding> = Vec::new();
    let mut summary = Summary::default();

    for rule in rules {
        let finding = rule.evaluate(image);

        match finding.status {
            Status::PASS => summary.pass += 1,
            Status::WARN => summary.warn += 1,
            Status::FAIL => summary.fail += 1,
            Status::SKIP => summary.skip += 1,
        }

        findings.push(finding);
    }

    Report {
    meta: image.meta.clone(),
    scan: image.scan.clone(),
    missing_artifacts: image.missing_artifacts.clone(),
    summary,
    findings,
    pseudo_dockerfile: None,
}
}

/// Retourne la liste des chemins du filesystem.
/// - Si fs_entries est fourni, on utilise ça
/// - Sinon, on fallback sur fs_paths
pub fn all_paths(image: &ImageData) -> Vec<String> {
    if !image.fs_entries.is_empty() {
        return image
            .fs_entries
            .iter()
            .map(|e| e.path.clone())
            .collect();
    }
    image.fs_paths.clone()
}

/// Retourne uniquement les entrées qui ont un mode.
/// Sert pour la règle permissions.
#[allow(dead_code)]
pub fn path_modes(image: &ImageData) -> Vec<(&str, u32)> {
    image
        .fs_entries
        .iter()
        .filter_map(|e| e.mode.map(|m| (e.path.as_str(), m)))
        .collect()
}

/// Petit helper optionnel : créer une evidence map rapidement.
/// (Tu peux l'utiliser dans les rules si tu veux éviter du boilerplate)
#[allow(dead_code)]
pub fn evidence_one(key: &str, value: &str) -> HashMap<String, String> {
    let mut ev = HashMap::new();
    ev.insert(key.to_string(), value.to_string());
    ev
}
