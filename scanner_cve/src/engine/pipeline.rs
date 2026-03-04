use crate::models::{ScanRequest, ScanResponse, ScanStatus};
use anyhow::Result;

/// Pipeline V1 (stub): à ce stade, on vérifie juste que le fichier manifest existe
/// et on renvoie une réponse PENDING / ERROR minimale.
///
/// Les étapes 2+ remplaceront ce contenu progressivement.
pub fn run(req: &ScanRequest) -> Result<ScanResponse> {
    let manifest_exists = std::path::Path::new(&req.manifest_path).exists();
    if !manifest_exists {
        return Ok(ScanResponse {
            request_id: req.request_id.clone(),
            status: ScanStatus::Error,
            missing_layers: vec![],
            message: Some(format!(
                "manifest_path not found: {}",
                req.manifest_path
            )),
            summary: None,
            findings: vec![],
            raw_trivy_json: None,
            meta: req.meta.clone(),
        });
    }

    Ok(ScanResponse {
        request_id: req.request_id.clone(),
        status: ScanStatus::Pending,
        missing_layers: vec![],
        message: Some("V1 stub: étape 1 OK (models+cli). Étape 2: parse manifest.".to_string()),
        summary: None,
        findings: vec![],
        raw_trivy_json: None,
        meta: req.meta.clone(),
    })
}