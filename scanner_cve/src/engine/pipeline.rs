use anyhow::Result;

use crate::manifest::parser::parse_manifest;
use crate::models::{ScanRequest, ScanResponse, ScanStatus};

pub fn run(req: &ScanRequest) -> Result<ScanResponse> {
    let parsed = parse_manifest(&req.manifest_path)?;

    Ok(ScanResponse {
        request_id: req.request_id.clone(),
        status: ScanStatus::Pending,
        missing_layers: vec![],
        message: Some(format!(
            "parsed manifest: {} layers",
            parsed.layer_digests.len()
        )),
        summary: None,
        findings: vec![],
        raw_trivy_json: None,
        meta: req.meta.clone(),
    })
}