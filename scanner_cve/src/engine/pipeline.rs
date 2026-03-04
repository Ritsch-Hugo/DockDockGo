use anyhow::Result;

use crate::engine::layer_gate::check_layers;
use crate::manifest::parser::parse_manifest;
use crate::models::{ScanRequest, ScanResponse, ScanStatus};
use crate::workspace::Workspace;

pub fn run(req: &ScanRequest) -> Result<ScanResponse> {

    let parsed = parse_manifest(&req.manifest_path)?;

    let (complete, missing) =
        check_layers(&req.blob_store_dir, &parsed.layer_digests);

    if !complete {
        return Ok(ScanResponse {
            request_id: req.request_id.clone(),
            status: ScanStatus::Pending,
            missing_layers: missing,
            message: Some("waiting for layers".to_string()),
            summary: None,
            findings: vec![],
            raw_trivy_json: None,
            meta: req.meta.clone(),
        });
    }

    // création workspace temporaire
    let ws = Workspace::new()?;
    println!("workspace created at {:?}", ws.rootfs);

    Ok(ScanResponse {
        request_id: req.request_id.clone(),
        status: ScanStatus::Complete,
        missing_layers: vec![],
        message: Some("all layers present".to_string()),
        summary: None,
        findings: vec![],
        raw_trivy_json: None,
        meta: req.meta.clone(),
    })
}