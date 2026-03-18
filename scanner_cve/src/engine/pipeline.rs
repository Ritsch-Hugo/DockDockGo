use anyhow::Result;

use crate::engine::layer_gate::check_layers;
use crate::fs::apply_layer::apply_layer;
use crate::manifest::parser::parse_manifest;
use crate::models::{ScanRequest, ScanResponse, ScanStatus};
use crate::scanner::trivy::run_trivy;
use crate::scanner::trivy_parser::parse_trivy;
use crate::workspace::Workspace;

pub fn run(req: &ScanRequest) -> Result<ScanResponse> {
    let parsed = parse_manifest(&req.manifest_path)?;

    let (complete, missing) = check_layers(&req.blob_store_dir, &parsed.layer_digests);

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

    // workspace temporaire
    let ws = Workspace::new()?;
    println!("workspace created at {:?}", ws.rootfs);

    // reconstruction rootfs
    for layer in &parsed.layer_digests {
        println!("applying layer {}", layer);

        apply_layer(&req.blob_store_dir, layer, &ws.rootfs)?;
    }

    println!("rootfs ready at {:?}", ws.rootfs);
    let trivy_output = run_trivy(&ws.rootfs)?;

    let (summary, findings) = parse_trivy(&trivy_output);

    Ok(ScanResponse {
        request_id: req.request_id.clone(),
        status: ScanStatus::Complete,
        missing_layers: vec![],
        message: Some("scan completed".to_string()),
        summary: Some(summary),
        findings,
        raw_trivy_json: None,
        meta: req.meta.clone(),
    })
}
