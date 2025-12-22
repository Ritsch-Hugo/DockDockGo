use serde::{Serialize, Deserialize};
use serde_json::Value;

use crate::scans::types::ScanType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    ///Type du scan
    pub scan_type: ScanType,

    ///Score partiel (0..100)
    pub score: u8,

    ///Résumé des points importants
    pub findings: Vec<String>,

    ///Sortie structuré (JSON)
    pub raw: Value,
}