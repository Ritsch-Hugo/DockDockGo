// Ils permettent de convertir automatiquement les structs/enums vers du JSON et inversement.
use serde::{Serialize, Deserialize};

// Value représente un JSON "brut" (objet, tableau, string, etc.)
// On l'utilise aux frontières du système (LLM, API, MCP).
use serde_json::Value;

// Import du type ScanType.
use crate::scans::types::ScanType;

// Structure représentant le résultat d'un scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {

    /// Type logique du scan ayant produit ce résultat.
    pub scan_type: ScanType,

    /// Sortie brute complète du scan, sous forme de JSON structuré.
    pub raw: Value,
}