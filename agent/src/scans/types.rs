// Ils permettent de convertir automatiquement les structs/enums vers du JSON et inversement.
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
// Définition des différents types de scan.
pub enum ScanType {
    Static,
    Dynamic,
    Compliance,
    Obsolescence,
}
