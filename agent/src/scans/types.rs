use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    Static,
    Dynamic,
    Compliance,
    Obsolescence,
}
