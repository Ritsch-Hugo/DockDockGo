use serde::{Serialize, Deserialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    RunStaticScan,
    RunDynamicScan,
    RunComplianceScan,
    RunObsolescenceAnalysis,
    ComputeFinalScore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub action: Action,
    pub params: Option<Value>,
}
