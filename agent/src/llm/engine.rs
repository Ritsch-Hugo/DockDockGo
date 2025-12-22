use crate::state::AgentState;
use crate::llm:decision:ToolCall;

pub trait ReasoningEngine {
    /// Analyse l'état courant et décide de la prochaine action à effectuer
    fn next_action(&self, state: &AgentState) -> ToolCall:

    ///Analyse finale : score, risques, alternatives
    fn final_assesment(&self, state: &AgentState) -> serde_json::Value;
}