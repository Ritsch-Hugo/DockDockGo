// Import de l'état global de l'agent.
use crate::state::AgentState;

// Import du type ToolCall.
use crate::llm::decision::ToolCall;

// Value représente un JSON "brut" (objet, tableau, string, etc.)
// On l'utilise aux frontières du système (LLM, API, MCP).
use serde_json::Value;

// Définition du contrat du moteur de raisonnement.
// Tout moteur de raisonnement (Qwen, GPT, Gemini, Claude, etc.)
// DOIT implémenter ce trait pour être utilisable par l'agent.
pub trait ReasoningEngine {

    /// Analyse l'état courant de l'agent et décide de la prochaine action.
    /// - Entrée : une référence immuable vers l'état actuel (AgentState)
    /// - Sortie : une décision unique (ToolCall)
    fn next_action(&self, state: &AgentState) -> ToolCall;

    /// Produit une analyse finale à partir de l'état complet.

    /// Elle retourne :
    /// - une synthèse des risques
    /// - des alternatives ou recommandations
    /// - une justification du score

    /// Le résultat est retourné sous forme de JSON brut (Value)
    fn final_assessment(&self, state: &AgentState) -> Value;
}