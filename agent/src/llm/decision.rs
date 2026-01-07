// Ils permettent de convertir automatiquement les structs/enums vers du JSON et inversement.
use serde::{Serialize, Deserialize};

// Value représente un JSON "brut" (objet, tableau, string, etc.)
// On l'utilise aux frontières du système (LLM, API, MCP).
use serde_json::Value;

// Définition des actions possibles que le LLM peut demander à l'agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    // Demande de lancer un scan statique
    RunStaticScan,

    // Demande de lancer un scan dynamique
    RunDynamicScan,

    // Demande de lancer un scan de compliance
    RunComplianceScan,

    // Demande de lancer une analyse d'obsolescence
    RunObsolescenceAnalysis,

    // Demande de passer à l'étape finale de calcul du score
    ComputeFinalScore,
}

// Structure représentant une décision complète prise par le LLM.
// Elle indique quoi faire et éventuellement comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    // Action demandée par le LLM (obligatoire)
    pub action: Action,

    // Paramètres optionnels associés à l'action.
    // Exemple :
    // - sévérité pour un scan statique
    // - options spécifiques pour un scan dynamique
    // - null si l'action n'a pas besoin de paramètres
    pub params: Option<Value>,
}
