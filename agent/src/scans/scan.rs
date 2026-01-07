// Import de l'état global de l'agent.
use crate::state::AgentState;

// Import du résultat d'un scan.
use crate::scans::result::ScanResult;

// Définition du contrat commun à tous les scans.
pub trait Scan {
    /// Retourne un nom lisible et stable pour identifier ce scan.
    fn name(&self) -> &'static str;

    /// Exécute le scan.
    fn run(&self, state: &mut AgentState) -> ScanResult;
}