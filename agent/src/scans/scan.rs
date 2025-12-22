use crate::state::AgentState;
use crate::scans::result::ScanResult;

pub trait Scan {
    /// Nom lisible du scan (pour logs/debug)
    fn name(&self) -> &'static str;

    /// Exécute le scan et modifie l’état si nécessaire
    fn run(&self, state: &mut AgentState) -> ScanResult;
}
