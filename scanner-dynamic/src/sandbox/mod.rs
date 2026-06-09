// ─────────────────────────────────────────────
// MODULE SANDBOX
// Regroupe les sous-modules de gestion de l'environnement
// d'analyse isolé (sandbox).
//
//   docker  → création, gestion et nettoyage des containers
//   seccomp → profil de filtrage des syscalls (réservé pour usage futur)
// ─────────────────────────────────────────────

/// Gestion des containers Docker sandboxés :
/// connexion, création réseau isolé, lancement, cleanup.
pub mod docker;

/// Profils seccomp pour filtrage fin des syscalls.
/// Non utilisé activement (Docker applique déjà son profil par défaut
/// qui bloque ~44 syscalls sensibles). Conservé pour extension future.
pub mod seccomp;