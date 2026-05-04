# llm-module

Composant d'analyse de sécurité par LLM du projet DocDockGo. Reçoit les artefacts d'une image Docker en quarantaine, fait voter plusieurs LLM sur les scans à effectuer, exécute ces scans, puis produit un verdict ALLOW/DENY avec score de vulnérabilité.

## Architecture

```
Orchestrateur (port 3000)
    │
    │  POST /v1/decision  (PullContext JSON)
    ▼
llm-decision (port 3005)
    │
    │  Phase 1 — Décision (tool calling)
    ├──► Worker 1 (OpenRouter) → vote scans
    ├──► Worker 2 (OpenRouter) → vote scans
    ├──► Worker 3 (OpenRouter) → vote scans
    └──► Arbitre (OpenRouter) → décision finale
    │
    │  Phase 2 — Exécution (MCP JSON-RPC 2.0)
    └──► mcp-tools-server (port 3004)
              ├── run_static_scan    → scanner-cve    (port 3002)
              ├── run_compliance_scan → scanner-compliance (port 3001)
              └── run_dynamic_scan   → stub (Falco non implémenté)
    │
    │  Phase 3a — Analyse des résultats (tool calling)
    ├──► Workers → score vulnérabilité + raisonnement
    └──► Arbitre → verdict ALLOW/DENY
    │
    │  Phase 3b — Alternatives (uniquement si DENY)
    └──► Workers + Arbitre → images alternatives suggérées
    │
    └──► FinalReport JSON → retourné à l'orchestrateur
```

## Services

| Service | Port | Rôle |
|---|---|---|
| `llm-decision` | 3005 | Pipeline décisionnel LLM |
| `llm-manager` | 3003 | Validation de la disponibilité des modèles |
| `mcp-tools-server` | 3004 | Bridge MCP → scanners |

## Prérequis

- Rust stable (≥ 1.85)
- Docker (pour les scanners CVE et compliance)
- Clé API OpenRouter (`sk-or-v1-...`)
- Images Docker `scanner-cve` et `scanner-compliance` buildées
- Quarantaine `library/alpine/3.18` présente (pour les tests)

## Démarrage rapide

```bash
# 1. Configurer les variables d'environnement
cp llm-module/.env.example llm-module/.env
# Renseigner OPENROUTER_API_KEY dans .env

# 2. Compiler
cd llm-module && cargo build --release

# 3. Lancer le pipeline complet (services + test)
bash llm-module/scripts/test_pipeline.sh
```

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `LLM_BASE_URL` | `http://localhost:8000` | URL du backend LLM |
| `OPENROUTER_API_KEY` | — | Clé API OpenRouter |
| `LLM_WORKER_1` | `minimax/minimax-m2.7` | Modèle worker 1 |
| `LLM_WORKER_2` | `qwen/qwen3.5-35b-a3b` | Modèle worker 2 |
| `LLM_WORKER_3` | `google/gemma-4-31b-it` | Modèle worker 3 |
| `LLM_ARBITER` | `mistralai/mistral-small-2603` | Modèle arbitre |
| `LLM_TIMEOUT_SECS` | `120` | Timeout appels LLM (secondes) |
| `QUARANTINE_PATH` | `../quarantaine` | Chemin vers la quarantaine |
| `MCP_SERVER_URL` | `http://localhost:3004/mcp` | URL du mcp-tools-server |
| `MCP_TIMEOUT_SECS` | `300` | Timeout appels MCP (secondes) |
| `DECISION_PORT` | `3005` | Port de llm-decision |
| `MANAGER_HOST` | `localhost` | Hôte de llm-manager (Kubernetes : nom du service) |
| `MANAGER_PORT` | `3003` | Port de llm-manager |

## Format de la requête

```
POST /v1/decision
Content-Type: application/json

{
  "uuid": "...",
  "registry": "registry-1.docker.io",
  "repository": "library/alpine",
  "tag": "3.18",
  "manifest_digests": [...],
  "blob_digests": [...],
  ...
}
```

## Format de la réponse (FinalReport)

```json
{
  "pull_id": "uuid",
  "image": "registry-1.docker.io/library/alpine:3.18",
  "analysed_at": "2026-04-28T13:00:00Z",
  "verdict": {
    "decision": "ALLOW",
    "vulnerability_score": 1.2,
    "confidence": 0.95,
    "rationale": "..."
  },
  "scan_analysis": { ... },
  "scan_reasoning": { ... },
  "alternatives": [],
  "decision_metadata": { ... }
}
```

Voir `output_template.md` pour un exemple complet.

## Tests

```bash
cd llm-module

# Tests unitaires (pas de dépendances réseau)
cargo test

# Pipeline complet (nécessite OpenRouter + scanners Docker)
bash scripts/test_pipeline.sh
```

## Logs

```bash
tail -f /tmp/llm-decision.log
tail -f /tmp/llm-manager.log
tail -f /tmp/mcp-tools-server.log
```

## Sécurité

- Tous les champs du `PullContext` sont validés à la frontière (longueur, format des digests, absence de séquences de traversal)
- Les artefacts JSON sont tronqués avant insertion dans les prompts (`sanitize()`)
- Le contenu des images est encadré par des balises `<ARTIFACT>` pour limiter le prompt injection
- Taille de body limitée à 1 MB
- Taille des fichiers artefacts limitée à 10 MB par fichier

## Production (air-gapped)

```bash
# Basculer sur vLLM local
LLM_BASE_URL=http://vllm-service:8000
# Supprimer OPENROUTER_API_KEY
# MANAGER_HOST=llm-manager  (nom du service Kubernetes)
```
