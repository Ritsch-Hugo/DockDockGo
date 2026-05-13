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

## Images Docker (ghcr.io)

```bash
docker pull ghcr.io/ritsch-hugo/llm-manager:latest
docker pull ghcr.io/ritsch-hugo/llm-decision:latest
```

## Build local (alternatif)

```bash
# Depuis le dossier llm-module/ (workspace Cargo — obligatoire)
cd llm-module
docker build -t llm-manager -f llm-manager/Dockerfile .
docker build -t llm-decision -f llm-decision/Dockerfile .
```

## Lancer avec Docker

Les services communiquent via un réseau Docker partagé. Les scanners et mcp-tools-server doivent être démarrés en premier (voir leurs README respectifs).

```bash
# Chemin absolu vers la quarantaine sur la machine hôte
QUARANTINE=/chemin/absolu/vers/quarantaine

# 1. Créer le réseau partagé (une seule fois)
docker network create docdockgo

# 2. Démarrer les scanners (voir README scanner-cve et scanner-compliance)
#    Les conteneurs doivent s'appeler "scanner-cve" et "scanner-compliance"
#    et être connectés au réseau docdockgo.

# 3. Démarrer mcp-tools-server (voir son README)
#    Le conteneur doit s'appeler "mcp-tools-server" sur le réseau docdockgo.

# 4. Démarrer llm-manager
docker run -d --name llm-manager --network docdockgo \
  --env-file llm-module/llm-manager/.env \
  -p 3003:3003 \
  ghcr.io/ritsch-hugo/llm-manager:latest

# 5. Démarrer llm-decision
docker run -d --name llm-decision --network docdockgo \
  --env-file llm-module/llm-decision/.env \
  -e MANAGER_HOST=llm-manager \
  -e MCP_SERVER_URL=http://mcp-tools-server:3004/mcp \
  -e QUARANTINE_PATH=/quarantaine \
  -v "$QUARANTINE":/quarantaine \
  -p 3005:3005 \
  ghcr.io/ritsch-hugo/llm-decision:latest
```

## Prérequis

- Docker
- Clé API OpenRouter (`sk-or-v1-...`)
- Quarantaine de test présente sur l'hôte (ex: `library/alpine/3.18`)

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
# Tests unitaires (pas de dépendances réseau)
cd llm-module && cargo test

# Test du pipeline complet — envoyer un PullContext à llm-decision
# (tous les services doivent être démarrés)
# Exemple avec library/alpine:3.18 (digests réels de la quarantaine de dev)
curl -X POST http://localhost:3005/v1/decision \
  -H "Content-Type: application/json" \
  -d '{
    "uuid": "550e8400-e29b-41d4-a716-446655440000",
    "ip_client": "172.17.0.1",
    "registry": "registry-1.docker.io",
    "repository": "library/alpine",
    "tag": "3.18",
    "manifest_digests": [
      {"algorithm": "sha256", "value": "fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7"}
    ],
    "blob_digests": [
      {"algorithm": "sha256", "value": "44cf07d57ee4424189f012074a59110ee2065adfdde9c7d9826bebdffce0a885"},
      {"algorithm": "sha256", "value": "802c91d5298192c0f3a08101aeb5f9ade2992e22c9e27fa8b88eab82602550d0"}
    ],
    "referrers_digests": [
      {"algorithm": "sha256", "value": "9b6731f6b4abfdb75a0dda7b7852355343bccdb4062d5c55a19571ddc6cb7668"}
    ],
    "manifest_racine_digest": {"algorithm": "sha256", "value": "de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f"},
    "digests_possible": [
      {"algorithm": "sha256", "value": "fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7"}
    ],
    "digests_expected": [
      {"algorithm": "sha256", "value": "fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7"}
    ],
    "os": "linux",
    "arch": "amd64",
    "pull_completed": true
  }'
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
