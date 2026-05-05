# mcp-tools-server

Bridge MCP (Model Context Protocol) entre `llm-decision` et les scanners de sécurité DocDockGo. Expose trois tools via JSON-RPC 2.0 que `llm-decision` appelle après la décision LLM pour exécuter les scans.

## Rôle dans le pipeline

```
llm-decision (port 3005)
    │
    │  JSON-RPC 2.0  POST /mcp
    ▼
mcp-tools-server (port 3004)
    ├── run_static_scan     → POST scanner-cve:3002/v1/scan-upload   (Trivy)
    ├── run_compliance_scan → POST scanner-compliance:3001/v1/scan
    └── run_dynamic_scan    → stub (NOT_IMPLEMENTED — Falco à venir)
```

## Tools exposés

### `run_static_scan`

Lance un scan CVE statique avec Trivy sur l'image en quarantaine.

**Paramètre :** `quarantine_path` — chemin absolu vers le dossier de l'image (ex: `/quarantaine/library/alpine/3.18`)

**Retourne :** JSON avec `summary` (totaux par sévérité) et `findings` (CVEs CRITICAL/HIGH).

### `run_compliance_scan`

Lance un scan de conformité sur l'image (règles de sécurité : root, secrets exposés, entrypoint dangereux, etc.).

**Paramètre :** `quarantine_path` — chemin absolu vers le dossier de l'image

**Retourne :** JSON avec `status`, `summary` (pass/fail/warn) et `findings` (règles échouées).

### `run_dynamic_scan`

Scan comportemental Falco — non encore implémenté.

**Retourne :** `{"status": "NOT_IMPLEMENTED", "message": "..."}`

## Démarrage

```bash
# Variables d'environnement (optionnelles, valeurs par défaut ci-dessous)
export MCP_SERVER_PORT=3004
export STATIC_SCANNER_URL=http://localhost:3002
export COMPLIANCE_SCANNER_URL=http://localhost:3001

cd mcp-tools-server && cargo run --release
```

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `MCP_SERVER_PORT` | `3004` | Port d'écoute |
| `STATIC_SCANNER_URL` | `http://localhost:3002` | URL du scanner CVE |
| `COMPLIANCE_SCANNER_URL` | `http://localhost:3001` | URL du scanner compliance |

## API JSON-RPC 2.0

```
POST /mcp
Content-Type: application/json
Accept: application/json, text/event-stream
```

### Lister les tools

```bash
curl -X POST http://localhost:3004/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### Appeler un tool

```bash
curl -X POST http://localhost:3004/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "run_static_scan",
      "arguments": { "quarantine_path": "/quarantaine/library/alpine/3.18" }
    }
  }'
```

## Structure de la quarantaine attendue

```
{quarantine_path}/
├── manifests/{digest}.json     ← manifest OCI image (avec champ "layers")
└── blobs/sha256/{digest}       ← config OCI ou layers (gzip ignorés)
```

## Sécurité

- Le `quarantine_path` reçu est validé : chemin absolu obligatoire, séquences `..` et caractères nuls interdits
- Les blobs sont filtrés par nom (64 caractères hexadécimaux uniquement) avant lecture
- Les layers gzip sont détectés par magic number (`0x1f 0x8b`) et ignorés pour le scan compliance

## Tests

```bash
cd mcp-tools-server && cargo test
```

## Docker

```bash
# Pull depuis ghcr.io
docker pull ghcr.io/ritsch-hugo/mcp-tools-server:latest

# Build local (alternatif)
docker build -t mcp-tools-server .

# Run
# Les conteneurs scanner-cve et scanner-compliance doivent être sur le même réseau.
# Le réseau "docdockgo" doit être créé au préalable : docker network create docdockgo
QUARANTINE=/chemin/absolu/vers/quarantaine

docker run -d --name mcp-tools-server --network docdockgo \
  -e STATIC_SCANNER_URL=http://scanner-cve:3002 \
  -e COMPLIANCE_SCANNER_URL=http://scanner-compliance:3001 \
  -v "$QUARANTINE":/quarantaine \
  -p 3004:3004 \
  ghcr.io/ritsch-hugo/mcp-tools-server:latest
```
