# mcp-tools-server

Microservice de la plateforme **DocDockGo** — pont entre le module LLM et les scanners de sécurité.

## Rôle

`mcp-tools-server` expose les outils de scan (CVE, conformité, dynamique) via le protocole **MCP (Model Context Protocol)** en JSON-RPC 2.0. Il reçoit les demandes de scan de `llm-decision` et les redirige vers les bons services de scan.

## Position dans l'architecture

```
llm-decision (port 3005)
    │
    │  JSON-RPC 2.0 (MCP)
    ▼
mcp-tools-server (port 3004)
    ├── run_static_scan     → scanner-cve       (port 3002, Trivy)
    ├── run_compliance_scan → scanner-compliance (port 3001)
    └── run_dynamic_scan    → stub (Falco, non implémenté)
```

## Tools exposés

| Tool | Description |
|---|---|
| `run_static_scan` | Scan CVE via Trivy — envoie les artefacts de la quarantaine au scanner CVE |
| `run_compliance_scan` | Scan de conformité — vérifie les règles de sécurité (root, secrets, entrypoint…) |
| `run_dynamic_scan` | Scan comportemental via Falco — **non implémenté**, retourne un stub |

Chaque tool prend un paramètre `quarantine_path` : chemin absolu vers le dossier de l'image dans la quarantaine.

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `MCP_SERVER_PORT` | `3004` | Port d'écoute du serveur |
| `STATIC_SCANNER_URL` | `http://localhost:3002` | URL du scanner CVE (Trivy) |
| `COMPLIANCE_SCANNER_URL` | `http://localhost:3001` | URL du scanner de conformité |

## Lancement

```bash
cargo run
```

Avec des variables personnalisées :
```bash
MCP_SERVER_PORT=3004 \
STATIC_SCANNER_URL=http://scanner-cve:3002 \
COMPLIANCE_SCANNER_URL=http://scanner-compliance:3001 \
cargo run
```

## Endpoint

```
POST /mcp
Content-Type: application/json
Accept: application/json, text/event-stream
```

Exemples d'appels directs :

```bash
# Lister les tools disponibles
curl -X POST http://localhost:3004/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Lancer un scan statique
curl -X POST http://localhost:3004/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "run_static_scan",
      "arguments": { "quarantine_path": "/quarantaine/library/alpine/3" }
    }
  }'
```

## Structure du projet

```
mcp-tools-server/
├── Cargo.toml
└── src/
    └── main.rs   ← serveur MCP (rmcp), logique d'appel aux scanners
```

## Dépendances principales

- [`rmcp`](https://crates.io/crates/rmcp) — crate officielle MCP (JSON-RPC 2.0, schema auto-généré)
- [`axum`](https://crates.io/crates/axum) — serveur HTTP
- [`reqwest`](https://crates.io/crates/reqwest) — appels HTTP vers les scanners (multipart pour CVE, JSON pour compliance)

## Prérequis pour les scans

- **scanner-cve** (Trivy) sur le port 3002 : `docker run -p 3002:3002 scanner-cve`
- **scanner-compliance** sur le port 3001 : `cargo run` dans son dossier
- Dossier quarantaine accessible en lecture avec les artefacts OCI de l'image à scanner
