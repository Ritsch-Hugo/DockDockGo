📦 DocDockGo — Format de la requête Scan Final (Proxy → Orchestrateur → LLM-Decision)

Ce document décrit précisément le format de la deuxième requête envoyée par le proxy Docker MITM vers l’orchestrateur (/v1/decision) lors du scan final.

👉 Ces données sont ensuite normalisées par l’orchestrateur et retransmises au module llm-decision pour analyse complète.

🧠 Vue d’ensemble
Docker Client
      ↓
Proxy (MITM)
      ↓
POST /v1/decision (multipart)
      ↓
Orchestrateur
      ↓
Transformation en PullContext
      ↓
LLM-Decision (analyse)
📦 Structure de la requête Proxy → Orchestrateur
POST /v1/decision
Content-Type: multipart/form-data
Contenu :
multipart/form-data
│
├── context (JSON string)
├── manifests (0..N fichiers JSON)
├── blobs (0..N fichiers binaires)
└── referrers (0..N fichiers JSON)
🟦 1. Champ JSON : context

Contient le ProxyPullContext.

Exemple :
{
  "uuid": "5cd20ed8-1367-587e-9321-5294f051c4f8",
  "ip_client": "192.168.1.249",
  "registry": "registry-1.docker.io",
  "repository": "library/alpine",
  "tag": "3.23.3",
  "manifest_digests": [...],
  "blob_digests": [...],
  "referrers_digests": [],
  "manifest_racine_digest": {...},
  "os": "linux",
  "arch": "amd64",
  "pull_completed": true,
  "scan_final_done": true,
  "scan_status": "PENDING",
  "client_type": "docker"
}
📁 2. Fichiers envoyés
🟨 manifests
JSON OCI (index ou manifest)
🟧 blobs
Layers Docker (binaire, tar.gz)
🟪 referrers
SBOM / signatures / metadata (optionnel)
🔄 Transformation dans l’orchestrateur

L’orchestrateur :

Parse le multipart
Convertit ProxyPullContext → PullContext interne
Stocke en base (pulls, digests, scan_events)
Déclenche la logique de décision
🧠 Format transmis au llm-decision

⚠️ Le LLM ne reçoit PAS directement le multipart.

Il reçoit une version normalisée et enrichie :

{
  "pull_id": "...",
  "registry": "registry-1.docker.io",
  "repository": "library/alpine",
  "tag": "3.23.3",
  "os": "linux",
  "arch": "amd64",
  "digests": [...],
  "metadata": {
    "source": "proxy_context",
    "scan_final_done": true
  }
}

👉 + accès indirect aux fichiers via :

filesystem (quarantaine)
ou services MCP (mcp-tools-server)
🔗 Rôle du LLM dans le scan final

Le llm-decision :

analyse le contexte (registry, repo, tag, OS, etc.)
déclenche des scans via MCP :
run_static_scan
run_compliance_scan
run_dynamic_scan
agrège les résultats
retourne :
{
  "decision": "ALLOW | DENY | PENDING",
  "score": 0-100,
  "reasoning": [...]
}