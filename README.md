# Orchestrateur DockDockGo

Service central qui reçoit les requêtes du proxy MITM, orchestre les scans et retourne une décision ALLOW / DENY / PENDING.

Port : **3000**

---

## Flux général

```
Proxy (MITM)
    │
    ├── Phase INITIAL (HEAD) ──► POST /v1/decision (context seul)
    │                                   │
    │                            Scan haut niveau (Gemini)
    │                                   │
    │                         score < 30 → DENY  ──► proxy bloque
    │                         score ≥ 30 → PENDING ──► proxy attend le GET
    │
    └── Phase FINAL (GET) ───► POST /v1/decision (context + fichiers)
                                        │
                                 Forward multipart → LLM-Decision
                                        │
                            ┌───────────┴────────────┐
                            │   Réponse LLM-Decision  │
                            │  - decision_metadata    │  → ia_decisions
                            │  - scan_analysis        │  → scan_events (1 ligne/scanner)
                            │  - scan_reasoning       │  → ia_decisions
                            │  - verdict              │  → ia_decisions + pulls
                            │  - alternatives         │  → ia_decisions
                            └─────────────────────────┘
                                        │
                               ALLOW / DENY / PENDING ──► proxy
```

---

## Stateless

L'orchestrateur ne conserve aucun état en mémoire. La phase (INITIAL / FINAL) est déterminée par le champ `scan_final_done` dans le `ProxyPullContext` reçu. Toute la persistance passe par PostgreSQL.

---

## Endpoint principal

### `POST /v1/decision`

Accepte un `multipart/form-data` avec :

| Champ | Type | Présence | Description |
|---|---|---|---|
| `context` | JSON string | toujours | `ProxyPullContext` sérialisé |
| `manifests` | fichier(s) | Phase FINAL | Manifests OCI (JSON) |
| `blobs` | fichier(s) | Phase FINAL | Layers Docker (binaire) |
| `referrers` | fichier(s) | optionnel | SBOM / signatures |

#### Réponse (format legacy proxy)

```json
{
  "pull_id": "9aea0f96-72cd-5bf2-b1ba-635e4934e86a",
  "state": "PENDING"
}
```

---

## Phase INITIAL — Scan haut niveau

1. Vérifie la blacklist en base → DENY immédiat si présente
2. Appelle le service HL scanner (`HIGH_LEVEL_URL`) avec le `ProxyPullContext`
3. Parse la réponse Gemini : extrait le score sur la dernière ligne `Resultat : NN`
4. score < 30 → **DENY** / score ≥ 30 → **PENDING**
5. Timeout interne : 25s (le proxy a un timeout de 30s)

### Écritures BDD

| Table | Action | Contenu |
|---|---|---|
| `pulls` | UPSERT + UPDATE | décision, scan_completed |
| `pull_digests` | INSERT | un enregistrement par digest reçu |
| `scan_events` | INSERT | `scanner_type='high-level'`, `executed=true`, `ia_decision_id=NULL`, `response_scanner` = score + texte Gemini |

Exemple `scan_events.response_scanner` :
```json
{
  "decision": "DENY",
  "score": 15.0,
  "reasoning": ["Le tag 3.1 est très ancien...", "Risque ÉLEVÉ..."],
  "raw_text": "Voici l'analyse DevSecOps...\nResultat : 15"
}
```

---

## Phase FINAL — Décision LLM

1. Reconstruit le multipart reçu (context + tous les fichiers) et le forward tel quel au service LLM-Decision (`LLM_DECISION_URL`)
2. Parse la réponse structurée du LLM
3. Si le service est injoignable → **PENDING** (fail-open, rien écrit en DB)

### Format de réponse attendu du LLM-Decision

```json
{
  "verdict": {
    "decision": "DENY",
    "vulnerability_score": 7.5,
    "confidence": 0.93,
    "rationale": "2 CVEs critiques + 3 règles compliance échouées..."
  },
  "scan_analysis": {
    "static":     { "executed": true,  "llm_summary": "...", "raw_result": {...} },
    "compliance": { "executed": true,  "llm_summary": "...", "raw_result": {...} },
    "dynamic":    { "executed": false, "llm_summary": null,  "raw_result": null  }
  },
  "scan_reasoning": {
    "workers": [...],
    "arbiter": { "model": "...", "vulnerability_score": 7.5, "confidence": 0.93, "reasoning": "..." }
  },
  "decision_metadata": {
    "workers": [...],
    "arbiter": { "model": "...", "reasoning": "..." }
  },
  "alternatives": [
    { "image": "cgr.dev/chainguard/alpine-base:latest", "reason": "...", "confidence": 0.90 }
  ]
}
```

### Écritures BDD

| Table | Action | Contenu |
|---|---|---|
| `pulls` | UPDATE | `decision_final`, `scan_completed` |
| `pull_digests` | INSERT | tous les digests complets (manifests + blobs) |
| `ia_decisions` | INSERT | verdict complet : decision, vulnerability_score, confidence, rationale, scan_reasoning, decision_metadata, alternatives |
| `scan_events` | INSERT × N | une ligne par scanner dans `scan_analysis` : scanner_type, executed, llm_summary, response_scanner (raw_result), ia_decision_id |

---

## Autres endpoints

| Route | Méthode | Description |
|---|---|---|
| `/health` | GET | Healthcheck (DB ping) |
| `/v1/decision/:pull_id` | GET | Consulter l'état d'une décision |
| `/v1/scanners/:type/callback` | POST | Callback pour les scanners async |

---

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `DATABASE_URL` | `postgres://docdockgo_admin:docdockgo@127.0.0.1:5432/docdockgo` | URL PostgreSQL |
| `BIND_ADDR` | `0.0.0.0:3000` | Adresse d'écoute |
| `HIGH_LEVEL_URL` | `http://127.0.0.1:4000/v1/high-level` | Service HL scanner (Gemini) |
| `LLM_DECISION_URL` | `http://127.0.0.1:5000/v1/decision` | Service LLM décision finale |
| `RUST_LOG` | `info` | Niveau de log |

---

## Schéma BDD utilisé

| Table | Rôle |
|---|---|
| `pulls` | Un enregistrement par pull, décision finale |
| `pull_digests` | Tous les digests vus (manifests, blobs, referrers) |
| `scan_events` | Résultats des scanners : `high-level` (Phase INITIAL) + `static/compliance/dynamic` (Phase FINAL) |
| `ia_decisions` | Décision complète retournée par le LLM de décision finale |
| `blacklist` / `whitelist` | Listes persistantes par (registry, repository, tag) |
