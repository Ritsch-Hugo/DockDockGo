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
                                INSERT ia_decisions (PENDING)
                                        │
                               spawn tâche background
                                        │
                         ┌──────────────┴──────────────┐
                         │  Attente réponse LLM-Decision │
                         │  (timeout = LLM_DECISION_     │
                         │   TIMEOUT_SECS)               │
                         └──────────────┬────────────────┘
                                        │
                              timeout écoulé ?
                              ├── OUI → retourne PENDING au proxy
                              │         (background task continue)
                              └── NON → retourne ALLOW/DENY au proxy
                                        │
                                (background task)
                                        │
                            UPDATE ia_decisions (décision réelle)
                            INSERT scan_events (1 ligne/scanner)
                            UPDATE pulls (decision_final)
                            ALLOW → copie quarantaine → cache
                                  → INSERT whitelist
                            DENY  → supprime fichiers quarantaine
                                  → INSERT blacklist
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
5. Timeout interne : 25 s

### Écritures BDD

| Table | Action | Contenu |
|---|---|---|
| `pulls` | UPSERT + UPDATE | décision, scan_completed |
| `pull_digests` | INSERT | un enregistrement par digest reçu |
| `scan_events` | INSERT | `scanner_type='high-level'`, `executed=true`, `ia_decision_id=NULL`, `response_scanner` = score + texte Gemini |

---

## Phase FINAL — Décision LLM

1. INSERT immédiat dans `ia_decisions` avec `decision='PENDING'` (satisfait la FK avant la réponse)
2. Spawn d'une tâche background qui forward le multipart au service LLM-Decision
3. Attente pendant `LLM_DECISION_TIMEOUT_SECS` secondes :
   - Réponse dans les temps → retourne la décision au proxy + background task met à jour la BDD
   - Timeout → retourne **PENDING** au proxy, la tâche background continue et met à jour la BDD à la réception
4. Si le service est injoignable → **PENDING**, `ia_decisions` reste à PENDING

### Format de réponse attendu du LLM-Decision

```json
{
  "verdict": {
    "decision": "ALLOW",
    "vulnerability_score": 1.5,
    "confidence": 0.91,
    "rationale": "..."
  },
  "scan_analysis": {
    "static":     { "executed": true,  "llm_summary": "...", "raw_result": {...} },
    "compliance": { "executed": true,  "llm_summary": "...", "raw_result": {...} },
    "dynamic":    { "executed": false, "llm_summary": null,  "raw_result": null  }
  },
  "scan_reasoning": {
    "workers": [...],
    "arbiter": { "model": "...", "vulnerability_score": 1.5, "confidence": 0.91, "reasoning": "..." }
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

### Écritures BDD (tâche background)

| Table | Action | Contenu |
|---|---|---|
| `pulls` | UPDATE | `decision_final`, `scan_completed` |
| `pull_digests` | INSERT | tous les digests complets (manifests + blobs) |
| `ia_decisions` | UPDATE | verdict complet : decision, vulnerability_score, confidence, rationale, scan_reasoning, decision_metadata, alternatives, static_scan, compliance_scan, dynamic_scan |
| `scan_events` | INSERT × N | une ligne par scanner dans `scan_analysis` |
| `whitelist` | INSERT | si ALLOW — (registry, repository, tag) |
| `blacklist` | INSERT | si DENY — (registry, repository, tag) |

### Opérations fichiers (tâche background)

| Décision | Action |
|---|---|
| ALLOW | Copie `quarantaine/` → `cache/` pour chaque digest + upsert table `cache` + supprime de `quarantaine` |
| DENY | Supprime les fichiers de `quarantaine/` + supprime de la table `quarantine` |

---

## Autres endpoints

| Route | Méthode | Description |
|---|---|---|
| `/health` | GET | Healthcheck (DB ping) |
| `/v1/decision/:pull_id` | GET | Consulter l'état d'une décision |
| `/v1/scanners/:type/callback` | POST | Callback pour les scanners async |

---

## Docker

```bash
docker run -d --name docdockgo-orchestrateur \
  --network host \
  -u 10001:10001 \
  --env-file .env \
  -v /path/to/proxy/quarantaine:/data/quarantaine \
  -v /path/to/proxy/cache:/data/cache \
  -p 3000:3000 \
  ghcr.io/ritsch-hugo/docdockgo-orchestrateur:latest
```

> **Note** : `--network host` permet d'atteindre PostgreSQL et les autres services sur `127.0.0.1`. Les volumes `-v` doivent pointer vers les mêmes répertoires que le proxy pour les opérations quarantaine → cache. Adapter `QUARANTINE_BASE` et `CACHE_BASE` dans le `.env` en conséquence (`/data/quarantaine` et `/data/cache`).

---

## Variables d'environnement

Chargées automatiquement depuis `.env` (via `dotenvy`).

| Variable | Défaut | Description |
|---|---|---|
| `DATABASE_URL` | `postgres://docdockgo_admin:docdockgo@127.0.0.1:5432/docdockgo` | URL PostgreSQL |
| `BIND_ADDR` | `0.0.0.0:3000` | Adresse d'écoute |
| `HIGH_LEVEL_URL` | `http://127.0.0.1:4000/v1/high-level` | Service HL scanner (Gemini) |
| `LLM_DECISION_URL` | `http://127.0.0.1:5000/v1/decision` | Service LLM décision finale |
| `LLM_DECISION_TIMEOUT_SECS` | `30` | Timeout avant retour PENDING au proxy |
| `QUARANTINE_BASE` | `./quarantaine` | Chemin de base de la quarantaine |
| `CACHE_BASE` | `./cache` | Chemin de base du cache |
| `RUST_LOG` | `info` | Niveau de log |

---

## Schéma BDD utilisé

| Table | Rôle |
|---|---|
| `pulls` | Un enregistrement par pull, décision finale |
| `pull_digests` | Tous les digests vus (manifests, blobs, referrers) |
| `scan_events` | Résultats des scanners : `high-level` (Phase INITIAL) + `static/compliance/dynamic` (Phase FINAL) |
| `ia_decisions` | Décision LLM : inséré en PENDING au démarrage du scan, mis à jour avec le verdict réel |
| `blacklist` / `whitelist` | Listes persistantes par (registry, repository, tag) |
| `quarantine` / `cache` | Index des fichiers sur disque |
