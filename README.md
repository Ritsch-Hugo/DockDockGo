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
    │                         score < 30 → DENY
    │                         score ≥ 30 → PENDING
    │
    └── Phase FINAL (GET) ───► POST /v1/decision (context + fichiers)
                                        │
                                 Forward multipart → LLM-Decision
                                        │
                               ALLOW / DENY / PENDING
```

---

## Endpoint principal

### `POST /v1/decision`

Accepte un `multipart/form-data` avec :

| Champ | Type | Obligatoire | Description |
|---|---|---|---|
| `context` | JSON string | oui | `ProxyPullContext` sérialisé |
| `manifests` | fichier(s) | Phase FINAL | Manifests OCI (JSON) |
| `blobs` | fichier(s) | Phase FINAL | Layers Docker (binaire) |
| `referrers` | fichier(s) | optionnel | SBOM / signatures |

La phase est déterminée automatiquement via `scan_final_done` dans le contexte :
- `scan_final_done: false` → **Phase INITIAL**
- `scan_final_done: true` → **Phase FINAL**

#### Réponse (format legacy proxy)

```json
{
  "pull_id": "9aea0f96-72cd-5bf2-b1ba-635e4934e86a",
  "state": "PENDING"
}
```

---

## Phase INITIAL — Scan haut niveau

1. Vérifie la blacklist en base — DENY immédiat si présente
2. Appelle le service HL scanner (`HIGH_LEVEL_URL`, défaut `http://127.0.0.1:4000/v1/high-level`) avec le `ProxyPullContext`
3. Parse la réponse Gemini : extrait le score sur la dernière ligne `Resultat : NN`
4. Décision : score < 30 → **DENY**, score ≥ 30 → **PENDING**
5. Timeout interne : 25s (le proxy a un timeout de 30s)

### Écritures BDD

| Table | Action | Contenu |
|---|---|---|
| `pulls` | UPSERT puis UPDATE | décision, scan_completed |
| `pull_digests` | INSERT | un enregistrement par digest reçu |
| `scan_events` | INSERT | `scanner_type='high-level'`, `executed=true`, `ia_decision_id=NULL`, `response_scanner` = score + texte Gemini |

Exemple `scan_events.response_scanner` pour un scan haut niveau :
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

1. Reconstruit un multipart avec le contexte brut + tous les fichiers reçus
2. Forward vers le service LLM-Decision (`LLM_DECISION_URL`, défaut `http://127.0.0.1:5000/v1/decision`)
3. Parse la réponse : champ `decision` (ALLOW/DENY/PENDING) ou champ `score` (≥ 50 = ALLOW)
4. Si le service est injoignable → **PENDING** (fail-open)

### Écritures BDD

| Table | Action | Contenu |
|---|---|---|
| `pulls` | UPDATE | décision finale, scan_completed |
| `pull_digests` | INSERT | tous les digests complets (manifests + blobs) |
| `ia_decisions` | INSERT | décision retournée par le LLM |

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

## Schema BDD utilisé

- `pulls` — un enregistrement par pull, décision finale
- `pull_digests` — tous les digests vus (manifests, blobs, referrers)
- `scan_events` — résultats des scanners (high-level, static, compliance, dynamic)
- `ia_decisions` — décisions retournées par le LLM de décision finale
- `blacklist` / `whitelist` — listes persistantes par (registry, repository, tag)
