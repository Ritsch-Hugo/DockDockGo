# HL Scanner — dockdockgo-mcp-llm

Scanner haut niveau du projet DocDockGo. Reçoit un `PullContext` de l'orchestrateur, interroge l'API Gemini et retourne une opinion (score 0–100) pour décider d'un ALLOW/DENY rapide avant le scan complet.

Port : **4000**

---

## Flux

```
Orchestrateur
    │
    └── POST /v1/high-level (PullContext JSON)
                │
         Requête GitHub Stars (owner/repo)
                │
         Appel Gemini 2.5 Flash
                │
         Parse score ("Resultat : NN")
                │
         Réponse { pull_id, opinion }
```

---

## Endpoint

### `POST /v1/high-level`

Corps JSON : `PullContext` (envoyé par l'orchestrateur).

#### Réponse

```json
{
  "pull_id": "9aea0f96-72cd-5bf2-b1ba-635e4934e86a",
  "opinion": "Analyse de l'image...\nResultat : 72"
}
```

Le score est extrait de la dernière occurrence de `Resultat : NN` dans le texte. L'orchestrateur applique ensuite le seuil (score < 30 → DENY, score ≥ 30 → PENDING).

---

## Arrêt gracieux

Le service intercepte `SIGTERM` (signal Docker `docker stop`) et `SIGINT` (Ctrl-C). À réception, axum attend la fin des requêtes en cours avant de fermer le listener.

---

## Docker

```bash
docker run -d --name docdockgo-hl-scanner \
  --network host \
  -u 10001:10001 \
  --env-file .env \
  ghcr.io/ritsch-hugo/docdockgo-hl-scanner:latest
```

---

## Variables d'environnement

| Variable | Requis | Description |
|---|---|---|
| `GEMINI_API_KEY` | oui | Clé API Google Gemini |
| `BIND_ADDR` | non (défaut `0.0.0.0:4000`) | Adresse d'écoute |
| `RUST_LOG` | non (défaut `info`) | Niveau de log |

Exemple `.env` :

```env
GEMINI_API_KEY=AIzaSy...
BIND_ADDR=0.0.0.0:4000
RUST_LOG=info
```
