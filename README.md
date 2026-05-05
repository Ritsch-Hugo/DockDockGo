# 🚀 Scanner Compliance - DocDockGo

Scanner de conformité pour images OCI, conçu pour analyser des artefacts (manifest, config, layers) **sans utiliser Docker daemon**.

---

## 🎯 Objectif

Ce scanner permet :

* d’analyser une image OCI à partir de fichiers bruts
* de reconstruire dynamiquement le filesystem
* d’appliquer des règles de conformité (sécurité, bonnes pratiques)
* de produire un rapport JSON structuré

Il est conçu pour être utilisé dans l’écosystème **DocDockGo** via un orchestrateur.

---

## ⚙️ Fonctionnement

1. Réception des artefacts :

   * manifest.json
   * blobs (layers + config)

2. Reconstruction du filesystem

3. Application des règles :

   * sécurité filesystem
   * configuration OCI
   * bonnes pratiques container

4. Génération d’un rapport :

   * PASS / WARN / FAIL
   * findings détaillés
   * pseudo-Dockerfile

---

## 🐳 Lancer avec Docker (recommandé)

### 1. Build l’image

```bash
docker build -t scanner-compliance .
```

### 2. Lancer le service

```bash
docker run -p 3001:3001 scanner-compliance
```

Les variables d'environnement sont toutes optionnelles (valeurs par défaut indiquées) :

| Variable | Défaut | Description |
|---|---|---|
| `PORT` | `3001` | Port d'écoute |
| `RATE_LIMIT_PER_SECOND` | `1` | 1 requête toutes les N secondes |
| `RATE_LIMIT_BURST` | `10` | Burst maximum autorisé |

Avec un fichier `.env` :

```bash
docker run -p 3001:3001 --env-file .env scanner-compliance
```

---

## ❤️ Test du service

```bash
curl http://localhost:3001/health
```

👉 doit répondre `ok` → serveur OK

---

## 🔍 Scan d’une image (multipart)

Depuis la racine du projet :

```bash
curl -X POST http://localhost:3001/v1/scan-upload \
  -F "manifest=@quarantaine/library/testcases/fs-secrets-pass/latest/manifests/000.json" \
  $(for f in quarantaine/library/testcases/fs-secrets-pass/latest/blobs/sha256/*; do echo -n "-F blob=@$f "; done)
```

---

## 📦 Exemple de réponse

```json
{
  "status": "PASS",
  "summary": {
    "pass": 14,
    "warn": 1,
    "fail": 0
  },
  "findings": [
    {
      "rule_id": "NON_ROOT_USER",
      "status": "PASS",
      "message": "Container runs as non-root user"
    }
  ]
}
```

---

## ⚠️ Notes importantes

* Le scanner est **stateless**
* Les fichiers sont stockés temporairement puis supprimés
* Aucun `docker pull` requis
* Compatible orchestrateur DocDockGo

---

## 🧪 Mode CLI (optionnel)

```bash
cd scanner_compliance

cargo run --bin scanner_compliance -- -r ../samples/request.json
```

---

## 🧠 Architecture

```
Orchestrator
     ↓
Scanner Compliance (HTTP)
     ↓
Reconstruction FS
     ↓
Rules Engine
     ↓
JSON Report
```

---

## 🔧 CI/CD

Le projet inclut :

* ✔ Format (`cargo fmt`)
* ✔ Lint (`cargo clippy`)
* ✔ Tests (`cargo test`)
* ✔ Audit sécurité (`cargo audit`)
* ✔ Build Docker

---

## 📁 Structure

```
scanner_compliance/
├── src/
├── Cargo.toml
Dockerfile
README.md
```

---

## 🔥 Features

* Stateless scanning
* OCI-compatible
* No Docker daemon required
* Rules-based compliance engine
* Microservice-ready (HTTP API)
* Orchestrator-friendly

---

## 🚀 Intégration

Le scanner est conçu pour être appelé via HTTP multipart :

* `manifest`
* `blob` (layers)

Compatible avec le modèle **PullContext** de DocDockGo.

---

## 👨‍💻 Auteur

Projet développé dans le cadre de DocDockGo (DevSecOps / Container Security).
