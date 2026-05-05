# 🚀 Scanner CVE - DockDockGo

Scanner de vulnérabilités basé sur Trivy, conçu pour analyser des images OCI à partir de leurs artefacts (manifest, config, layers) **sans utiliser Docker daemon**.

---

## 🎯 Objectif

Ce scanner permet :

* d’analyser une image OCI **à partir de fichiers bruts**
* de reconstruire dynamiquement le filesystem
* d’exécuter Trivy en mode filesystem
* de produire un rapport JSON structuré (CVE, sévérité, CVSS)

Il est conçu pour être intégré dans l’écosystème **DockDockGo** via un orchestrateur.

---

## ⚙️ Fonctionnement

1. Réception des fichiers :

   * manifest.json
   * config.json (optionnel)
   * blobs (layers)

2. Reconstruction du filesystem (rootfs)

3. Scan avec Trivy :

   * mode filesystem (`trivy fs`)

4. Parsing des résultats

5. Retour d’un JSON structuré

---

## 🐳 Lancer avec Docker (recommandé)

### 1. Build l’image

```bash
docker build -t scanner-cve .
```

### 2. Lancer le service

```bash
docker run -p 3002:3002 scanner-cve
```

---

## ❤️ Healthcheck

```bash
curl http://localhost:3002/health
```

Réponse attendue :

```text
ok
```

---

## 🔍 Scan d’une image

Depuis la racine du projet :

```bash
curl -X POST http://localhost:3002/v1/scan-upload \
  -F "manifest=@samples/manifest.json" \
  $(for f in samples/blobs/sha256/*; do echo -n "-F blob=@$f "; done)
```

---

## 📦 Exemple de réponse

```json
{
  "request_id": "uuid",
  "status": "COMPLETE",
  "summary": {
    "vulnerabilities_total": 30,
    "severity_count": {
      "critical": 2,
      "high": 4,
      "medium": 21,
      "low": 3,
      "unknown": 0
    }
  },
  "findings": [
    {
      "cve_id": "CVE-XXXX",
      "package": "openssl",
      "installed_version": "x.x.x",
      "fixed_version": "x.x.x",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "title": "Example vulnerability"
    }
  ]
}
```

---

## ⚠️ Notes importantes

* Le **premier scan est plus lent** (téléchargement de la base Trivy)
* Les scans suivants sont rapides
* Le scanner est **stateless** (workspace temporaire supprimé après exécution)
* Aucun `docker pull` n’est nécessaire

---

## 🧪 Mode CLI (optionnel)

```bash
cd scanner_cve

cargo run --bin scanner_cve -- -r ../samples/request.json --pretty
```

---

## 🧠 Architecture

```text
Client / Orchestrator
        ↓
  Scanner CVE (HTTP API)
        ↓
 Reconstruction rootfs
        ↓
     Trivy scan
        ↓
   JSON structuré
```

---

## 🔧 CI/CD

Le projet inclut :

* ✔ Format (`cargo fmt`)
* ✔ Lint (`cargo clippy`)
* ✔ Tests (`cargo test`)
* ✔ Build automatique
* ✔ Build Docker automatique

---

## 📁 Structure

```text
scanner_cve/
├── src/
├── Cargo.toml
samples/
├── manifest.json
├── blobs/
Dockerfile
README.md
```

---

## 🔥 Features

* Stateless scanning
* OCI-compatible
* No Docker daemon required
* Trivy integration
* Microservice-ready (HTTP API)
* Orchestrator-friendly

---

## 🚀 Intégration

Ce scanner est conçu pour être appelé par un orchestrateur DocDockGo via une requête HTTP multipart contenant :

* manifest
* blobs
* (optionnel) pull_context

---

## 👨‍💻 Auteur

Projet développé dans le cadre de DocDockGo (DevSecOps / Container Security).
