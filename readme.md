# 🚀 Scanner CVE – DockDockGo

Ce scanner analyse des images OCI (Docker) **sans Docker daemon** en reconstruisant le filesystem à partir des layers, puis en exécutant un scan de vulnérabilités avec **Trivy**.

---

## ⚙️ Prérequis

### 1. Installer Trivy

```bash
sudo snap install trivy
```

ou :

```bash
brew install trivy
```

---

### 2. Initialiser la base de vulnérabilités

⚠️ À faire une seule fois :

```bash
trivy fs /
```

---

## ▶️ Lancer le scanner

```bash
cargo run --bin scanner_cve_http
```

---

## ❤️ Health check

```bash
curl http://localhost:3002/health
```

Résultat attendu :

```
ok
```

---

## 🧪 Test du scan

### 1. Générer un sample OCI

```bash
docker pull alpine
docker save alpine -o alpine.tar
```

### 2. Extraire

```bash
mkdir samples
tar -xf alpine.tar -C samples
```

### 3. Lancer le scan

```bash
curl -X POST http://localhost:3002/v1/scan-upload   -F "manifest=@samples/manifest.json"   $(for f in samples/blobs/sha256/*; do echo -n "-F blob=@$f "; done)
```

---

## 📊 Résultat attendu

```json
{
  "status": "COMPLETE",
  "summary": {
    "vulnerabilities_total": 30,
    "severity_count": {
      "low": 3,
      "medium": 21,
      "high": 4,
      "critical": 2
    }
  }
}
```

---

## 🧠 Fonctionnement

1. Réception des fichiers (manifest + blobs)
2. Reconstruction du root filesystem
3. Scan avec Trivy
4. Parsing des résultats
5. Retour JSON structuré

---

## ⚡ Notes

- Utilise `--skip-db-update` → scan rapide
- Cache Trivy local utilisé automatiquement
- Workspace temporaire dans `/tmp/dockdockgo-cve-*`

👉 Oui : **le /tmp est automatiquement nettoyé après chaque scan** grâce au CleanupGuard.

---

## 🔌 Endpoint

```
POST /v1/scan-upload
```

---

## 👤 Auteur

Projet DockDockGo – Scanner CVE