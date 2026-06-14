# DocDockGo

> Proxy de sécurité pour images Docker/OCI — analyse, scan et contrôle des pulls de conteneurs en entreprise.

---

## 🗂️ Organisation des branches

Ce dépôt est organisé par branches, chacune dédiée à un composant ou usage spécifique :

| Branche | Contenu |
|---|---|
| `deployment` | **Déploiement complet** du projet sur k3s via Helm ou docker compose |
| `feature/dashboard` | Service dashboard web |
| `feature/proxy` | Service proxy MITM TLS |
| `feature/orchestrateur` | Service orchestrateur |
| `feature/continuous-monitoring` |Service de Surveillance continue basé sur les nouvelles CVE |
| `feature/llm-decision` | Service decisionel LLM |
| `feature/scanner-compliance` | Scanner de conformité OCI |
| `feature/scanner-haut-niveau` | Scanner haut-niveau (Gemini) |
| `feature/scanner-static` | Scanner CVE statique (Trivy) |
| `feature/scanner-dynamique` | Scanner avec execution de l'image (Falco, firecracker)  |
| `feature/mcp` | Serveur MCP tools |

---

## 🚀 Déployer le projet

Tout ce dont vous avez besoin pour installer et déployer DocDockGo via Kubernetes ou docker compose se trouve dans la branche **`deployment`**, qui contiendra les guides d'installations

```bash
git checkout deployment
```

Suivre le `INSTALLATION.md` dans le dossier k8s/ pour Kubernetes (recommandé).

---

## 📖 Documentation par service

Chaque branche de service contient son propre `README.md` détaillant :
- le rôle du service
- les endpoints disponibles
- les variables d'environnement
- comment le lancer en local

---

## 👨‍💻 Auteur

Projet développé dans le cadre d'un Master en cybersécurité (DevSecOps / Container Security).
