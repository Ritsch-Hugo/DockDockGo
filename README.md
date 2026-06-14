# DocDockGo
 
> Proxy de sécurité pour images Docker/OCI — analyse, scan et contrôle des pulls de conteneurs en entreprise.
 
---
 
## 🩺 Le problème
 
Dans les environnements DevOps modernes, des centaines d'images Docker transitent chaque jour dans les pipelines de production. Les solutions de sécurité actuelles souffrent de deux défauts majeurs : elles génèrent trop de faux positifs, saturant les équipes de fausses alertes, et interviennent souvent trop tard — après que l'image est déjà déployée.
 
Résultat : les équipes de sécurité sont débordées, les equipes DevSecOps priorisent eux meme les choix des scans et les images qui rentrent en prod ou non. 
 
---
 
## 💡 La solution — DocDockGo
 
DocDockGo agit comme un **médecin de garde pour votre infrastructure** : il ausculte chaque image Docker et décide, selon son état de santé, si elle a le droit de franchir la porte de la production.
 
Techniquement, c'est un **proxy qui s'insère au moment du `docker pull`** — il intercepte les requêtes avant même que l'image n'arrive sur le poste du développeur et est capable de detecter :
 
- 🔍 les **vulnérabilités connues** (CVE)
- ⚠️ les **risques de sécurité** et problèmes de conformité
- 📋 les **écarts aux bonnes pratiques** container
- 🌐 la **provenance et réputation** de l'image
### Ce qui le distingue
 
DocDockGo intègre un **assistant IA agentique** capable d'orchestrer intelligemment différents outils de scan selon le profil de chaque image. Une image officielle publiée par une organisation reconnue ne subira pas le même niveau d'examen qu'une image provenant d'une source inconnue — l'analyse est adaptée, optimisée, et décidée par l'IA.
 
En agissant comme une synthèse intelligente des outils du marché, DocDockGo permet de **sécuriser plus rapidement les pipelines** tout en **réduisant drastiquement la charge opérationnelle** des équipes.
 
---
 
## 🗂️ Organisation des branches
 
Ce dépôt est organisé par branches, chacune dédiée à un composant ou usage spécifique :
 
| Branche | Contenu |
|---|---|
| `deployment` | **Déploiement complet** du projet sur k3s via Helm ou docker compose |
| `feature/dashboard` | Service dashboard web |
| `feature/proxy` | Service proxy MITM TLS |
| `feature/orchestrateur` | Service orchestrateur |
| `feature/continuous-monitoring` | Service de Surveillance continue basé sur les nouvelles CVE |
| `feature/llm-decision` | Service decisionel LLM |
| `feature/scanner-compliance` | Scanner de conformité OCI |
| `feature/scanner-haut-niveau` | Scanner haut-niveau (Gemini) |
| `feature/scanner-static` | Scanner CVE statique (Trivy) |
| `feature/scanner-dynamique` | Scanner avec execution de l'image (Falco, firecracker) |
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
