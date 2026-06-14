# DocDockGo — Environnement de test (docker compose)


### Pour le Deployment en production via Kubernetes veuillez suivre le fichier INSTALLATION.md dans le dossier k8s/




## Prérequis

- Docker + Docker Compose
- PostgreSQL local sur `127.0.0.1:5432` avec la DB `docdockgo` et l'utilisateur `docdockgo_admin`
- CA du proxy installé et Docker redémarré (voir section Test)

---

## Démarrer les services

```bash
docker compose up -d
```

## Arrêter les services

```bash
docker compose down
```

## Suivre les logs en live

```bash
docker compose logs -f
# ou un service spécifique :
docker compose logs -f proxy
```

---

## Services et ports

| Service            | Port  | Rôle                                      |
|--------------------|-------|-------------------------------------------|
| proxy              | 8443  | TLS MITM — point d'entrée des pulls Docker |
| orchestrateur      | 3000  | Routage des scans, décision ALLOW/DENY    |
| scanner-haut-niveau| 4000  | Scanner LLM (Gemini)                      |
| scanner-compliance | 3001  | Règles OCI compliance                     |
| scanner-static     | 3002  | Scanner CVE (Trivy)                       |
| mcp-tools-server   | 3004  | Serveur MCP pour llm-decision             |
| llm-manager        | 3003  | Gestion des workers LLM (OpenRouter)      |
| llm-decision       | 3005  | Décision LLM multi-modèles                |
| dashboard          | 3010  | Interface web (auth Zitadel)              |

---

## Tester un pull Docker via le proxy

### 1. Installer le CA du proxy (une seule fois)

```bash
sudo cp proxy/certs-mitm/myca.crt /usr/local/share/ca-certificates/docdockgo-ca.crt
sudo update-ca-certificates
sudo systemctl restart docker
```

### 2. Rediriger le trafic registry vers le proxy

```bash
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -d registry-1.docker.io -j REDIRECT --to-port 8443
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -d ghcr.io -j REDIRECT --to-port 8443
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -d quay.io -j REDIRECT --to-port 8443
```

### 3. Lancer un pull

```bash
docker pull hello-world
```

Les logs du proxy montrent le pull en temps réel :

```bash
docker compose logs -f proxy orchestrateur llm-decision
```

### 4. Nettoyer les règles iptables après le test

```bash
sudo iptables -t nat -F OUTPUT
```

---

## Registries supportés

Définis dans `proxy/registry_whitelist.json` et couverts par les certificats dans `proxy/certs-mitm/` :

- `registry-1.docker.io` (Docker Hub)
- `ghcr.io` (GitHub Container Registry)
- `quay.io`

---

## Variables d'environnement

Chaque service a son `.env` dans son sous-dossier. Les surcharges Docker-spécifiques (URLs inter-services, chemins absolus) sont dans `docker-compose.yml` et prennent la priorité.
