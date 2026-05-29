# DocDockGo — Guide d'installation et d'utilisation

DocDockGo est une plateforme DevSecOps qui sécurise les `docker pull` via un proxy TLS MITM. Il intercepte le trafic vers les registres OCI, met les artefacts en quarantaine, et exécute des scans de sécurité multi-étapes avant d'autoriser ou de bloquer la livraison de l'image.

---

## Table des matières

1. [Architecture](#1-architecture)
2. [Prérequis](#2-prérequis)
3. [Récupérer la branche test](#3-récupérer-la-branche-test)
4. [Configurer les variables d'environnement](#4-configurer-les-variables-denvironnement)
5. [Installer le CA sur les machines clientes](#5-installer-le-ca-sur-les-machines-clientes)
6. [Démarrer les services](#6-démarrer-les-services)
7. [Ajouter des utilisateurs autorisés](#7-ajouter-des-utilisateurs-autorisés)
8. [Accéder au dashboard](#8-accéder-au-dashboard)
9. [Tester un pull Docker](#9-tester-un-pull-docker)
10. [Comprendre le cycle de vie d'un pull](#10-comprendre-le-cycle-de-vie-dun-pull)
11. [Commandes utiles](#11-commandes-utiles)
12. [Ajouter un nouveau registre](#12-ajouter-un-nouveau-registre)
13. [Dépannage](#13-dépannage)

---

## 1. Architecture

```
Machine cliente (docker pull)
  │
  │  (TLS port 443, intercepté par iptables → 8443)
  ▼
┌─────────────────────────────────────────────────────┐
│  Proxy MITM (port 8443)                             │
│  - Déchiffre le TLS avec certificat par registre    │
│  - Télécharge manifests + blobs en quarantaine      │
│  - Bloque le client en attendant la décision        │
└────────────────────┬────────────────────────────────┘
                     │ POST /v1/decision (multipart)
                     ▼
┌─────────────────────────────────────────────────────┐
│  Orchestrateur (port 3000)                          │
│  Phase 1 (HEAD) : scanner haut-niveau (Gemini)      │
│    score ≥ 90 → ALLOW direct                        │
│    score < 30 → DENY direct                         │
│    sinon      → continuer                           │
│  Phase 2 (GET) : pipeline LLM multi-modèles         │
│    Workers → Scans (CVE + compliance) → Arbitre     │
│    → ALLOW / DENY                                   │
└──────┬──────────────────────────────────────────────┘
       │
       ├── Scanner haut-niveau (port 4000) — Gemini API
       ├── LLM Decision (port 3005) — OpenRouter multi-modèles
       │     └── MCP Tools Server (port 3004)
       │           ├── Scanner CVE/statique (port 3002) — Trivy
       │           └── Scanner compliance (port 3001) — règles OCI
       ├── LLM Manager (port 3003) — gestion des workers
       └── Dashboard (port 3010) — interface web temps réel
             └── Cycle de vie (port 3020) — surveillance SBOM/CVE
```

**Décisions possibles :**
- `ALLOW` → image copiée de quarantaine → cache, servie au client
- `DENY` → quarantaine supprimée, blacklist mise à jour, 403 retourné
- `PENDING` → scan en cours (cas d'erreur transitoire)

---

## 2. Prérequis

### Sur la machine hôte (serveur DocDockGo)

- **Docker Engine** ≥ 24 et **Docker Compose** v2
- **Accès NET_ADMIN** (pour iptables dans le conteneur `iptables-redirect`)
- Ports disponibles : `5432`, `3000`–`3005`, `3010`, `3020`, `4000`, `8443`
- Accès internet pour le téléchargement des images GHCR et de la base Trivy

### Clés API requises

| Service | Variable | Où obtenir |
|---|---|---|
| Scanner haut-niveau | `GEMINI_API_KEY` | [Google AI Studio](https://aistudio.google.com) — gratuit (20 req/jour) ou payant |
| LLM Decision + Manager | `OPENROUTER_API_KEY` | [OpenRouter](https://openrouter.ai) — crédit à l'utilisation |

### OIDC (dashboard)

Le dashboard utilise **Zitadel** pour l'authentification. La configuration fournie pointe vers une instance cloud partagée. Pour une instance propre, modifier `dashboard/.env` (voir section 4).

---

## 3. Récupérer la branche test

```bash
git clone git@github.com:Ritsch-Hugo/DocDockGo.git
cd DocDockGo
git checkout test
cd Test/
```

Structure du dossier `Test/` :

```
Test/
├── docker-compose.yml
├── db/
│   └── init.sql                  # Schéma PostgreSQL complet
├── proxy/
│   ├── .env                      # Config proxy (timeouts, limites)
│   ├── certs-mitm/               # CA + certificats par registre
│   └── registry_whitelist.json   # Registres autorisés
├── orchestrateur/
│   └── .env
├── scanner-haut-niveau/
│   └── .env                      # GEMINI_API_KEY ici
├── scanner-compliance/
│   └── .env
├── scanner-static/
│   └── .env
├── mcp-tools-server/
│   └── .env
├── llm-manager/
│   └── .env                      # OPENROUTER_API_KEY ici
├── llm-decision/
│   └── .env
└── dashboard/
    └── .env                      # OIDC + IPs autorisées
```

---

## 4. Configurer les variables d'environnement

### 4.1 Scanner haut-niveau — `scanner-haut-niveau/.env`

```env
GEMINI_API_KEY=AIza...votre_clé_gemini
```

> **Note quota :** Le free tier Gemini est limité à 20 requêtes/jour sur `gemini-2.5-flash`. Au-delà, le scanner retourne 500 et l'orchestrateur passe en PENDING. Utiliser un compte payant en production.

### 4.2 LLM Manager et LLM Decision — `llm-manager/.env` et `llm-decision/.env`

```env
# llm-manager/.env
LLM_BASE_URL=https://openrouter.ai/api
OPENROUTER_API_KEY=sk-or-v1-...votre_clé_openrouter

LLM_WORKER_1=minimax/minimax-m2.7
LLM_WORKER_2=qwen/qwen3.5-35b-a3b
LLM_WORKER_3=google/gemma-4-31b-it
LLM_ARBITER=mistralai/mistral-small-2603
LLM_TIMEOUT_SECS=120
MANAGER_PORT=3003
```

```env
# llm-decision/.env
LLM_BASE_URL=https://openrouter.ai/api
OPENROUTER_API_KEY=sk-or-v1-...votre_clé_openrouter

LLM_WORKER_1=minimax/minimax-m2.7
LLM_WORKER_2=qwen/qwen3.5-35b-a3b
LLM_WORKER_3=google/gemma-4-31b-it
LLM_ARBITER=mistralai/mistral-small-2603
LLM_TIMEOUT_SECS=120

DECISION_PORT=3005
MANAGER_PORT=3003
STARTUP_MAX_RETRIES=24
STARTUP_RETRY_DELAY_SECS=5
MAX_REQUEST_BODY_BYTES=1048576
```

### 4.3 Dashboard — `dashboard/.env`

```env
DATABASE_URL=postgres://docdockgo_admin:docdockgo@localhost:5432/docdockgo

# IPs des machines autorisées à se connecter au dashboard
ALLOWED_IPS="192.168.1.10,192.168.1.20"

# OIDC Zitadel (instance partagée — remplacer pour usage propre)
ZITADEL_ISSUER=https://docdockgo-kgfmnj.eu1.zitadel.cloud
CLIENT_ID=365975639251042712
REDIRECT_URI=http://localhost:3010/callback
POST_LOGOUT_REDIRECT_URI=http://localhost:3010/logged-out

LISTEN_ADDR=0.0.0.0:3010
```

> `ALLOWED_IPS` dans le dashboard contrôle l'accès à l'interface web (couche réseau). Ce n'est pas la même chose que `allowed_ips` dans la table `users` qui contrôle quelles IPs peuvent faire des `docker pull` via le proxy.

### 4.4 Proxy — `proxy/.env`

```env
DATABASE_URL=postgres://docdockgo_admin:docdockgo@localhost:5432/docdockgo

MAX_BLOB_SIZE=2147483648       # 2 Go max par blob
MAX_CONCURRENT_PULLS=200
CONTEXT_TIMEOUT=360            # Durée de vie max d'un contexte de pull (sec)

ORCH_URL=http://127.0.0.1:3000/v1/decision
ORCH_TIMEOUT_SECS=300          # Proxy attend 5 min l'orchestrateur

SHUTDOWN_DRAIN_TIMEOUT_SECS=0
QUARANTINE_BASE=/app/quarantaine
CACHE_BASE=/app/cache
```

### 4.5 Orchestrateur — `orchestrateur/.env`

```env
DATABASE_URL=postgres://docdockgo_admin:docdockgo@postgres:5432/docdockgo
BIND_ADDR=0.0.0.0:3000
HIGH_LEVEL_URL=http://127.0.0.1:4000/v1/high-level
LLM_DECISION_URL=http://127.0.0.1:3005/v1/decision
RUST_LOG=info

QUARANTINE_BASE=../Proxy/quarantaine
CACHE_BASE=../Proxy/cache

HL_TIMEOUT_SECS=60             # Timeout scanner Gemini
LLM_DECISION_TIMEOUT_SECS=270  # Timeout pipeline LLM complet (< ORCH_TIMEOUT_SECS)

HL_ALLOW_THRESHOLD=90          # Score Gemini ≥ 90 → ALLOW direct
HL_DENY_THRESHOLD=30           # Score Gemini < 30 → DENY direct
```

**Hiérarchie des timeouts (à toujours respecter) :**
```
HL_TIMEOUT_SECS(60) < LLM_DECISION_TIMEOUT_SECS(270) < ORCH_TIMEOUT_SECS(300) < CONTEXT_TIMEOUT(360)
```

---

## 5. Installer le CA sur les machines clientes

Le proxy effectue un MITM TLS : chaque machine qui fait des `docker pull` doit faire confiance au CA du proxy, sinon Docker rejettera les certificats.

### Linux (Ubuntu/Debian)

```bash
# Depuis la machine cliente, copier le CA (ou le transférer via scp)
sudo cp /chemin/vers/Test/proxy/certs-mitm/myca.crt \
     /usr/local/share/ca-certificates/docdockgo-ca.crt

sudo update-ca-certificates

# Redémarrer Docker pour qu'il recharge les CA système
sudo systemctl restart docker
```

### Vérification

```bash
# Ce curl doit retourner 200 sans erreur TLS (proxy doit être démarré)
curl -v https://registry-1.docker.io/v2/ 2>&1 | grep "SSL certificate verify"
# Expected: SSL certificate verify ok.
```

---

## 6. Démarrer les services

```bash
cd Test/

# Premier démarrage : télécharge les images et initialise la DB
docker compose up -d

# Vérifier que tous les services sont healthy
docker compose ps
```

**Ordre de démarrage automatique :**
1. `postgres` (healthcheck avant tout)
2. `trivy-db-init` (télécharge la base CVE, ~quelques minutes)
3. `scanner-haut-niveau`, `scanner-compliance`, `scanner-static`
4. `llm-manager`, `mcp-tools-server`
5. `llm-decision`
6. `orchestrateur`
7. `proxy`, `dashboard`, `cycle-de-vie`
8. `iptables-redirect` (redirige port 443 → 8443 sur l'hôte)

> **Premier démarrage :** `trivy-db-init` télécharge ~300 Mo de base CVE. Attendre qu'il se termine (`Exited (0)`) avant de tester.

### Suivre les logs

```bash
# Tous les services
docker compose logs -f

# Pipeline de décision uniquement
docker compose logs -f proxy orchestrateur llm-decision

# Un service spécifique
docker compose logs -f scanner-static
```

### Arrêter les services

```bash
docker compose down          # Arrête les conteneurs (volumes conservés)
docker compose down -v       # Arrête ET supprime tous les volumes (reset complet)
```

---

## 7. Ajouter des utilisateurs autorisés

Le proxy autorise les `docker pull` uniquement depuis des IPs enregistrées dans la table `users`. Un utilisateur correspond à une personne (RSSI ou dev) avec ses IPs de machines.

```bash
# Se connecter à PostgreSQL
PGPASSWORD=docdockgo psql -U docdockgo_admin -d docdockgo -h localhost

# Ajouter un utilisateur RSSI
INSERT INTO users (username, role, allowed_ips, sub)
VALUES ('alice', 'rssi', ARRAY['192.168.1.50'], 'sub_alice_zitadel');

# Ajouter un utilisateur dev avec plusieurs IPs
INSERT INTO users (username, role, allowed_ips, sub)
VALUES ('bob', 'dev', ARRAY['192.168.1.51', '10.0.0.5'], 'sub_bob_zitadel');

# Vérifier
SELECT username, role, allowed_ips FROM users;
```

**Rôles :**
- `rssi` — accès dashboard complet (métriques globales, décisions, alertes CVE)
- `dev` — accès dashboard filtré sur ses propres pulls

> La colonne `sub` correspond au `sub` OIDC Zitadel (identifiant unique de l'utilisateur). Elle peut rester vide tant que l'auth OIDC n'est pas configurée.

---

## 8. Accéder au dashboard

Le dashboard est disponible sur **http://\<hôte\>:3010**.

### Authentification

1. Naviguer vers `http://localhost:3010`
2. Redirection vers Zitadel pour login
3. Après login, retour sur le dashboard

### Vues disponibles

| Vue | Rôle | Contenu |
|---|---|---|
| Vue d'ensemble | RSSI | Métriques globales : pulls totaux, décisions, whitelist/blacklist, alertes CVE |
| Activité | RSSI | Tableau de tous les pulls en temps réel (SSE) |
| Whitelist | RSSI | Images autorisées définitivement |
| Blacklist | RSSI | Images bloquées définitivement |
| Alertes CVE | RSSI | Notifications CVE poussées par cycle-de-vie |
| Vue d'ensemble | Dev | Métriques sur ses propres pulls |

### Temps réel

Le dashboard se met à jour automatiquement via **Server-Sent Events** (SSE). Chaque INSERT/UPDATE en base de données déclenche une notification PostgreSQL → SSE → UI sans rechargement de page.

---

## 9. Tester un pull Docker

### Depuis une machine cliente (avec le CA installé)

```bash
# Pull simple
docker pull alpine:latest

# Pull depuis ghcr.io
docker pull ghcr.io/library/nginx:latest

# Pull depuis quay.io
docker pull quay.io/prometheus/prometheus:latest
```

### Depuis la même machine que le serveur DocDockGo

Le service `iptables-redirect` configure automatiquement la redirection `PREROUTING` (trafic entrant). Pour le trafic sortant de l'hôte lui-même, ajouter en plus :

```bash
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 \
  -d registry-1.docker.io -j REDIRECT --to-port 8443
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 \
  -d ghcr.io -j REDIRECT --to-port 8443
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 \
  -d quay.io -j REDIRECT --to-port 8443
```

> Supprimer après le test : `sudo iptables -t nat -F OUTPUT`

### Observer la décision en temps réel

```bash
docker compose logs -f proxy orchestrateur llm-decision
```

**Indicateurs clés dans les logs :**

```
proxy      | [SCAN FINAL] lancement pour uuid=...     ← scan final déclenché
llm-decision | Lancement des 3 workers en parallèle... ← analyse LLM
llm-decision | Décision arbitre : static=true ...      ← résultat arbitre
scanner-static | scan complete ... total=0 critical=0  ← 0 CVE trouvés
orchestrateur | Décision retournée au proxy: state=ALLOW ← décision finale
proxy      | [ALLOW] Image autorisée                  ← image servie
```

---

## 10. Comprendre le cycle de vie d'un pull

### Phase 1 — HEAD (analyse préliminaire rapide)

```
docker pull alpine:latest
  └─ HEAD /v2/library/alpine/manifests/latest
       └─ Proxy → Orchestrateur → Scanner haut-niveau (Gemini)
            score ≥ 90 : ALLOW direct (pas de scan complet)
            score < 30 : DENY (403 au client)
            sinon      : PENDING → le pull continue vers la phase 2
```

### Phase 2 — GET + blobs (scan complet)

```
GET /v2/library/alpine/manifests/sha256:<digest>
  └─ Proxy préfetch tous les blobs → quarantaine/
       └─ Proxy → Orchestrateur (multipart : context + fichiers)
            └─ LLM Decision pipeline :
                 1. 3 workers LLM analysent l'image en parallèle (~2 min)
                 2. Scans CVE (Trivy) + Compliance (règles OCI) via MCP
                 3. 3 workers LLM analysent les résultats de scan
                 4. Arbitre consolide → ALLOW / DENY
            └─ ALLOW : quarantaine → cache, whitelist mise à jour, 200 au client
            └─ DENY  : quarantaine supprimée, blacklist mise à jour, 403 au client
```

### Durée typique

| Étape | Durée |
|---|---|
| Phase 1 (Gemini) | 1–3 secondes |
| Phase 2 workers LLM (×2) | ~2 minutes chacune |
| Scans CVE + compliance | < 1 seconde |
| **Total (image inconnue)** | **~5 minutes** |

> Le client Docker attend le résultat pendant toute cette durée. La connexion TCP reste ouverte.

### Cache et whitelist

Une fois une image ALLOWée, elle est mise en **whitelist** (registry + repo + tag). Les pulls suivants du même tag sont servis depuis le **cache** sans re-scan, instantanément.

---

## 11. Commandes utiles

### Reset BDD + volumes (garder les utilisateurs)

```bash
PGPASSWORD=docdockgo psql -U docdockgo_admin -d docdockgo -h localhost \
  -c "TRUNCATE pulls, pull_digests, scan_events, ia_decisions, whitelist, blacklist,
      cache, quarantine, sboms, cve_notifications CASCADE;"

docker run --rm \
  -v test_quarantaine:/q \
  -v test_cache:/c \
  alpine sh -c "rm -rf /q/* /c/*"
```

### Forcer un re-scan d'une image whitelistée

```bash
PGPASSWORD=docdockgo psql -U docdockgo_admin -d docdockgo -h localhost \
  -c "DELETE FROM whitelist WHERE registry='registry-1.docker.io'
      AND repository='library/alpine' AND tag='latest';"
```

### Inspecter les décisions LLM

```bash
PGPASSWORD=docdockgo psql -U docdockgo_admin -d docdockgo -h localhost \
  -c "SELECT p.repository, p.tag, p.decision_final, i.decision,
             i.static_scan, i.compliance_scan, i.confidence
      FROM ia_decisions i JOIN pulls p ON p.uuid = i.pull_id
      ORDER BY i.created_at DESC LIMIT 10;"
```

### Accéder à Adminer (UI BDD)

```bash
docker compose --profile tools up -d adminer
# puis ouvrir http://localhost:8080
# Serveur: localhost | User: docdockgo_admin | Mot de passe: docdockgo | DB: docdockgo
```

### Redémarrer un service après changement de .env

```bash
docker compose up -d --force-recreate proxy orchestrateur
```

---

## 12. Ajouter un nouveau registre

Pour supporter un registre non listé (ex: `myregistry.company.com`) :

### 1. Générer un certificat signé par le CA du proxy

```bash
cd Test/proxy/certs-mitm/

# Générer la clé et le CSR
openssl genrsa -out myregistry.company.com.key 2048
openssl req -new -key myregistry.company.com.key \
  -out myregistry.company.com.csr \
  -subj "/CN=myregistry.company.com"

# Signer avec le CA du proxy
openssl x509 -req -in myregistry.company.com.csr \
  -CA myca.crt -CAkey myca.key -CAcreateserial \
  -out myregistry.company.com.crt -days 825 \
  -extfile <(printf "subjectAltName=DNS:myregistry.company.com")
```

### 2. Ajouter à la whitelist

```bash
# proxy/registry_whitelist.json
[
  "registry-1.docker.io",
  "ghcr.io",
  "quay.io",
  "myregistry.company.com"
]
```

### 3. Redémarrer le proxy

```bash
docker compose up -d --force-recreate proxy
```

---

## 13. Dépannage

### Le pull reste PENDING indéfiniment

**Cause probable :** timeout entre le proxy et l'orchestrateur trop court par rapport à la durée du pipeline LLM.

Vérifier la hiérarchie des timeouts dans `proxy/.env` et `orchestrateur/.env` :
```
HL_TIMEOUT_SECS < LLM_DECISION_TIMEOUT_SECS < ORCH_TIMEOUT_SECS < CONTEXT_TIMEOUT
```

### Le scanner haut-niveau retourne 500

**Cause probable :** quota Gemini épuisé (free tier : 20 req/jour).

```bash
docker compose logs scanner-haut-niveau
# Chercher : "429 Too Many Requests" ou "RESOURCE_EXHAUSTED"
```

**Solution :** utiliser une clé API payante, ou attendre le reset quotidien (minuit heure du Pacifique).

### TLS error / x509 certificate signed by unknown authority

Le CA n'est pas installé sur la machine cliente, ou Docker n'a pas été redémarré après l'installation.

```bash
sudo cp proxy/certs-mitm/myca.crt /usr/local/share/ca-certificates/docdockgo-ca.crt
sudo update-ca-certificates
sudo systemctl restart docker
```

### IP non autorisée (403 du proxy)

L'IP de la machine cliente n'est pas dans `allowed_ips` d'un utilisateur en base.

```bash
# Vérifier l'IP du client dans les logs
docker compose logs proxy | grep "IP non autorisée"

# Ajouter l'IP
PGPASSWORD=docdockgo psql -U docdockgo_admin -d docdockgo -h localhost \
  -c "UPDATE users SET allowed_ips = allowed_ips || ARRAY['192.168.1.XX']
      WHERE username = 'mon_user';"
```

### Trivy ne démarre pas / scanner-static en erreur

La base CVE Trivy n'est pas encore téléchargée. Attendre que `trivy-db-init` termine :

```bash
docker compose logs trivy-db-init
# Attendre "Exited (0)" dans docker compose ps
```

### Le dashboard ne se met pas à jour en temps réel

Vérifier que le trigger PostgreSQL est actif :

```bash
PGPASSWORD=docdockgo psql -U docdockgo_admin -d docdockgo -h localhost \
  -c "SELECT trigger_name, event_object_table FROM information_schema.triggers
      WHERE trigger_name LIKE 'trg_notify%';"
```

Si vide, ré-appliquer `db/init.sql` ou exécuter manuellement les triggers manquants.
