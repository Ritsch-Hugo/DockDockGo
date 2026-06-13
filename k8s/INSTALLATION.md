# DocDockGo — Guide d'installation et d'utilisation (k3s)

> Installation complète depuis zéro sur un nœud Ubuntu avec k3s.  
> Validé sur : Ubuntu 24.04 LTS, k3s v1.35.5, Helm v3.21.0.

---

## Table des matières

1. [Prérequis](#1-prérequis)
2. [Clés API requises](#2-clés-api-requises)
3. [Installation de k3s et Helm](#3-installation-de-k3s-et-helm)
4. [Clonage du dépôt](#4-clonage-du-dépôt)
5. [Génération des certificats TLS MITM](#5-génération-des-certificats-tls-mitm)
6. [Création du Secret Kubernetes des certificats](#6-création-du-secret-kubernetes-des-certificats)
7. [Préparation des volumes](#7-préparation-des-volumes)
8. [Configuration des valeurs secrètes](#8-configuration-des-valeurs-secrètes)
9. [Déploiement Helm](#9-déploiement-helm)
10. [Configuration iptables](#10-configuration-iptables)
11. [Confiance en le CA sur les clients](#11-confiance-en-le-ca-sur-les-clients)
12. [Vérification du déploiement](#12-vérification-du-déploiement)
13. [Utilisation](#13-utilisation)
14. [Ajouter un nouveau registre](#14-ajouter-un-nouveau-registre)
15. [Maintenance](#15-maintenance)

---

## 1. Prérequis

### Matériel (nœud k3s)

| Ressource | Minimum recommandé |
|---|---|
| CPU | 4 cœurs |
| RAM | 8 Go |
| Disque | 100 Go libres (quarantaine 50 Go + cache 20 Go + OS) |

### Logiciels à installer sur le nœud

- Ubuntu 22.04 ou 24.04 LTS
- `curl`, `openssl`, `git`
- `iptables-persistent` (pour la persistance des règles réseau)

### Ports réseau à ouvrir sur le nœud

| Port | Usage |
|---|---|
| 443/tcp | Interception des pulls Docker/Podman (redirigé vers le proxy) |
| 3010/tcp | Dashboard web (redirigé vers le NodePort) |
| 6443/tcp | API Kubernetes (optionnel, pour kubectl distant) |

---

## 2. Clés API requises

Avant de commencer, obtenir :

| Clé | Où l'obtenir | Usage |
|---|---|---|
| `GEMINI_API_KEY` | [Google AI Studio](https://aistudio.google.com/) | Scanner haut-niveau (HL Scan) |
| `OPENROUTER_API_KEY` | [OpenRouter](https://openrouter.ai/) | LLM Decision (analyse multi-modèles) |
| OIDC issuer + clientId | Zitadel, Keycloak, ou autre IdP | Authentification dashboard |

---

## 3. Installation de k3s et Helm

### k3s (single-node)

```bash
curl -sfL https://get.k3s.io | sh -
```

Vérifier que le nœud est prêt :

```bash
sudo kubectl get nodes
# NAME   STATUS   ROLES           AGE   VERSION
# ...    Ready    control-plane   ...   v1.35.x+k3s1
```

Copier la kubeconfig pour l'utilisateur courant :

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
```

### Helm

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## 4. Clonage du dépôt

```bash
git clone <url-du-dépôt> DocDockGo
cd DocDockGo/Test/k8s
```

---

## 5. Génération des certificats TLS MITM

Le proxy effectue du TLS MITM : il faut une CA personnelle et un certificat par registre intercepté.  
Les registres par défaut sont : `registry-1.docker.io`, `ghcr.io`, `quay.io`.

### 5.1 Créer le dossier des certificats

```bash
mkdir -p ../../proxy/certs-mitm
cd ../../proxy/certs-mitm
```

### 5.2 Générer la CA racine

```bash
openssl genrsa -out myca.key 4096
openssl req -new -x509 -days 3650 -key myca.key -out myca.crt \
  -subj "/CN=DocDockGo CA/O=DocDockGo"
```

### 5.3 Générer un certificat par registre

Répéter pour chaque registre (`registry-1.docker.io`, `ghcr.io`, `quay.io`) :

```bash
REGISTRY="registry-1.docker.io"

# Fichier de config openssl
cat > ${REGISTRY}.cnf <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = ${REGISTRY}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${REGISTRY}
EOF

# Clé + CSR + signature
openssl genrsa -out ${REGISTRY}.key 4096
openssl req -new -key ${REGISTRY}.key -out ${REGISTRY}.csr -config ${REGISTRY}.cnf
openssl x509 -req -in ${REGISTRY}.csr -CA myca.crt -CAkey myca.key \
  -CAcreateserial -out ${REGISTRY}.crt -days 825 \
  -extfile ${REGISTRY}.cnf -extensions req_ext
```

### 5.4 Résultat attendu dans `certs-mitm/`

```
myca.crt
myca.key
registry-1.docker.io.crt
registry-1.docker.io.key
ghcr.io.crt
ghcr.io.key
quay.io.crt
quay.io.key
```

Revenir dans `Test/k8s/` :

```bash
cd ../../Test/k8s
```

---

## 6. Création du Secret Kubernetes des certificats

Ce script lit le dossier `certs-mitm` et crée le Secret `proxy-certs` dans le namespace `docdockgo` :

```bash
kubectl create namespace docdockgo --dry-run=client -o yaml | kubectl apply -f -
bash scripts/create-certs-secret.sh docdockgo
```

---

## 7. Préparation des volumes

### 7.1 Créer les répertoires hostPath sur le nœud

```bash
sudo mkdir -p /data/docdockgo/quarantaine /data/docdockgo/cache
```

### 7.2 Fixer les permissions pour l'utilisateur applicatif (UID 10001)

```bash
sudo chown -R 10001:10001 /data/docdockgo/quarantaine /data/docdockgo/cache
```

---

## 8. Configuration des valeurs secrètes

Créer le fichier `values-secret.yaml` (jamais commité, déjà dans `.gitignore`) :

```bash
cat > values-secret.yaml <<'EOF'
postgres:
  credentials:
    password: <mot-de-passe-fort>

scannerHautNiveau:
  geminiApiKey: "<votre-clé-gemini>"

llmManager:
  openrouterApiKey: "<votre-clé-openrouter>"

dashboard:
  config:
    # IPs autorisées à accéder au dashboard (séparées par virgule)
    allowedIps: "127.0.0.1,<votre-ip>"
  oidc:
    issuer: "<url-issuer-oidc>"
    clientId: "<client-id-oidc>"
    redirectUri: "http://<ip-noeud>:3010/callback"
    postLogoutRedirectUri: "http://<ip-noeud>:3010/logged-out"
EOF
```

---

## 9. Déploiement Helm

```bash
cd Test/k8s   # si pas déjà dans ce dossier

helm install docdockgo ./docdockgo \
  -n docdockgo \
  -f docdockgo/values.yaml \
  -f values-secret.yaml
```

Attendre que tous les pods soient prêts (le job `trivy-db-init` peut prendre 2-5 minutes) :

```bash
kubectl get pods -n docdockgo -w
```

État attendu :

```
NAME                                   READY   STATUS      RESTARTS
cycle-de-vie-...                       1/1     Running     0
dashboard-...                          1/1     Running     0
llm-decision-...                       2/2     Running     0    ← 2 conteneurs (+ sidecar mcp)
llm-manager-...                        1/1     Running     0
mcp-tools-server-...                   1/1     Running     0
orchestrateur-...                      1/1     Running     0
postgres-0                             1/1     Running     0
proxy-...                              1/1     Running     0
scanner-compliance-...                 1/1     Running     0
scanner-haut-niveau-...                1/1     Running     0
scanner-static-...                     1/1     Running     0
trivy-db-init-...                      0/1     Completed   0
```

---

## 10. Configuration iptables

Le proxy écoute sur le NodePort 30443. Il faut rediriger les ports système 443 (Docker/Podman) et 3010 (dashboard) vers ces NodePorts.

### 10.1 Appliquer les règles

```bash
sudo bash scripts/setup-iptables.sh
```

Ce script :
- Récupère automatiquement l'IP courante du pod proxy
- Ajoute une règle DNAT `443 → <ip-pod>:8443` (clients externes uniquement)
- Exclut le réseau pods k3s `10.42.0.0/16` pour éviter les boucles
- Redirige `3010 → 30010` pour le dashboard

### 10.2 Rendre les règles persistantes au reboot

```bash
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

> **Important** : si le pod proxy redémarre, son IP change. Relancer `sudo bash scripts/setup-iptables.sh` puis `sudo netfilter-persistent save`.

---

## 11. Confiance en le CA sur les clients

Sur **chaque machine** qui effectuera des `docker pull` ou `podman pull` via DocDockGo :

### Ubuntu / Debian

```bash
# Copier myca.crt depuis le nœud k3s (ou le dépôt)
sudo cp myca.crt /usr/local/share/ca-certificates/docdockgo-ca.crt
sudo update-ca-certificates
sudo systemctl restart docker   # si Docker
```

### Configurer le registre Docker pour utiliser le proxy

Créer ou modifier `/etc/docker/daemon.json` :

```json
{
  "insecure-registries": [],
  "registry-mirrors": []
}
```

Pointer Docker vers le proxy en configurant `/etc/hosts` ou le DNS pour que `registry-1.docker.io` resolve vers l'IP du nœud k3s :

```bash
echo "<ip-noeud-k3s>  registry-1.docker.io" | sudo tee -a /etc/hosts
```

Alternativement, configurer les clients pour utiliser le proxy HTTPS :

```bash
# Pour Docker
sudo mkdir -p /etc/systemd/system/docker.service.d
cat | sudo tee /etc/systemd/system/docker.service.d/proxy.conf <<EOF
[Service]
Environment="HTTPS_PROXY=https://<ip-noeud-k3s>:443"
EOF
sudo systemctl daemon-reload && sudo systemctl restart docker
```

### Ajouter l'IP du client dans la base DocDockGo

Le proxy n'autorise que les IPs enregistrées dans la table `users`. Se connecter à PostgreSQL depuis le nœud k3s :

```bash
kubectl exec -n docdockgo postgres-0 -- psql -U docdockgo_admin -d docdockgo \
  -c "INSERT INTO users (ip, label) VALUES ('<ip-client>', 'nom-machine') ON CONFLICT DO NOTHING;"
```

---

## 12. Vérification du déploiement

### Vérifier les logs du proxy

```bash
kubectl logs -n docdockgo -l app=proxy --tail=30
```

Doit afficher :
```
[TLS] Certificat chargé pour registry-1.docker.io
[TLS] Certificat chargé pour ghcr.io
[TLS] Certificat chargé pour quay.io
[DB] Connecté à PostgreSQL
✅ MITM Docker registry en écoute sur https://registry-1.docker.io:443
```

### Vérifier l'orchestrateur

```bash
kubectl logs -n docdockgo -l app=orchestrateur --tail=20
```

### Vérifier llm-decision

```bash
kubectl logs -n docdockgo -l app=llm-decision -c llm-decision --tail=20
```

Doit afficher :
```
MCP tools chargés avec succès (3 tools)
  - run_compliance_scan
  - run_dynamic_scan
  - run_static_scan
llm-decision en écoute sur http://0.0.0.0:3005
```

---

## 13. Utilisation

### Effectuer un pull sécurisé

Depuis un client configuré :

```bash
docker pull alpine:latest
# ou
podman pull alpine:latest
```

#### Comportement attendu

1. **Premier pull** d'une image inconnue :
   - Le proxy retourne `403 Image en cours de scan` (état PENDING)
   - Les scanners s'exécutent en arrière-plan (compliance + LLM multi-modèles)
   - Si l'image est ALLOW : elle est mise en cache et ajoutée à la whitelist
   - **Relancer le pull** quelques secondes/minutes plus tard pour obtenir l'image depuis le cache

2. **Pull d'une image déjà en whitelist** :
   - Servi immédiatement depuis le cache (pas de nouveau scan)

3. **Image DENY** :
   - `403 Image refusée` — l'image est blacklistée, les pulls ultérieurs seront refusés directement

### Consulter le dashboard

Ouvrir `http://<ip-noeud>:3010` dans un navigateur depuis une IP autorisée.

Le dashboard affiche :
- Historique des pulls (ALLOW / DENY / PENDING)
- Détail des scans par image (score LLM, findings compliance, CVEs)
- Whitelist / blacklist
- Statistiques

### Consulter les décisions en base

```bash
kubectl exec -n docdockgo postgres-0 -- psql -U docdockgo_admin -d docdockgo \
  -c "SELECT registry, repository, tag, decision_final, created_at FROM pulls ORDER BY created_at DESC LIMIT 10;"
```

### Gérer la whitelist manuellement

```bash
# Ajouter une image à la whitelist sans scan
kubectl exec -n docdockgo postgres-0 -- psql -U docdockgo_admin -d docdockgo \
  -c "INSERT INTO whitelist (registry, repository, tag) VALUES ('registry-1.docker.io', 'library/alpine', 'latest');"

# Supprimer de la blacklist
kubectl exec -n docdockgo postgres-0 -- psql -U docdockgo_admin -d docdockgo \
  -c "DELETE FROM blacklist WHERE registry='registry-1.docker.io' AND repository='library/alpine';"
```

---

## 14. Ajouter un nouveau registre

Exemple : ajouter `quay.io` si absent.

### 14.1 Générer le certificat

```bash
cd proxy/certs-mitm
REGISTRY="quay.io"

cat > ${REGISTRY}.cnf <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = ${REGISTRY}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${REGISTRY}
EOF

openssl genrsa -out ${REGISTRY}.key 4096
openssl req -new -key ${REGISTRY}.key -out ${REGISTRY}.csr -config ${REGISTRY}.cnf
openssl x509 -req -in ${REGISTRY}.csr -CA myca.crt -CAkey myca.key \
  -CAcreateserial -out ${REGISTRY}.crt -days 825 \
  -extfile ${REGISTRY}.cnf -extensions req_ext
```

### 14.2 Ajouter au whitelist du proxy

Éditer `Test/k8s/docdockgo/files/registry_whitelist.json` :

```json
[
  "registry-1.docker.io",
  "ghcr.io",
  "quay.io",
  "mon-nouveau-registre.example.com"
]
```

### 14.3 Mettre à jour le Secret et redéployer

```bash
cd Test/k8s
bash scripts/create-certs-secret.sh docdockgo

helm upgrade docdockgo ./docdockgo \
  -n docdockgo \
  -f docdockgo/values.yaml \
  -f values-secret.yaml
```

---

## 15. Maintenance

### Mettre à jour les règles iptables après redémarrage du pod proxy

```bash
sudo bash Test/k8s/scripts/setup-iptables.sh
sudo netfilter-persistent save
```

### Mettre à jour le chart Helm

```bash
cd Test/k8s
helm upgrade docdockgo ./docdockgo \
  -n docdockgo \
  -f docdockgo/values.yaml \
  -f values-secret.yaml
```

### Vider la quarantaine (fichiers en attente de scan)

```bash
sudo rm -rf /data/docdockgo/quarantaine/*
```

### Réinitialiser la base de données

```bash
kubectl exec -n docdockgo postgres-0 -- psql -U docdockgo_admin -d docdockgo \
  -c "TRUNCATE pulls, pull_digests, whitelist, blacklist, cache, quarantine, ia_decisions, scan_events RESTART IDENTITY CASCADE;"
```

### Vérifier l'espace disque

```bash
df -h /data/docdockgo/quarantaine /data/docdockgo/cache
```

### Logs en temps réel de tous les composants

```bash
kubectl logs -n docdockgo -l app=proxy -f &
kubectl logs -n docdockgo -l app=orchestrateur -f &
kubectl logs -n docdockgo -l app=llm-decision -c llm-decision -f &
```
