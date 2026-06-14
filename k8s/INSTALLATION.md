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
| 30010/tcp | Dashboard web (redirigé vers le NodePort) |
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
kubectl get nodes
# NAME   STATUS   ROLES           AGE   VERSION
# ...    Ready    control-plane   ...   v1.35.x+k3s1
```

Copier la kubeconfig pour l'utilisateur courant :

```bash
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
```

> **Important** : cette étape est indispensable. Sans elle, `kubectl` ne fonctionnera pas sans `sudo`, et les scripts qui utilisent `kubectl` en `sudo` échoueront avec `connection refused` sur `localhost:8080`.

### Helm

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## 4. Clonage du dépôt

```bash
git clone <url-du-dépôt> DocDockGo
cd DocDockGo/k8s
```

---

## 5. Génération des certificats TLS MITM

Le proxy effectue du TLS MITM : il faut une CA personnelle et un certificat par registre intercepté.  
Les registres par défaut sont : `registry-1.docker.io`, `ghcr.io`, `quay.io`.

### 5.1 Créer le dossier des certificats

```bash
mkdir -p ../proxy/certs-mitm
cd ../proxy/certs-mitm
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

Revenir dans `k8s/` :

```bash
cd ../k8s
```

---

## 6. Création du Secret Kubernetes des certificats

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

Copier le fichier exemple et le remplir :

```bash
cp docdockgo/values-secret.yaml.example values-secret.yaml
```

Éditer `values-secret.yaml` :

```yaml
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
    redirectUri: "http://localhost:30010/callback"
    postLogoutRedirectUri: "http://localhost:30010/logged-out"
```

> **Note** : les `redirectUri` utilisent `localhost:3010` — ne pas mettre d'IP réseau ici. Vérifier que les mêmes URIs sont configurées dans votre IdP (Zitadel).

> **Sécurité** : `values-secret.yaml` est dans `.gitignore`. Ne jamais le committer.

---

## 9. Déploiement Helm

### 9.1 Premier déploiement

```bash
helm install docdockgo ./docdockgo \
  -n docdockgo \
  -f docdockgo/values.yaml \
  -f values-secret.yaml
```

> **Si le release existe déjà** (erreur `cannot re-use a name that is still in use`), utiliser `upgrade` à la place :
> ```bash
> helm upgrade docdockgo ./docdockgo \
>   -n docdockgo \
>   -f docdockgo/values.yaml \
>   -f values-secret.yaml
> ```

### 9.2 Attendre que tous les pods soient prêts

Le job `trivy-db-init` télécharge la base de données Trivy — cela peut prendre 2 à 5 minutes selon la connexion.

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

> **Si `scanner-static` reste en `Pending`** : le PVC `trivy-db` est peut-être bloqué en `Terminating`. Forcer la suppression puis redémarrer :
> ```bash
> kubectl patch pvc trivy-db -n docdockgo -p '{"metadata":{"finalizers":null}}'
> kubectl rollout restart deployment/scanner-static -n docdockgo
> ```

> **Rappel** : par défaut kubectl cible le namespace `default`. Toujours ajouter `-n docdockgo` ou définir le namespace par défaut une fois pour toutes :
> ```bash
> kubectl config set-context --current --namespace=docdockgo
> ```

---

## 10. Configuration iptables

Le proxy écoute sur le NodePort 30443. Il faut rediriger les ports système 443 (Docker/Podman) et 3010 (dashboard) vers ce NodePort.

### 10.1 Appliquer les règles

```bash
sudo KUBECONFIG=$HOME/.kube/config bash scripts/setup-iptables.sh
```

Ce script :
- Récupère automatiquement l'IP courante du pod proxy
- Ajoute une règle DNAT `443 → <ip-pod>:8443` (clients externes uniquement)
- Exclut le réseau pods k3s `10.42.0.0/16` pour éviter les boucles

### 10.2 Rendre les règles persistantes au reboot

```bash
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

> **Important** : si le pod proxy redémarre, son IP change. Relancer les étapes 10.1 et 10.2.

---

## 11. Confiance en le CA sur les clients

Sur **chaque machine** qui effectuera des `docker pull` ou `podman pull` via DocDockGo :

### Ubuntu / Debian

Mettre le certificat CA sur la machine client pour que celle ci fasse confiance au proxy

```bash
sudo cp myca.crt /usr/local/share/ca-certificates/docdockgo-ca.crt
sudo update-ca-certificates
sudo systemctl restart docker   # si Docker
```

### Configurer Docker pour passer par le proxy

Pointer Docker vers le proxy en ajoutant l'IP du nœud k3s dans `/etc/hosts` :
Le fichier doit ressembler a ça : 

```bash
<ip-noeud-k3s> registry-1.docker.io
<ip-noeud-k3s> ghcr.io
<ip-noeud-k3s> quay.io
...
```


### Enregistrer le premier utilisateur

L'accès au dashboard est géré via OIDC (Zitadel, Keycloak…). La table `users` est alimentée automatiquement lors du premier login OIDC — **il n'est pas nécessaire d'insérer manuellement un utilisateur**.

Se connecter une première fois sur `http://localhost:30010` depuis le nœud k3s pour déclencher la création du compte en base.

Pour mettre à jour les IPs autorisées d'un utilisateur **après son premier login** :

```bash
kubectl exec -n docdockgo postgres-0 -- psql -U docdockgo_admin -d docdockgo \
  -c "UPDATE users SET allowed_ips = ARRAY['<ip-client>'] WHERE username = '<username>';"
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

### Accéder au dashboard

Ouvrir `http://localhost:30010` dans un navigateur depuis le nœud k3s.

Le dashboard affiche :
- Historique des pulls (ALLOW / DENY / PENDING)
- Détail des scans par image (score LLM, findings compliance, CVEs)
- Whitelist / blacklist
- Statistiques

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

### Accéder à la base de données (Adminer ou psql)

PostgreSQL est exposé en ClusterIP uniquement. Pour y accéder depuis l'extérieur du cluster, utiliser un port-forward :

```bash
kubectl port-forward -n docdockgo svc/postgres 5432:5432
```

Puis se connecter avec :
- Serveur : `127.0.0.1`
- Port : `5432`
- Utilisateur : `docdockgo_admin`
- Mot de passe : (celui défini dans `values-secret.yaml`)
- Base de données : `docdockgo`

---

## 14. Ajouter un nouveau registre

Exemple : ajouter `mon-registre.example.com`.

### 14.1 Générer le certificat

```bash
cd proxy/certs-mitm
REGISTRY="mon-registre.example.com"

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

Éditer `k8s/docdockgo/files/registry_whitelist.json` :

```json
[
  "registry-1.docker.io",
  "ghcr.io",
  "quay.io",
  "mon-registre.example.com"
]
```

### 14.3 Mettre à jour le Secret et redéployer

```bash
cd k8s
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
sudo KUBECONFIG=$HOME/.kube/config bash scripts/setup-iptables.sh
sudo netfilter-persistent save
```

### Mettre à jour le chart Helm

```bash
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
