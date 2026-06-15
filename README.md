# DocDockGo — Environnement de test (docker compose)


### Pour le Deployment en production via Kubernetes veuillez suivre le fichier INSTALLATION.md dans le dossier k8s/


---


## 1. Prérequis

- Docker + Docker Compose
- PostgreSQL local sur `127.0.0.1:5432` avec la DB `docdockgo` et l'utilisateur `docdockgo_admin`
- CA du proxy installé et Docker redémarré (voir section Test)

---

## 2. Clonage du dépôt

```bash
git clone <url-du-dépôt> DocDockGo
cd DocDockGo/k8s
```

---

## 3. Clés API requises

Avant de commencer, obtenir :

| Clé | Où l'obtenir | Usage |
|---|---|---|
| `GEMINI_API_KEY` | [Google AI Studio](https://aistudio.google.com/) | Scanner haut-niveau (HL Scan) |
| `OPENROUTER_API_KEY` | [OpenRouter](https://openrouter.ai/) | LLM Decision (analyse multi-modèles) |
| OIDC issuer + clientId | Zitadel, Keycloak, ou autre IdP | Authentification dashboard |

---

## 4. Variables d'environnement

Il faut ajouter manuellement les variables d'environement pour chaques services directement dans leurs dossier. Il y a aussi le .env global present a la racine. Chaques dossiers qui doivent contenir leur fichier .env on un .env.exemple pour aider à remplir. La documentation des exemples .env se trouve aussi dans le fichier exemple_var_env.md.

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
---


## 6. Démarrage / Arrêt

### 6.1 Démarrer les services 

```bash
docker compose up -d
```

### 6.2 Arrêter les services

```bash
docker compose down
```

### 6.3 Suivre les logs en live

```bash
docker compose logs -f
# ou un service spécifique :
docker compose logs -f proxy
```

---

## 7. Services et ports

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

## 8. Tester un pull Docker via le proxy

### 8.1 Confiance en le CA sur les clients

Sur **chaque machine** qui effectuera des `docker pull` ou `podman pull` via DocDockGo :

Mettre le certificat CA sur la machine client pour que celle ci fasse confiance au proxy

```bash
sudo cp myca.crt /usr/local/share/ca-certificates/docdockgo-ca.crt
sudo update-ca-certificates
sudo systemctl restart docker   # si Docker
```

### 8.2 Configurer Docker pour passer par le proxy

Pointer Docker vers le proxy en ajoutant l'IP du nœud k3s dans `/etc/hosts` :
Le fichier doit ressembler a ça : 

```bash
<ip-proxy> registry-1.docker.io
<ip-proxy> ghcr.io
<ip-proxy> quay.io
...
```


### 8.3 Enregistrer le premier utilisateur

L'accès au dashboard est géré via OIDC (Zitadel, Keycloak…). La table `users` est alimentée automatiquement lors du premier login OIDC — **il n'est pas nécessaire d'insérer manuellement un utilisateur**.

Se connecter une première fois sur `http://localhost:3010` depuis le nœud k3s pour déclencher la création du compte en base.

Pour mettre à jour les IPs autorisées d'un utilisateur **après son premier login** :

```bash
kubectl exec -n docdockgo postgres-0 -- psql -U docdockgo_admin -d docdockgo \
  -c "UPDATE users SET allowed_ips = ARRAY['<ip-client>'] WHERE username = '<username>';"
```

### 8.4 Lancer un pull

```bash
docker pull hello-world
```

Les logs du proxy montrent le pull en temps réel :

```bash
docker compose logs -f proxy orchestrateur llm-decision
```
---

## 9. Registries supportés

Définis dans `proxy/registry_whitelist.json` et couverts par les certificats dans `proxy/certs-mitm/` :

- `registry-1.docker.io` (Docker Hub)
- `ghcr.io` (GitHub Container Registry)
- `quay.io`

---
