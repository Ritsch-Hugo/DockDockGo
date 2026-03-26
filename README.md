# 🛡️ DockDockGo - Proxy MITM Docker/Podman

Proxy MITM TLS pour intercepter et analyser les pulls Docker/Podman **en temps réel**

---

## 🎯 Objectif

DockDockGo s'intercale de manière transparente entre le client Docker/Podman et les registres OCI distants (Docker Hub, GHCR, Quay.io...).

Il permet de :

* Intercepter chaque pull d'image en TLS (port 443)
* Mettre en quarantaine les fichiers téléchargés (manifests, blobs, referrers)
* Soumettre les artefacts à un scan de sécurité
* Autoriser ou bloquer le pull selon la décision du scanner
* Maintenir un cache local des images approuvées
* Gérer une whitelist/blacklist persistante en base PostgreSQL
* Journaliser l'ensemble des événements en base de données en temps réel

---

## ⚙️ Fonctionnement

1. **HEAD** — Le proxy intercepte la première requête, crée un `PullContext` (session du pull courant) et appelle le **scanner de haut niveau**
2. **GET manifests/blobs/referrers** — Comporement defini en fonction de si l'image est presente en cache, whitelist ou blacklist | Si client Podman on crée le `PullContext` des le premier GET
3. **Scan final** — Quand tous les digests attendus sont reçus, le proxy déclenche le **scan final** complet
4. **Décision** :
   - `ALLOW` → copie quarantaine → cache, ajout whitelist, réponse 200
   - `DENY` → suppression quarantaine, ajout blacklist, réponse 403
   - `PENDING` → scan toujours en cours côté orchestrateur, réponse 403 temporaire

---

## 🐳 Lancer avec Docker (recommandé)

### 1. Build l'image

```bash
docker build -t docdockgo .
```

### 2. Lancer le container

```bash
docker run \
  --user root \
  -v $(pwd)/registry_whitelist.json:/app/registry_whitelist.json \
  -v $(pwd)/certs-mitm:/app/certs-mitm \
  -e DATABASE_URL=postgres://docdockgo_admin:docdockgo@172.17.0.1:5432/docdockgo \
  -p 443:443 \
  ghcr.io/ritsch-hugo/docdockgo:latest
```

> ⚠️ `--user root` est requis car le proxy écoute sur le port 443 (port privilégié < 1024).
> `172.17.0.1` correspond à l'IP de l'hôte pour la base de donnée
> `registry_whitelist.json` doit etre ajouté a la racine du projet et doit contenir le json qui indique les registres autorisés

---

## 🔐 Gestion des certificats MITM

Le proxy présente un certificat TLS signé par sa propre CA pour chaque registre intercepté. Le client doit faire confiance à cette CA.
Le certificat **myca.crt** (signé par le proxy MITM) doit etre placé dans le dossier client **/usr/local/share/ca-certificate** 

### Ajouter un nouveau registre

Exemple avec quay.io

```bash
cd certs-mitm/

# 1. Générer la clé privée
openssl genrsa -out quay.io.key 2048

# 2. Générer le CSR (Certificate Signing Request)
openssl req -new -key quay.io.key -out quay.io.csr -subj "/CN=quay.io"

# 3. Signer avec la CA du proxy
openssl x509 -req -in quay.io.csr -CA myca.crt -CAkey myca.key \
  -CAcreateserial -out quay.io.crt -days 3650 \
  -extfile <(printf "subjectAltName=DNS:quay.io")
```

### Déclarer le registre comme autorisé

Ajouter le domaine dans `registry_whitelist.json` :

```json
[
  "registry-1.docker.io",
  "ghcr.io",
  "quay.io"
]
```

> Un certificat `.crt` et `.key` doivent exister dans `certs-mitm/` pour chaque registre déclaré.

---

## 🗄️ Base de données PostgreSQL

Le proxy utilise PostgreSQL pour journaliser les pulls et maintenir les listes de contrôle.

### Connexion

```bash
psql -U docdockgo_admin -d docdockgo -h localhost
```

### Tables principales

| Table | Rôle |
|---|---|
| `pulls` | Un enregistrement par pull, avec statut et décision finale |
| `pull_digests` | Chaque digest reçu (manifest, blob, referrer) lié à un pull |
| `whitelist` | Images approuvées (`registry`, `repository`, `tag`) |
| `blacklist` | Images refusées (`registry`, `repository`, `tag`) |
| `cache` | Index des fichiers présents dans le dossier `cache/` |
| `quarantine` | Index des fichiers présents dans le dossier `quarantaine/` |
| `ia_decisions` | Décisions de l'IA pour chaque appel à l'orchestrateur |
| `scan_events` | Résultats des scanners individuels |
| `users` | Comptes utilisateurs du dashboard |

La base est mise à jour dynamiquement au fil des pulls et des scans

### Variable d'environnement

Dans main.rs configurer l'adresse qui heberge la base de donnée

```bash
DATABASE_URL=postgres://docdockgo_admin:docdockgo@localhost:5432/docdockgo
```

---

## 📁 Structure du filesystem

```
DockDockGo/
├── src/
│   ├── main.rs                  # Serveur TLS, Fonctions principales
│   ├── pull_context.rs          # Logique de recupèration du contexte
│   ├── utils.rs                 # Fonctions annexes
│   ├── db.rs                    # Gestion de BDD
│   ├── predict_digests_utils.rs # Prediction des digests demandés par Docker/Podman
│   ├── registry_auth.rs         # Authentification pour registres (DockerHub + Generic)
│   └── validation.rs            # Validation des inputs
├── certs-mitm/                  # Certificats
├── cache/                       # Images approuvées (préalablement scannées) 
├── quarantaine/                 # Images en cours d'analyse
├── tmp/                         # Manifests stockés temporairement
├── registry_whitelist.json      # Liste des registres autorisés
├── Cargo.toml
├── Dockerfile
└── README.md
```

---

## 🔥 Features

* Proxy MITM TLS (Docker et Podman)
* Support multi-registres (Docker Hub, GHCR, Quay.io...)
* Quarantaine / Cache locale des artefacts OCI
* Whitelist / Blacklist persistantes en PostgreSQL
* Journalisation temps réel en base (pulls, digests...)

## 🔒 Securité

* Validations inputs
* Rate limiting par IP
* Validation cryptographique SHA256 des digests
* Vérification de la taille des blobs
* Timeout(s)

## 🏗️  Robustesse

* Scalabilité
* Gestion de la concurrence
* Resistant aux conditions de courses
* Compatible OCI (manifests, blobs, referrers)

---

## ⚠️ Notes importantes

* Le proxy doit être lancé en `root` pour écouter sur le port 443
* La CA du proxy doit être installée comme CA de confiance sur les machines clientes dans `/usr/local/share/ca-certificates/`
* Le dossier `certs-mitm/` doit contenir un certificat pour chaque registre listé dans `registry_whitelist.json`
* PostgreSQL doit être accessible avant le démarrage du proxy
* Les dossiers `cache/`, `quarantaine/` et `tmp/` sont créés automatiquement

---

## 🔧 CI/CD

Le projet inclut :

* ✔ Format (`cargo fmt`)
* ✔ Lint (`cargo clippy`)
* ✔ Tests (`cargo test`)
* ✔ Audit sécurité (`cargo audit`)
* ✔ Build Docker

---

## 👨‍💻 Auteur

Projet développé dans le cadre de **DocDockGo** (DevSecOps / Container Security).
