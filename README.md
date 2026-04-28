  # 🖥️ DockDockGo — Dashboard

  Interface web de supervision et d'administration du proxy MITM DockDockGo, avec authentification SSO via Zitadel (OIDC).

  ---

  ## 🎯 Objectif

  Le Dashboard s'intercale comme couche de supervision entre les équipes et le proxy DockDockGo.

  Il permet de :

  * Visualiser en temps réel les pulls d'images en cours (statut, décision, progression)
  * Consulter la timeline détaillée de chaque pull (digests, décisions IA, scan events)
  * Gérer la whitelist et la blacklist d'images depuis une interface web
  * Inspecter la quarantaine et le cache local du proxy
  * Accéder à l'historique complet des pulls avec filtres
  * Recevoir des mises à jour en direct via Server-Sent Events (SSE) depuis PostgreSQL

  ---

  ## 👥 Rôles

  Le dashboard expose deux interfaces distinctes selon le rôle de l'utilisateur, attribué par Zitadel :

  | Rôle | Accès | Périmètre |
  |---|---|---|
  | `rssi` | `/dashboard/rssi` | Vue globale, tous les pulls, quarantaine, cache, whitelist, blacklist, historique complet |
  | `dev` | `/dashboard/dev` | Pulls filtrés sur ses IPs, historique personnel, recherche restreinte |

  ---

  ## ⚙️ Fonctionnement

  1. **Authentification** — L'utilisateur est redirigé vers Zitadel via OIDC (Authorization Code + PKCE). Le rôle est extrait du JWT et stocké dans un cookie `HttpOnly`.
  2. **Rendu serveur** — Les dashboards sont rendus côté serveur en Rust (Axum) par injection dans les templates HTML. Les données sont lues depuis PostgreSQL au moment de la requête.
  3. **Temps réel** — Un endpoint SSE (`/dashboard/events`) écoute les notifications PostgreSQL (`LISTEN dashboard_updates`) et pousse les changements aux clients connectés sans rechargement de page.
  4. **API REST** — Des endpoints JSON permettent les actions depuis l'interface : ajout/suppression en whitelist ou blacklist, suppression d'une entrée du cache, recherche avec autocomplétion.

  ---

  ## 🐳 Lancer avec Docker (recommandé)

  ### 1. Build l'image

  ```bash
  docker build -t docdockgo-dashboard .
  ```

  ### 2. Lancer le container

  ```bash
  docker run -d \
    --name docdockgo-dashboard \
    --env-file .env \
    --network host \
    ghcr.io/ritsch-hugo/docdockgo-dashboard:latest
  ```

  > `--env-file` charge toutes les variables d'environnement depuis le fichier `.env`  
  > `--network host` permet l'accès à la base PostgreSQL locale

  ---

  ## 🔐 Authentification Zitadel

  Le dashboard utilise OpenID Connect (Authorization Code Flow + PKCE) via Zitadel.

  ### Flux d'authentification

  ```
  Utilisateur → GET /  →  Redirect Zitadel
                  ↓
  Zitadel  →  GET /callback?code=...
                  ↓
  Decode JWT → Extrait le rôle → Cookie HttpOnly (role, sub, id_token)
                  ↓
  Redirect vers /dashboard/rssi  ou  /dashboard/dev
  ```

  ### Logout

  Le logout appelle l'endpoint `end_session` de Zitadel avec `id_token_hint` pour détruire la session SSO, puis redirige vers `/logged-out`.

  ### Configuration requise dans Zitadel

  * Application de type **Web** avec Authorization Code Flow activé
  * `redirect_uri` configurée : `http://<host>:<port>/callback`
  * `post_logout_redirect_uri` configurée : `http://<host>:<port>/logged-out`
  * Rôles `rssi` et `dev` déclarés au niveau projet et assignés aux utilisateurs

  ---

  ## 🔴 Temps réel (SSE)

  Le dashboard écoute le channel PostgreSQL `dashboard_updates` via `LISTEN/NOTIFY`.

  Chaque notification est un JSON de la forme :

  ```json
  {
    "table": "pulls",
    "action": "INSERT",
    "data": { "uuid": "...", "repository": "...", "decision_final": "ALLOW", ... }
  }
  ```

  Les tables supportées : `pulls`, `pull_digests`, `ia_decisions`, `scan_events`, `quarantine`, `cache`, `whitelist`, `blacklist`.

  Le client SSE reconnecte automatiquement en cas de coupure (retry après 3 secondes).

  ---


  ### Exemple de réponse `/health`

  ```json
  { "status": "ok", "database": "ok" }
  ```

  Retourne `503` si la base de données est inaccessible.

  ---

  ## 🗄️ Base de données PostgreSQL

  Le dashboard se connecte à la même base PostgreSQL que le proxy DockDockGo (lecture seule pour les dashboards, écriture pour les APIs whitelist/blacklist/cache).

  ### Connexion

  ```bash
  psql -U docdockgo_admin -d docdockgo -h localhost
  ```

  ---

  ## 🔧 Variables d'environnement

  Toutes les variables sont chargées depuis un fichier `.env` à la racine du projet. Aucune valeur n'est hardcodée dans le binaire.

  ### Fichier `.env` complet

  ```env
  # ── Base de données ────────────────────────────────────────────────────────────
  DATABASE_URL=postgres://UTILISATEUR:MOT_DE_PASSE@HOST:PORT/NOM_DE_LA_BASE

  # ── OIDC Zitadel ──────────────────────────────────────────────────────────────
  ZITADEL_ISSUER=https://<votre-instance>.zitadel.cloud
  CLIENT_ID=<votre-client-id>
  REDIRECT_URI=http://localhost:3010/callback
  POST_LOGOUT_REDIRECT_URI=http://localhost:3010/logged-out

  # ── IPs autorisées par défaut (pour les devs, séparées par des virgules) ───────
  # Ces IPs sont associées à l'utilisateur lors de sa première connexion
  ALLOWED_IPS=192.168.1.10,192.168.1.11

  # ── Serveur ────────────────────────────────────────────────────────────────────
  LISTEN_ADDR=0.0.0.0:3010
  ```

  ---

  ## 📁 Structure du projet

  ```
  dashboard/
  ├── src/
  │   ├── main.rs              # Serveur Axum, routeur, graceful shutdown
  │   ├── auth.rs              # OIDC (login, callback, logout), gestion des cookies
  │   └── dashboard/
  │       ├── mod.rs           # Routeur du dashboard
  │       ├── handlers.rs      # Handlers HTTP (dashboards, SSE, APIs)
  │       └── store.rs         # (réservé)
  ├── template/
  │   ├── rssi.html            # Template dashboard RSSI
  │   └── dev.html             # Template dashboard Dev
  ├── .env                     # Variables d'environnement (non versionné)
  ├── Cargo.toml
  └── Dockerfile
  ```

  ---

  ## 🔥 Features

  * Authentification SSO OIDC (Zitadel) avec PKCE
  * Deux interfaces selon le rôle (RSSI / Dev)
  * Mise à jour temps réel via SSE (PostgreSQL LISTEN/NOTIFY)
  * Vue détaillée par pull : digests, décisions IA, scan events, timeline
  * Gestion whitelist / blacklist depuis l'interface
  * Healthcheck exposé pour Kubernetes
  * Graceful shutdown sur SIGTERM et SIGINT
  * Toutes les variables d'environnement centralisées dans `.env`

  ## 🔒 Sécurité

  * Cookies `HttpOnly` + `SameSite=Lax` pour le rôle, le sub et l'id_token
  * Vérification du rôle à chaque requête sensible
  * Les devs ne voient que les pulls associés à leurs IPs
  * Les endpoints d'écriture (whitelist, blacklist, cache) sont réservés au rôle `rssi`
  * Logout SSO avec `id_token_hint` pour détruire la session Zitadel

  ---

  ## ⚠️ Notes importantes

  * Le fichier `.env` ne doit pas être versionné (ajouter au `.gitignore`)
  * `REDIRECT_URI` et `POST_LOGOUT_REDIRECT_URI` doivent correspondre exactement aux URIs déclarées dans Zitadel
  * PostgreSQL doit être accessible et le channel `dashboard_updates` doit être activé (géré par le proxy DockDockGo via triggers)
  * Le dashboard est stateless : aucune session n'est stockée côté serveur, tout repose sur les cookies signés par Zitadel

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
