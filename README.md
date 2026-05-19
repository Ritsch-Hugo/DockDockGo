# cycle-de-vie

Microservice Rust de surveillance du cycle de vie des images Docker.

Surveille les CVEs publiées sur [OSV](https://osv.dev) et notifie le dashboard DocDockGo dès qu'une image de la whitelist est concernée.

## Flux

```
OSV (api.osv.dev)
    └─ polling incrémental toutes les POLL_INTERVAL_SECS secondes
         └─ nouvelles CVEs → Matcher (compare name+version avec les SBOMs)
              └─ match trouvé → Notifier (POST HTTP vers le dashboard)
```

## Démarrage

```bash
cp .env.example .env
# éditer .env si besoin
cargo run
```

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `PORT` | `3020` | Port d'écoute HTTP |
| `DASHBOARD_URL` | _(vide)_ | URL de notification du dashboard — laisser vide pour désactiver |
| `POLL_INTERVAL_SECS` | `60` | Intervalle entre deux polls OSV (secondes) |
| `WHITELIST_PATH` | `config/whitelist` | Chemin vers la whitelist TOML (sans extension) |

## Endpoints

| Méthode | Route | Description |
|---|---|---|
| `GET` | `/health` | Santé du service |
| `GET` | `/images` | Whitelist d'images chargée en mémoire |
| `GET` | `/notifications` | Historique des notifications envoyées |

## Whitelist

Éditer `config/whitelist.toml`. Les packages doivent avoir un champ `ecosystem` (valeurs OSV : `PyPI`, `npm`, `Go`, `Alpine:3.18`, `Debian`…) pour être interrogés auprès d'OSV. Les packages sans ecosystem sont ignorés par le poller.

```toml
[[images]]
name = "mon-app:1.0"

[[images.sbom.packages]]
name = "pillow"
version = "9.0.0"
ecosystem = "PyPI"
```

Les SBOMs réels sont générés via Trivy :
```bash
trivy image --format json mon-app:1.0
```

## Tests

```bash
cargo test
```

## Lint

```bash
cargo clippy -- -D warnings
cargo fmt
```
