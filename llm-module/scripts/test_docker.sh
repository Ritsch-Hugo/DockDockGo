#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LLM_MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$LLM_MODULE_DIR/.." && pwd)"
QUARANTINE="$REPO_ROOT/quarantaine"
NETWORK="docdockgo"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()   { echo -e "${GREEN}[TEST]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERREUR]${NC} $1"; exit 1; }

FORCE_PULL=false
for arg in "$@"; do
    [ "$arg" = "--pull" ] && FORCE_PULL=true
done

cleanup() {
    echo ""
    log "Arrêt et suppression des conteneurs..."
    docker rm -f mcp-tools-server llm-manager llm-decision 2>/dev/null || true
}
trap cleanup EXIT

# ============================================================
# Vérifications préalables
# ============================================================

[ -f "$LLM_MODULE_DIR/llm-manager/.env" ] || error ".env introuvable : $LLM_MODULE_DIR/llm-manager/.env"
[ -f "$LLM_MODULE_DIR/llm-decision/.env" ] || error ".env introuvable : $LLM_MODULE_DIR/llm-decision/.env"
[ -d "$QUARANTINE/library/alpine/3.18" ]   || error "Quarantaine introuvable : $QUARANTINE/library/alpine/3.18"

# ============================================================
# Pull des images
# ============================================================

log "Téléchargement des images depuis ghcr.io..."
docker pull ghcr.io/ritsch-hugo/mcp-tools-server:latest
docker pull ghcr.io/ritsch-hugo/llm-manager:latest
docker pull ghcr.io/ritsch-hugo/llm-decision:latest

# ============================================================
# Réseau Docker
# ============================================================

docker network create "$NETWORK" 2>/dev/null || true

# Vérifier que les scanners sont sur le réseau
for name in scanner-cve scanner-compliance; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
        warn "Le conteneur '$name' n'est pas en cours d'exécution — les scans retourneront une erreur."
    else
        docker network connect "$NETWORK" "$name" 2>/dev/null || true
    fi
done

# ============================================================
# Démarrage des services
# ============================================================

docker rm -f mcp-tools-server llm-manager llm-decision 2>/dev/null || true

log "Démarrage mcp-tools-server..."
docker run -d --name mcp-tools-server --network "$NETWORK" \
    -e STATIC_SCANNER_URL=http://scanner-cve:3002 \
    -e COMPLIANCE_SCANNER_URL=http://scanner-compliance:3001 \
    -v "$QUARANTINE":/quarantaine \
    -p 3004:3004 \
    ghcr.io/ritsch-hugo/mcp-tools-server:latest

log "Démarrage llm-manager..."
docker run -d --name llm-manager --network "$NETWORK" \
    --env-file "$LLM_MODULE_DIR/llm-manager/.env" \
    -p 3003:3003 \
    ghcr.io/ritsch-hugo/llm-manager:latest

log "Attente de llm-manager (/health)..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:3003/health > /dev/null 2>&1; then
        log "llm-manager prêt."
        break
    fi
    sleep 2
    [ "$i" -eq 30 ] && error "llm-manager n'a pas répondu dans les temps."
done

log "Démarrage llm-decision..."
docker run -d --name llm-decision --network "$NETWORK" \
    --env-file "$LLM_MODULE_DIR/llm-decision/.env" \
    -e MANAGER_HOST=llm-manager \
    -e MCP_SERVER_URL=http://mcp-tools-server:3004/mcp \
    -e QUARANTINE_PATH=/quarantaine \
    -v "$QUARANTINE":/quarantaine \
    -p 3005:3005 \
    ghcr.io/ritsch-hugo/llm-decision:latest

log "Attente de llm-decision (/health)..."
for i in $(seq 1 60); do
    if curl -sf http://localhost:3005/health > /dev/null 2>&1; then
        log "llm-decision prêt."
        break
    fi
    sleep 2
    [ "$i" -eq 60 ] && error "llm-decision n'a pas répondu dans les temps."
done

# ============================================================
# Test — envoi du PullContext (library/alpine:3.18)
# ============================================================

log "Envoi du PullContext (library/alpine:3.18)..."
log "Traitement LLM en cours — prévoir 5 à 10 minutes..."
echo ""

RESULT=$(curl -sf --max-time 900 \
    -X POST http://localhost:3005/v1/decision \
    -H "Content-Type: application/json" \
    -d '{
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "ip_client": "172.17.0.1",
      "registry": "registry-1.docker.io",
      "repository": "library/alpine",
      "tag": "3.18",
      "manifest_digests": [
        {"algorithm": "sha256", "value": "fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7"}
      ],
      "blob_digests": [
        {"algorithm": "sha256", "value": "44cf07d57ee4424189f012074a59110ee2065adfdde9c7d9826bebdffce0a885"},
        {"algorithm": "sha256", "value": "802c91d5298192c0f3a08101aeb5f9ade2992e22c9e27fa8b88eab82602550d0"}
      ],
      "referrers_digests": [
        {"algorithm": "sha256", "value": "9b6731f6b4abfdb75a0dda7b7852355343bccdb4062d5c55a19571ddc6cb7668"}
      ],
      "manifest_racine_digest": {"algorithm": "sha256", "value": "de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f"},
      "digests_possible": [
        {"algorithm": "sha256", "value": "fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7"}
      ],
      "digests_expected": [
        {"algorithm": "sha256", "value": "fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7"}
      ],
      "os": "linux",
      "arch": "amd64",
      "pull_completed": true
    }') || error "La requête a échoué (curl). Vérifiez les logs : docker logs llm-decision"

# ============================================================
# Résultat
# ============================================================

echo ""
log "=== RÉSULTAT ==="
echo "$RESULT" | python3 -m json.tool 2>/dev/null || echo "$RESULT"

echo ""
VERDICT=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['verdict']['decision'])" 2>/dev/null || echo "INCONNU")
SCORE=$(echo "$RESULT"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['verdict']['vulnerability_score'])" 2>/dev/null || echo "?")
log "Verdict : $VERDICT  |  Score de vulnérabilité : $SCORE"
