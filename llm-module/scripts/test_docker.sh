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
CYAN='\033[0;36m'
NC='\033[0m'

log()    { echo -e "${GREEN}[TEST]${NC} $1"; }
info()   { echo -e "${CYAN}[INFO]${NC} $1"; }
warn()   { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()  { echo -e "${RED}[ERREUR]${NC} $1"; exit 1; }
section(){ echo -e "\n${CYAN}══════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}══════════════════════════════════════════${NC}"; }

MOCK_PID=""
LOG_PID=""

cleanup() {
    echo ""
    log "Nettoyage..."
    [ -n "$LOG_PID" ]  && kill "$LOG_PID"  2>/dev/null || true
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
    docker rm -f scanner-cve scanner-compliance mcp-tools-server llm-manager llm-decision 2>/dev/null || true
}
trap cleanup EXIT

FORCE_PULL=false
for arg in "$@"; do [ "$arg" = "--pull" ] && FORCE_PULL=true; done

# ============================================================
# Vérifications préalables
# ============================================================

section "Vérifications"

[ -f "$LLM_MODULE_DIR/llm-manager/.env" ] || error ".env introuvable : $LLM_MODULE_DIR/llm-manager/.env"
[ -f "$LLM_MODULE_DIR/llm-decision/.env" ] || error ".env introuvable : $LLM_MODULE_DIR/llm-decision/.env"
[ -d "$QUARANTINE/library/alpine/3.18" ]   || error "Quarantaine introuvable : $QUARANTINE/library/alpine/3.18"

# Afficher la config des modèles
section "Configuration LLM"
WORKER_1=$(grep "^LLM_WORKER_1" "$LLM_MODULE_DIR/llm-decision/.env" | cut -d= -f2)
WORKER_2=$(grep "^LLM_WORKER_2" "$LLM_MODULE_DIR/llm-decision/.env" | cut -d= -f2)
WORKER_3=$(grep "^LLM_WORKER_3" "$LLM_MODULE_DIR/llm-decision/.env" | cut -d= -f2)
ARBITER=$(grep  "^LLM_ARBITER"  "$LLM_MODULE_DIR/llm-decision/.env" | cut -d= -f2)
info "Worker 1  : $WORKER_1"
info "Worker 2  : $WORKER_2"
info "Worker 3  : $WORKER_3"
info "Arbitre   : $ARBITER"
info "Image test : library/alpine:3.18"

# ============================================================
# Pull des images llm (si besoin)
# ============================================================

section "Images Docker"

LLM_IMAGES=(
    ghcr.io/ritsch-hugo/mcp-tools-server:latest
    ghcr.io/ritsch-hugo/llm-manager:latest
    ghcr.io/ritsch-hugo/llm-decision:latest
)

if [ "$FORCE_PULL" = true ]; then
    log "Téléchargement forcé (--pull)..."
    for img in "${LLM_IMAGES[@]}"; do docker pull "$img"; done
else
    for img in "${LLM_IMAGES[@]}"; do
        if ! docker image inspect "$img" > /dev/null 2>&1; then
            log "Image absente, téléchargement : $img"
            docker pull "$img"
        else
            log "Image présente en local : $img"
        fi
    done
fi

# ============================================================
# Réseau Docker
# ============================================================

docker network create "$NETWORK" 2>/dev/null || true

# ============================================================
# Scanners
# ============================================================

section "Scanners"

docker rm -f scanner-cve scanner-compliance 2>/dev/null || true

if docker image inspect scanner-cve:latest > /dev/null 2>&1 && \
   docker image inspect scanner-compliance:latest > /dev/null 2>&1; then

    log "Images scanner-cve et scanner-compliance trouvées — démarrage..."

    docker run -d --name scanner-cve --network "$NETWORK" \
        -p 3002:3002 \
        scanner-cve:latest
    log "scanner-cve démarré (port 3002)"

    docker run -d --name scanner-compliance --network "$NETWORK" \
        -p 3001:3001 \
        scanner-compliance:latest
    log "scanner-compliance démarré (port 3001)"

    log "Attente des scanners (port TCP)..."
    for name in scanner-cve scanner-compliance; do
        port=3002; [ "$name" = "scanner-compliance" ] && port=3001
        for i in $(seq 1 30); do
            if bash -c "echo >/dev/tcp/localhost/$port" 2>/dev/null; then
                log "$name prêt (port $port)."
                break
            fi
            sleep 2
            [ "$i" -eq 30 ] && warn "$name n'a pas répondu sur le port $port."
        done
    done

    STATIC_SCANNER_URL="http://scanner-cve:3002"
    COMPLIANCE_SCANNER_URL="http://scanner-compliance:3001"
    EXTRA_HOST=""

else
    warn "Images scanner absentes — démarrage des mock scanners sur l'hôte (ports 3001 + 3002)..."
    python3 "$SCRIPT_DIR/mock_scanners.py" > /tmp/mock-scanners.log 2>&1 &
    MOCK_PID=$!
    sleep 1
    kill -0 "$MOCK_PID" 2>/dev/null || error "mock_scanners.py n'a pas démarré. Voir /tmp/mock-scanners.log"
    log "Mock scanners démarrés (PID $MOCK_PID)."
    STATIC_SCANNER_URL="http://host.docker.internal:3002"
    COMPLIANCE_SCANNER_URL="http://host.docker.internal:3001"
    EXTRA_HOST="--add-host=host.docker.internal:host-gateway"
fi

# ============================================================
# Démarrage mcp-tools-server, llm-manager, llm-decision
# ============================================================

section "Services LLM"

docker rm -f mcp-tools-server llm-manager llm-decision 2>/dev/null || true

log "Démarrage mcp-tools-server..."
docker run -d --name mcp-tools-server --network "$NETWORK" \
    ${EXTRA_HOST:+$EXTRA_HOST} \
    -e STATIC_SCANNER_URL="$STATIC_SCANNER_URL" \
    -e COMPLIANCE_SCANNER_URL="$COMPLIANCE_SCANNER_URL" \
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
    [ "$i" -eq 30 ] && error "llm-manager n'a pas répondu. Logs : docker logs llm-manager"
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

sleep 1
docker logs -f llm-decision 2>&1 | sed "s/^/  [llm-decision] /" &
LOG_PID=$!

log "Attente de llm-decision (/health)..."
for i in $(seq 1 90); do
    if curl -sf http://localhost:3005/health > /dev/null 2>&1; then
        log "llm-decision prêt."
        break
    fi
    sleep 2
    if [ "$i" -eq 90 ]; then
        echo ""
        warn "llm-decision n'a pas répondu. Derniers logs :"
        docker logs --tail 30 llm-decision 2>&1 | sed 's/^/  /'
        error "llm-decision n'a pas démarré."
    fi
done

# ============================================================
# Logs en temps réel (arrière-plan)
# ============================================================

section "Pipeline en cours"
log "Logs llm-decision en temps réel :"
echo ""
docker logs -f llm-decision 2>&1 | sed "s/^/  ${CYAN}[llm-decision]${NC} /" &
LOG_PID=$!

# ============================================================
# Envoi du PullContext
# ============================================================

log "Envoi du PullContext (library/alpine:3.18) — prévoir 5 à 10 minutes..."
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
    }') || error "La requête a échoué. Logs : docker logs llm-decision"

kill "$LOG_PID" 2>/dev/null || true
LOG_PID=""

# ============================================================
# Résultat final
# ============================================================

section "Résultat final"
echo "$RESULT" | python3 -m json.tool 2>/dev/null || echo "$RESULT"

echo ""
VERDICT=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['verdict']['decision'])" 2>/dev/null || echo "INCONNU")
SCORE=$(echo   "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['verdict']['vulnerability_score'])" 2>/dev/null || echo "?")
CONF=$(echo    "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['verdict']['confidence'])" 2>/dev/null || echo "?")

echo ""
log "Verdict            : $VERDICT"
log "Score vulnérabilité : $SCORE"
log "Confiance          : $CONF"
