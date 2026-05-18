#!/usr/bin/env bash
# =============================================================================
#  test_pipeline.sh — Lancement et test du pipeline complet
#
#  Ce script lance tout de A à Z :
#    3002 scanner-cve        (Docker)
#    3001 scanner-compliance (Docker)
#    3003 llm-manager
#    3004 mcp-tools-server
#    3005 llm-decision
#    3000 orchestrateur
#
#  Backend LLM : OpenRouter (cloud) — configuré dans llm-decision/.env et llm-manager/.env
#
#  Puis envoie un POST multipart à l'orchestrateur avec alpine/3.18
#  et affiche la décision finale ALLOW / DENY.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$MODULE_DIR")"
QUARANTINE="$REPO_DIR/quarantaine"

# Branche mcp-tools-server clonée séparément
MCP_REPO_DIR="${MCP_REPO_DIR:-/home/scuti/temp/mcp/DocDockGo}"

# ── Charger les .env ──────────────────────────────────────────────────────────
DECISION_ENV="$MODULE_DIR/llm-decision/.env"
MANAGER_ENV="$MODULE_DIR/llm-manager/.env"

for env_file in "$DECISION_ENV" "$MANAGER_ENV"; do
    if [ -f "$env_file" ]; then
        set -a
        source "$env_file"
        set +a
    else
        echo "[ERR] Fichier .env introuvable : $env_file"
        echo "      Crée-le avec les variables de configuration (voir CLAUDE.md)"
        exit 1
    fi
done

if [ -z "$OPENROUTER_API_KEY" ]; then
    echo "[ERR] OPENROUTER_API_KEY manquant dans $DECISION_ENV"
    exit 1
fi

# ── Configuration ─────────────────────────────────────────────────────────────
COMPLIANCE_IMAGE="scanner-compliance"
CVE_IMAGE="scanner-cve"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[TEST]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC}  $*"; }

PIDS=()
DOCKER_CONTAINERS=()
cleanup() {
    echo ""
    log "Arrêt des services..."
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    for cid in "${DOCKER_CONTAINERS[@]}"; do docker stop "$cid" 2>/dev/null || true; done
    log "Nettoyage terminé."
}
trap cleanup EXIT INT TERM

# ── 1. Vérifier la quarantaine ────────────────────────────────────────────────
if [ ! -d "$QUARANTINE/library/alpine/3.18/manifests" ]; then
    err "Quarantaine introuvable : $QUARANTINE/library/alpine/3.18"
    exit 1
fi
log "Quarantaine OK"

# ── 2. Libérer tous les ports ─────────────────────────────────────────────────
log "Libération des ports 3000 3001 3002 3003 3004 3005..."
for port in 3000 3001 3002 3003 3004 3005; do
    fuser -k "${port}/tcp" 2>/dev/null || true
done
docker ps -q --filter "publish=3001" --filter "publish=3002" | xargs -r docker stop 2>/dev/null || true
sleep 1

# ── 3. Scanner CVE (3002) ────────────────────────────────────────────────────
log "Démarrage scanner CVE — image $CVE_IMAGE (port 3002)..."
CID_CVE=$(docker run -d --rm -p 3002:3002 -v trivy-cache:/root/.cache/trivy "$CVE_IMAGE" 2>/dev/null)
if [ -z "$CID_CVE" ]; then
    err "Impossible de démarrer $CVE_IMAGE"
    err "Vérifie que l'image existe : docker images | grep $CVE_IMAGE"
    exit 1
fi
DOCKER_CONTAINERS+=("$CID_CVE")

log "Attente scanner CVE..."
for i in $(seq 1 30); do
    if curl -s http://localhost:3002/health 2>/dev/null | grep -q "ok"; then
        log "Scanner CVE prêt (${i}s)"
        break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
        err "Scanner CVE pas prêt après 30s — vérifie : docker logs $CID_CVE"
        exit 1
    fi
done

# ── 4. Scanner compliance (3001) ─────────────────────────────────────────────
log "Démarrage scanner compliance — image $COMPLIANCE_IMAGE (port 3001)..."
CID_COMPLIANCE=$(docker run -d --rm -p 3001:3001 "$COMPLIANCE_IMAGE" 2>/dev/null)
if [ -z "$CID_COMPLIANCE" ]; then
    err "Impossible de démarrer $COMPLIANCE_IMAGE"
    err "Vérifie que l'image existe : docker images | grep $COMPLIANCE_IMAGE"
    exit 1
fi
DOCKER_CONTAINERS+=("$CID_COMPLIANCE")

log "Attente scanner compliance..."
for i in $(seq 1 30); do
    if curl -sv http://localhost:3001/v1/scan 2>&1 | grep -q "405\|200"; then
        log "Scanner compliance prêt (${i}s)"
        break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
        err "Scanner compliance pas prêt après 30s — vérifie : docker logs $CID_COMPLIANCE"
        exit 1
    fi
done

# ── 5. Build ──────────────────────────────────────────────────────────────────
log "Build du workspace llm-module..."
cd "$MODULE_DIR"
cargo build -q 2>/dev/null || cargo build 2>&1 | tail -5

log "Build de mcp-tools-server..."
cd "$MCP_REPO_DIR/mcp-tools-server"
cargo build -q 2>/dev/null || cargo build 2>&1 | tail -5

log "Build de l'orchestrateur..."
cd "$REPO_DIR/orchestrator"
cargo build -q 2>/dev/null || cargo build 2>&1 | tail -5
cd "$MODULE_DIR"

# ── 6. llm-manager (3003) ─────────────────────────────────────────────────────
log "Démarrage llm-manager (3003)..."
log "  Backend : $LLM_BASE_URL"
log "  Workers : $LLM_WORKER_1 / $LLM_WORKER_2 / $LLM_WORKER_3"
log "  Arbitre : $LLM_ARBITER"
MANAGER_PORT=3003 \
    ./target/debug/llm-manager > /tmp/llm-manager.log 2>&1 &
PIDS+=($!)

log "Attente llm-manager..."
for i in $(seq 1 60); do
    if curl -s http://localhost:3003/health 2>/dev/null | grep -qiE "ok|true|healthy|model"; then
        log "llm-manager prêt (${i}×2s)"
        break
    fi
    sleep 2
    if [ $i -eq 60 ]; then
        warn "llm-manager lent — vérifie : tail /tmp/llm-manager.log"
    fi
done

# ── 7. Scanner dynamique (8080) ──────────────────────────────────────────────
log "Démarrage scanner dynamique — image dockdockgo-scan-dynamique:1.0.0 (port 8080)..."
CID_DYNAMIC=$(docker run -d --rm \
    --name ddg-scanner \
    --network host \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/log/falco.log:/var/log/falco.log \
    dockdockgo-scan-dynamique:1.0.0 2>/dev/null)
if [ -z "$CID_DYNAMIC" ]; then
    warn "Impossible de démarrer dockdockgo-scan-dynamique:1.0.0"
    warn "Vérifie que l'image existe : docker images | grep dockdockgo-scan-dynamique"
    warn "Build : cd /home/scuti/temp/dynamique/DocDockGo/docdockgo-scan-dynamique && docker build -t dockdockgo-scan-dynamique:1.0.0 ."
else
    DOCKER_CONTAINERS+=("$CID_DYNAMIC")
    log "Attente scanner dynamique..."
    for i in $(seq 1 30); do
        if curl -s http://localhost:8080/health 2>/dev/null | grep -q "DockDockGo"; then
            log "Scanner dynamique prêt (${i}s)"
            break
        fi
        sleep 1
        if [ $i -eq 30 ]; then
            warn "Scanner dynamique pas prêt après 30s — vérifie : docker logs ddg-scanner"
        fi
    done
fi

# ── 8. mcp-tools-server (3004) ────────────────────────────────────────────────
log "Démarrage mcp-tools-server (3004)..."
MCP_SERVER_PORT=3004 \
STATIC_SCANNER_URL="http://localhost:3002" \
COMPLIANCE_SCANNER_URL="http://localhost:3001" \
DYNAMIC_SCANNER_URL="http://localhost:8080" \
    "$MCP_REPO_DIR/mcp-tools-server/target/debug/mcp-tools-server" > /tmp/mcp-tools-server.log 2>&1 &
PIDS+=($!)

log "Attente mcp-tools-server..."
for i in $(seq 1 30); do
    RESP=$(curl -s --max-time 2 -X POST http://localhost:3004/mcp \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' 2>/dev/null || true)
    if echo "$RESP" | grep -q "run_static_scan"; then
        log "mcp-tools-server prêt (${i}s) — tools :"
        echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for t in d.get('result',{}).get('tools',[]): print(f'  - {t[\"name\"]}')
" 2>/dev/null
        break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
        warn "mcp-tools-server pas prêt — vérifie : tail /tmp/mcp-tools-server.log"
    fi
done

# ── 8. llm-decision (3005) ───────────────────────────────────────────────────
log "Démarrage llm-decision (3005)..."
DECISION_PORT=3005 \
MANAGER_PORT=3003 \
MANAGER_HOST=localhost \
MCP_SERVER_URL="http://localhost:3004/mcp" \
QUARANTINE_PATH="$QUARANTINE" \
    ./target/debug/llm-decision > /tmp/llm-decision.log 2>&1 &
PIDS+=($!)

log "Attente llm-decision..."
for i in $(seq 1 60); do
    if grep -qi "en écoute sur\|listening on" /tmp/llm-decision.log 2>/dev/null; then
        log "llm-decision prêt (${i}×2s)"
        break
    fi
    sleep 2
    if [ $i -eq 60 ]; then
        warn "llm-decision pas prêt après 120s — vérifie : tail /tmp/llm-decision.log"
    fi
done

# ── 9. Orchestrateur (3000) ──────────────────────────────────────────────────
log "Démarrage orchestrateur (3000)..."
"$REPO_DIR/orchestrator/target/debug/orchestrator" > /tmp/orchestrator.log 2>&1 &
PIDS+=($!)
sleep 2
log "Orchestrateur prêt"

# ── 10. Test — POST multipart à l'orchestrateur ───────────────────────────────
log ""
log "═══════════════════════════════════════════════════════"
log " POST /v1/decision → orchestrateur → llm-decision"
log " → mcp-tools-server → scanners (3001 + 3002 + 8080)"
log " Image : alpine/3.18"
log "═══════════════════════════════════════════════════════"

MANIFEST_FILE="$QUARANTINE/library/alpine/3.18/manifests/fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7.json"

CONTEXT='{
  "uuid": "550e8400-e29b-41d4-a716-446655440003",
  "ip_client": "192.168.1.100",
  "registry": "library",
  "repository": "alpine",
  "tag": "3.18",
  "manifest_digests": [
    {"algorithm":"sha256","value":"fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7"}
  ],
  "blob_digests": [
    {"algorithm":"sha256","value":"802c91d5298192c0f3a08101aeb5f9ade2992e22c9e27fa8b88eab82602550d0"},
    {"algorithm":"sha256","value":"44cf07d57ee4424189f012074a59110ee2065adfdde9c7d9826bebdffce0a885"}
  ],
  "referrers_digests": [],
  "manifest_racine_digest": {"algorithm":"sha256","value":"fd032399cd767f310a1d1274e81cab9f0fd8a49b3589eba2c3420228cd45b6a7"},
  "digests_possible": [],
  "digests_expected": [],
  "os": "linux",
  "arch": "amd64",
  "pull_completed": true
}'

log "(OpenRouter — jusqu'à 8 LLM en séquentiel : 4-10 min estimées pour ALLOW, plus si DENY)"
RESPONSE=$(curl -s --max-time 900 \
    -X POST http://localhost:3000/v1/decision \
    -F "context=$CONTEXT" \
    -F "manifest=@$MANIFEST_FILE" \
    2>/dev/null || true)

echo ""
log "═══════════════════════════════════════════════════════"
if [ -z "$RESPONSE" ]; then
    err "Pas de réponse (timeout ou service non prêt)"
    warn "Logs : tail /tmp/orchestrator.log"
    warn "Logs : tail /tmp/llm-decision.log"
else
    log "Réponse orchestrateur :"
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
    echo ""
    log "─── Logs llm-decision (phases 1→3) ────────────────"
    python3 -c "
with open('/tmp/llm-decision.log') as f:
    logs = f.read()
for line in logs.splitlines():
    if any(k in line for k in [
        'scan', 'Scan', 'MCP', 'mcp', 'Exéc', 'terminé', 'échoué', 'ERROR',
        'arbitre', 'Arbitre', 'Worker', 'raisonnement',
        'phase 3', 'Phase 3', 'analyse', 'Analyse', 'verdict', 'Verdict',
        'vulnérabilité', 'score', 'Score', 'ALLOW', 'DENY',
        'alternative', 'Alternative', 'catalogue', 'Catalogue',
        '→', '✓',
    ]):
        print(' ', line.strip())
" 2>/dev/null
fi

log "─── Réponse envoyée à l'orchestrateur ─────────────"
python3 -c "
import json, re, sys

with open('/tmp/llm-decision.log') as f:
    content = f.read()

for line in content.splitlines():
    if '[réponse]' not in line:
        continue
    idx = line.find('[réponse] ')
    raw = line[idx + len('[réponse] '):]
    try:
        data = json.loads(raw)
        print(json.dumps(data, indent=2, ensure_ascii=False))
    except Exception:
        print(raw)
    break
" 2>/dev/null

echo ""
log "Logs complets disponibles :"
log "  tail -f /tmp/orchestrator.log"
log "  tail -f /tmp/llm-decision.log"
log "  tail -f /tmp/mcp-tools-server.log"
log "  tail -f /tmp/llm-manager.log"
log ""
log "Ctrl+C pour tout arrêter."
wait
