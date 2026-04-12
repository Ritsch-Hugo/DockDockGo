#!/usr/bin/env bash
# =============================================================================
#  test_pipeline.sh — Test du pipeline complet
#
#  Prérequis (déjà lancés manuellement) :
#    - scanner compliance  sur http://localhost:3001  (cargo run)
#    - scanner CVE         sur http://localhost:3002  (docker run)
#
#  Ce script lance :
#    3003 llm-manager
#    3004 mcp-tools-server
#    3005 llm-decision  (FORCE_SCANS=true → bypass LLM, scans forcés)
#    3000 orchestrateur
#
#  Puis envoie un POST multipart à l'orchestrateur avec alpine/3.18
#  et affiche la décision finale ALLOW / DENY.
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$MODULE_DIR")"
QUARANTINE="$REPO_DIR/quarantaine"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[TEST]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC}  $*"; }

PIDS=()
cleanup() {
    echo ""
    log "Arrêt des services..."
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    log "Nettoyage terminé (scanners 3001/3002 laissés actifs)."
}
trap cleanup EXIT INT TERM

# ── 1. Vérifier les prérequis ─────────────────────────────────────────────────
log "Vérification des prérequis..."

if ! curl -s http://localhost:11434/api/version > /dev/null 2>&1; then
    err "Ollama non accessible sur localhost:11434 → lance : ollama serve"
    exit 1
fi
log "Ollama OK"

if ! curl -sv http://localhost:3001/v1/scan 2>&1 | grep -q "405\|200"; then
    err "Scanner compliance (3001) non accessible → lance le manuellement"
    exit 1
fi
log "Scanner compliance (3001) OK"

if ! curl -s http://localhost:3002/health | grep -q "ok"; then
    err "Scanner CVE (3002) non accessible → lance : docker run -p 3002:3002 scanner-cve"
    exit 1
fi
log "Scanner CVE (3002) OK"

if [ ! -d "$QUARANTINE/library/alpine/3.18/manifests" ]; then
    err "Quarantaine introuvable : $QUARANTINE/library/alpine/3.18"
    exit 1
fi
log "Quarantaine OK : $QUARANTINE/library/alpine/3.18"

# ── 2. Libérer uniquement les ports des services qu'on va lancer ──────────────
log "Libération des ports 3000 3003 3004 3005..."
for port in 3000 3003 3004 3005; do
    fuser -k "${port}/tcp" 2>/dev/null || true
done
sleep 1

# ── 3. Build ──────────────────────────────────────────────────────────────────
log "Build du workspace llm-module..."
cd "$MODULE_DIR"
cargo build -q 2>/dev/null || cargo build 2>&1 | tail -5

log "Build de mcp-tools-server..."
cd "$REPO_DIR/mcp-tools-server"
cargo build -q 2>/dev/null || cargo build 2>&1 | tail -5

log "Build de l'orchestrateur..."
cd "$REPO_DIR/orchestrator"
cargo build -q 2>/dev/null || cargo build 2>&1 | tail -5
cd "$MODULE_DIR"

# ── 4. llm-manager (3003) ─────────────────────────────────────────────────────
log "Démarrage llm-manager (3003)..."
OLLAMA_BASE_URL="http://localhost:11434" MANAGER_PORT=3003 \
    ./target/debug/llm-manager > /tmp/llm-manager.log 2>&1 &
PIDS+=($!)

log "Attente llm-manager..."
for i in $(seq 1 60); do
    if curl -s http://localhost:3003/health 2>/dev/null | grep -qiE "ok|true|healthy|model"; then
        log "llm-manager prêt (${i}s)"
        break
    fi
    sleep 2
    if [ $i -eq 60 ]; then
        warn "llm-manager lent — vérifie : tail /tmp/llm-manager.log"
    fi
done

# ── 5. mcp-tools-server (3004) ────────────────────────────────────────────────
log "Démarrage mcp-tools-server (3004)..."
MCP_SERVER_PORT=3004 \
STATIC_SCANNER_URL="http://localhost:3002" \
COMPLIANCE_SCANNER_URL="http://localhost:3001" \
    "$REPO_DIR/mcp-tools-server/target/debug/mcp-tools-server" > /tmp/mcp-tools-server.log 2>&1 &
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

# ── 6. llm-decision (3005) — FORCE_SCANS=true ────────────────────────────────
log "Démarrage llm-decision (3005)..."
OLLAMA_BASE_URL="http://localhost:11434" \
DECISION_PORT=3005 \
MANAGER_PORT=3003 \
MANAGER_HOST=localhost \
MCP_SERVER_URL="http://localhost:3004/mcp" \
QUARANTINE_PATH="$QUARANTINE" \
LLM_TIMEOUT_SECS=180 \
    ./target/debug/llm-decision > /tmp/llm-decision.log 2>&1 &
PIDS+=($!)

log "Attente llm-decision (peut prendre 2-3 min le temps que llm-manager valide les modèles)..."
for i in $(seq 1 120); do
    if grep -qi "en écoute sur\|listening on" /tmp/llm-decision.log 2>/dev/null; then
        log "llm-decision prêt (${i}s)"
        break
    fi
    sleep 2
    if [ $i -eq 120 ]; then
        warn "llm-decision pas prêt après 240s — vérifie : tail /tmp/llm-decision.log"
    fi
done

# ── 7. Orchestrateur (3000) ───────────────────────────────────────────────────
log "Démarrage orchestrateur (3000)..."
"$REPO_DIR/orchestrator/target/debug/orchestrator" > /tmp/orchestrator.log 2>&1 &
PIDS+=($!)
sleep 2
log "Orchestrateur prêt"

# ── 8. Test — POST multipart à l'orchestrateur ────────────────────────────────
log ""
log "═══════════════════════════════════════════════════════"
log " POST /v1/decision → orchestrateur → llm-decision"
log " → mcp-tools-server → scanners (3001 + 3002)"
log " Image : alpine/3.18"
log "═══════════════════════════════════════════════════════"

# Manifest principal d'alpine/3.18 amd64 (config OCI + layer)
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

log "(les LLM peuvent prendre 5-15 min en séquentiel — patience)"
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
    log "─── Résultats des scans (dans llm-decision) ────────"
    python3 -c "
import subprocess, json, re

# Lire les logs llm-decision pour voir les résultats MCP
with open('/tmp/llm-decision.log') as f:
    logs = f.read()

# Afficher les lignes importantes
for line in logs.splitlines():
    if any(k in line for k in ['FORCE_SCANS', 'scan', 'Scan', 'MCP', 'mcp', 'Exéc', 'terminé', 'échoué', 'ERROR']):
        print(' ', line.strip())
" 2>/dev/null
fi

echo ""
log "Logs complets disponibles :"
log "  tail -f /tmp/orchestrator.log"
log "  tail -f /tmp/llm-decision.log"
log "  tail -f /tmp/mcp-tools-server.log"
log "  tail -f /tmp/llm-manager.log"
log ""
log "Ctrl+C pour tout arrêter."
wait
