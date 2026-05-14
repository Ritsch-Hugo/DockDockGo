#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# test_reliability.sh v3 — Tests fiabilité, parsing fiabilisé
#
# Corrections v3 :
#   - Parser mode Docker robuste (CLI affiche du texte, pas du JSON)
#     → on lit jusqu'à "SCORE : XX/100" et "Niveau  : EMOJI XXXXX"
#   - Strip des codes ANSI (\033[...m) avant le parsing
#   - Retry automatique sur ERROR (1 retry par scan)
#   - Timeout augmenté à 500s
#   - Tape "n" pour répondre au prompt "Voir détails ?"
#   - Tee aussi vers stdout pour voir en direct
#
# Usage : sudo bash test_reliability.sh
# ═══════════════════════════════════════════════════════════════

set -u

CYAN='\033[0;36m'; GREEN='\033[0;32m'
RED='\033[0;31m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCAN_SCRIPT="$PROJECT_DIR/scan_vm.sh"
REPORT_DIR="/tmp/ddg-reliability"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="$REPORT_DIR/reliability-report-$TIMESTAMP.md"

mkdir -p "$REPORT_DIR"

# Vérifie jq
if ! command -v jq &>/dev/null; then
    echo "Installation jq..."
    apt-get install -y -qq jq 2>/dev/null
fi

# ─────────────────────────────────────────────
# IMAGES À TESTER
# ─────────────────────────────────────────────
IMAGES_LEGIT=(
    "alpine:latest"
    "busybox:latest"
    "python:3.11-slim"
    "node:20-alpine"
    "nginx:alpine"
    "redis:alpine"
    "httpd:alpine"
)

IMAGES_EVIL=(
    "dockdockgo-evil"
)

# ─────────────────────────────────────────────
# UTILS : strip codes ANSI
# ─────────────────────────────────────────────
strip_ansi() {
    sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g'
}

# ─────────────────────────────────────────────
# CAPTURE ÉTAT HÔTE (hash pour comparer)
# ─────────────────────────────────────────────
capture_host_state() {
    local label=$1
    local file="$REPORT_DIR/host-$label-$TIMESTAMP.txt"

    {
        echo "=== ÉTAT HÔTE : $label ==="
        echo "Date          : $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""

        echo "--- HASH /etc/passwd ---"
        md5sum /etc/passwd
        echo ""

        echo "--- HASH /etc/shadow ---"
        md5sum /etc/shadow 2>/dev/null || echo "(non lisible)"
        echo ""

        echo "--- Containers Docker (hôte) ---"
        docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null \
            | head -20 || echo "Aucun"
        echo ""

        echo "--- Containers ddg_observe sur l'hôte ---"
        docker ps --filter "name=ddg_observe" \
            --format '{{.Names}} | {{.Image}} | {{.Status}}' 2>/dev/null \
            || echo "Aucun"
        echo ""

        echo "--- Processus Firecracker ---"
        pgrep -af firecracker | head -5 || echo "Aucun"
        echo ""
    } > "$file"

    echo "$file"
}

# ─────────────────────────────────────────────
# SCAN VM (parser JSON)
# ─────────────────────────────────────────────
run_vm_scan() {
    local image=$1
    local attempt=${2:-1}
    local log="$REPORT_DIR/scan-vm-$(echo $image | tr '/:' '--')-$TIMESTAMP.log"

    echo -e "${BLUE}[VM]${NC}     Scan $image (tentative $attempt)..." >&2

    timeout 500 bash "$SCAN_SCRIPT" "$image" --details > "$log" 2>&1
    local rc=$?

    if [[ $rc -ne 0 ]] && [[ $rc -ne 124 ]]; then
        # Timeout = 124, autre code = erreur
        if [[ $attempt -lt 2 ]]; then
            echo -e "${YELLOW}    Retry (code=$rc)...${NC}" >&2
            sleep 5
            run_vm_scan "$image" 2
            return
        fi
        echo "ERROR-RC$rc|ERROR|false|$log"
        return
    fi

    if [[ $rc -eq 124 ]]; then
        echo "ERROR-TIMEOUT|ERROR|false|$log"
        return
    fi

    # Extrait le JSON via Python (plus robuste)
    local result
    result=$(python3 << PYEOF
import re, json, sys

try:
    content = open('$log').read()
    # Strip ANSI
    content = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', content)

    # Cherche le premier JSON valide qui contient "score"
    start = 0
    while True:
        idx = content.find('{', start)
        if idx == -1:
            break
        # Essai de parsing depuis cet endroit
        for end_idx in range(len(content), idx, -1):
            try:
                data = json.loads(content[idx:end_idx])
                if isinstance(data, dict) and 'score' in data:
                    print(f"{data.get('score','?')}|{data.get('verdict','?')}|{data.get('allowed', False)}|$log")
                    sys.exit(0)
            except json.JSONDecodeError:
                continue
        start = idx + 1

    print("ERROR-NOJSON|ERROR|false|$log")
except Exception as e:
    print(f"ERROR-EXC|ERROR|false|$log")
PYEOF
)

    if [[ -z "$result" ]] || [[ "$result" == ERROR* ]]; then
        # Retry si erreur de parsing
        if [[ $attempt -lt 2 ]]; then
            echo -e "${YELLOW}    Retry (parsing)...${NC}" >&2
            sleep 3
            run_vm_scan "$image" 2
            return
        fi
        echo "ERROR-PARSE|ERROR|false|$log"
    else
        echo "$result"
    fi
}

# ─────────────────────────────────────────────
# SCAN DOCKER (parser TEXTE)
# ─────────────────────────────────────────────
# Ton scanner CLI affiche :
#   ========== SCORE : 100/100 [mode: docker] ==========
#     Niveau  : 💀 CRITIQUE
#     Verdict : Image hautement malveillante.
#
# Avec ANSI possible.
# ─────────────────────────────────────────────
run_docker_scan() {
    local image=$1
    local attempt=${2:-1}
    local log="$REPORT_DIR/scan-docker-$(echo $image | tr '/:' '--')-$TIMESTAMP.log"

    echo -e "${BLUE}[DOCKER]${NC} Scan $image (tentative $attempt)..." >&2

    cd "$PROJECT_DIR"
    # On envoie "n" en stdin pour la question "Voir détails ?"
    echo "n" | timeout 300 cargo run --release --quiet -- "$image" --docker \
        > "$log" 2>&1
    local rc=$?

    # Strip ANSI dans le log
    strip_ansi < "$log" > "${log}.clean"

    # Parsing
    local score verdict
    score=$(grep -oP 'SCORE\s*:\s*\K[0-9]+' "${log}.clean" | head -1)

    # Niveau peut être après un emoji, "PROPRE", "ÉLEVÉ", "FAIBLE", "MODÉRÉ", "CRITIQUE"
    verdict=$(grep -E '^\s*Niveau\s*:' "${log}.clean" | head -1 \
              | grep -oE '[A-ZÉÈ]{4,}' | head -1)

    if [[ -z "$score" ]]; then
        # Retry
        if [[ $attempt -lt 2 ]]; then
            echo -e "${YELLOW}    Retry...${NC}" >&2
            sleep 3
            run_docker_scan "$image" 2
            return
        fi
        echo "ERROR-NOSCORE|ERROR|$log"
        return
    fi

    echo "${score}|${verdict:-?}|$log"
}

# ─────────────────────────────────────────────
# DÉBUT RAPPORT
# ─────────────────────────────────────────────
{
    echo "# DockDockGo — Rapport de fiabilité v3"
    echo ""
    echo "**Date** : $(date '+%Y-%m-%d %H:%M:%S')"
    echo "**Hôte** : $(hostname)"
    echo "**Kernel hôte** : $(uname -r)"
    echo ""
    echo "## Méthodologie"
    echo ""
    echo "Pour chaque image testée :"
    echo "1. **Scan mode VM Firecracker** (isolation totale)"
    echo "2. **Scan mode Docker direct** (sur l'hôte, plus rapide)"
    echo ""
    echo "Pour prouver l'isolation du mode VM, on capture l'état hôte AVANT/APRÈS :"
    echo "- Hash MD5 de \`/etc/passwd\` et \`/etc/shadow\` (doit rester identique)"
    echo "- Liste des containers Docker hôte"
    echo "- Containers \`ddg_observe_*\` (doit être vide en mode VM)"
    echo ""
    echo "---"
    echo ""
    echo "## Résultats résumé"
    echo ""
    echo "| Image | Mode VM | Mode Docker | Cohérent ? |"
    echo "|-------|---------|-------------|------------|"
} > "$REPORT_FILE"

declare -A VM_RESULTS
declare -A DOCKER_RESULTS

ALL_IMAGES=("${IMAGES_LEGIT[@]}" "${IMAGES_EVIL[@]}")

for IMG in "${ALL_IMAGES[@]}"; do
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  Test : $IMG${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════${NC}"

    # Pull si nécessaire
    if [[ "$IMG" != "dockdockgo-evil" ]]; then
        if ! docker image inspect "$IMG" &>/dev/null; then
            echo -e "${BLUE}[*]${NC} Pull $IMG..."
            docker pull "$IMG" >/dev/null 2>&1 || {
                echo -e "${RED}[✗]${NC} Pull échoué"; continue
            }
        fi
    fi

    BEFORE=$(capture_host_state "before-$(echo $IMG | tr '/:' '--')")

    # SCAN VM
    VM_RESULT=$(run_vm_scan "$IMG")
    VM_RESULTS["$IMG"]="$VM_RESULT"
    IFS='|' read -r VS VV VA VL <<< "$VM_RESULT"
    echo "    Score VM     : ${VS:-?}/100, Verdict : ${VV:-?}"

    sleep 3

    AFTER_VM=$(capture_host_state "after-vm-$(echo $IMG | tr '/:' '--')")

    # SCAN DOCKER
    DOCKER_RESULT=$(run_docker_scan "$IMG")
    DOCKER_RESULTS["$IMG"]="$DOCKER_RESULT"
    IFS='|' read -r DS DV DL <<< "$DOCKER_RESULT"
    echo "    Score Docker : ${DS:-?}/100, Verdict : ${DV:-?}"

    # Cohérence
    COHERENT="✅"
    case "$VV" in
        CRITICAL|HIGH)
            if [[ "$DV" != "CRITIQUE" ]] && [[ "$DV" != *"ÉLEVÉ"* ]]; then
                COHERENT="⚠️"
            fi ;;
        CLEAN|LOW)
            if [[ "$DV" != *"PROPRE"* ]] && [[ "$DV" != *"FAIBLE"* ]]; then
                COHERENT="⚠️"
            fi ;;
    esac

    echo "| \`$IMG\` | $VS/100 **$VV** | $DS/100 **$DV** | $COHERENT |" >> "$REPORT_FILE"

    echo "$BEFORE|$AFTER_VM" > "$REPORT_DIR/refs-$(echo $IMG | tr '/:' '--').txt"
done

# ─────────────────────────────────────────────
# DÉTAILS PAR IMAGE
# ─────────────────────────────────────────────
{
    echo ""
    echo "---"
    echo ""
    echo "## Détails par image"
    echo ""

    for IMG in "${ALL_IMAGES[@]}"; do
        [[ -z "${VM_RESULTS[$IMG]:-}" ]] && continue
        IFS='|' read -r VS VV VA VL <<< "${VM_RESULTS[$IMG]}"
        IFS='|' read -r DS DV DL <<< "${DOCKER_RESULTS[$IMG]:-||}"

        echo "### \`$IMG\`"
        echo ""
        echo "| Mode | Score | Verdict | Autorisé |"
        echo "|------|-------|---------|----------|"
        echo "| VM Firecracker | $VS/100 | $VV | $VA |"
        echo "| Docker direct | $DS/100 | $DV | - |"
        echo ""

        REFS_FILE="$REPORT_DIR/refs-$(echo $IMG | tr '/:' '--').txt"
        if [[ -f "$REFS_FILE" ]]; then
            IFS='|' read -r BEFORE AFTER_VM < "$REFS_FILE"

            HASH_BEFORE=$(grep -A1 "HASH /etc/passwd" "$BEFORE" | tail -1 | awk '{print $1}')
            HASH_AFTER=$(grep -A1 "HASH /etc/passwd" "$AFTER_VM" | tail -1 | awk '{print $1}')

            if [[ "$HASH_BEFORE" == "$HASH_AFTER" ]]; then
                echo "✅ \`/etc/passwd\` non modifié sur l'hôte (hash identique)"
            else
                echo "⚠️ \`/etc/passwd\` modifié — isolation compromise"
            fi
            echo ""
        fi
        echo "---"
        echo ""
    done

    # METRICS
    echo "## Métriques globales"
    echo ""

    TP=0; TN=0; FP=0; FN=0; ER=0
    for IMG in "${IMAGES_LEGIT[@]}"; do
        [[ -z "${VM_RESULTS[$IMG]:-}" ]] && continue
        IFS='|' read -r VS VV _ _ <<< "${VM_RESULTS[$IMG]}"
        case "$VV" in
            CLEAN|LOW)              ((TN++)) ;;
            MODERATE|HIGH|CRITICAL) ((FP++)) ;;
            ERROR)                  ((ER++)) ;;
        esac
    done

    for IMG in "${IMAGES_EVIL[@]}"; do
        [[ -z "${VM_RESULTS[$IMG]:-}" ]] && continue
        IFS='|' read -r VS VV _ _ <<< "${VM_RESULTS[$IMG]}"
        case "$VV" in
            HIGH|CRITICAL)          ((TP++)) ;;
            CLEAN|LOW|MODERATE)     ((FN++)) ;;
            ERROR)                  ((ER++)) ;;
        esac
    done

    TOTAL=$((TP+TN+FP+FN))
    if [[ $TOTAL -gt 0 ]]; then
        ACCURACY=$(python3 -c "print(round(($TP+$TN)*100/$TOTAL, 1))")

        echo "| Métrique | Valeur |"
        echo "|----------|--------|"
        echo "| Vrais positifs (TP) | $TP / ${#IMAGES_EVIL[@]} |"
        echo "| Vrais négatifs (TN) | $TN / ${#IMAGES_LEGIT[@]} |"
        echo "| Faux positifs (FP) | $FP |"
        echo "| Faux négatifs (FN) | $FN |"
        echo "| Erreurs techniques | $ER |"
        echo "| **Accuracy mode VM** | **$ACCURACY%** |"
        echo ""
    fi

} >> "$REPORT_FILE"

# ─────────────────────────────────────────────
# AFFICHAGE FINAL
# ─────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✓ Tests terminés${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo ""

printf "%-25s %-22s %-22s\n" "Image" "VM" "Docker"
printf "%-25s %-22s %-22s\n" "─────" "──" "──────"

for IMG in "${ALL_IMAGES[@]}"; do
    [[ -z "${VM_RESULTS[$IMG]:-}" ]] && continue
    IFS='|' read -r VS VV _ _ <<< "${VM_RESULTS[$IMG]}"
    IFS='|' read -r DS DV _ <<< "${DOCKER_RESULTS[$IMG]:-||}"

    case "$VV" in
        CLEAN|LOW)             COLOR=$GREEN ;;
        MODERATE)              COLOR=$YELLOW ;;
        HIGH|CRITICAL)         COLOR=$RED ;;
        *)                     COLOR=$NC ;;
    esac

    printf "%-25s ${COLOR}%-22s${NC} %-22s\n" \
        "$IMG" "$VS/100 $VV" "$DS/100 $DV"
done

echo ""
echo "  📊 Rapport : $REPORT_FILE"
echo ""