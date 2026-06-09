#!/bin/bash
# ─────────────────────────────────────────────────────────────
# install.sh — DockDockGo Installation hôte (mode Docker direct)
#
# Configure Falco + 18 règles DDG sur l'hôte, pour permettre :
#   - Scan rapide via cargo run -- <image> --docker
#   - Pas besoin de microVM Firecracker (mais moins isolé)
#
# Pour le mode VM Firecracker (recommandé), utilisez :
#   sudo bash setup_firecracker.sh
#
# Usage : sudo bash install.sh
# ─────────────────────────────────────────────────────────────

set -e

# Couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_FILE="$PROJECT_DIR/falco_rules.local.yaml"

# ─────────────────────────────────────────────
# VÉRIFICATIONS
# ─────────────────────────────────────────────
check_root() {
    [[ $EUID -ne 0 ]] && log_error "Lancez : sudo bash install.sh"
    log_success "Root OK"
}

check_docker() {
    log_info "Vérification Docker..."
    command -v docker &>/dev/null || \
        log_error "Docker non installé : https://docs.docker.com/engine/install/"
    docker info &>/dev/null || log_error "Docker daemon inaccessible"
    log_success "Docker OK ($(docker --version))"
}

check_rules_file() {
    [[ ! -f "$RULES_FILE" ]] && log_error "Règles introuvables : $RULES_FILE
Le fichier falco_rules.local.yaml doit être à la racine du projet."
    local count
    count=$(grep -c "^- rule:" "$RULES_FILE")
    log_success "Règles DDG : $count règles dans $RULES_FILE"
}

# ─────────────────────────────────────────────
# INSTALLATION FALCO (HÔTE)
# ─────────────────────────────────────────────
install_falco() {
    log_info "Installation Falco..."

    if command -v falco &>/dev/null; then
        log_warn "Déjà installé : $(falco --version 2>&1 | head -1)"
        return
    fi

    apt-get update -qq
    apt-get install -y -qq curl gnupg apt-transport-https

    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
        | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
        > /etc/apt/sources.list.d/falcosecurity.list

    apt-get update -qq
    FALCO_DRIVER_LOADER=no apt-get install -y falco || true

    log_success "Falco installé"
}

# ─────────────────────────────────────────────
# CONFIGURATION FALCO
# ─────────────────────────────────────────────
configure_falco() {
    log_info "Configuration Falco..."

    local config="/etc/falco/falco.yaml"
    [[ ! -f "$config" ]] && log_error "$config introuvable"

    cp "$config" "${config}.bak.$(date +%s)"

    sed -i 's/^json_output:.*/json_output: true/' "$config"
    sed -i 's/^json_include_output_property:.*/json_include_output_property: true/' "$config"
    sed -i 's/^buffered_outputs:.*/buffered_outputs: false/' "$config"
    sed -i '/^file_output:/,/^[^ ]/ s/enabled: false/enabled: true/' "$config"
    sed -i 's|filename: .*falco.*\.txt|filename: /var/log/falco.log|' "$config"

    # Rate limiting (évite explosion logs sur fork bombs)
    if ! grep -q "^outputs:" "$config"; then
        cat >> "$config" <<'EOF'

outputs:
  rate: 100
  max_burst: 1000
EOF
    fi

    log_success "Falco configuré"
}

# ─────────────────────────────────────────────
# RÈGLES DDG (depuis le projet)
# ─────────────────────────────────────────────
install_ddg_rules() {
    log_info "Installation des 18 règles DDG..."

    # Supprime les anciennes versions
    rm -f /etc/falco/rules.d/ddg_rules.yaml

    # Copie depuis le projet
    cp "$RULES_FILE" /etc/falco/falco_rules.local.yaml
    chmod 644 /etc/falco/falco_rules.local.yaml

    local count
    count=$(grep -c "^- rule:" /etc/falco/falco_rules.local.yaml)
    log_success "18 règles installées dans /etc/falco/falco_rules.local.yaml"

    # Affiche les règles
    log_info "Règles actives :"
    grep "^- rule:" /etc/falco/falco_rules.local.yaml | sed 's/- rule: /    → /'
}

# ─────────────────────────────────────────────
# LOG FILE
# ─────────────────────────────────────────────
setup_log_file() {
    log_info "Config log..."
    touch /var/log/falco.log
    chmod 644 /var/log/falco.log

    if [[ -n "$SUDO_USER" ]]; then
        chown "$SUDO_USER" /var/log/falco.log
        log_success "falco.log → $SUDO_USER (lecture/écriture)"
    fi
}

# ─────────────────────────────────────────────
# SERVICE FALCO MODERN_BPF
# ─────────────────────────────────────────────
enable_falco() {
    log_info "Activation falco-modern-bpf..."

    systemctl enable falco-modern-bpf 2>/dev/null || true
    systemctl restart falco-modern-bpf

    for i in {1..10}; do
        if systemctl is-active --quiet falco-modern-bpf; then
            log_success "Service actif"
            return
        fi
        sleep 1
    done

    log_error "Falco non démarré. Voir : journalctl -u falco-modern-bpf -n 50"
}

# ─────────────────────────────────────────────
# SUDOERS POUR AUTOMATISATION (MCP/IA)
# Permet à l'utilisateur de lancer scan_vm.sh
# sans saisir le mot de passe sudo.
# ─────────────────────────────────────────────
setup_sudoers() {
    log_info "Configuration sudoers (automatisation MCP)..."

    if [[ -z "$SUDO_USER" ]]; then
        log_warn "SUDO_USER non défini — sudoers skippé"
        return
    fi

    local sudoers_file="/etc/sudoers.d/dockdockgo-scan"
    cat > "$sudoers_file" <<EOF
# DockDockGo — autorise scan_vm.sh sans mot de passe pour l'automatisation
$SUDO_USER ALL=(root) NOPASSWD: $PROJECT_DIR/scan_vm.sh
$SUDO_USER ALL=(root) NOPASSWD: $PROJECT_DIR/setup_firecracker.sh
EOF
    chmod 440 "$sudoers_file"

    # Vérifie syntaxe
    if visudo -c -f "$sudoers_file" &>/dev/null; then
        log_success "sudoers OK : $SUDO_USER peut lancer scan_vm.sh sans mot de passe"
    else
        rm -f "$sudoers_file"
        log_warn "sudoers invalide, supprimé"
    fi
}

# ─────────────────────────────────────────────
# VÉRIFICATION FINALE
# ─────────────────────────────────────────────
verify() {
    log_info "Vérification finale..."
    local ok=true

    systemctl is-active --quiet falco-modern-bpf && \
        log_success "Falco actif" || { log_warn "Falco inactif"; ok=false; }

    [[ -f /etc/falco/falco_rules.local.yaml ]] && \
        log_success "Règles DDG présentes ($(grep -c '^- rule:' /etc/falco/falco_rules.local.yaml))" \
        || { log_warn "Règles manquantes"; ok=false; }

    [[ -r /var/log/falco.log ]] && \
        log_success "falco.log lisible" || { log_warn "falco.log non lisible"; ok=false; }

    echo ""
    if $ok; then
        log_success "Installation hôte complète ✓"
        echo ""
        echo "  Modes disponibles :"
        echo "    cargo run -- <image>            → mode VM Firecracker (recommandé)"
        echo "    cargo run -- <image> --docker   → mode Docker direct (sur l'hôte)"
        echo "    cargo run -- --server           → API HTTP"
        echo ""
        echo "  Tests :"
        echo "    cargo run -- python:3.11-slim --docker  → CLEAN attendu"
        echo "    cargo run -- dockdockgo-evil --docker   → CRITIQUE attendu"
        echo ""
        echo "  Pour le mode VM (recommandé) :"
        echo "    sudo bash setup_firecracker.sh"
    fi
}

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
main() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "   DockDockGo — Install hôte (Docker mode)"
    echo "═══════════════════════════════════════════"
    echo ""

    check_root
    check_docker
    check_rules_file
    install_falco
    configure_falco
    install_ddg_rules
    setup_log_file
    enable_falco
    setup_sudoers
    verify
}

main "$@"