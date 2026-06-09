#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# setup_mcp_automation.sh — Permet l'automatisation MCP
#
# Configure sudoers pour que ton user puisse lancer scan_vm.sh
# SANS taper le mot de passe sudo. Indispensable pour que ton
# orchestrateur MCP/IA puisse appeler le scanner automatiquement.
#
# Sécurité :
#   - NOPASSWD limité à scan_vm.sh + setup_firecracker.sh UNIQUEMENT
#   - Pas un sudo NOPASSWD global
#   - L'utilisateur garde tous ses autres droits sudo normaux
#
# Usage : sudo bash setup_mcp_automation.sh
# ═══════════════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

[[ $EUID -ne 0 ]] && {
    echo -e "${RED}[✗]${NC} Lancez : sudo bash setup_mcp_automation.sh"
    exit 1
}

[[ -z "$SUDO_USER" ]] && {
    echo -e "${RED}[✗]${NC} SUDO_USER non défini"
    exit 1
}

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUDOERS_FILE="/etc/sudoers.d/dockdockgo-mcp"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  DockDockGo — Setup automatisation MCP/IA"
echo "═══════════════════════════════════════════════════"
echo ""
echo -e "${BLUE}[*]${NC} Utilisateur : $SUDOUSER"
echo -e "${BLUE}[*]${NC} Projet      : $PROJECT_DIR"
echo ""

# Vérifie que les scripts existent
SCAN_VM="$PROJECT_DIR/scan_vm.sh"
SETUP_FC="$PROJECT_DIR/setup_firecracker.sh"

[[ ! -f "$SCAN_VM" ]] && {
    echo -e "${RED}[✗]${NC} $SCAN_VM introuvable"
    exit 1
}

# Crée le fichier sudoers
cat > "$SUDOERS_FILE" <<EOF
# ═════════════════════════════════════════════════════════
# DockDockGo MCP Automation
# Permet à $SUDO_USER d'exécuter le scanner sans mot de passe
# pour les automatisations (orchestrateur MCP, IA Qwen, etc.)
# ═════════════════════════════════════════════════════════

# Scan d'image Docker via microVM
$SUDO_USER ALL=(root) NOPASSWD: $SCAN_VM
$SUDO_USER ALL=(root) NOPASSWD: $SCAN_VM *

# Setup Firecracker
$SUDO_USER ALL=(root) NOPASSWD: $SETUP_FC
$SUDO_USER ALL=(root) NOPASSWD: $SETUP_FC *
EOF

chmod 440 "$SUDOERS_FILE"

# Validation syntaxe (CRITIQUE — sinon sudo cassé !)
if visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
    echo -e "${GREEN}[✓]${NC} Configuration sudoers validée"
    echo ""
    echo -e "${BLUE}[*]${NC} $SUDO_USER peut maintenant lancer SANS mot de passe :"
    echo "    sudo $SCAN_VM <image>"
    echo "    sudo $SCAN_VM <image> --details"
    echo "    sudo $SETUP_FC"
    echo ""
    echo -e "${YELLOW}[!]${NC} Test rapide :"
    echo "    sudo -n $SCAN_VM dockdockgo-evil"
    echo "    (option -n = pas de prompt — si ça marche, c'est OK)"
else
    rm -f "$SUDOERS_FILE"
    echo -e "${RED}[✗]${NC} Configuration sudoers invalide — supprimée"
    echo "    Ne pas s'inquiéter, sudo n'est pas cassé."
    exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Pour DÉSACTIVER l'automatisation :"
echo "    sudo rm $SUDOERS_FILE"
echo "═══════════════════════════════════════════════════"
