#!/usr/bin/env bash
# Redirige le port 443 → NodePort 30443 (proxy TLS MITM)
# et le port 3010 → NodePort 30010 (dashboard).
# À exécuter une fois sur le nœud (nécessite sudo).

set -euo pipefail

add_rule() {
  local dport=$1 toport=$2
  iptables -t nat -C PREROUTING -p tcp --dport "$dport" -j REDIRECT --to-port "$toport" 2>/dev/null \
    || iptables -t nat -A PREROUTING -p tcp --dport "$dport" -j REDIRECT --to-port "$toport"
  # Pour les connexions locales (même machine)
  iptables -t nat -C OUTPUT -p tcp --dport "$dport" -j REDIRECT --to-port "$toport" 2>/dev/null \
    || iptables -t nat -A OUTPUT -p tcp --dport "$dport" -j REDIRECT --to-port "$toport"
  echo "443→$toport : OK"
}

add_rule 443 30443
add_rule 3010 30010

echo "Règles iptables en place."
