#!/usr/bin/env bash
# Redirige le port 443 → NodePort 30443 (proxy TLS MITM)
# et le port 3010 → NodePort 30010 (dashboard).
# À exécuter une fois sur le nœud (nécessite sudo).

set -euo pipefail

add_rule() {
  local dport=$1 toport=$2
  # PREROUTING uniquement — intercepte les clients externes (vm_antoine, etc.)
  # Ne pas ajouter de règle OUTPUT : elle casserait containerd et les process hôtes
  iptables -t nat -C PREROUTING -p tcp --dport "$dport" -j REDIRECT --to-port "$toport" 2>/dev/null \
    || iptables -t nat -A PREROUTING -p tcp --dport "$dport" -j REDIRECT --to-port "$toport"
  # Exception : le réseau pods k8s (10.42.0.0/16) passe directement sans interception
  iptables -t nat -C PREROUTING -s 10.42.0.0/16 -p tcp --dport "$dport" -j ACCEPT 2>/dev/null \
    || iptables -t nat -I PREROUTING 1 -s 10.42.0.0/16 -p tcp --dport "$dport" -j ACCEPT
  echo "$dport→$toport : OK"
}

add_rule 443 30443
add_rule 3010 30010

echo "Règles iptables en place."
