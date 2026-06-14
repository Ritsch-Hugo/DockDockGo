#!/usr/bin/env bash
# Redirige le port 443 → proxy pod k8s (via DNAT direct sur l'IP du pod)
# À exécuter une fois sur le nœud (nécessite sudo).
# Ré-exécuter après un redémarrage du pod proxy (l'IP change).
set -euo pipefail
export KUBECONFIG="${KUBECONFIG:-$(getent passwd ${SUDO_USER:-$USER} | cut -d: -f6)/.kube/config}"

NAMESPACE="docdockgo"

# Récupère l'IP courante du pod proxy
PROXY_POD_IP=$(kubectl get pod -n "$NAMESPACE" -l app=proxy \
  -o jsonpath='{.items[0].status.podIP}')

if [[ -z "$PROXY_POD_IP" ]]; then
  echo "ERREUR : aucun pod proxy trouvé dans le namespace $NAMESPACE" >&2
  exit 1
fi
echo "IP du pod proxy : $PROXY_POD_IP"

# ── Port 443 → proxy pod (DNAT direct pour éviter le problème KUBE-SERVICES) ──
# Exception : le réseau pods k8s (10.42.0.0/16) passe directement sans interception
iptables -t nat -C PREROUTING -s 10.42.0.0/16 -p tcp --dport 443 -j ACCEPT 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -s 10.42.0.0/16 -p tcp --dport 443 -j ACCEPT

# Supprimer toute ancienne règle DNAT sur le port 443 (IP de pod périmée)
while iptables -t nat -D PREROUTING ! -s 10.42.0.0/16 -p tcp --dport 443 -j DNAT 2>/dev/null; do :; done

# Ajouter la règle DNAT vers l'IP courante du pod
iptables -t nat -I PREROUTING 2 ! -s 10.42.0.0/16 -p tcp --dport 443 \
  -j DNAT --to-destination "$PROXY_POD_IP:8443"
echo "443 → $PROXY_POD_IP:8443 : OK"

echo "Règles iptables en place."
