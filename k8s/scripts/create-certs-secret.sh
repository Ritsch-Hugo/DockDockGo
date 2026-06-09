#!/usr/bin/env bash
# Crée le Secret Kubernetes "proxy-certs" depuis le dossier certs-mitm local.
# À exécuter une fois avant helm install.
#
# Usage : ./scripts/create-certs-secret.sh [namespace]

set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

NAMESPACE="${1:-docdockgo}"
CERTS_DIR="$(dirname "$0")/../../proxy/certs-mitm"

if [ ! -d "$CERTS_DIR" ]; then
  echo "Erreur : dossier certs-mitm introuvable ($CERTS_DIR)"
  exit 1
fi

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic proxy-certs \
  --namespace "$NAMESPACE" \
  --from-file="$CERTS_DIR" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "Secret 'proxy-certs' créé dans le namespace '$NAMESPACE'."
