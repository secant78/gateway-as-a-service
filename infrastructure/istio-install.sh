#!/usr/bin/env bash
# ============================================================
# GaaS Local Bootstrap Script
# Provisions a Minikube cluster with Istio service mesh
# and applies the base GaaS namespace/mTLS configuration.
#
# Prerequisites:
#   - minikube >= 1.32
#   - kubectl >= 1.28
#   - istioctl >= 1.20  (https://istio.io/latest/docs/setup/getting-started/)
#   - helm >= 3.12
#   - At least 8 GB RAM and 4 CPU cores available
#
# Usage:
#   chmod +x istio-install.sh
#   ./istio-install.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ISTIO_VERSION="1.20.3"
MINIKUBE_CPUS=4
MINIKUBE_MEMORY=8192

echo "==> [1/6] Starting Minikube cluster"
minikube start \
  --driver=docker \
  --cpus="${MINIKUBE_CPUS}" \
  --memory="${MINIKUBE_MEMORY}" \
  --kubernetes-version=v1.28.7

echo "==> [2/6] Verifying cluster readiness"
kubectl wait --for=condition=Ready nodes --all --timeout=120s

echo "==> [3/6] Installing Istio (demo profile)"
# The 'demo' profile installs: istiod (control plane), istio-ingressgateway,
# and istio-egressgateway. It also enables access logging for debugging.
# DO NOT use 'minimal' profile — it omits the ingress gateway needed for APISIX.
istioctl install --set profile=demo -y

echo "==> [4/6] Waiting for Istio control plane readiness"
kubectl wait --for=condition=Ready pods --all -n istio-system --timeout=180s

echo "==> [5/6] Applying GaaS namespaces"
kubectl apply -f "${SCRIPT_DIR}/namespace.yaml"

echo "==> [6/6] Enforcing mTLS STRICT mode across GaaS namespaces"
# The PeerAuthentication CR must be applied AFTER the namespace exists.
# Applying it before creates a resource in a non-existent namespace, which
# kubectl silently ignores on some versions — always check the output.
kubectl apply -f "${SCRIPT_DIR}/peer-authentication.yaml"

echo ""
echo "✓ Bootstrap complete. Verify installation:"
echo "  kubectl get pods -n istio-system"
echo "  kubectl get peerauthentication -A"
echo ""
echo "Next steps:"
echo "  1. Deploy Vault:  kubectl apply -f ../security/vault/vault-deployment.yaml"
echo "  2. Install APISIX: helm install apisix apisix/apisix -f ../gateway/apisix-values.yaml -n gaas"
echo "  3. Run RBAC audit: python ../ops/rbac_audit.py --fail-on-findings"
