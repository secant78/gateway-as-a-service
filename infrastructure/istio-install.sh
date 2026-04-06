#!/usr/bin/env bash
# ============================================================
# GaaS Local Bootstrap Script
# ============================================================
#
# PURPOSE:
#   One-command setup of a local Minikube Kubernetes cluster with Istio
#   service mesh and GaaS namespace/mTLS configuration. Run this once on
#   a fresh machine to get a working local development environment.
#
# WHAT IT DOES (in order):
#   1. Starts a Minikube cluster using Docker as the hypervisor
#   2. Waits for all cluster nodes to be Ready
#   3. Installs Istio control plane + gateways using the `demo` profile
#   4. Waits for all Istio pods to be Ready
#   5. Creates the gaas and gaas-vault namespaces (with istio-injection labels)
#   6. Applies STRICT mTLS PeerAuthentication policies to both namespaces
#
# PREREQUISITES (must be installed before running this script):
#   minikube >= 1.32   https://minikube.sigs.k8s.io/docs/start/
#   kubectl  >= 1.28   https://kubernetes.io/docs/tasks/tools/
#   istioctl >= 1.20   https://istio.io/latest/docs/setup/getting-started/
#   helm     >= 3.12   https://helm.sh/docs/intro/install/
#   Docker Desktop     https://www.docker.com/products/docker-desktop/
#   RAM: at least 8 GB free for the Minikube VM
#   CPU: at least 4 cores available
#
# USAGE:
#   chmod +x istio-install.sh
#   ./istio-install.sh
#
# ERROR HANDLING:
#   set -euo pipefail means the script STOPS immediately if:
#     -e: any command exits with a non-zero status code
#     -u: any undefined variable is referenced
#     -o pipefail: any command in a pipe fails (not just the last one)
#   This prevents silent failures where a broken step is ignored and
#   subsequent steps run on a broken cluster.
# ============================================================

set -euo pipefail

# SCRIPT_DIR resolves to the absolute path of the directory containing this script.
# This makes the kubectl apply commands work regardless of where you run the script from.
# "${BASH_SOURCE[0]}" is the path to this script; dirname gets the directory; cd + pwd resolves symlinks.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pin versions so the bootstrap is reproducible.
# If you upgrade Istio, update this version AND re-run the script.
ISTIO_VERSION="1.20.3"

# Minikube resource allocation — tune these based on your machine.
# 4 CPUs and 8 GB RAM supports: Istio control plane + APISIX + Vault + auth-service
# If you see OOMKilled pods, increase MINIKUBE_MEMORY to 12288 (12 GB).
MINIKUBE_CPUS=4
MINIKUBE_MEMORY=8192  # MB

# ============================================================
# Step 1: Start Minikube
# ============================================================
echo "==> [1/6] Starting Minikube cluster"
minikube start \
  --driver=docker \           # Use Docker Desktop as the container runtime (no VM needed)
  --cpus="${MINIKUBE_CPUS}" \
  --memory="${MINIKUBE_MEMORY}" \
  --kubernetes-version=v1.28.7  # Pin K8s version for reproducibility

# ============================================================
# Step 2: Wait for cluster readiness
# ============================================================
echo "==> [2/6] Verifying cluster readiness"
# Block until ALL nodes report Ready status.
# Without this, istioctl install may fail because the API server isn't fully up yet.
kubectl wait --for=condition=Ready nodes --all --timeout=120s

# ============================================================
# Step 3: Install Istio
# ============================================================
echo "==> [3/6] Installing Istio (demo profile)"
# istioctl install is Istio's own installation CLI.
# --set profile=demo installs the `demo` profile which includes:
#   - istiod:                 The Istio control plane (certificate authority + config distributor)
#   - istio-ingressgateway:   External traffic entry point (replaces Kubernetes Ingress)
#   - istio-egressgateway:    Controls outbound traffic (optional but useful for auditing)
#   - Access logging:         Every request is logged to stdout by the Envoy sidecar
#
# WHY `demo` profile instead of `minimal`?
#   The `minimal` profile installs ONLY istiod — it omits both gateways.
#   APISIX needs to communicate through Istio's ingress gateway for external traffic.
#   Without the ingress gateway, APISIX would have no managed entry point.
#
# WHY NOT Helm-based Istio installation?
#   Helm-based Istio requires managing 3 separate charts (base, istiod, gateway).
#   `istioctl install` is a single idempotent command that handles ordering and
#   dependencies automatically. Simpler = fewer things to go wrong.
#
# -y: auto-confirm the installation prompt (required for non-interactive CI use)
istioctl install --set profile=demo -y

# ============================================================
# Step 4: Wait for Istio readiness
# ============================================================
echo "==> [4/6] Waiting for Istio control plane readiness"
# All Istio pods must be Ready before we create namespaces with injection labels.
# If istiod isn't running, the MutatingWebhookAdmissionController isn't active —
# namespaces labeled for injection won't actually get sidecars injected.
kubectl wait --for=condition=Ready pods --all -n istio-system --timeout=180s

# ============================================================
# Step 5: Create GaaS namespaces
# ============================================================
echo "==> [5/6] Applying GaaS namespaces"
# The namespace.yaml creates both `gaas` and `gaas-vault` with the
# `istio-injection: enabled` label. Critically, this label is only processed
# at pod CREATION time — so namespaces must exist before any pods are deployed.
kubectl apply -f "${SCRIPT_DIR}/namespace.yaml"

# ============================================================
# Step 6: Apply mTLS Zero Trust policy
# ============================================================
echo "==> [6/6] Enforcing mTLS STRICT mode across GaaS namespaces"
# PeerAuthentication must be applied AFTER the namespace exists.
# If applied before, kubectl may silently succeed (the resource is created in a
# pending state) or fail with "namespace not found" depending on the kubectl version.
# Applying after ensures the policy is immediately active for all new pods.
kubectl apply -f "${SCRIPT_DIR}/peer-authentication.yaml"

# ============================================================
# Bootstrap complete
# ============================================================
echo ""
echo "Bootstrap complete. Verify your installation:"
echo "  kubectl get pods -n istio-system               # All Istio pods should be Running"
echo "  kubectl get peerauthentication -A              # Should show gaas-strict-mtls and vault-strict-mtls"
echo "  kubectl get ns gaas gaas-vault                 # Both namespaces should exist"
echo ""
echo "Next steps:"
echo "  1. Deploy Vault:   kubectl apply -f ../security/vault/vault-deployment.yaml"
echo "  2. Install APISIX: helm install apisix apisix/apisix -f ../gateway/apisix-values.yaml -n gaas"
echo "  3. Deploy Consumer: kubectl apply -f ../gateway/apisix-consumer.yaml"
echo "  4. Run RBAC audit: python ../ops/rbac_audit.py --fail-on-findings"
