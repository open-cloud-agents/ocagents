#!/usr/bin/env bash
set -euo pipefail

# run_kind_sandbox.sh - Automated lifecycle runner for ephemeral KinD sandbox tests

CLUSTER_NAME="kind-sandbox-$(date +%s)"
TARGET_TYPE=""
TARGET_PATH=""

usage() {
  echo "Usage: $0 [--manifest <PATH> | --helm <PATH> | --kustomize <PATH>]"
  echo "  --manifest <PATH>   Test raw YAML manifest or directory of manifests"
  echo "  --helm <PATH>       Test Helm chart directory"
  echo "  --kustomize <PATH>  Test Kustomize overlay directory"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      TARGET_TYPE="manifest"
      TARGET_PATH="$2"
      shift 2
      ;;
    --helm)
      TARGET_TYPE="helm"
      TARGET_PATH="$2"
      shift 2
      ;;
    --kustomize)
      TARGET_TYPE="kustomize"
      TARGET_PATH="$2"
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

if [ -z "$TARGET_TYPE" ] || [ -z "$TARGET_PATH" ]; then
  usage
fi

echo "=========================================================="
echo "🚀 Initializing Ephemeral KinD Sandbox: $CLUSTER_NAME"
echo "Target Type: $TARGET_TYPE | Target: $TARGET_PATH"
echo "=========================================================="

# Check requirements
for bin in kind kubectl; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "✖ Error: '$bin' is required on PATH to run KinD sandbox tests."
    exit 1
  fi
done

# Setup safe isolated KUBECONFIG
ISOLATED_KUBECONFIG=$(mktemp -t kind-kubeconfig.XXXXXX)
export KUBECONFIG="$ISOLATED_KUBECONFIG"

cleanup() {
  echo ""
  echo "🧹 Teardown: Deleting ephemeral KinD cluster '$CLUSTER_NAME'..."
  kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
  rm -f "$ISOLATED_KUBECONFIG"
  echo "✔ Cleanup complete. Zero residual state on host."
}
trap cleanup EXIT

echo "ℹ Creating KinD cluster (1 control-plane, 1 worker)..."
cat << 'EOF' | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
EOF

echo "✔ KinD cluster '$CLUSTER_NAME' is ready."
kubectl get nodes -o wide

echo ""
echo "=========================================================="
echo "🧪 Executing Sandbox Verification Suite"
echo "=========================================================="

TEST_NS="sandbox-test"
kubectl create namespace "$TEST_NS"

case "$TARGET_TYPE" in
  manifest)
    echo "ℹ Performing server-side dry-run on manifest: $TARGET_PATH"
    kubectl apply -n "$TEST_NS" --server-side --dry-run=server -f "$TARGET_PATH"
    echo "ℹ Applying manifests to ephemeral sandbox..."
    kubectl apply -n "$TEST_NS" -f "$TARGET_PATH"
    ;;
  kustomize)
    echo "ℹ Building Kustomize overlay and testing server-side admission..."
    kubectl apply -n "$TEST_NS" --server-side --dry-run=server -k "$TARGET_PATH"
    echo "ℹ Deploying Kustomize overlay to ephemeral sandbox..."
    kubectl apply -n "$TEST_NS" -k "$TARGET_PATH"
    ;;
  helm)
    echo "ℹ Linting Helm chart..."
    helm lint "$TARGET_PATH" --strict
    echo "ℹ Installing Helm release into sandbox..."
    helm install test-release "$TARGET_PATH" --namespace "$TEST_NS" --wait --timeout=120s
    ;;
esac

echo ""
echo "ℹ Inspecting deployed resources in namespace '$TEST_NS':"
kubectl get all -n "$TEST_NS"

echo ""
echo "=========================================================="
echo "🎉 Sandbox test completed successfully with zero errors!"
echo "=========================================================="
