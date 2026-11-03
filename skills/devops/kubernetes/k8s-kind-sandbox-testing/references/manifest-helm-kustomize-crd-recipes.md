# Sandbox Test Recipes: Manifests, Kustomize, Helm, CRDs & Krew

This reference provides exact command sequences for validating Kubernetes artifacts inside an isolated KinD cluster.

---

## 📄 1. Raw Manifest & Kustomize Overlay Recipes

### Validate Overlay Hydration & Patch Application
```bash
# Verify that Kustomize builds cleanly without syntax errors:
kustomize build overlays/production > /tmp/hydrated-prod.yaml

# Server-side validation against live API server admission:
kubectl apply --server-side --dry-run=server -f /tmp/hydrated-prod.yaml

# Live deployment into a dedicated test namespace:
kubectl create namespace test-sandbox
kubectl apply -n test-sandbox -f /tmp/hydrated-prod.yaml

# Assert rollout status:
kubectl rollout status -n test-sandbox deployment/my-app --timeout=60s
```

---

## ⛵ 2. Helm Chart Validation Recipes

### Validate Helm Values Schemas & Upgrades
```bash
# 1. Lint chart and schema:
helm lint charts/my-chart/ --strict

# 2. Test chart installation with values overrides:
helm install test-release charts/my-chart/ \
  --namespace test-helm --create-namespace \
  --set replicaCount=3 \
  --wait --timeout=90s

# 3. Test seamless chart upgrade:
helm upgrade test-release charts/my-chart/ \
  --namespace test-helm \
  --set replicaCount=5 \
  --wait --timeout=90s

# 4. Run test pods:
helm test test-release -n test-helm
```

---

## 🧩 3. Custom Resource Definition (CRD) Testing

### Testing Schema Registration & Conversion
```bash
# 1. Apply CRD definition:
kubectl apply -f crds/mycustomresource.crd.yaml

# 2. Wait for CRD to be established in API server:
kubectl wait --for condition=established --timeout=30s crd/mycustomresources.example.com

# 3. Apply sample Custom Resource instance:
kubectl apply -f examples/cr-instance.yaml

# 4. Verify custom resource state:
kubectl get mycustomresources -o yaml
```

---

## 🔌 4. Kubectl Krew Plugin Auditing

Test kubectl plugins against live workloads in the sandbox:

```bash
# Clean YAML manifests (strip status, creationTimestamp, uid):
kubectl neat -f deployment.yaml

# Check RBAC capabilities for a service account:
kubectl who-can delete pods -n test-sandbox

# Visualize resource ownership trees:
kubectl tree deployment my-app -n test-sandbox
```
