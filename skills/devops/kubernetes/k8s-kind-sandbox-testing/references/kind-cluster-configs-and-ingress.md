# KinD Multi-Node Configurations, Ingress & Registry Mirrors

This reference provides production-tested KinD cluster manifests and ingress setup scripts for isolated sandbox testing.

---

## 🏗️ 1. Multi-Node KinD Cluster with Ingress Port Mappings

Save as `kind-config-ingress.yaml`:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
    extraPortMappings:
      - containerPort: 80
        hostPort: 80
        protocol: TCP
      - containerPort: 443
        hostPort: 443
        protocol: TCP
  - role: worker
  - role: worker
```

### Spin up the cluster:
```bash
kind create cluster --name sandbox-ingress --config kind-config-ingress.yaml
```

---

## 🌐 2. Deploy Ingress-NGINX to KinD

Deploy the official KinD-optimized NGINX ingress controller:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

# Wait for Ingress controller readiness:
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=90s
```

Now any `Ingress` resource with `ingressClassName: nginx` will route HTTP traffic hitting `http://localhost/` directly to your backing test service.

---

## 📦 3. Sideloading Local Docker/Podman Images into KinD

Avoid pushing dirty or work-in-progress images to external cloud registries:

```bash
# 1. Build image locally:
docker build -t local-app:v1 .

# 2. Sideload image into KinD worker nodes:
kind load docker-image local-app:v1 --name sandbox-ingress

# 3. Reference in Pod spec with:
#    image: local-app:v1
#    imagePullPolicy: IfNotPresent
```
