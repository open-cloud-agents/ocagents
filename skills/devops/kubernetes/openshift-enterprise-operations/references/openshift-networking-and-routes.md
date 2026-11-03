# OpenShift Networking, Routes & OVN-Kubernetes Egress

This reference covers the networking architecture of OpenShift Routes, HAProxy router tuning, and egress traffic control with the OVN-Kubernetes CNI plugin.

---

## 🌐 1. OpenShift Routes vs Kubernetes Ingress

OpenShift native `Route` CRDs are implemented by an internal HAProxy ingress router:

```text
               Client Request
                     │
                     ▼
             [HAProxy Ingress]
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
  Edge TLS      Re-encrypt     Passthrough
  (Decrypted)   (Re-encrypted) (Direct SSL)
       │             │             │
       ▼             ▼             ▼
  Pod (Port 80) Pod (Port 443) Pod (Port 8443)
```

### Insecure Edge Termination Policy

Always enforce automatic redirection from HTTP to HTTPS:

```yaml
spec:
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
```

---

## ⚡ 2. HAProxy Ingress Route Annotations

Tune route performance and prevent premature 504 timeouts:

```yaml
metadata:
  annotations:
    # Buffer slow API calls and large payload streaming:
    haproxy.router.openshift.io/timeout: 60s
    # Enable sticky sessions via cookies:
    router.openshift.io/cookie_name: "MYAPP_SESSION"
    # Rate limiting client connections:
    haproxy.router.openshift.io/rate-limit-connections: "true"
    haproxy.router.openshift.io/rate-limit-connections.rate-tcp: "100"
```

---

## 🔒 3. OVN-Kubernetes EgressIPs

When calling external firewalled partner APIs or legacy enterprise databases, pods must present a static, predictable outbound public IP address rather than arbitrary worker node IPs:

```yaml
apiVersion: k8s.ovn.org/v1
kind: EgressIP
metadata:
  name: payment-gateway-egress
spec:
  egressIPs:
    - 203.0.113.50
  namespaceSelector:
    matchLabels:
      env: production
      app: payments
```
*(All outbound egress packets originating from matching pods are SNAT'ed to `203.0.113.50` automatically by the OVN-Kubernetes network fabric).*
