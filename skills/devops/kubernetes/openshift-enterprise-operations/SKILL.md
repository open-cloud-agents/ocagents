---
name: openshift-enterprise-operations
description: Operate, secure, and troubleshoot enterprise Red Hat OpenShift Container Platform (OCP/ROSA/ARO) workloads covering Security Context Constraints (SCC), Routes, ImageStreams, Operator Lifecycle Manager (OLM), and MachineConfigPools.
---

# Red Hat OpenShift Enterprise Operations & Workload Hardening

## Purpose & Scope

This skill provides architectural guidance, security baselines, and troubleshooting runbooks for **Red Hat OpenShift Container Platform (OCP)**, **Red Hat OpenShift Service on AWS (ROSA)**, and **Azure Red Hat OpenShift (ARO)**. It guides engineers through the 5 core OpenShift operational domains: **Security Context Constraints (SCC), OpenShift Routes, ImageStreams/S2I, Operator Lifecycle Manager (OLM), and MachineConfigPool node management**.

---

## 🏛️ OpenShift Architecture vs Upstream Kubernetes

OpenShift extends Kubernetes with enterprise security and platform tooling:

```text
OpenShift Workload Architecture:
┌────────────────────────────────────────────────────────┐
│ OpenShift Route (HAProxy router, TLS Edge/Passthrough) │
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ Kubernetes Service (ClusterIP)                         │
└──────────────────────────┬─────────────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ Pod (Enforced by Security Context Constraints - SCC)   │
│ • Random allocated UID/GID (openshift.io/sa.scc.uid)   │
│ • Default restricted-v2 policy                         │
└────────────────────────────────────────────────────────┘
```

---

## 🚨 The 5 OpenShift Production Non-Negotiables

### 1. Security Context Constraints (SCC) Hierarchy
* **The Rule:** By default on OpenShift 4.12+, all workloads run under the `restricted-v2` SCC, which mandates non-root execution, random allocated UIDs, dropped capabilities, and read-only root filesystems.
* **The Danger:** Granting `anyuid` or `privileged` SCC to a service account grants root privileges and bypasses OpenShift's multi-tenant isolation.
* **Remediation:** Build containers that can run with an arbitrary assigned UID (`USER 1001` or arbitrary non-root). Never bind `privileged` SCC unless deploying kernel-level host monitoring daemonsets.

### 2. Routes vs Kubernetes Ingress (TLS Termination Models)
OpenShift Routes use an internal HAProxy routing tier with three explicit TLS termination modes:
* **Edge Termination:** TLS terminates at the HAProxy router; unencrypted traffic is routed to pod.
* **Re-encrypt Termination:** TLS terminates at router, health is inspected, and new TLS session is established to pod with internal certificate.
* **Passthrough Termination:** TLS traffic flows untouched directly to pod; certificate is managed by the application.

```yaml
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: secure-app-route
spec:
  to:
    kind: Service
    name: secure-app-service
  tls:
    termination: reencrypt
    insecureEdgeTerminationPolicy: Redirect
```

### 3. ImageStreams, Triggers & Builds
* **The Rule:** Decouple deployment manifests from external registry image URLs by using OpenShift `ImageStreams` and `ImageChange` deployment triggers.
* **Best Practice:** Keep production ImageStreams pinned to image digests (SHA-256) rather than floating tags.

### 4. Operator Lifecycle Manager (OLM)
* **The Rule:** Manage all platform operators (Cert-Manager, OpenShift Virtualization, Red Hat Advanced Cluster Management) via OLM.
* **Production Guardrail:** Enforce `installPlanApproval: Manual` on production operator subscriptions to prevent unexpected major operator upgrades during business hours.

### 5. MachineConfig & OS Immutability (Red Hat Enterprise Linux CoreOS)
* **The Rule:** Never SSH into RHCOS worker nodes to modify `/etc` or apply manual sysctl parameters.
* **Remediation:** Manage all kernel parameters, container runtime settings, and authorized keys declaratively using `MachineConfig` CRDs applied to `MachineConfigPools` (`worker` or `master`).

---

## 🛠️ Step-by-Step Triage & Verification Workflow

- [ ] 1. **Check Project & Active Cluster Context:**
  ```bash
  oc project <PROJECT_NAME>
  oc status
  ```
- [ ] 2. **Audit Workload SCC Allocation:**
  ```bash
  ./scripts/audit_openshift_scc.sh <PROJECT_NAME>
  ```
- [ ] 3. **Inspect Pod Admission SCC Assignment:**
  ```bash
  oc get pod <POD_NAME> -o jsonpath='{.metadata.annotations.openshift\.io/scc}'
  ```
- [ ] 4. **Triage Route Health & Endpoints:**
  ```bash
  oc describe route <ROUTE_NAME>
  oc get endpoints <SERVICE_NAME>
  ```

---

## ⚠️ Known Edge Cases & Production Traps

* **`CreateContainerError` (Permission Denied on `/var/run` or `/tmp`):** OpenShift runs containers as an arbitrary high UID (e.g. `1000670000`) assigned by the project's namespace annotation. If the container image hardcoded `USER 1000` with restrictive root directory permissions, writes fail. Fix by adding `chown -R 0 /app && chmod -R g=u /app` in the Dockerfile.
* **Route 504 Gateway Timeout:** HAProxy router defaults to a 30s timeout. Long-running REST or streaming endpoints fail with 504. Apply the annotation: `haproxy.router.openshift.io/timeout: 60s`.
* **MachineConfigPool Degradation Lock:** Modifying a MachineConfig triggers a rolling node drain and reboot. If a PodDisruptionBudget (PDB) blocks node eviction, the `MachineConfigPool` enters `Degraded: True` state.

---

## 📚 References & Scripts

* [openshift-scc-and-security.md](references/openshift-scc-and-security.md): Security Context Constraints deep-dive and rolebindings.
* [openshift-networking-and-routes.md](references/openshift-networking-and-routes.md): Route TLS architectures and OVN-Kubernetes egress IP policies.
* [audit_openshift_scc.sh](scripts/audit_openshift_scc.sh): Automated SCC privilege escalation auditor.

