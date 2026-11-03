# OpenShift Security Context Constraints (SCC) & Workload Security

This reference details the mechanics of Security Context Constraints (SCC) in Red Hat OpenShift and how they map to upstream Kubernetes Pod Security Standards (PSS).

---

## 🏛️ 1. SCC Hierarchy in OpenShift 4

| SCC Name | Privilege Level | Use Case | Security Characteristics |
|---|---|---|---|
| **`restricted-v2`** | Lowest (Default) | Standard tenant applications | Random UID allocated from project namespace, drops ALL capabilities, read-only root FS, seccomp `RuntimeDefault`. |
| **`restricted`** | Legacy Low | Pre-OpenShift 4.11 default | Random UID, drops all capabilities except `KILL`, `MKNOD`, `SETGID`, `SETUID`. |
| **`nonroot-v2`** | Medium | Workloads requiring defined non-root UID | Allows specified `runAsUser` $> 0$; drops capabilities. |
| **`anyuid`** | High | Legacy images requiring UID 0 | Allows root execution inside container; prohibited in multi-tenant environments. |
| **`privileged`** | Maximum | Node agents, CNI plugins, CSI drivers | Full host root access, host networking, host PID, all Linux capabilities. |

---

## 🔍 2. Diagnosing SCC Admission Failures

When a pod fails admission or is denied execution:

```bash
# 1. Identify which SCC the pod was admitted under:
oc get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{.metadata.annotations.openshift\.io/scc}{"\n"}'

# 2. Check the namespace UID range:
oc get project <NAMESPACE> -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.uid-range}{"\n"}'

# 3. Audit which ServiceAccounts have elevated SCC bindings:
oc get clusterrolebindings,rolebindings -A -o json | jq -r '
  .items[] | select(.roleRef.name | test("scc:anyuid|scc:privileged")) |
  "\(.metadata.namespace // "cluster") -> \(.metadata.name): \(.subjects[].name)"'
```

---

## 🛡️ 3. Safe Container Packaging for OpenShift

To ensure container images run seamlessly under `restricted-v2`:

```dockerfile
# Standard OpenShift Non-Root Dockerfile Pattern:
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

WORKDIR /app
COPY . .

# Set directory ownership to root group (GID 0) and grant group write permissions:
RUN chown -R 1001:0 /app && \
    chmod -R g=u /app

USER 1001
EXPOSE 8080
CMD ["./app"]
```
*(OpenShift runs containers with an arbitrary UID, but always binds the container to GID 0).*
