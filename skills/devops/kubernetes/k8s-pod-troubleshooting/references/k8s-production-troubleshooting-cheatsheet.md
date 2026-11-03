# Kubernetes Production Triage Cheat Sheet: The 10 Non-Negotiables & 25 Failure States

This cheat sheet maps the 10 DevSecOps Non-Negotiables and the **25 Universal Kubernetes Production Failure States** directly to root causes, real-time diagnostic commands, and tactical remediations.

---

## 🚨 The 25 Production Failure States Triage Matrix

This master matrix maps the 25 universal Kubernetes failure states across Pod Crashes, Image & Configuration, Scheduling, Networking, and Storage & Access.

### 1. Pod Crashes (01–05)

| # | Error State | Outage Symptom | Root Cause | Triage Command | Immediate Remediation & Guardrail |
|---|---|---|---|---|---|
| **01** | `CrashLoopBackOff` | App keeps crashing; restart count increments exponentially. | Application runtime crash, uncaught exception, or rapid panic on startup. | `kubectl logs <POD> -n <NS> --previous --tail=50` | Fix runtime exception; add `startupProbe` if framework initialization exceeds liveness probe delay. |
| **02** | `OOMKilled (137)` | Process abruptly killed; Exit code `137`; sudden drop in available pods. | Container memory consumption exceeded cgroup `limits.memory` or node ran out of memory. | `kubectl describe pod <POD> \| grep -E "(OOMKilled\|Exit Code)"` | Profile memory leaks; set matching `requests.memory == limits.memory` for **Guaranteed QoS**. |
| **03** | `Init:Error` | Main application container never starts; pod stuck in `Init:0/1`. | Initialization container failed (e.g. database schema migration or secret fetch failed). | `kubectl logs <POD> -c <INIT_CONTAINER> -n <NS>` | Verify database migration scripts and external network reachability from init container. |
| **04** | `RunContainerError` | Container fails to start immediately; Exit code `2` or `127`. | Bad executable command in `command: []`, permission failure, or failed volume mount. | `kubectl describe pod <POD> -n <NS> \| grep -A 8 Events:` | Verify entrypoint binary exists in image; check securityContext user file write permissions. |
| **05** | `Liveness probe failed` | Pod killed and restarted periodically; cascading restart storm across fleet. | Health check failed or timed out (`timeoutSeconds`). External dependency checked in liveness. | `kubectl describe pod <POD> \| grep -A 5 "Liveness probe failed"` | **Invariant:** Never probe downstream databases in `livenessProbe`. Check dependencies only in `readinessProbe`. |

### 2. Image & Configuration (06–10)

| # | Error State | Outage Symptom | Root Cause | Triage Command | Immediate Remediation & Guardrail |
|---|---|---|---|---|---|
| **06** | `ErrImagePull` | Container cannot start; image download fails. | Incorrect image tag, private registry 401/403, or rate limit exceeded. | `kubectl describe pod <POD> \| grep -A 5 Events:` | Verify image tag exists in registry; attach valid `imagePullSecrets` to service account. |
| **07** | `ImagePullBackOff` | Continuous image pull retry loop with exponential backoff. | Persistent image pull failure (credentials, network block, or image deleted). | `kubectl get pod <POD> -o jsonpath='{.status.containerStatuses[*].state.waiting.message}'` | Test registry pull from worker node; verify VPC PrivateLink endpoint for container registry. |
| **08** | `InvalidImageName` | Pod rejected immediately by admission controller or kubelet. | Malformed image reference string, illegal characters, or floating untagged reference. | `kubectl get events -n <NS> --field-selector reason=Failed` | Fix image reference syntax in manifest (e.g. `repo/image:v1.2.3`); ban `:latest` in CI. |
| **09** | `CreateContainerConfigError` | Container blocked before start; config resolution failure. | Referenced `ConfigMap` or `Secret` is missing, misspelled, or in another namespace. | `kubectl describe pod <POD> \| grep -E "(ConfigMap\|Secret)"` | Provision missing ConfigMap/Secret; deploy External Secrets Operator to auto-sync. |
| **10** | `CreateContainerError` | Container runtime engine fails to initialize execution sandbox. | Linux cgroup allocation failure, invalid security context, or read-only filesystem trap. | `kubectl describe pod <POD> \| grep -A 5 "CreateContainerError"` | Mount writable `emptyDir` volume at `/tmp`; ensure non-root UID has access to workspace. |

### 3. Scheduling (11–15)

| # | Error State | Outage Symptom | Root Cause | Triage Command | Immediate Remediation & Guardrail |
|---|---|---|---|---|---|
| **11** | `Pending (0/N nodes available)` | Pod stays in `Pending` state indefinitely; zero replicas scheduled. | No node in cluster matches pod's resource requests, selector, or affinity rules. | `kubectl describe pod <POD> \| grep -A 10 Events:` | Inspect cluster autoscaler logs; verify if node pool is scaled to max quota. |
| **12** | `Insufficient cpu/memory` | New pods blocked; cluster scheduler cannot fit pods. | Cumulative `requests` across running pods consume 100% of allocatable node capacity. | `kubectl describe nodes \| grep -A 5 "Allocated resources:"` | Rightsize bloated pod requests; add worker node pool or trigger Karpenter autoscaling. |
| **13** | `Untolerated taint` | Specific dedicated nodes reject pod (`node(s) had untolerated taint`). | Worker node has a taint (e.g., `dedicated=gpu:NoSchedule`), and pod lacks matching toleration. | `kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints` | Add matching `tolerations: [{key: "dedicated", value: "gpu", effect: "NoSchedule"}]`. |
| **14** | `Node affinity mismatch` | Pod cannot schedule (`0/N nodes matched pod affinity/anti-affinity`). | `nodeSelector` or `nodeAffinity` requires labels that no active worker node possesses. | `kubectl get nodes --show-labels` | Harmonize pod `nodeSelector` with actual node labels; adjust topology spread constraints. |
| **15** | `Evicted` | Pod forcefully terminated; status shows `Evicted`. | Node memory, ephemeral disk, or PID capacity dropped below eviction threshold (`node.kubernetes.io/memory-pressure`). | `kubectl get pod <POD> -o jsonpath='{.status.message}'` | Clean up node ephemeral storage; assign Guaranteed QoS (`requests.memory == limits.memory`). |

### 4. Networking (16–20)

| # | Error State | Outage Symptom | Root Cause | Triage Command | Immediate Remediation & Guardrail |
|---|---|---|---|---|---|
| **16** | `Readiness probe failed` | Pod is `Running 1/1` but receives zero customer traffic (`Endpoints: <none>`). | Application initialization slow, downstream dependency down, or `/ready` endpoint failing. | `kubectl describe pod <POD> \| grep -A 5 "Readiness probe failed"` | Verify readiness endpoint health; buffer `initialDelaySeconds` and `periodSeconds`. |
| **17** | `Service has no endpoints` | HTTP 503 / connection drop when routing traffic through Kubernetes Service. | Service `spec.selector` labels do not match any running pods (`Endpoints: <none>`). | `kubectl get endpoints <SERVICE> -n <NS>; kubectl get pods --show-labels` | Match Service `selector` exactly with `pod.metadata.labels`; verify pod is passing readiness. |
| **18** | `Connection refused` | TCP `RST` received; `connect: connection refused` on inter-service call. | Target process crashed, listening on `127.0.0.1` instead of `0.0.0.0`, or port mismatch. | `kubectl debug -it <POD> --image=nicolaka/netshoot -- ss -tulpn` | Bind server process to `0.0.0.0`; ensure Service `targetPort` matches container `containerPort`. |
| **19** | `no such host (DNS)` | Sporadic 5-second latency spikes or unresolved service names. | CoreDNS single-threaded UDP conntrack race conditions under high throughput (> 10k QPS). | `kubectl logs -n kube-system ds/coredns --tail=50` | **Learned Fact:** Configure `dnsConfig.options` with `ndots: 2` and `single-request-reopen`; deploy NodeLocal DNSCache. |
| **20** | `502 / 503 from Ingress` | End users receive intermittent 502 Bad Gateway during rolling deployments. | `kube-proxy` routes in-flight requests to terminating pods before endpoint table sync. | `kubectl get ingress <NAME> -o yaml; kubectl logs -n ingress-nginx` | **Invariant:** Add `lifecycle.preStop: exec: command: ["/bin/sh", "-c", "sleep 10"]` to pod spec. |

### 5. Storage & Access (21–25)

| # | Error State | Outage Symptom | Root Cause | Triage Command | Immediate Remediation & Guardrail |
|---|---|---|---|---|---|
| **21** | `PVC Pending` | Pod stuck in `Pending`; persistent storage volume never binds. | No PersistentVolume matches PVC request; StorageClass does not support dynamic provisioning. | `kubectl describe pvc <PVC_NAME> -n <NS>` | Check `StorageClass` availability; verify storage quota and cloud provider CSI driver health. |
| **22** | `FailedMount / FailedAttachVolume` | Pod cannot start; events show `Volume is already exclusively attached to one node`. | Multi-Attach error for ReadWriteOnce (RWO) volume after node crash or cross-AZ migration. | `kubectl describe pod <POD> \| grep -E "(FailedMount\|FailedAttachVolume)"` | Force volume detachment from orphaned node; ensure StatefulSet pods pin to matching AZ. |
| **23** | `Forbidden (RBAC)` | API calls fail with `403 Forbidden: User cannot list resource in API group`. | `ServiceAccount` bound to pod lacks necessary RBAC `Role` / `ClusterRole` permissions. | `kubectl auth can-i <VERB> <RESOURCE> --as=system:serviceaccount:<NS>:<SA>` | Grant least-privilege `Role` and `RoleBinding` targeting specific API groups and verbs. |
| **24** | `Unauthorized (401)` | Client or cloud provider API calls rejected with `401 Unauthorized`. | Expired service account token, invalid kubeconfig certificate, or IRSA OIDC trust drift. | `kubectl get serviceaccount <SA> -o yaml; aws sts get-caller-identity` | Rotate kubeconfig credentials; verify Cloud IAM OIDC federation and service account annotations. |
| **25** | `Stuck in Terminating` | Namespace or pod cannot be deleted (`Terminating` state persists for hours). | Resource has hanging `metadata.finalizers` waiting on non-existent storage or admission webhook. | `kubectl get pod <POD> -o jsonpath='{.metadata.finalizers}'` | Remove zombie finalizer: `kubectl patch pod <POD> -p '{"metadata":{"finalizers":null}}'`. |

---

## ⚡ 10 Non-Negotiables Triage Matrix

| # | Non-Negotiable | Outage Symptom / Alert | Triage Command | Root Cause Indicator | Immediate Remediation |
|---|---|---|---|---|---|
| **1** | **Probes** | 502 Bad Gateway during rollout; Pod is `Running 1/1` but dropping requests. | `kubectl describe pod <NAME> \| grep -A 8 Conditions:` | `ContainersReady: False` or missing `readinessProbe`. | Add `readinessProbe` with proper `initialDelaySeconds`. Never check downstream DB in liveness. |
| **2** | **Resources** | Exit Code `137` (`OOMKilled`); slow API latency; random node evictions. | `kubectl describe pod <NAME> \| grep -E "(OOMKilled\|Exit Code)"` | `Last State: Terminated Reason: OOMKilled`. | Increase `resources.limits.memory` or match `requests == limits` for Guaranteed QoS. |
| **3** | **Autoscaling** | High CPU saturation (> 90%); request queuing; pod count remains static. | `kubectl get hpa; kubectl describe hpa <NAME>` | `unable to get metric` or `Target: <unknown>`. | Verify `metrics-server` health; fix HPA metric resource target. |
| **4** | **NetworkPolicy** | Connection timeout (`ETIMEDOUT`) between microservices; cross-namespace block. | `kubectl get networkpolicy -n <NS>; kubectl get pods -l app=<APP>` | Ingress rule missing source `podSelector` or `namespaceSelector`. | Add explicit allow rule for calling service pod label and port. |
| **5** | **PDB** | Node drain hangs indefinitely; `kubectl drain` fails; voluntary eviction blocked. | `kubectl get pdb -n <NS>; kubectl describe pdb <NAME>` | `DisruptionsAllowed: 0` with `minAvailable == replicas`. | Set `maxUnavailable: 1` or `maxUnavailable: 25%` and increase replica count $\ge 2$. |
| **6** | **SecurityContext** | Pod fails admission with `PodSecurityViolation`; `CrashLoopBackOff` on file write. | `kubectl get events -n <NS> --field-selector reason=FailedCreate` | `violates PodSecurity "restricted": runAsNonRoot != true`. | Add non-root UID (`runAsUser: 10001`) and mount `emptyDir` at `/tmp` for scratch writes. |
| **7** | **Observability** | Pod crashed with no logs; silent error rate spikes without alerting. | `kubectl logs <NAME> --previous --tail=50` | Empty logs; missing structured JSON formatting; collector drop. | Route logs to DaemonSet collector (Fluent Bit / Vector) and verify OTel pipeline. |
| **8** | **Image Security** | `ImagePullBackOff` or `ErrImagePull`; admission webhook rejects unsigned image. | `kubectl describe pod <NAME> \| grep -A 5 Events:` | `cosign: signature verification failed` or registry auth error. | Verify image signature with Cosign and configure valid `imagePullSecrets`. |
| **9** | **Secrets** | Pod crashes with missing env vars; database authentication failure (`401`). | `kubectl get externalsecret -n <NS>; kubectl describe es <NAME>` | `SecretSynced: False` or SecretStore auth failure. | Verify SecretStore IAM / IRSA permissions and refresh token. |
| **10** | **Rollouts** | 502 errors during deployment; in-flight requests dropped upon container termination. | `kubectl rollout history deployment/<NAME>; kubectl describe deploy/<NAME>` | Missing `preStop: sleep 10` hook or `maxUnavailable > 0`. | Add `preStop` hook to container lifecycle; run `kubectl rollout undo deployment/<NAME>`. |

---

## 🛠️ Step-by-Step Diagnostic Recipes

### 1. Diagnosing Probe Failures & Traffic Dropping

```bash
# Check probe definitions and recent probe event failures
kubectl describe pod <POD_NAME> -n <NAMESPACE> | grep -E "(Liveness|Readiness|Startup|Unhealthy)"

# Inspect pod IP endpoint registration in the backing Service
kubectl get endpoints <SERVICE_NAME> -n <NAMESPACE>

# Test readiness endpoint directly from inside the cluster
kubectl run probe-test --rm -it --image=curlimages/curl -- curl -Iv http://<POD_IP>:8080/ready
```

### 2. Diagnosing OOMKilled & Resource Throttling

```bash
# Check if container was terminated due to OOM
kubectl get pod <POD_NAME> -n <NAMESPACE> -o jsonpath='{range .status.containerStatuses[*]}{.name}{": "}{.lastState.terminated.reason}{" (exit: "}{.lastState.terminated.exitCode}{")\n"}{end}'

# Check real-time CPU & memory consumption
kubectl top pod <POD_NAME> -n <NAMESPACE> --containers

# Check container cgroup memory limits from inside the node
kubectl exec -it <POD_NAME> -n <NAMESPACE> -- cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes
```

### 3. Diagnosing NetworkPolicy Blocks

```bash
# Check active NetworkPolicies in the target namespace
kubectl get networkpolicy -n <NAMESPACE> -o wide

# Test TCP socket connectivity using ephemeral netshoot container
kubectl debug -it <POD_NAME> -n <NAMESPACE> --image=nicolaka/netshoot -- nc -zvw3 <TARGET_SERVICE> 8080

# Check Cilium / Calico drop logs (if CNI supports eBPF tracing)
kubectl exec -n kube-system ds/cilium -- cilium monitor --type drop
```

### 4. Diagnosing PDB Eviction Deadlocks

```bash
# Identify which PDB is blocking node drains
kubectl get pdb -A -o wide

# Check disruptive allowance on target service
kubectl describe pdb <PDB_NAME> -n <NAMESPACE>

# Safe drain override (in non-production emergencies only)
kubectl drain <NODE_NAME> --ignore-daemonsets --delete-emptydir-data --force --disable-eviction
```

### 5. Executing Safe Zero-Downtime Rollbacks

```bash
# Check rollout revision history
kubectl rollout history deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# Revert to the immediately preceding stable revision
kubectl rollout undo deployment/<DEPLOYMENT_NAME> -n <NAMESPACE>

# Monitor rollback status until completion
kubectl rollout status deployment/<DEPLOYMENT_NAME> -n <NAMESPACE> --timeout=120s
```

---

## 📚 References

- [k8s-pod-diagnostic-decision-tree.md](k8s-pod-diagnostic-decision-tree.md): Diagnostic decision tree and Linux exit code reference.
- [k8s-production-non-negotiables.md](../../helm-chart-scaffold/references/k8s-production-non-negotiables.md): The 10 DevSecOps Production Non-Negotiables.
