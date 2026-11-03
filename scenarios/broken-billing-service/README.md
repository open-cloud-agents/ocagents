# 🚨 Live-Fire Incident Drill: Billing Service Outage

Welcome to the **Open Cloud Agents Incident Response Sandbox**. This scenario contains a deliberately broken multi-service Kubernetes application designed for testing autonomous SRE triage and remediation.

---

## 📋 Incident Briefing: PagerDuty SEV-2 Alert (#INC-2026-11-409)

* **Impacted Service:** `billing-api`, `billing-cache`, and `billing-worker`
* **Namespace:** `demo-billing`
* **Symptoms:**
  * Ingress returning `HTTP 502 Bad Gateway` on all payment webhook endpoints.
  * `billing-cache` crashing continuously with Linux container exit code `137`.
  * `billing-worker` stuck in `CreateContainerConfigError` / `CrashLoopBackOff`.

---

## 🔬 Injected Failure States (Mapped to 25-Point K8s Matrix)

| Service | Failure State | Matrix Code | Root Cause |
|---|---|---|---|
| `billing-api-service` | `Service has no endpoints` | **State 17** | Service selector `app: billing-api-v2` mismatches pod label `app: billing-api`. |
| `billing-cache` | `OOMKilled (Exit Code 137)` | **State 02** | Python runtime allocates 30MiB while container cgroup limit is capped at 16MiB. |
| `billing-worker` | `CreateContainerConfigError` | **State 09** | Pod references environment variable from non-existent ConfigMap `billing-worker-config`. |

---

## 🚀 Interactive Walkthrough (Try It Live)

### Step 1: Deploy the Broken Scenario into an Ephemeral KinD Sandbox
Run the sandbox runner to spin up a local KinD cluster and deploy the broken workload:

```bash
ocagents sandbox --scenario scenarios/broken-billing-service/ --keep-cluster
```

Inspect the cluster state to observe the failures live:
```bash
kubectl get pods,svc,endpoints -n demo-billing
```

Expected output:
```text
NAME                                READY   STATUS                       RESTARTS
pod/billing-api-7b89f-2m4k1         1/1     Running                      0
pod/billing-cache-59df8-9xzl2       0/1     OOMKilled (137)              3
pod/billing-worker-84d7c-k98p1      0/1     CreateContainerConfigError   0

NAME                          TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   ENDPOINTS
service/billing-api-service   ClusterIP   10.96.142.108   <none>        80/TCP    <none>
```

---

### Step 2: Run Autonomous SRE Agent Triage
Invoke the Open Cloud Agents pipeline to diagnose the root causes and formulate the surgical patch:

```bash
ocagents run --task "Investigate and resolve all failing pods and ingress 502s in namespace demo-billing"
```

The multi-agent pipeline will:
1. **SRE Reliability Engineer:** Consults `skills/devops/kubernetes/k8s-pod-troubleshooting` and the 25-state matrix.
2. **DevSecOps Reviewer:** Audits `endpoints`, identifies the selector mismatch, memory cgroup limits, and missing ConfigMap.
3. **DevSecOps Engineer:** Emits the surgical patch.

---

### Step 3: Apply the Solution Patch & Verify Recovery
Apply the generated fix:

```bash
kubectl apply -f scenarios/broken-billing-service/solution-patch.yaml
```

Wait 5 seconds and verify the health of the namespace:
```bash
kubectl get pods,svc,endpoints -n demo-billing
```

All pods will report `Running (1/1)` and the service will show active endpoints:
```text
NAME                                READY   STATUS    RESTARTS   AGE
pod/billing-api-7b89f-2m4k1         1/1     Running   0          4m
pod/billing-cache-774f9-w3q21       1/1     Running   0          12s
pod/billing-worker-91b6c-8v11z      1/1     Running   0          10s

NAME                          TYPE        CLUSTER-IP      PORT(S)   ENDPOINTS
service/billing-api-service   ClusterIP   10.96.142.108   80/TCP    10.244.0.5:80,10.244.0.6:80
```

---

### Step 4: Teardown Sandbox
When finished, clean up the cluster with zero residual footprint on your workstation:

```bash
kind delete cluster --name $(kind get clusters | grep kind-sandbox | head -n 1)
```
