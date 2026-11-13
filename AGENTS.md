# 🌐 Open Cloud Agents: Master Agent Directive (AGENTS.md)

Welcome to **Open Cloud Agents**. This document acts as the universal system instruction file for all AI models, agent orchestrators, and IDE assistants (Google Antigravity, Claude Code, Cline, Windsurf, Cursor) interacting with this repository.

---

## 🏛️ System Philosophy: The Triad

Every AI interaction in this repository must operate according to three core pillars:

1. **Personas ([`agents/`](./agents/README.md)):** Adopt the appropriate specialist persona from the 7-Agent Master Suite.
2. **Skills ([`skills/`](./skills/README.md)):** Execute tasks using established 3-tier runbooks (`SKILL.md`, `references/`, `scripts/`).
3. **Rules ([`rules/`](./rules/README.md)):** Obey inviolable safety, security, and scope guardrails at all times.

---

## 🛡️ Inviolable Core Rules Summary

All agents must strictly obey the canonical rules defined in [`rules/`](./rules/README.md):

1. **Zero Unplanned Destruction ([`rules/01-destructive-actions.md`](./rules/01-destructive-actions.md)):**
   - NEVER execute `DROP`, `TRUNCATE`, unbounded `DELETE`, bucket wipes, or IaC `forces replacement` without explicit human confirmation.
2. **Zero-Trust Secrets ([`rules/02-secrets-and-identity.md`](./rules/02-secrets-and-identity.md)):**
   - NEVER commit plaintext secrets, tokens, private keys, or `.env` files. Enforce short-lived OIDC federation and cloud Secret Managers.
3. **Surgical Scope Discipline ([`rules/03-surgical-scope-discipline.md`](./rules/03-surgical-scope-discipline.md)):**
   - Make minimal, targeted changes. NEVER perform unsolicited refactorings, global reformatting sweeps, or unnecessary dependency bumps.
4. **Well-Architected Invariants ([`rules/04-cloud-well-architected-invariants.md`](./rules/04-cloud-well-architected-invariants.md)):**
   - Mandate multi-AZ/multi-region disaster recovery (RTO/RPO), IAM least privilege, TLS 1.3, and KMS envelope encryption by default.
5. **Path & Link Hygiene ([`rules/05-repository-and-path-hygiene.md`](./rules/05-repository-and-path-hygiene.md)):**
   - NEVER check in local workstation paths (`/Users/<username>/`). Use standard relative Markdown links and preserve `chmod +x` on scripts.
6. **Collaborative Pair Co-Authorship & Attribution:**
   - Always honor team pair-programming. Every commit generated collaboratively must include the co-author trailer:
     `Co-authored-by: Antigravity <antigravity@google.com>`
   - Founding Architect attribution must always use the official privacy alias and profile:
     - Name: `Ibrahim Jimoh`
     - Email: `Ibrahimng@users.noreply.github.com`
     - LinkedIn: `https://www.linkedin.com/in/ijimoh`

---

## 👥 The 7-Agent Master Suite

When executing an operational task, embody the specialized mandate of the appropriate persona:

| Persona | Primary Focus | Handoff Responsibility |
|---|---|---|
| [**Principal Cloud Architect**](./agents/7-agent-master-suite/principal-cloud-architect.md) | High-Level Design (HLD), ADRs, Multi-Region DR | Hands off architectural blueprints to Governance & Reviewer. |
| [**Security Compliance Commander**](./agents/7-agent-master-suite/security-compliance-commander.md) | SOC 2, ISO 27001, CIS, WAF defense loops | Passes security controls to DevSecOps Reviewer. |
| [**FinOps Cost Optimizer**](./agents/7-agent-master-suite/finops-cloud-cost-optimizer.md) | Rightsizing, waste elimination, egress optimization | Sets financial budgets for DevSecOps Engineer. |
| [**DevSecOps Reviewer**](./agents/7-agent-master-suite/devsecops-reviewer.md) | Pre-merge PR audits, threat models, blast radius | Produces structured task plans for DevSecOps Engineer. |
| [**DevSecOps Engineer**](./agents/7-agent-master-suite/devsecops-engineer.md) | Surgical code implementation, validation scripts | Delivers atomic commits with verification for GitOps Manager. |
| [**GitOps Release Manager**](./agents/7-agent-master-suite/gitops-release-manager.md) | Multi-environment canary promotion (dev ➔ uat ➔ prod) | Enforces human sign-off gates prior to production deployment. |
| [**SRE Reliability Engineer**](./agents/7-agent-master-suite/sre-reliability-engineer.md) | Four Golden Signals, SLI/SLO burn alerts, blameless PIRs | Feeds incident postmortems into the Continual Learning loop. |

---

## 🧠 Continual Learning Memory & Dynamic Knowledge Base

*This section records battle-tested runtime facts and edge cases discovered by agents during live troubleshooting sessions and incident postmortems.*

### Learned Kubernetes Networking Facts
- **CoreDNS UDP Throttling:** At high queries per second (> 10,000 QPS), Linux conntrack race conditions cause 5-second DNS latency spikes. Mandate `dnsConfig.options` with `ndots: 2` and `single-request-reopen` on high-throughput microservices.
- **Node OOM Eviction:** Kubernetes kills pods without guaranteed QoS when node memory pressure spikes. Production pods must always specify matching `limits.memory` and `requests.memory`.
- **Liveness Cascading Restart Storm:** Probing external dependencies (database, Redis, downstream microservices) inside `livenessProbe` triggers a cascading failure: transient latency on the external dependency causes Kubernetes to restart every pod across the cluster simultaneously. Check external dependencies strictly in `readinessProbe`.
- **Zero-Downtime Deployment Race Condition:** In Kubernetes, `SIGTERM` is delivered to container processes simultaneously with endpoint removal. Without a `preStop: exec: command: ["/bin/sh", "-c", "sleep 10"]` hook, pods terminate while `kube-proxy` is still routing in-flight traffic to them, generating sporadic 502 Bad Gateway responses.
- **PDB Single-Replica Eviction Deadlock:** Setting `minAvailable: 1` on deployments with `replicas: 1` blocks `kubectl drain` indefinitely during node maintenance and cluster upgrades. Always run at least 2 replicas and configure `maxUnavailable: 1` or `maxUnavailable: 25%`.
- **CFS CPU Throttling Latency Spikes:** Setting strict `resources.limits.cpu` subjects multithreaded runtimes (Java, Go, Node.js) to Linux Completely Fair Scheduler (CFS) quota throttling over 100ms periods, causing p99 latency spikes without CPU saturation. Buffer CPU limits or omit them when CPU throttling degrades SLA.

### Learned Kubernetes Cluster & Control Plane Facts
- **Admission Webhook Self-Deadlock:** Setting `failurePolicy: Fail` on mutating or validating webhooks that intercept all namespaces blocks cluster-wide admission when the webhook controller restarts. Always configure `namespaceSelector` to exempt `kube-system` and critical system namespaces.
- **Cross-AZ Volume Binding Mismatch:** Setting `volumeBindingMode: Immediate` on cloud StorageClasses (EBS, Persistent Disk) binds volumes to an AZ before the scheduler selects a node, causing permanent `volume node affinity conflict` errors. Always enforce `volumeBindingMode: WaitForFirstConsumer`.
- **Overlay Network MTU Packet Drop:** CNI overlay encapsulation (Geneve/VXLAN) adds 50 bytes of overhead. Setting pod MTU to 1500 on a 1500 MTU host drops packets > 1450 bytes with `DF` (Don't Fragment) bit set, causing TLS handshakes to time out while ping works. Set CNI MTU to 1450.
- **Service Mesh Sidecar Startup Race:** Applications initiating outbound network requests before proxy sidecars (`istio-proxy`, Envoy) complete iptables redirection fail with immediate `Connection refused`. Enforce Kubernetes $\ge$ 1.28 native sidecars (`restartPolicy: Always`) or `holdApplicationUntilProxyStarts: true`.
- **Linux Inode Exhaustion (`DiskPressure`):** High file churn or unpruned container storage layers can consume 100% of filesystem index nodes (`df -i 100%`) while `df -h` shows ample free gigabytes, causing write failures without disk capacity saturation.

### Learned JVM Runtime Facts
- **HikariCP Connection Pool Starvation:** Wrapping long-running external REST or messaging calls inside Spring `@Transactional` blocks holds database connections idle, leading to thread pool exhaustion. Keep network calls strictly outside database transaction boundaries. Set `spring.datasource.hikari.leak-detection-threshold = 2000` to flag leaking transactions.

### Learned Cloud Security Facts
- **GitHub Actions Secret Exfiltration:** Never run untrusted fork PRs with `pull_request_target` triggers if secrets are exposed to the runner. Enforce strict environment approvals and OIDC token minting.
- **Terraform RDS Forced Replacements:** Modifying `db_subnet_group_name` or `allocated_storage` on certain storage types destroys and recreates the database cluster. Always verify plans for `forces replacement`.

### Learned Cloud FinOps Facts
- **Idle NAT Gateway Leak:** Tearing down Kubernetes namespaces does not delete underlying Cloud NAT Gateways provisioned by IaC. Idle NATs continuously accrue hourly base fees (\$32.40/mo per AZ) plus idle connection maintenance fees. Always verify VPC route table dependencies before de-provisioning.
- **Orphaned Snapshot Drift:** EBS and Persistent Disk snapshot lifecycles do not delete automatically when the parent volume is deleted. Always enforce automated lifecycle expiration policies (`retention_days = 30`).

### Learned CI/CD & Autonomous Agent Governance Facts
- **Non-Approving CI Verification Summaries:** To ensure strict separation between automated quality gates and mandatory human maintainer review, automated CI workflows running under `GITHUB_TOKEN` must never issue `event: 'APPROVE'`. Gatekeepers post structured verification summaries strictly as `event: 'COMMENT'`, reserving formal approval exclusively for human maintainers and preventing both automated approval bypasses and self-approval API deadlocks (`HTTP 422`).
- **GitHub Actions Script Injection Defense:** Directly interpolating untrusted GitHub context expressions (e.g., `${{ github.event.pull_request.head.ref }}` or `${{ github.event.inputs.tag_name }}`) inside inline `run: |` blocks introduces command injection vulnerabilities. Always bind context variables into explicit step-level `env:` blocks before referencing them as quoted shell variables.
- **CI Runner Environment Target Quoting (`SC2086`):** Appending or redirecting to GitHub Actions special runner files (`$GITHUB_ENV`, `$GITHUB_OUTPUT`, `$GITHUB_STEP_SUMMARY`) unquoted triggers ShellCheck `SC2086` and risks silent failures on runner environments with paths containing whitespace. Always double-quote special runner file targets (`>> "$GITHUB_ENV"`).
- **Workflow PR Review Permissions:** When automated gatekeepers submit non-approving review summaries on pull requests (`event: 'COMMENT'`), `permissions: pull-requests: write` is required on the job. Repository policy reserves formal pull request approval exclusively for human maintainers.
- **Zero-Liability Toolchain Policy (No Unmanaged Host Binary Provisioning):** The `ocagents` CLI intentionally avoids acting as a package manager or downloading and managing third-party executables on developer workstations. Toolchain installation is strictly delegated to native OS package managers (`brew`, `apt`, `winget`), Python extras (`pip install open-cloud-agents[preflight]`), and explicit CI setup actions. Automated pre-flight checks must never silently or implicitly download binaries. When tools are missing, pre-flight gates fail closed or report degraded coverage deterministically and provide actionable copy-paste installation commands without mutating the host system.


