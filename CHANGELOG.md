# 📜 Changelog

All notable changes to **Open Cloud Agents** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.3.2] - 2026-11-04

### 🎨 CLI Registry Banner Integration & Adaptive Terminal Formatting

This maintenance release integrates the stylized `OCA` ANSI Shadow terminal banner into the primary `ocagents list` command and enhances terminal header formatting across all CLI entry points.

---

### ✨ Added & Improved

* **Registry Header Banner (`ocagents list`):** Connected `get_cli_header()` directly to `ocagents list` and `oca ls`, displaying the stylized circuit-node `OCA` ASCII banner and version header above the 7-Agent Master Suite Registry.
* **Banner Formatting Robustness:** Added automated newline stripping (`OCA_ASCII_BANNER.strip("\n")`) within `get_cli_header()` to guarantee consistent single-line vertical padding across all terminal themes and ANSI/non-TTY modes.
* **Distribution Manifest Alignment:** Bumped package release manifests to `1.3.2` across Homebrew (`Formula/ocagents.rb`), Alpine Linux (`APKBUILD`), Windows Winget (`manifest.yaml`), PyPI (`pyproject.toml`), and local launchers.

---

## [1.3.1] - 2026-11-04

### 🚀 KinD Ephemeral Sandboxing, Continual Learning Ingestion, and High-Trust Engineering Standards

This release introduces first-class KinD (Kubernetes in Docker) sandbox testing, automated continual learning ingestion for runtime edge cases, rigorous engineering standards calibration, and a stylized CLI terminal banner.

---

### ✨ Added

#### 1. First-Class KinD Sandbox Testing Engine (`ocagents sandbox`)
* **Ephemeral Cluster Execution:** Launch short-lived, hermetic KinD clusters across Kubernetes versions v1.29.4, v1.30.2, and v1.31.0 for rapid validation of Kubernetes manifests, Helm charts, and Kustomize overlays.
* **Incident Scenario Triage:** Integrated support for deploying live failure scenarios (e.g. billing service outages) for interactive agent-assisted triage with `--keep-cluster` and `--scenario`.
* **CI Matrix Testing:** Multi-version GitHub Actions workflow (`.github/workflows/kind-matrix-ci.yml`) validating deployments across multiple Kubernetes releases.
* **KinD Sandbox Testing Skill ([`skills/kubernetes/kind-sandbox-testing/`](./skills/kubernetes/kind-sandbox-testing/SKILL.md)):** 3-tier runbook covering manifest dry-run, ingress-nginx configuration, CRD verification, and Krew plugin testing.

#### 2. Continual Learning Runtime Ingestion (`ocagents learn`)
* **Incident Postmortem Ingestion:** Standalone CLI capability to ingest runtime edge cases, postmortems, or operator-discovered failure modes directly into `AGENTS.md` Dynamic Knowledge Base.
* **Safe Category Targeting:** Automatically organizes learned facts under categorized headings (e.g. Kubernetes Networking, Control Plane, FinOps, CI/CD Governance) with `--dry-run` safety preview.

#### 3. Stylized Terminal Header & ASCII Branding
* **Canonical `OCA` Banner:** Integrated compact ANSI Shadow terminal banner into `ocagents` CLI, delivering high-legibility circuit/node ASCII art across `ocagents --help`, `ocagents version`, and `ocagents info`.
* **Adaptive Terminal Formatting:** Honors `NO_COLOR` and non-TTY stdout streams with clean ASCII fallback.

#### 4. Enterprise Hardening & Infrastructure Operations Skills
* **Ansible System Hardening ([`skills/systems/ansible-hardening/`](./skills/systems/ansible-hardening/SKILL.md)):** Production playbooks for CIS OS hardening, OpenSCAP compliance, SSH cipher suites, and auditd configurations.
* **OpenShift Operations ([`skills/kubernetes/openshift/`](./skills/kubernetes/openshift/SKILL.md)):** Enterprise OpenShift 4.x runbooks for SCCs, MachineConfigPools, ingress routers, and operator triage.
* **Production Failure States & Runbooks:** Codified 25-point Kubernetes production failure states triage matrix and cluster control plane failure recovery runbooks.

---

### 🛡️ Security & Governance

* **Non-Approving CI Quality Gates:** Enforced strict separation between automated CI verification and human peer review in `.github/workflows/autonomous-gatekeeper.yml`. Automated gatekeeper reviews submit structured reports exclusively as non-approving comments (`event: 'COMMENT'`), strictly reserving formal PR approval for human maintainers.
* **Fail-Closed Diff Auditor (`scripts/ci/audit_pr_diff.py`):** Upgraded pre-merge heuristic auditor to fail closed (`NEEDS_REVIEW`) if Git diff execution fails or output cannot be verified.
* **Dynamic Gate Status Reporting:** Pre-merge verification summaries now dynamically distinguish passed checks from conditionally skipped jobs.

---

### 🔄 Changed & Calibrated

* **Engineering Standards ([`docs/engineering-standards.md`](./docs/engineering-standards.md)):** Re-scoped all claims to match Beta project maturity (`Development Status :: 4 - Beta`). Accurately documented that `ocagents run` is currently a local scripted simulation producing example stage results, clarified spec validator boundaries, and reframed destructive action rules as agent behavioral policy requiring host environment controls.
* **Interactive Demo Onboarding:** Re-anchored documentation landing page (`docs/index.md`) and `README.md` around the safe, local-first interactive demo sandbox.
* **Package Version:** Bumped project version to `1.3.1` across `pyproject.toml`, CLI modules, package manifests, and distribution scripts.

---

## [1.3.0] - 2026-10-28

### 🛡️ Runtime Threat Detection, CIS Complete Audit, and AI Governance & LLM Safety Suites
This major feature release introduces an enterprise-grade **Cloud Security, Runtime Threat Detection, and Compliance Ecosystem** across merged Pull Request #25. It integrates CNCF eBPF kernel security with **Falco & Falco Talon**, **Sysdig** CNAPP drift control, **Wazuh** enterprise SIEM/XDR active response, **Microsoft Sentinel** cloud-native SIEM/SOAR threat hunting, a comprehensive 4-layer **CIS Complete Audit** suite, and full-lifecycle **AI Governance & OWASP Top 10 for LLMs** defense pipelines aligned with ISO/IEC 42001:2023 and the EU AI Act.

---

### ✨ Added

#### 1. CIS Complete Multi-Layer Compliance Audit Suite ([`skills/security/cis-complete-audit/`](./skills/security/cis-complete-audit/SKILL.md))
* **4-Layer Unified CIS Auditing:** Automated evaluation, scoring, and drift detection across Cloud Foundations (AWS CIS 3.0, Azure CIS 2.1, GCP CIS 3.0), Kubernetes (CIS K8s 1.9), Linux Host Hardening (CIS Benchmark Level 1 & 2), and Docker Containers (CIS Docker 1.6).
* **Automated Audit Engine (`audit_cis_compliance.py`):** Multi-framework Python scanner generating compliance reports, weighted severity scoring (Critical, High, Medium, Low), and machine-readable JSON artifacts.
* **Declarative Remediation Automation (`cis_remediation_helper.sh`):** Shell execution helper providing safe, automated dry-run and apply modes for CIS drift remediation.
* **Comprehensive Technical Reference Matrices:** Reference guides for Cloud Foundations, Kubernetes CIS guidelines, Linux host hardening vectors, Docker container isolation rules, and remediation playbooks.

#### 2. Falco & Falco Talon: eBPF Kernel Threat Detection & Real-Time Prevention ([`skills/security/falco/`](./skills/security/falco/SKILL.md))
* **Syscall-Level Behavioral Monitoring:** CNCF graduated eBPF kernel tracing intercepting unauthorized process spawns, interactive shells in production, container namespace escapes, and unexpected network egress.
* **Falco Talon Active Response Actionners:** Autonomous threat neutralization playbooks executing zero-grace pod eviction (`kubernetes:terminate`), instant CNI network isolation (`kubernetes:networkpolicy` egress-deny-all via Cilium/Calico), and node-level process termination (`SIGKILL`).
* **Declarative Rule Architecture & Testing Tools:** Complete rule compiler validator (`validate_falco_rules.py`) and mock alert generator (`simulate_falco_alerts.py`).

#### 3. Sysdig: Cloud Native Application Protection & Runtime Drift Control ([`skills/security/sysdig/`](./skills/security/sysdig/SKILL.md))
* **Container Runtime Drift Prevention:** Sysdig Secure and OSS chisel tracing intercepting drift between immutable container images and runtime process state.
* **Admission Control & Image Vulnerability Gatekeeping:** Automated evaluation of CVE severities and non-compliant package blocking before deployment.
* **Forensic Capture Analysis & Policy Tooling:** Dedicated trace capture parser (`parse_sysdig_capture.py`) and Falco-to-Sysdig declarative policy generator (`sysdig_policy_generator.py`).

#### 4. Wazuh: Enterprise Open-Source SIEM, XDR & Active Response ([`skills/security/wazuh/`](./skills/security/wazuh/SKILL.md))
* **Host OS & File Integrity Monitoring (FIM):** Real-time `syscheck` tracking unauthorized file modifications, permission escalations, and binary tampering across Linux and Windows nodes.
* **Automated Active Response Playbooks:** Autonomous host containment scripts (`firewall-drop`, `host-deny`, custom container freeze) neutralizing brute-force and lateral movement attacks.
* **Log Decoders & Rules Testing Engine:** Custom XML decoder definitions and rule verification runner (`wazuh_rule_tester.py`) alongside an active response simulator (`wazuh_active_response_simulator.py`).

#### 5. Microsoft Sentinel: Cloud-Native SIEM & SOAR Threat Hunting ([`skills/security/sentinel/`](./skills/security/sentinel/SKILL.md))
* **Advanced Kusto Query Language (KQL) Threat Hunting:** Production KQL hunting library detecting credential dumping, abnormal multi-cloud data egress, and privileged identity manipulation.
* **SOAR Automation Playbooks (Logic Apps):** Automated incident triage, entity analytics (UEBA), and declarative JSON ARM/Bicep remediation templates.
* **Analytical Rule Authoring & Verification:** CLI syntax validator for KQL queries (`validate_kql_queries.py`) and automated Logic App playbook template generator (`sentinel_playbook_generator.py`).

#### 6. AI Governance & Regulatory Compliance Suite ([`skills/security/compliance/ai-governance-audit/`](./skills/security/compliance/ai-governance-audit/SKILL.md))
* **ISO/IEC 42001:2023 AIMS Control Matrix:** Deep-dive governance mapping covering Organizational Controls (A.5.2 AI Policy, A.8.3 AI System Impact) and Annex B Technical Controls (B.9.2 Data Lineage, B.10.4 Algorithmic Transparency).
* **EU AI Act Conformity Guide (Regulation EU 2024/1689):** High-Risk AI system classification, technical documentation requirements (Art. 11), automatic logging obligations (Art. 12), and cybersecurity resilience (Art. 15).
* **Cryptographic Data Provenance Verification Engine (`verify_ai_lineage.py`):** Standalone CLI auditor enforcing mandatory `dataset_provenance` metadata schemas, static SHA-256 dataset hash integrity, and immutable version tags.

#### 7. OWASP Top 10 for LLMs Application Security Defenses ([`skills/security/owasp-llm-security/`](./skills/security/owasp-llm-security/SKILL.md))
* **Static Prompt Injection Code Scanner (`scan_prompt_injection.py`):** AST regex scanner intercepting dynamic string interpolation (`f"..."`, concatenation) in prompt templates and evaluating prompt payloads against known jailbreak signatures.
* **Model Output Integrity Verification (`validate_llm_outputs.sh`):** Post-generation filter intercepting downstream RCE shell commands, SQL injection strings, and XSS artifacts before execution.
* **Declarative Edge Perimeter Rules:** AWS WAFv2 WebACL JSON inspection policies and Google Cloud Armor rules blocking administrative override strings at ingress gateways.
* **Runtime Input Sanitization Middleware ([`src/middleware/guards.py`](./src/middleware/guards.py)):** Hardened payload builder enforcing structural role arrays and delimiter stripping.

#### 8. Automated AI Safety & Governance CI/CD Pipeline ([`.github/workflows/ai-safety-pipeline.yml`](./.github/workflows/ai-safety-pipeline.yml))
* **Centralized CI Pipeline:** Executes on every push and pull request, orchestrating dataset lineage verification, static prompt injection scans, and output integrity checks via [`run_ai_security_pipeline.sh`](./skills/security/compliance/ai-governance-audit/scripts/run_ai_security_pipeline.sh).
* **Local Desktop Pre-Commit Shield:** Tracked hook ([`scripts/git-hooks/pre-commit`](./scripts/git-hooks/pre-commit)) preventing unvalidated prompt concatenations from being committed locally.

#### 9. Standalone `ocagents` Universal CLI & Zero-Friction Package Distribution ([`src/ocagents/`](./src/ocagents/))
* **Standalone CLI Tooling (`ocagents` / `oca`):** Production command-line tool with zero-dependency execution for listing, syncing, validating, simulating, and updating Open Cloud Agents personas and specialist skills across any repository.
* **One-Liner Installers:**
  * macOS & Linux: `curl -fsSL https://open-cloud-agents.github.io/ocagents/install.sh | bash`
  * Windows (PowerShell): `irm https://open-cloud-agents.github.io/ocagents/install.ps1 | iex`
* **Package Manager Distribution Specs:**
  * Homebrew Formula: [`Formula/ocagents.rb`](./Formula/ocagents.rb)
  * Python Packaging: [`pyproject.toml`](./pyproject.toml)
  * Windows Package Manager: [`packaging/winget/manifest.yaml`](./packaging/winget/manifest.yaml)
  * Alpine Linux (APK): [`packaging/alpine/APKBUILD`](./packaging/alpine/APKBUILD)
  * Debian / Ubuntu (APT): [`packaging/debian/control`](./packaging/debian/control)
* **Master Suite Skills Mapping:** Mapped specialist skills in YAML frontmatter and multi-workspace sync protocols across all 7 Master Suite agent specifications.

---

### 🔄 Changed
* **README.md:** Updated release badge to `v1.3.0` and added the 5 new security subdomains to the catalog.
* **Security Subdomain Hub ([`skills/security/README.md`](./skills/security/README.md)):** Added the Core Structural Reference Matrix connecting compliance reference specifications directly to automated script engines.
* **Security Compliance Commander Persona ([`agents/7-agent-master-suite/security-compliance-commander.md`](./agents/7-agent-master-suite/security-compliance-commander.md)):** Expanded operational purview to include AI governance, ISO 42001, EU AI Act conformity, and Falco/Wazuh runtime defense loops.

---

## [1.2.0] - 2026-10-27

### 🌐 Multi-Cloud IaC Standards, Token Optimization Architecture & Autonomous Gatekeeper Pipeline
This feature release integrates production-grade **Infrastructure as Code (IaC)** engineering standards across AWS, Azure, GCP, and Docker, introduces a comprehensive **Token Optimization Architecture** framework, and establishes the **Autonomous Gatekeeper CI Pipeline** with automated PR reviews and approvals powered by `Antigravity-AI` across merged Pull Requests #17, #18, #19, and #20.

---

### ✨ Added

#### 1. Centralized Terraform Infrastructure Planner ([`skills/devops/iac/terraform-infrastructure-planner/`](./skills/devops/iac/terraform-infrastructure-planner/SKILL.md))
* **Machine-Readable Pre-Code Architecture Plans:** Generates structured `.terraform-planning-files/INFRA.{provider}.{goal}.md` specifications covering architecture blueprints, remote state locking, resource dependency graphs, blast-radius assessments, and rollback runbooks.
* **Multi-Cloud Provider Support:** Uniform planning taxonomy covering AWS, Azure, GCP, and Docker ecosystems aligned to Well-Architected Framework pillars.
* **Automated Plan Validation Tool (`validate_infra_plan.py`):** CLI linter verifying required plan sections, target file paths, and naming conventions prior to code generation.

#### 2. Multi-Cloud & Docker Terraform Implementation Standards
* **AWS Implementation Standards ([`skills/devops/iac/aws-terraform-implementation/`](./skills/devops/iac/aws-terraform-implementation/SKILL.md)):**
  * S3 secure defaults (encryption, public access blocks, versioning), least-privilege IAM policies, KMS CMK envelope encryption, and private subnet topology.
  * Golden validation script (`validate_terraform.sh`) ensuring formatting, syntax validation, and state-destruction trap detection.
* **Azure Implementation Standards ([`skills/devops/iac/azure-terraform-implementation/`](./skills/devops/iac/azure-terraform-implementation/SKILL.md)):**
  * Entra ID granular RBAC roles, Azure Key Vault with 90-day soft-delete and purge protection, Storage Account TLS 1.2+ secure defaults, and isolated VNet NSG boundaries.
  * Dedicated validation script (`validate_azure_tf.sh`).
* **GCP Implementation Standards ([`skills/devops/iac/gcp-terraform-implementation/`](./skills/devops/iac/gcp-terraform-implementation/SKILL.md)):**
  * Custom-mode VPC with Private Google Access, Cloud KMS CMEK encryption with 90-day rotation, uniform bucket-level access on GCS, and Workload Identity federation over service account keys.
  * Dedicated validation script (`validate_gcp_tf.sh`).
* **Docker Container Orchestration Standards ([`skills/devops/iac/docker-terraform-implementation/`](./skills/devops/iac/docker-terraform-implementation/SKILL.md)):**
  * Hardened container configurations enforcing explicit non-root execution (`10001:10001`), read-only root filesystems, dropped Linux capabilities (`drop = ["ALL"]`), immutable SHA256 image digests, and internal bridge network isolation.
  * Dedicated validation script (`validate_docker_tf.sh`).

#### 3. Token Optimization Architecture Guide ([`docs/token-optimization-architecture.md`](./docs/token-optimization-architecture.md))
* **Three-Tier Token Conservation Model:** Preserves LLM context windows through concise agent system prompts (~1.5k-4.5k tokens), on-demand 3-tier skills (~1k-2k tokens loaded only when triggered), and off-loaded execution scripts (0 LLM tokens).
* **Enterprise ROI & Latency Benchmarks:** Documents 70-85% prompt token reduction, 40-60% faster inference latency, and ~80% operational cost savings compared to monolithic monolithic prompting.

#### 4. Autonomous Gatekeeper CI Pipeline ([`.github/workflows/autonomous-gatekeeper.yml`](./.github/workflows/autonomous-gatekeeper.yml))
* **Unified Directed Acyclic Graph (DAG):** Consolidated previous fragmented workflows (`ci.yml` and `agents-pipeline.yml`) into a single, cohesive GitHub Actions pipeline with zero duplicate runner waste.
* **Deterministic Quality Gates:** Executes repository hygiene, agent contract validations, 6-stage multi-agent handoff simulation, Gitleaks secret detection, ShellCheck linting, and FinOps waste regression in parallel.
* **Terminal Autonomous Gatekeeper (`Antigravity-AI`):**
  * Automatically evaluates upstream job statuses and analyzes incoming PR diffs via `scripts/ci/audit_pr_diff.py`.
  * Blocks merge and comments itemized failure lists if any upstream check fails or if destructive IaC traps are detected.
  * Submits automated pre-merge verification reports (`event: 'COMMENT'`) on clean PRs, assisting human maintainers with structured quality gate summaries.

---

### 🔄 Changed
* **Agent Master Suite Enhancements:**
  * Updated **Principal Cloud Architect** with multi-cloud and Docker pre-code planning mandates.
  * Expanded **DevSecOps Reviewer** with comprehensive multi-cloud (AWS, Azure, GCP, Docker) pre-merge audit checklists.
  * Enhanced **DevSecOps Engineer** with verified provider modules and golden implementation standards.
* **CI & Workflow Hardening:**
  * Double-quoted environment files (`"$GITHUB_ENV"`, `"$GITHUB_OUTPUT"`, `"$GITHUB_STEP_SUMMARY"`) across all active workflows to prevent word splitting (`SC2086`).
  * Safely mapped untrusted context expressions (`head.ref`, `inputs.tag_name`, `ref_name`) via `env:` blocks to eliminate script injection vectors.
  * Achieved 100% clean status with `actionlint`.

---

### 🏆 Merged Pull Requests in this Release
* **PR #17:** `feat(iac): integrate AWS Terraform planner & implementation standards across agents and skills`
* **PR #18:** `feat(iac): integrate Azure, GCP, and Docker Terraform standards across agents and skills`
* **PR #19:** `docs(architecture): add token optimization and architectural benefits guide`
* **PR #20:** `ci(gatekeeper): unify quality checks and autonomous Antigravity-AI approval into autonomous-gatekeeper.yml`

---

## [1.1.0] - 2026-10-26

### 💰 FinOps Cloud Waste Reaper, Docs-as-Code & Automated Governance
This minor release introduces the complete **FinOps & Cost Optimization** domain, an automated **Docs-as-Code** static site on GitHub Pages, selective CI change detection, and automated **Dependabot** daily security auditing across 12 merged Pull Requests (#1-#12).

---

### ✨ Added

#### 1. FinOps Cloud Waste Reaper ([`skills/finops/cloud-waste-reaper/`](./skills/finops/cloud-waste-reaper/SKILL.md))
* **3-Tier Skill Architecture:** Runbook, quantitative metrics matrix, multi-cloud query syntax, and executable automation script.
* **Multi-Cloud Waste Hunter Script (`reap_cloud_waste.sh`):**
  * **AWS Scanning:** Unattached EBS volumes (`gp3`/`io2`), unassociated Elastic IPs, idle NAT Gateways, and empty ALBs.
  * **GCP Scanning:** Unattached Persistent Disks (`pd-standard`/`pd-ssd`) and reserved static IPs.
  * **Azure Scanning:** Unattached Managed Disks and unassociated Public IPs.
  * **Deterministic Mock Engine:** Simulated multi-cloud environment producing \$107.90/mo (\$1,294.80/yr) waste baseline for CI and local verification.
  * **Reporting Formats:** Generates structured JSON (`--export-json`) and GitHub-flavored Markdown PR summary tables (`--export-markdown`).
* **Real-World Incident Cases:** Documented root-cause postmortems for the \$14,000 Abandoned NAT Gateway, 80,000 Orphaned Snapshots, and Ghost Kubernetes StatefulSet PVC leaks.
* **Non-Destructive Safety Gate:** Strict compliance with Rule 01 (dry-run by default; requires explicit DevSecOps handoff and human sign-off before reclamation).

#### 2. Docs-as-Code Static Site on GitHub Pages
* **Live Documentation Portal:** Public searchable documentation website hosted at [https://open-cloud-agents.github.io/ocagents/](https://open-cloud-agents.github.io/ocagents/).
* **Single Source of Truth (`scripts/docs/prepare_docs.py`):** Automatically aggregates in-repo Markdown documents (agents, skills, rules, specs, changelog) with zero documentation drift.
* **Theme & Features (`mkdocs.yml`):** MkDocs Material with light/dark mode auto-detection, Mermaid diagram rendering, instant client-side search, and hierarchical sidebar navigation.
* **Automated CD Workflow (`.github/workflows/docs.yml`):** Automatic deployment to GitHub Pages upon pushes to `main`.

#### 3. Subsystem Selective Change Detection in CI
* **Pre-Flight Filter (`dorny/paths-filter`):** Evaluates changed files in ~1.5s to trigger only relevant test jobs (`scripts`, `finops`, `docs_only`).
* **Conventional Branch Triggers:** Expanded CI triggers across `feat/**`, `fix/**`, `docs/**`, `chore/**`, and `refactor/**`.
* **Zero Runner Waste:** Documentation-only pull requests complete in ~3 seconds while preserving all branch protection status checks.

#### 4. Automated Governance & Daily Auditing
* **Code Ownership ([`.github/CODEOWNERS`](./.github/CODEOWNERS)):** Enforces mandatory review and sign-off from `@ibrahimng` on protected branches.
* **Dependabot Configuration ([`.github/dependabot.yml`](./.github/dependabot.yml)):** Daily automated dependency and vulnerability scanning at 04:00 UTC for GitHub Actions and Python tooling.
* **Scheduled Daily Codebase Audit ([`.github/workflows/scheduled-audit.yml`](./.github/workflows/scheduled-audit.yml)):** Daily 4:00 AM regression runner testing repository hygiene, agent contracts, simulation, and FinOps reaper, with automated GitHub Issue alerts on failure.

---

### 🔄 Changed
* **Upgraded GitHub Actions Toolchain (PRs #3-#12):** Bumped all workflow actions to Node 24-compatible releases (`actions/checkout@v7`, `actions/deploy-pages@v5`, `actions/upload-pages-artifact@v5`, `actions/configure-pages@v6`, `actions/setup-python@v7`, `actions/upload-artifact@v7`, `actions/github-script@v9`, `softprops/action-gh-release@v3`, `dorny/paths-filter@v4`).
* **Python Tooling:** Pinned `requirements.txt` with `mkdocs-material` and `pyyaml>=6.0.3` (PR #2, PR #3).
* **Local `act` Runner:** Configured `.actrc` with `catthehacker/ubuntu:act-latest` on `linux/amd64` to prevent interactive prompts and Apple Silicon warnings.

---

### 🏆 Merged Pull Requests in this Release
* **PR #1:** `feat(finops): introduce cloud waste reaper 3-tier skill and automated discovery script`
* **PR #2:** `chore(deps): update mkdocs-material requirement`
* **PR #3:** `chore(deps): update pyyaml requirement from >=6.0.1 to >=6.0.3`
* **PR #4:** `ci(deps): bump actions/upload-artifact from 4 to 7`
* **PR #5:** `ci(deps): bump actions/checkout from 4 to 7`
* **PR #6:** `ci(deps): bump softprops/action-gh-release from 2 to 3`
* **PR #7:** `ci(deps): bump actions/configure-pages from 5 to 6`
* **PR #8:** `ci(deps): bump actions/deploy-pages from 4 to 5`
* **PR #9:** `ci(deps): bump dorny/paths-filter from 3 to 4`
* **PR #10:** `ci(deps): bump actions/upload-pages-artifact from 3 to 5`
* **PR #11:** `ci(deps): bump actions/setup-python from 5 to 7`
* **PR #12:** `ci(deps): bump actions/github-script from 7 to 9`

---

## [1.0.0] - 2026-10-26

### 🚀 Initial General Availability (GA) Release
This foundational release establishes **Open Cloud Agents** as an open-source, enterprise-grade multi-agent cloud engineering framework mapped 1:1 across the **AWS, Microsoft Azure, and Google Cloud Well-Architected Frameworks**.

---

### ✨ Added

#### 1. The 7-Agent Master Suite ([`agents/`](./agents/README.md))
* **Principal Cloud Architect & System Designer:** High-Level Design (HLD), authoritative Architecture Decision Records (ADRs), Domain-Driven Design (DDD), and quantitative multi-region RTO/RPO disaster recovery models.
* **Security Compliance & Cyber Defense Commander:** Automated compliance mapping across SOC 2 Type II, ISO 27001, CIS Benchmarks, and continuous WAF defense loops.
* **FinOps & Cloud Cost Optimizer:** Rightsizing, idle waste elimination, S3/storage lifecycle tiering, and intra-cloud NAT data egress trap prevention.
* **DevSecOps Reviewer:** Pre-merge PR defensive auditing, threat modeling, and state-destruction prevention (`forces replacement`).
* **DevSecOps Engineer:** Surgical code generation, zero-scope-creep bug fixes, executable test verification, and conventional commit generation.
* **GitOps Release Manager:** Progressive multi-environment promotion (`dev` ➔ `uat` ➔ `prod`) via ArgoCD/Kustomize with mandatory human sign-off gates.
* **SRE & Reliability Incident Engineer:** Four Golden Signals monitoring, multi-window SLI/SLO burn alerts, endpoint root-cause analysis (502/503/504), and blameless postmortems.

#### 2. The 3-Tier Enterprise Skills Ecosystem ([`skills/`](./skills/README.md))
* Over 360 skills standardized into a structured 3-tier architecture:
  * **Tier 1:** Autonomous runbooks (`SKILL.md`) with YAML frontmatter, incident case studies, and safety guardrails.
  * **Tier 2:** Deep architectural specs, decision trees, and cheatsheets (`references/`).
  * **Tier 3:** Executable verification and linting tools (`scripts/`).
* **Cloud Service Provider (CSP) Remix Standards:** Curated toolkits for AWS, Microsoft Azure, and Google Cloud.
* **Core Domains:** DevOps (Terraform, Kubernetes, Docker, Helm, ArgoCD, Prometheus, OpenTelemetry), Security (CIS, SOC 2, IAM, Secret Scrubbing, KMS), and modern programming languages (Dart, Python, TypeScript, Go, Java).

#### 3. Inviolable Rule Governance ([`rules/`](./rules/README.md))
* Canonical, non-negotiable guardrails protecting cloud systems from autonomous AI mistakes:
  * `01-destructive-actions.md`: Zero unplanned destruction (`DROP`, `TRUNCATE`, bucket wipes, IaC `forces replacement`).
  * `02-secrets-and-identity.md`: Zero hardcoded credentials, short-lived OIDC tokens, and log redaction.
  * `03-surgical-scope-discipline.md`: Zero unsolicited refactorings, whole-repo formatting sweeps, or unrequested dependency bumps.
  * `04-cloud-well-architected-invariants.md`: Multi-AZ/region redundancy, KMS envelope encryption, and least-privilege IAM defaults.
  * `05-repository-and-path-hygiene.md`: Mandatory relative Markdown links and strict prohibition of leaking `/Users/<username>/` workstation paths.

#### 4. Universal IDE & Agent Directives
* **`AGENTS.md`:** Universal root directive for Google Antigravity, Claude Code, Cline, and terminal agents, featuring the dynamic **Continual Learning Memory**.
* **`.cursorrules`:** System instructions for Cursor and VS Code AI assistants.

#### 5. CI Guardrails & Multi-Agent Orchestration Pipeline
* **GitHub Actions CI (`.github/workflows/ci.yml`):** Automated Gitleaks secret detection, ShellCheck script linting, and repository hygiene validation.
* **Multi-Agent Pipeline (`scripts/agents/agent_pipeline.py` & `.github/workflows/agents-pipeline.yml`):** Executable 6-stage handoff simulation runner verifying schema contracts between agents.
* **Local Runner Support (`act`):** Verified support for executing the full CI suite locally in Docker.

#### 6. Community & Open Governance
* **Contributor Hall of Fame (`CONTRIBUTORS.md`):** Roster acknowledging founding and community contributors.
* **Pull Request Template (`.github/pull_request_template.md`):** Automated PR checklist with Developer Certificate of Origin (DCO) sign-off and GitHub Privacy Alias standard.
* **Social Preview & Hero Banner (`docs/images/social-preview.png`):** High-resolution branding card.

