# 🛡️ Open Cloud Agents: Engineering & Security Standards

### *Operational quality, security guardrails, and AI safety invariants across the Open Cloud Agents ecosystem.*

---

## 🏛️ Purpose & The Triad

These engineering standards define the technical quality, security discipline, and AI governance requirements for all contributors, automated agents, and workflows in **Open Cloud Agents**.

Every interaction in this repository operates according to three core pillars:

1. **Personas ([`agents/`](../agents/README.md)):** Specialized mandates and explicit handoff contracts defined across the 7-Agent Master Suite.
2. **Skills ([`skills/`](../skills/README.md)):** Established 3-tier runbooks (`SKILL.md`, `references/`, `scripts/`) ensuring deterministic, repeatable execution.
3. **Rules ([`rules/`](../rules/README.md)):** Inviolable safety, security, and scope guardrails enforced across all automated workflows.

---

## 🎯 Scope

These standards apply to:
- Application code, scripts, APIs, CLI utilities (`ocagents`), and Infrastructure-as-Code (Terraform, OpenTofu, Helm).
- Agent definitions, system prompts, skill specifications, and evaluation runbooks.
- Model routing, context assembly, memory ingestion, and retrieval pipelines.
- Agentic systems that plan, invoke tools, inspect cloud assets, or propose infrastructure changes.
- Human contributors and automated AI agents operating locally or in CI/CD pipelines.

---

## 🧱 Core Engineering Standards

- **Modular & Testable:** Write clear, modular, testable code with small functions and explicit interfaces.
- **Secure by Default:** Prefer secure defaults over convenience; fail closed when security controls are uncertain.
- **Version Control Discipline:** Use Git for all changes; no unreviewed or ad-hoc edits to production assets.
- **Peer Review & Verification:** Require peer review and automated CI validation for all non-trivial changes.
- **Continuous Quality Gates:** Enforce linting, formatting, dependency audits, unit tests, and link validation in CI.
- **Documented Decisions:** Document architectural decisions (ADRs), trade-offs, assumptions, and rollback procedures.
- **Zero Secret Exposure:** Keep credentials out of source code, logs, prompts, notebooks, and issue trackers.
- **Minimal Surface Area:** Minimize complexity; aggressively remove dead code, unused dependencies, and redundant permissions.

---

## 💻 Coding Policy

### Required
- Validate and sanitize all inputs at trust boundaries.
- Use parameterized queries and safe ORM/IaC abstractions.
- Encode outputs appropriately for their destination context (HTML, SQL, shell arguments, URLs).
- Handle errors gracefully without exposing sensitive stack traces or internal environment variables.
- Use strictly typed interfaces (Python type annotations, TypeScript strict mode) wherever practical.
- Add regression tests for security-sensitive logic, parser edge cases, and failure modes.
- Apply least privilege to service accounts, tokens, and runtime permissions.

### Prohibited
- Hardcoded secrets, API tokens, cloud access keys, or private certificates.
- Dynamic code execution (`eval`, `exec`) from untrusted or unvalidated input.
- Unsafe deserialization of untrusted payloads.
- Blind shell execution with unescaped user-controlled arguments.
- Disabling TLS verification in any environment except isolated local unit tests with explicit approval.
- Exporting production data into test or third-party environments without authorization and sanitization.

---

## 🧠 AI and Model Governance Policy

### Data Governance
- Use only approved datasets and documentation sources with clear provenance and retention boundaries.
- Classify data before use: public, internal, confidential, or restricted.
- Minimize exposure of personal data and proprietary infrastructure context; prefer pseudonymization.
- Track dataset lineage, consent constraints, transformations, and access history.

### Model Development & Prompt Engineering
- Define objectives, evaluation metrics, failure modes, and misuse cases before deploying new agent roles.
- Version system instructions, persona definitions, and evaluation benchmarks alongside codebase releases.
- Evaluate accuracy, robustness, prompt-injection resilience, and privacy exposure before release.
- Never deploy agent workflows without documented fallback behaviors and clear human intervention gates.
- Require mandatory human review for decisions affecting infrastructure state, security policies, or billing.

### Model Operations
- Monitor for model drift, prompt abuse, abnormal tool call volume, and anomalous outputs.
- Log security-relevant decision events without capturing credentials or sensitive tenant data.
- Restrict model access by role, environment, and approved capability scope.
- Rotate provider credentials immediately upon any suspected token exposure.

---

## 🛡️ Generative AI & Context Safety

### Prompt and Context Safety
- Treat prompts, system instructions, memories, retrieved files, and tool outputs as security-sensitive inputs.
- Sanitize retrieved repository content before injecting it into agent context windows.
- Defend against prompt injection by isolating trusted system instructions from untrusted external text.
- Never expose internal system directives, hidden credentials, or private file paths in generated agent outputs.

### Output Safety
- Validate generated code, Terraform plans, and shell commands before execution or pull-request submission.
- Require deterministic confirmation gates for high-risk actions (file deletion, privilege modifications, resource de-provisioning).
- Block the generation of malicious payloads, credential harvesting routines, or evasive exploits.

---

## 🤖 Agentic Systems & Execution Controls

### Authorization Boundaries
- Agents must operate with explicit task scopes, bounded objectives, step limits, and tool allowlists.
- Every tool invocation must be attributable to an authenticated session and a logged decision rationale.
- Agents may only access the minimum tools and repository context required for the immediate task.

### Execution Controls
- Enforce confirmation gates for destructive, irreversible, regulated, or externally visible actions.
- Enforce timeout limits, rate limits, network boundaries, and recursion safeguards.
- Sandbox code execution, shell commands, and file writes within isolated runtimes.
- Prohibit autonomous self-modification, policy relaxation, or permission escalation.

### Human Oversight
- Human approval is mandatory for production changes, secret access, deployment promotions, and policy exceptions.
- Operators must be able to interrupt, audit, inspect, and terminate any running agent session.
- Incidents involving unexpected agent behavior require a blameless post-incident review (PIR) and guardrail updates.

---

## 🔒 Cybersecurity Invariants

### Identity and Secrets Management
- Enforce SSO, MFA, strong session handling, and short-lived credentials wherever possible.
- Store secrets exclusively in approved secret managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault).
- Never log secrets or include them in prompts, transcripts, error reports, or crash dumps.
- Strictly obey [`rules/02-secrets-and-identity.md`](../rules/02-secrets-and-identity.md) across all workflows.

### Secure Development Lifecycle (SDLC)
- Maintain threat models for core architecture and update them when design boundaries change.
- Run automated security checks (SAST, secret scanning, dependency audits, IaC linters) in CI/CD.
- Patch critical vulnerabilities on an emergency timeline.
- Block release merges with unresolved critical security findings unless authorized by risk owners.

### Infrastructure and Network Defense
- Isolate production environments from development, staging, and demo sandboxes.
- Enforce default-deny network security policies and explicit egress boundaries.
- Mandate TLS 1.3 in transit and KMS envelope encryption at rest per [`rules/04-cloud-well-architected-invariants.md`](../rules/04-cloud-well-architected-invariants.md).
- Keep audit logs tamper-evident, centralized, and time-synchronized.

---

## 🔄 Common Architectural Patterns

### Pattern 1: Input ➔ Model ➔ Action
Use this pattern when an agent receives input, analyzes context with an LLM, and triggers a bounded tool:
- Ingest data through strictly validated and typed schemas.
- Run pre-execution policy checks before any tool call or external API request.
- Produce structured outputs with confidence ratings, technical rationale, and proposed next steps.
- Require human approval for destructive, state-altering, or public-facing operations.

### Pattern 2: Retrieval-Augmented Automation (RAG)
Use this pattern when an agent inspects repository files, architectural runbooks, or learned facts:
- Restrict retrieval strictly to approved workspace directories and skill reference files.
- Sanitize retrieved Markdown and source code before appending to prompt context.
- Attach provenance metadata (file path, line range, commit SHA) to generated findings.
- Decline action when supporting documentation is ambiguous or conflicting.

### Pattern 3: Human-in-the-Loop (HITL) Escalation
Use this pattern for high-risk operations, ambiguous plan outcomes, or policy violations:
- Define clear risk thresholds that trigger automatic escalation to human operators.
- Present a concise decision summary, supporting evidence, and proposed remediation diff.
- Log the reviewer's identity, timestamp, and verdict.
- Resume execution strictly within the explicitly approved scope.

### Pattern 4: Safe Code & IaC Generation
Use this pattern when agents draft Terraform modules, Kubernetes manifests, or remediation scripts:
- Propose code changes into an isolated branch or sandbox environment.
- Run static linters (`tflint`, `tfsec`), syntax validators, and dry-run applies before merge.
- Strictly obey [`rules/01-destructive-actions.md`](../rules/01-destructive-actions.md) to detect and block `forces replacement` state destruction.
- Prohibit direct, unattended promotion to production environments.

---

## ⚡ Verification & Tooling Reference

Engineering standards are enforced using the `ocagents` CLI and automated CI validation scripts.

### Repository Hygiene & Skill Validation
```bash
# Validate all 380 skill specs, shell script permissions, and Markdown link hygiene:
ocagents validate

# Or execute the native Python repository validation suite directly:
python3 scripts/ci/validate_repo.py
```

### Multi-Agent Simulation & Contract Verification
```bash
# Run deterministic hermetic simulation to verify agent handoff contracts in 0.001s:
ocagents simulate

# Execute an autonomous review task with strict guardrail adherence:
ocagents run --task "Audit Terraform PR in ./terraform/ for state destruction risks"
```

### Continual Learning Standards Ingestion
```bash
# Codify newly discovered edge cases or postmortem findings into AGENTS.md:
ocagents learn \
  --fact "Measure peak memory under load before configuring cgroup limits" \
  --category "Kubernetes Resource Management"
```

---

## 📋 Enforcement Checklist

Before merging any code or promoting an agent workflow, verify:
- [ ] **No Secrets Exposed:** Zero plaintext credentials in code, prompts, logs, or commits ([`rules/02`](../rules/02-secrets-and-identity.md)).
- [ ] **No Destructive Operations:** Zero unplanned `DROP`, `TRUNCATE`, bucket wipes, or IaC `forces replacement` ([`rules/01`](../rules/01-destructive-actions.md)).
- [ ] **Surgical Scope:** Changes are strictly confined to the task mandate; zero unsolicited mass refactorings ([`rules/03`](../rules/03-surgical-scope-discipline.md)).
- [ ] **Path Hygiene:** Zero local workstation paths (`/Users/<username>/`) in committed files ([`rules/05`](../rules/05-repository-and-path-hygiene.md)).
- [ ] **CI Validation Clean:** `ocagents validate` passes with zero errors across all specifications.
- [ ] **Peer Review Approved:** Non-trivial changes reviewed and approved by human risk owners.

---

## 📚 Normative References

These standards are anchored to established industry frameworks:
- **OWASP ASVS:** Application Security Verification Standard.
- **OWASP Top 10 for LLMs:** Security and safety risks for generative AI applications.
- **NIST SSDF (SP 800-218):** Secure Software Development Framework.
- **NIST AI RMF (AI 100-1):** Artificial Intelligence Risk Management Framework.
- **MITRE ATLAS:** Adversarial Threat Landscape for Artificial-Intelligence Systems.
- **CIS Critical Security Controls:** Version 8 foundational and operational benchmarks.
- **ISO/IEC 27001 & ISO/IEC 42001:** Information security and AI management system requirements.
- **AWS, Azure & GCP Well-Architected Frameworks:** Core operational, reliability, and security pillars.
