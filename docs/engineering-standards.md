# 🛡️ Open Cloud Agents: Engineering & Security Standards

### *Operational quality, security guardrails, and AI safety invariants across the Open Cloud Agents ecosystem.*

---

## 🏛️ Purpose & The Triad

These engineering standards define the technical quality, security discipline, and AI governance requirements for all contributors, automated agents, and workflows in **Open Cloud Agents**.

> [!NOTE] Project Status
> Open Cloud Agents is an early-stage open-source project under active development (Beta status). While automated CI gates and safety rules guard against formatting regressions and credential leaks, agent recommendations and generated code must always be reviewed by human engineers before applying changes to production environments.

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

These standards establish the baseline for all code, configurations, and documentation in the project:

- **Modular & Testable:** Write clear, modular, testable code with small functions and explicit interfaces.
- **Secure by Default:** Prefer secure defaults over convenience; fail closed when security controls are uncertain.
- **Version Control Discipline:** Use Git for all changes; no unreviewed or ad-hoc edits to production assets.
- **Peer Review & Verification:** Require human peer review and passing CI verification gates for all pull requests.
- **Automated CI Quality Gates:** Automated workflows in [`.github/workflows/`](../.github/workflows/) enforce repository hygiene checks, skill specification validation, secret detection (`gitleaks`), shell script linting (`shellcheck`), agent contract validation, and documentation build verification.
- **Contributor Quality Practices:** Contributors are expected to maintain unit tests, clean linting/formatting, and dependency audits within their respective modules before proposing changes.
- **Documented Decisions:** Document architectural decisions (ADRs), trade-offs, assumptions, and rollback procedures.
- **Zero Secret Exposure:** Keep credentials out of source code, logs, prompts, notebooks, and issue trackers per [`rules/02-secrets-and-identity.md`](../rules/02-secrets-and-identity.md).
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

These controls define how agent workflows must be structured, distinguishing target architecture requirements for enterprise deployments from the current local CLI behavior.

### Target Controls for Agent Runtime Integrations
When embedding or deploying Open Cloud Agents into production or multi-tenant platforms, hosting runtimes must implement:
- **Authorization Boundaries:** Enforce explicit task scopes, bounded step limits, and strict tool allowlists so agents only access the minimum tools and context required.
- **Audit Trails:** Ensure every model-directed action is attributable to an authenticated session and logged with its decision rationale.
- **Runtime Sandboxing:** Isolate code execution, shell commands, and file operations within ephemeral sandboxes (e.g., containers or virtual machines) rather than executing directly on host operating systems.
- **Boundary Invariants:** Prohibit autonomous self-modification, policy relaxation, or permission escalation.

### Current CLI Operating Model
In the local `ocagents` CLI toolkit:
- **Local Simulation Runner:** The `ocagents run` command executes a local multi-agent simulation that produces deterministic reference outputs across the 6-stage Master Suite pipeline without network latency or external API calls.
- **Provider Status (Stub / Beta Roadmap):** While the CLI accepts `--provider` (e.g., `ollama`, `gemini`, `anthropic`, `openai`) and `--model` flags and checks whether corresponding API keys exist in the environment, live API dispatch to hosted providers is currently a simulation stub. Live agentic execution currently occurs within AI IDEs (Cursor, Copilot, Claude Code) consuming the specialist system prompts in [`agents/`](../agents/README.md) and skills in [`skills/`](../skills/README.md).
- **Local Demo Sandboxing:** Live incident drills (such as KinD cluster incident triage) execute in local Docker-based containers rather than touching live production infrastructure.

### Human Oversight & Safety Invariants
- **Destructive Action Policy ([`rules/01-destructive-actions.md`](../rules/01-destructive-actions.md)):** Project rules strictly forbid executing destructive operations (`DROP`, `TRUNCATE`, bucket wipes, IaC `forces replacement`) without explicit human confirmation. This invariant is enforced as an instruction constraint on agent personas and an operational review requirement for engineers, rather than an automatic CLI interactive gate.
- **Production Change Approval:** Human approval is mandatory before applying any agent-recommended changes to live environments, granting secret access, promoting deployments, or approving policy exceptions.
- **Operator Intervention:** Operators must always retain the ability to interrupt, inspect, and terminate running agent operations.
- **Continual Learning Loop:** Operational surprises or unexpected agent behaviors require a blameless post-incident review (PIR) and codification of guardrails via `ocagents learn`.

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
- Mandate modern encryption standards by default per [`rules/04-cloud-well-architected-invariants.md`](../rules/04-cloud-well-architected-invariants.md):
  - **In Transit:** TLS 1.3 by default (minimum TLS 1.2 where legacy client or cloud provider compatibility requires it, with documented exception rationales).
  - **At Rest:** Cloud-managed or customer-managed KMS envelope encryption (AES-256) on all disks, storage buckets, and managed databases.
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

Engineering standards are verified locally using the `ocagents` CLI and automated repository scripts:

### Repository Hygiene & Specification Validation
```bash
# Run the unified CLI validation suite (agent specs + repository hygiene):
ocagents validate

# Or execute the repository validator directly:
python3 scripts/ci/validate_repo.py
```

The validation suite executes targeted checks across the repository:
1. **Agent Specification Validation (`agent_pipeline.py --validate`):** Verifies that all 7 required agent Markdown files exist, opening metadata declares `name`, `description`, and tools from the approved allowlist, a core mandate or objectives section is present, and estimated prompt tokens remain within the 8,000-token budget heuristic (~4 characters per token). (Note: this verifies file metadata and heuristic limits rather than runtime handoff schemas).
2. **Skill Header Check (`validate_repo.py`):** Scans the first 20 lines of each tracked `SKILL.md` file to confirm that `name:` and `description:` header lines are present (note: this is a header line scan rather than full YAML parsing).
3. **Shell Script Permissions (`validate_repo.py`):** Enforces executable permissions (`chmod +x`) on all automation shell scripts (`*.sh`).
4. **Internal Markdown Links (`validate_repo.py`):** Validates relative link targets across core architectural documentation to prevent dead links.
5. **Path Leakage Prevention (`validate_repo.py`):** Scans tracked source files to ensure no local machine paths (`/Users/<username>/`) are committed.
6. **Unicode Security (`validate_repo.py`):** Scans for Trojan Source directional overrides, invisible control characters, and confusables.

### Multi-Agent Pipeline Simulation
```bash
# Run local deterministic simulation to review pipeline stages without external API calls:
ocagents simulate

# Execute a simulated evaluation review task:
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
