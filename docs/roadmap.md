# Open Cloud Agents: v2.0 Architecture Roadmap

> **Current Status & Disclaimer:** Early-stage project. Milestones v1.4 through v2.2 are implemented and released (CLI version 2.2.0); live multi-provider benchmarks and model calibration are active engineering targets under Milestone v2.3. Roadmap milestones represent engineering objectives, not claims about untested external services.
>
> 📋 For the detailed task-level engineering breakdown, see the **[Implementation Backlog](./implementation-backlog.md)**.

---

## Strategic Focus

This roadmap transitions Open Cloud Agents from an opinionated catalog of skills and agent specifications into a predictable, schema-validated, token-budgeted multi-agent engineering framework. Each milestone delivers an independently testable capability without implying that the current simulator already provides a live multi-agent runtime.

---

### v1.x — Establish a Trustworthy Baseline

- Keep the demo scenarios and CLI simulation usable as evaluation tools.
- Clearly label simulated output, experimental features, and provider stubs.
- Maintain repository hygiene, agent-spec validation, and human review for security-sensitive changes.
- Avoid claiming production readiness or autonomous remediation.

**Exit Criteria:** Docs accurately describe what is implemented today, and the demo’s paths and commands work as documented.

---

### v1.4 — Structured Findings Contracts

- Publish a versioned, machine-readable finding schema (`schemas/v1/finding.json`).
- Define shared fields for origin (`deterministic_linter` vs. `model_assertion`), rule ID, category, resource, locator URI evidence (`diff:`, `repo:`, `cloud:`), recommendation, severity, and mandatory nullable confidence (`float | null`).
- Publish valid and invalid test fixtures in `tests/fixtures/findings/`.
- Implement validator engine and CLI command `ocagents findings validate <path>`.
- Support `diff:` and `repo:` evidence anchor corroboration; defer live `cloud:` provider corroboration until live integrations are enabled.
- Add optional token-budget and handoff-contract metadata to agent specifications.

**Measurable Acceptance Criteria & Enforcement:**
* **Validation Command:** `python3 -m unittest discover -s tests -p "test_*.py"` and `./bin/ocagents findings validate tests/fixtures/findings/valid_diff_finding.json`.
* **Expected Exit Statuses:**
  * Exit `0`: All finding records adhere to `finding.json` schema, referenced `rule_id` exists in `rules/`, and locator lines exist in diff/repo.
  * Exit `1`: Schema violation (missing mandatory fields, invalid origin enum, non-numeric/non-null confidence) or broken anchor (unmatched line range).
* **Test Coverage Target:** Unit tests cover valid fixtures, schema violations, invalid enum values, non-existent rule IDs, and diff/repo anchor boundary cases.
* **Gate Enforcement Level:** **Advisory in v1.4** (tooling and contract validation; not a required CI PR block).

---

### v1.5 — Deterministic Pre-Flight Checks

- Add a local pre-flight command (`ocagents preflight` / `ocagents check --deterministic`) for selected repository checks and supported static-analysis tools.
- Convert supported tool results into the shared finding format with `confidence: null`, preserving source and rule provenance.
- Define required versus advisory scanner catalog per file type.
- Enforce fail-closed scanner availability outcomes: missing required scanners halt before LLM execution with `INCOMPLETE_CHECK_FAILED`; missing advisory scanners mark runs `INCONCLUSIVE_PARTIAL_AUDIT`.
- Run checks only when relevant files change, and report checks that were skipped.

**Measurable Acceptance Criteria & Enforcement:**
* **Validation Command:** `./bin/ocagents preflight --diff`
* **Expected Exit Statuses:**
  * Exit `0`: All executed deterministic checks pass cleanly.
  * Exit `1`: Required scanner invariant failure or required scanner unavailable (`INCOMPLETE_CHECK_FAILED`).
  * Exit `2`: Advisory check finding or advisory scanner missing (`INCONCLUSIVE_PARTIAL_AUDIT`).
* **Test Coverage Target:** Tests cover clean inputs, violation detections, missing required tools, unparseable input files, and fail-closed audit outcomes.
* **Gate Enforcement Level:** **Deterministic Baseline is Merge-Gating** (required checks block PR merge); advisory checks remain informational.

---

### v1.6 — Risk Triage & Local Findings Store

- Classify changed files into documented risk tiers (Tier 0: Docs/Assets, Tier 1: Application, Tier 2: IaC/IAM/Network).
- Implement run metadata envelope (`run_id`), deterministic deduplication key (`FND-` + SHA256), and local append-only store (SQLite WAL / locked JSONL).
- Let specialists consume structured resource context and findings, while retaining concise narrative summaries for human operators.
- Record run metadata and tool provenance; keep secrets and unnecessary sensitive data out of stored findings.

**Measurable Acceptance Criteria & Enforcement:**
* **Validation Command:** `./bin/ocagents findings store list --run-id <id>` and parallel write stress test script.
* **Expected Exit Statuses:**
  * Exit `0`: Findings store accepts concurrent writes without data corruption or lock timeouts, and successfully deduplicates identical invariant findings.
* **Test Coverage Target:** Concurrency tests for parallel writes, deduplication logic, schema version evolution, and store corruption recovery.
* **Gate Enforcement Level:** **Advisory / Framework Storage Layer**.

---

### v2.0 — Shared Findings Workflow & Merge Gate

- Integrate pre-flight checks, risk triage, findings store, and specialist workflow in the CLI.
- Add provider integrations only when each provider path is implemented, tested, and documented.
- Validate model-produced findings against the schema before storing or routing them.
- Introduce `open-cloud-agents/triage-gate` status check context to GitHub CI:
  * If unresolved P0/P1 model assertions exist, `open-cloud-agents/triage-gate` holds state in `PENDING` until an authorized maintainer (from `CODEOWNERS`) signs off with `/ocagents triage accept|dismiss` or an approving PR review (`event: 'APPROVE'`).
- Do not automatically apply remediation by default; any future fix or apply flow requires explicit human review and approval.

**Measurable Acceptance Criteria & Enforcement:**
* **Validation Command:** `./bin/ocagents review --pr <pr_number> --provider <provider>`
* **Expected Exit Statuses:**
  * Exit `0`: All deterministic checks pass and no unresolved P0/P1 findings remain.
  * Exit `1`: Deterministic invariant failure (hard CI failure).
  * Exit `0` (with Triage Gate `PENDING`): Deterministic checks pass but P0/P1 model findings are escalated for human maintainer triage.
* **Gate Enforcement Level:** **Merge-Gating for both Deterministic Engine and Human Triage Gate**. Standard GitHub branch protection prevents PR merge until `triage-gate` transitions from `PENDING` to `SUCCESS`.

---

### v2.1 — Multi-VCS & Enterprise Forge Adapters (Delivered)

- Abstract base `VCSProvider` interface and dynamic forge auto-detection engine across CI environments.
- Native GitLab Merge Request discussions and Code Quality artifacts (`gl-code-quality-report.json`).
- Azure DevOps Pull Request Status Check policies and iteration thread comments.
- Bitbucket Cloud Code Insights reports and inline diff annotations.
- Gitea & Forgejo air-gapped sovereign cloud adapter with strict `--offline` mode.

---

### v2.2 — Anti-Proliferation, Anti-Swamp & Dynamic Triage (Delivered)

- 4-Tier Adaptive Change-Set Risk Classifier: Tier 0 documentation LLM bypass to Tier 3 full Master Suite activation.
- Anti-Swamp blackboard deduplication, TTL expiration, and signal-to-noise evidence ranking.
- Bounded Execution DAG engine and interaction circuit breaker enforcing token ceilings, ping-pong cycle breaking, and phase ordering constraints.

---

### v2.3 — Empirical Evaluation, Model Calibration & Live Benchmarks (Active Planned)

- Multi-provider live API token consumption, latency, and cost evaluation matrix (Anthropic, OpenAI, Google Gemini).
- Versioned ground-truth multi-cloud PR benchmark corpus (`v2026.11-corpus-v1`) spanning AWS, Azure, GCP, and Kubernetes with true positives and distractors.
- Empirical Expected Calibration Error (ECE) and Brier scores to optimize human triage routing thresholds ($\tau$).
- Automated CI token consumption and cost regression gate (`.github/workflows/benchmark-regression.yml`).

---

### Beyond v2.3 — Guarded Remediation & Continual Learning Governance

- Evaluate guarded remediation workflows only after evidence shows they are safe, auditable, and non-destructive.
- Continual learning memory loop with automated drift detection, human approval workflows, and false-positive de-biasing.

---

## Architectural Principles & Guardrails

The implementation of this roadmap adheres to six architectural safeguards formalized in [ADR-002](./adr-002-blackboard-findings-and-token-budgets.md):

1. **Avoid the "Zero Hallucination" Claim:** Structured schemas improve schema validation, field completeness, and traceability, but do not guarantee that a model's finding is factually true.
2. **Treat Token Savings as a Hypothesis:** The estimated 65–80% token reduction is an architectural hypothesis that requires reproducible benchmarking against a measured baseline before becoming a project claim.
3. **Evidence-Based Gating Over Model Confidence:** Automated CI blocks must rest on deterministic rules or verified evidence—never solely on uncalibrated model confidence. Model confidence serves strictly to prioritize human review queues (P0 urgent vs. P1 standard review), not as proof that a model finding is factually correct. Potentially serious (Critical/High) findings must never be silently suppressed.
4. **Rejection Over Truncation for Output Budgets:** Never truncate JSON payloads to enforce token limits. Truncation corrupts syntax. Oversized outputs are rejected, retried with bounded strategy, or escalated for review.
5. **Strict Separation of Verification from Approval:** Automated bots and CI gates may post non-approving verification summaries (`event: 'COMMENT'`). Formal pull request approval (`event: 'APPROVE'`) is strictly reserved for human maintainers.
6. **Remediation Proposals are Strictly Advisory:** Any auto-fix diff or draft remediation PR is strictly a proposed preview. It is never automatically merged, applied, or deployed, and requires deterministic validation and explicit human maintainer approval.

