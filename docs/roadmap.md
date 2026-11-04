# Open Cloud Agents: v2.0 Architecture Roadmap

> **Current Status & Disclaimer:** Early-stage project. The CLI's multi-agent pipeline is currently a scripted simulation; provider integration and the shared findings runtime are future roadmap targets. Roadmap milestones represent engineering objectives, not claims about existing functionality.

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
- Define shared fields for rule ID, category, resource, evidence, recommendation, severity, and confidence.
- Add schema validation and valid/invalid example test fixtures.
- Add optional token-budget and handoff-contract metadata to agent specifications.
- Update validation tooling to report exactly which fields and limits it checks.

**Exit Criteria:** Example findings validate cleanly; malformed, incomplete, or unsupported findings fail tests. Token-budget checks are explicitly labeled as structural estimates unless measured with a model-specific tokenizer.

---

### v1.5 — Deterministic Pre-Flight Checks

- Add a local pre-flight command (`ocagents preflight` / `ocagents check --deterministic`) for selected repository checks and supported static-analysis tools.
- Convert supported tool results into the shared finding format, preserving source and rule provenance.
- Run checks only when relevant files change, and report checks that were skipped.
- Keep results advisory unless a specific, documented policy is configured to block.

**Exit Criteria:** Tests cover clean input, findings, missing tools, and tool execution errors. A failed or unavailable check must never be reported as a clean audit.

---

### v1.6 — Risk Triage & Local Findings Store

- Classify changed files into documented risk tiers (Tier 0: Docs/Assets, Tier 1: Application, Tier 2: IaC/IAM/Network).
- Prototype a local, append-only findings store with stable IDs and schema-version handling.
- Let specialists consume structured resource context and findings, while retaining concise narrative summaries for human operators.
- Record run metadata and tool provenance; keep secrets and unnecessary sensitive data out of stored findings.

**Exit Criteria:** The classifier and store have unit and integration tests for relevant file types, deduplication, schema changes, and error handling. Low-confidence, high-severity findings remain visible for review rather than silently disappearing.

---

### v2.0 — Shared Findings Workflow

- Integrate pre-flight checks, risk triage, findings store, and specialist workflow in the CLI.
- Add provider integrations only when each provider path is implemented, tested, and documented.
- Validate model-produced findings against the schema before storing or routing them.
- Route results to advisory comments, CI failures, or human review using configurable, documented policy.
- Keep automated verification separate from formal human approval.
- Do not automatically apply remediation by default; any future fix or apply flow requires explicit human review and approval.

**v2.0 Exit Criteria:**
- End-to-end tests exercise deterministic findings, model-produced findings, malformed outputs, provider failures, and interrupted runs.
- High-severity findings cannot be silently suppressed due to low confidence.
- CI reports passed, failed, and skipped checks accurately.
- No clean verdict is produced when required checks fail or cannot run.
- Documentation, CLI behavior, and package maturity claims agree.

---

### After v2.0 — Evaluate Before Expanding

- Benchmark token use and latency against a documented baseline.
- Measure finding precision and recall on a versioned evaluation set.
- Tune confidence thresholds using evaluation data; do not present model confidence as calibrated until it is empirically measured.
- Consider guarded remediation workflows only after evidence shows they are safe and useful.

---

## Architectural Principles & Guardrails

The implementation of this roadmap adheres to five architectural safeguards formalized in [ADR-002](./adr-002-blackboard-findings-and-token-budgets.md):

1. **Avoid the "Zero Hallucination" Claim:** Structured schemas improve schema validation, field completeness, and traceability, but do not guarantee that a model's finding is factually true.
2. **Treat Token Savings as a Hypothesis:** The estimated 65–80% token reduction is an architectural hypothesis that requires reproducible benchmarking against a measured baseline before becoming a project claim.
3. **Close Confidence-Routing Gaps:** Routing rules must cover the entire $[0.00, 1.00]$ range without gaps. Potentially serious (Critical/High) findings must never be silently suppressed simply because model confidence is low; they route to human review.
4. **Rejection Over Truncation for Output Budgets:** Never truncate JSON payloads to enforce token limits. Truncation corrupts syntax. Oversized outputs are rejected, retried with bounded strategy, or escalated for review.
5. **Strict Separation of Verification from Approval:** Automated bots and CI gates may post non-approving verification summaries (`event: 'COMMENT'`). Formal pull request approval (`event: 'APPROVE'`) is strictly reserved for human maintainers.
