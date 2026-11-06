# Open Cloud Agents: Pipeline Implementation Backlog

This document defines the actionable, engineering-grade implementation backlog for Open Cloud Agents, translating the architectural decisions in [ADR-002](./adr-002-blackboard-findings-and-token-budgets.md) and the milestones in the [v2.0 Roadmap](./roadmap.md) into concrete, trackable development tasks.

---

## 📊 Backlog Overview & Progress Tracker

| Epic / Milestone | Status | Key Deliverables | Gate Enforcement |
|---|---|---|---|
| **Epic 1: v1.4 Structured Findings Contracts** | 🟢 **In Review (PR #40)** | `finding.json` schema, `FindingValidator`, diff/repo provenance, test fixtures, unit tests | Advisory |
| **Epic 2: v1.5 Deterministic Pre-Flight Gate** | 🟡 **Next Up** | Scanner catalog, SARIF normalizer, Checkov/Trivy ingest, OPA evaluator, `ocagents preflight` | **Merge-Gating (Deterministic)** |
| **Epic 3: v1.6 Risk Triage & Blackboard Store** | ⚪ **Planned** | Diff risk tiering (Tier 0–2), SQLite WAL findings store, deterministic deduplication, TOON prompt projection | Advisory |
| **Epic 4: v2.0 Shared Workflow & Triage Gate** | ⚪ **Target** | Provider SDK integration, constrained decoding, human triage gate (`open-cloud-agents/triage-gate`) | **Merge-Gating (CI + Human)** |

---

## Epic 1: Milestone v1.4 — Structured Findings Contracts (Current)

* **Objective:** Establish machine-readable contracts, zero-dependency schema validation, and evidence provenance checking before any multi-agent execution is wired up.
* **Tracking Branch:** `feature/v1.4` ([Pull Request #40](https://github.com/open-cloud-agents/ocagents/pull/40))

- [x] **TASK-1.1: Canonical Finding JSON Schema (`schemas/v1/finding.json`)**
  - Publish Draft 2020-12 compatible JSON schema.
  - Define mandatory fields: `id`, `agent`, `origin`, `rule_id`, `category`, `resource`, `fact`, `evidence`, `recommendation`, `severity`, `confidence`, `corroboration_status`.
  - Enforce strict Nullable Confidence Contract (`confidence: null` for linters, float in $[0.0, 1.0]$ for model assertions).
  - Enforce URI locator regex (`^(diff|repo|cloud):...`).
- [x] **TASK-1.2: Schema Validation Engine (`src/ocagents/findings/schema_validator.py`)**
  - Implement zero-dependency validator using standard library (`json`, `re`).
  - Validate field types, required presence, forbidden extra properties (`additionalProperties: false`), and enums.
- [x] **TASK-1.3: Provenance & Anchor Corroborator (`src/ocagents/findings/provenance.py`)**
  - Verify `rule_id` against catalog in `rules/`.
  - Corroborate `diff:` locators against unified diff hunks (line intersection verification).
  - Corroborate `repo:` locators against workspace file line boundaries.
  - Validate `cloud:` provider identifier syntax.
- [x] **TASK-1.4: Unified Finding Validator & CLI Subcommand (`src/ocagents/findings/validator.py`, `src/ocagents/cli.py`)**
  - Implement `FindingValidator` orchestrator.
  - Add `ocagents findings validate <path> [--diff <diff>] [--repo-root <path>]`.
- [x] **TASK-1.5: Test Fixtures & Unit Test Suite (`tests/`)**
  - Create 8 valid and invalid JSON fixtures in `tests/fixtures/findings/`.
  - Implement 19 unit tests in `tests/test_findings_validation.py` running in <5ms.
- [x] **TASK-1.6: Agent Frontmatter Contract Specifications**
  - Add optional `token_budget` and `handoff_contract` sections to YAML frontmatter of the 7 agent specs in `agents/7-agent-master-suite/`.
  - Update `ocagents validate` to check structural token approximations.

---

## Epic 2: Milestone v1.5 — Deterministic Pre-Flight Gate & Sensor Ingestion

* **Objective:** Build the local and CI pre-flight engine (Stage 1 Deterministic Baseline, 0 LLM tokens). Ingest static scanner outputs into canonical findings, enforcing fail-closed semantics when required tools are missing.
* **Target Branch:** `feature/v1.5`
* **Prerequisite:** Epic 1 merged into `main`.

- [x] **TASK-2.1: Scanner Requirement & Target Mapping Catalog (`src/ocagents/scanner/registry.py`)**
  - Map file extensions to supported tools:
    - `.tf`, `.tfvars`, `.bicep` $\rightarrow$ Checkov, Trivy (IaC).
    - `.yaml`, `.yml` (K8s/Helm) $\rightarrow$ Checkov, Trivy, OPA/Rego.
    - `.sh` $\rightarrow$ ShellCheck.
    - `.py` $\rightarrow$ Flake8/Ruff, CodeQL.
    - `Dockerfile`, `Containerfile` $\rightarrow$ Trivy.
  - Classify scanners into `requirement_level: "required" | "advisory"`.
- [x] **TASK-2.2: Universal SARIF & Tool Result Normalizer (`src/ocagents/findings/normalizer.py`)**
  - Ingest SARIF v2.1.0 JSON payloads (output by CodeQL, Trivy, Checkov, Semgrep).
  - Map SARIF `results[]` into `schemas/v1/finding.json`:
    - `ruleId` $\rightarrow$ canonical repository `rule_id` mapping.
    - Physical location $\rightarrow$ `repo:<file>#L<start>-L<end>`.
    - Level (`error`, `warning`) $\rightarrow$ `severity` (`critical`, `high`, `medium`, `low`).
    - Stamped with `origin: "deterministic_linter"`, `confidence: null`, `corroboration_status: "tool_verified"`.
- [x] **TASK-2.3: Checkov & Trivy Ingest Bridges**
  - Implement native adapters parsing Checkov JSON and Trivy JSON/SARIF.
  - Automatically filter findings to modified lines when running against a PR diff.
- [x] **TASK-2.4: OPA (Rego) Policy Evaluator Integration (`src/ocagents/scanner/opa.py`)**
  - Add institutional Rego policies enforcing `rules/01-destructive-actions.md` and `rules/04-cloud-well-architected-invariants.md`.
  - Evaluate Terraform plan JSON or Kubernetes manifests against institutional rules.
- [ ] **TASK-2.5: Fail-Closed Scanner Availability Protocol**
  - Detect missing tool binaries in runtime environment.
  - If a **required scanner** is missing: halt before LLM execution, emit status `INCOMPLETE_CHECK_FAILED`, exit code `1`.
  - If an **advisory scanner** is missing: emit `SKIPPED_SCANNER_UNAVAILABLE`, mark run `INCONCLUSIVE_PARTIAL_AUDIT`, exit code `2`.
  - Implement `.ocagents/exceptions.json` parser checking signed exceptions and 90-day expiry.
- [ ] **TASK-2.6: CLI Command `ocagents preflight` (`src/ocagents/cli.py`)**
  - Implement `ocagents preflight [--diff] [--strict] [--json]`.
  - Output colorized terminal summary: executed scanners, skipped checks, and normalized finding counts.
- [ ] **TASK-2.7: Pre-Flight Test Suite & CI Integration**
  - Unit tests covering clean pass, invariant failure, missing required scanner, unparseable input file, and expired exception rejection.
  - Wire `ocagents preflight --diff` into `.github/workflows/autonomous-gatekeeper.yml`.

---

## Epic 3: Milestone v1.6 — Risk-Based Triage & Blackboard Findings Store

* **Objective:** Implement the Git diff triage classifier and local append-only findings store with deterministic deduplication, concurrency safety, and compact prompt context projection.
* **Target Branch:** `feature/v1.6`
* **Prerequisite:** Epic 2 merged into `main`.

- [ ] **TASK-3.1: Blast Radius Risk Tier Classifier (`src/ocagents/triage/classifier.py`)**
  - Parse Git diff changeset and categorize into risk tiers:
    - **Tier 0 (Docs & Non-Code Assets):** `.md`, `.txt`, `.png`, `.jpg`, `.svg` $\rightarrow$ bypass specialist LLMs completely.
    - **Tier 1 (Application Code Only):** `.py`, `.go`, `.java`, `.ts` without IaC changes $\rightarrow$ route exclusively to DevSecOps Reviewer.
    - **Tier 2 (High Blast Radius Infrastructure):** `.tf`, `.yaml` (K8s), IAM policies, routing, `.github/workflows/` $\rightarrow$ activate Master Suite blackboard.
- [ ] **TASK-3.2: Run Metadata Envelope Engine (`src/ocagents/blackboard/envelope.py`)**
  - Generate deterministic run identifier:
    `run_id = "run-" + sha256(repo_url + ":" + commit_sha + ":" + pr_number + ":" + timestamp_utc)[0:16]`
  - Record environment manifests: `commit_sha`, `base_sha`, `schema_version`, `engine_version`, `agent_manifest`, `tool_manifest`.
- [ ] **TASK-3.3: Deterministic Finding ID & Deduplication Engine (`src/ocagents/blackboard/dedup.py`)**
  - Compute deterministic composite key:
    `id = "FND-" + sha256(rule_id + ":" + resource + ":" + evidence)[0:12].upper()`
  - Implement deduplication logic: update existing record metadata on duplicate emissions instead of appending phantom records.
- [ ] **TASK-3.4: Local Append-Only Blackboard Storage (`src/ocagents/blackboard/store.py`)**
  - Implement embedded SQLite backend with WAL (Write-Ahead Logging) mode and busy timeout (`busy_timeout = 5000ms`).
  - Implement file-based JSONL fallback with cross-platform advisory locking (`fcntl.flock` on Unix, `msvcrt.locking` on Windows).
  - Provide CRUD APIs: `store.publish(finding)`, `store.get_by_id(id)`, `store.query(run_id, severity, origin)`.
- [ ] **TASK-3.5: TOON / Compact Tabular Prompt Projection Serializer (`src/ocagents/blackboard/projections.py`)**
  - Implement projection function compiling uniform arrays of blackboard findings into TOON-style tabular headers and rows.
  - Benchmark token reduction (target: 30% to 50% prompt token reduction compared to raw JSON array injection).
- [ ] **TASK-3.6: CLI Command `ocagents findings store` (`src/ocagents/cli.py`)**
  - Subcommands: `ocagents findings store list --run-id <id>`, `export --format json|toon`, `clear`.
- [ ] **TASK-3.7: Concurrency & Lock Stress Tests (`tests/test_blackboard_concurrency.py`)**
  - Multiprocessing stress tests verifying zero database corruption or lock timeouts during concurrent writes from simulated parallel agents.

---

## Epic 4: Milestone v2.0 — Specialist Runtime, Provider Bridge & CI Triage Gate

* **Objective:** Connect live foundation model providers using constrained decoding, execute parallel specialist loops against the blackboard, compile human review summaries, and deploy the non-blocking triage gate.
* **Target Branch:** `feature/v2.0`
* **Prerequisite:** Epic 3 merged into `main`.

- [ ] **TASK-4.1: Model Provider Integrations with Constrained Decoding (`src/ocagents/providers/`)**
  - Implement client adapters for Anthropic Claude, Google Gemini, OpenAI, and Ollama/vLLM.
  - Enforce provider-native JSON Schema constrained decoding (`response_format: { type: "json_schema" }` or equivalent tool calling) using `schemas/v1/finding.json`.
  - Enforce bounded retry strategy (reject on invalid payload, retry with schema error feedback up to declared agent token budget).
- [ ] **TASK-4.2: Specialist Agent Blackboard Execution Loop (`src/ocagents/orchestration/blackboard_runner.py`)**
  - Subscribe agents to risk-tiered diffs and existing findings.
  - Parallel execution of Tier 2 specialists (Principal Cloud Architect, Security Compliance Commander, FinOps Cost Optimizer, SRE Reliability Engineer).
  - Enforce per-agent token limits declared in agent specifications (`max_context_tokens`, `max_output_tokens`).
- [ ] **TASK-4.3: Stage 5 User-Facing Markdown Synthesis Reporter (`src/ocagents/reporting/synthesis.py`)**
  - Compile structured findings into clean, actionable PR review Markdown summaries.
  - Group findings by severity, include clickable line anchor links, and embed proposed remediation diff previews.
- [ ] **TASK-4.4: Dedicated CI Status Check: `open-cloud-agents/triage-gate`**
  - Add GitHub Actions status check context `open-cloud-agents/triage-gate`.
  - When P0/P1 model assertions exist: set check to `state: "pending"`, apply PR label `needs-security-review`, request review from `CODEOWNERS`.
  - When all findings are clean or resolved: set check to `SUCCESS`.
- [ ] **TASK-4.5: Human Triage Resolution Directives (`src/ocagents/triage/resolution.py`)**
  - Support slash directives in PR comments: `/ocagents triage FND-XXX accept` or `/ocagents triage FND-XXX dismiss --reason "..."`.
  - Automatically update `corroboration_status` to `"human_verified"` or `"rejected_false_positive"`.
  - Release `open-cloud-agents/triage-gate` to `SUCCESS` once all P0/P1 items are resolved or upon human maintainer PR approval (`event: 'APPROVE'`).
- [ ] **TASK-4.6: Evaluation Benchmark & Token Calibration Suite**
  - Benchmark token consumption against linear conversational baselines.
  - Validate and calibrate provisional model confidence thresholds ($\ge 0.85$, $< 0.85$) against versioned synthetic test callsets.
  - Publish empirical benchmark results before making official project claims.

---

## 🎯 Definition of Done (DoD) per Milestone

1. **Deterministic Quality Gates:** All unit and integration tests pass with 100% clean exit codes (`0`).
2. **Repository Hygiene Invariants:** Zero broken Markdown links, zero leaking workstation paths (`/Users/<username>/`), valid SKILL frontmatter, and preserved script executable permissions (`validate_repo.py`).
3. **No Unplanned Destruction:** Zero automated PR approvals by bots; all remediation diffs remain proposal-only previews requiring explicit human maintainer approval.
4. **Transparent Documentation:** Every capability delivered in CLI or CI agrees exactly with documentation and roadmap status.
