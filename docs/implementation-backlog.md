# Open Cloud Agents: Pipeline Implementation Backlog

This document defines the actionable, engineering-grade implementation backlog for Open Cloud Agents, translating the architectural decisions in [ADR-002](./adr-002-blackboard-findings-and-token-budgets.md) and the milestones in the [v2.0 Roadmap](./roadmap.md) into concrete, trackable development tasks.

---

## 📊 Backlog Overview & Progress Tracker

| Epic / Milestone | Status | Key Deliverables | Gate Enforcement |
|---|---|---|---|
| **Epic 1: v1.4 Structured Findings Contracts** | 🟢 **Complete** | `finding.json` schema, `FindingValidator`, diff/repo provenance, test fixtures, unit tests | Advisory |
| **Epic 2: v1.5 Deterministic Pre-Flight Gate** | 🟢 **Complete** | Scanner catalog, SARIF normalizer, Checkov/Trivy ingest, OPA evaluator, `ocagents preflight`, CI gate | **Merge-Gating (Deterministic)** |
| **Epic 3: v1.6 Risk Triage & Blackboard Store** | 🟢 **Complete** | Diff risk tiering (Tier 0–2), SQLite WAL findings store, deterministic deduplication, TOON prompt projection | Advisory |
| **Epic 4: v2.0 Shared Workflow & Triage Gate** | 🟢 **Complete** | Provider SDK integration, constrained decoding, human triage gate (`open-cloud-agents/triage-gate`), benchmark suite | **Merge-Gating (CI + Human)** |
| **Epic 5: v2.1 Multi-VCS & Forge Adapters** | 🟢 **Complete** | Universal `VCSProvider` interface, GitLab MR & Code Quality JSON, Azure DevOps status policies & pipelines task, Bitbucket Code Insights, Gitea | **Merge-Gating (Multi-Forge)** |
| **Epic 6: v2.2 Anti-Proliferation & Dynamic Triage** | 🟢 **Complete** | 4-Tier Adaptive Risk Classifier (Issue #102), Anti-Swamp Deduplication & TTL (Issue #101), Bounded Execution DAG (Issue #100) | **Merge-Gating (Dynamic Matrix)** |

---

## Epic 1: Milestone v1.4 — Structured Findings Contracts (Complete)

* **Objective:** Establish machine-readable contracts, zero-dependency schema validation, and evidence provenance checking before any multi-agent execution is wired up.
* **Tracking Branch:** `feature/v1.4` (Merged to `main`)

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
- [x] **TASK-2.5: Fail-Closed Scanner Availability Protocol**
  - Detect missing tool binaries in runtime environment.
  - If a **required scanner** is missing: halt before LLM execution, emit status `INCOMPLETE_CHECK_FAILED`, exit code `1`.
  - If an **advisory scanner** is missing: emit `SKIPPED_SCANNER_UNAVAILABLE`, mark run `INCONCLUSIVE_PARTIAL_AUDIT`, exit code `2`.
  - Implement `.ocagents/exceptions.json` parser checking signed exceptions and 90-day expiry.
- [x] **TASK-2.6: CLI Command `ocagents preflight` (`src/ocagents/cli.py`)**
  - Implement `ocagents preflight [--diff] [--strict] [--json]`.
  - Output colorized terminal summary: executed scanners, skipped checks, and normalized finding counts.
- [x] **TASK-2.7: Pre-Flight Test Suite & CI Integration**
  - Unit tests covering clean pass, invariant failure, missing required scanner, unparseable input file, and expired exception rejection.
  - Wire `ocagents preflight --diff` into `.github/workflows/autonomous-gatekeeper.yml`.

---

## Epic 3: Milestone v1.6 — Risk-Based Triage & Blackboard Findings Store (Complete)

* **Objective:** Implement the Git diff triage classifier and local append-only findings store with deterministic deduplication, concurrency safety, and compact prompt context projection.
* **Target Branch:** `feature/v1.6`
* **Prerequisite:** Epic 2 merged into `main`.

- [x] **TASK-3.1: Blast Radius Risk Tier Classifier (`src/ocagents/triage/classifier.py`)**
  - Parse Git diff changeset and categorize into risk tiers:
    - **Tier 0 (Docs & Non-Code Assets):** `.md`, `.txt`, `.png`, `.jpg`, `.svg` $\rightarrow$ bypass specialist LLMs completely.
    - **Tier 1 (Application Code Only):** `.py`, `.go`, `.java`, `.ts` without IaC changes $\rightarrow$ route exclusively to DevSecOps Reviewer.
    - **Tier 2 (High Blast Radius Infrastructure):** `.tf`, `.yaml` (K8s), IAM policies, routing, `.github/workflows/` $\rightarrow$ activate Master Suite blackboard.
- [x] **TASK-3.2: Run Metadata Envelope Engine (`src/ocagents/blackboard/envelope.py`)**
  - Generate deterministic run identifier:
    `run_id = "run-" + sha256(repo_url + ":" + commit_sha + ":" + pr_number + ":" + timestamp_utc)[0:16]`
  - Record environment manifests: `commit_sha`, `base_sha`, `schema_version`, `engine_version`, `agent_manifest`, `tool_manifest`.
- [x] **TASK-3.3: Deterministic Finding ID & Deduplication Engine (`src/ocagents/blackboard/dedup.py`)**
  - Compute deterministic composite key:
    `id = "FND-" + sha256(rule_id + ":" + resource + ":" + evidence)[0:12].upper()`
  - Implement deduplication logic: update existing record metadata on duplicate emissions instead of appending phantom records.
- [x] **TASK-3.4: Local Append-Only Blackboard Storage (`src/ocagents/blackboard/store.py`)**
  - Implement embedded SQLite backend with WAL (Write-Ahead Logging) mode and busy timeout (`busy_timeout = 5000ms`).
  - Implement file-based JSONL fallback with cross-platform advisory locking (`fcntl.flock` on Unix, `msvcrt.locking` on Windows).
  - Provide CRUD APIs: `store.publish(finding)`, `store.get_by_id(id)`, `store.query(run_id, severity, origin)`.
- [x] **TASK-3.5: TOON / Compact Tabular Prompt Projection Serializer (`src/ocagents/blackboard/projections.py`)**
  - Implement projection function compiling uniform arrays of blackboard findings into TOON-style tabular headers and rows.
  - Benchmark token reduction (target: 30% to 50% prompt token reduction compared to raw JSON array injection).
- [x] **TASK-3.6: CLI Command `ocagents findings store` (`src/ocagents/cli.py`)**
  - Subcommands: `ocagents findings store list --run-id <id>`, `export --format json|toon`, `clear`.
- [x] **TASK-3.7: Concurrency & Lock Stress Tests (`tests/test_blackboard_concurrency.py`)**
  - Multiprocessing stress tests verifying zero database corruption or lock timeouts during concurrent writes from simulated parallel agents.

### 🛡️ Toolchain Philosophy & Missing-Tool UX (Zero-Liability Architecture)
* **Objective:** Ensure preflight reports missing tools with clear, copy-pasteable installation instructions without forcing users to download packages through ocagents or managing third-party binaries in our repository.
- [x] **TASK-3.8: Actionable Missing-Tool Installation Guidance (Zero-Liability Architecture)**
  - Intentionally avoid acting as a package manager or downloading third-party binaries onto developer PCs.
  - Empower users via native package managers (`brew install`, `apt-get install`, `winget install`) and Python extras (`pip install open-cloud-agents[preflight]`).
  - Embed actionable copy-paste installation commands directly in `ocagents preflight` output for missing required and advisory scanners (`ruff`, `shellcheck`, `checkov`, `trivy`, `opa`, `codeql`).

---

## Epic 4: Milestone v2.0 — Specialist Runtime, Provider Bridge & CI Triage Gate

* **Objective:** Connect live foundation model providers using constrained decoding, execute parallel specialist loops against the blackboard, compile human review summaries, and deploy the non-blocking triage gate.
* **Target Branch:** `feature/v2.0`
* **Prerequisite:** Epic 3 merged into `main`.

- [x] **TASK-4.1: Model Provider Integrations with Constrained Decoding (`src/ocagents/providers/`)**
  - Implement client adapters for Anthropic Claude, Google Gemini, OpenAI, and Ollama/vLLM.
  - Enforce provider-native JSON Schema constrained decoding (`response_format: { type: "json_schema" }` or equivalent tool calling) using `schemas/v1/finding.json`.
  - Enforce bounded retry strategy (reject on invalid payload, retry with schema error feedback up to declared agent token budget).
- [x] **TASK-4.2: Specialist Agent Blackboard Execution Loop (`src/ocagents/orchestration/blackboard_runner.py`)**
  - Subscribe agents to risk-tiered diffs and existing findings.
  - Parallel execution of Tier 2 specialists (Principal Cloud Architect, Security Compliance Commander, FinOps Cost Optimizer, SRE Reliability Engineer).
  - Enforce per-agent token limits declared in agent specifications (`max_context_tokens`, `max_output_tokens`).
- [x] **TASK-4.3: Stage 5 User-Facing Markdown Synthesis Reporter (`src/ocagents/reporting/synthesis.py`)** *(Merged in PR #84)*
  - Compile structured findings into clean, actionable PR review Markdown summaries.
  - Group findings by severity, include clickable line anchor links, and embed proposed remediation diff previews.
  - CLI command `ocagents report` with Markdown, SARIF 2.1.0, and JUnit XML outputs.
- [x] **TASK-4.4: Dedicated CI Status Check: `open-cloud-agents/triage-gate`**
  - Add GitHub Actions status check context `open-cloud-agents/triage-gate`.
  - When P0/P1 model assertions exist: set check to `state: "pending"`, apply PR label `needs-security-review`, request review from `CODEOWNERS`.
  - When all findings are clean or resolved: set check to `SUCCESS`.
  - CLI subcommand and flag `ocagents triage gate` / `ocagents triage --gate`.
  - Added 13 unit tests in `tests/test_triage_gate.py`.
- [x] **TASK-4.5: Human Triage Resolution Directives (`src/ocagents/triage/resolution.py`)**
  - Support slash directives in PR comments: `/ocagents triage FND-XXX accept` or `/ocagents triage FND-XXX dismiss --reason "..."`.
  - Automatically update `corroboration_status` to `"human_verified"` or `"rejected_false_positive"`.
  - Enforce repository `CODEOWNERS` authorization checks on directive authors.
  - Release `open-cloud-agents/triage-gate` to `SUCCESS` once all P0/P1 items are resolved or upon human maintainer PR approval (`event: 'APPROVE'`).
  - Added CLI resolution commands: `ocagents triage accept/dismiss/resolve/directive/approve`.
  - Added GitHub Actions automation workflow `.github/workflows/triage-directive.yml`.
  - Added 13 unit tests in `tests/test_triage_resolution.py`.
- [x] **TASK-4.6: Evaluation Benchmark & Token Calibration Suite (`src/ocagents/benchmark/`)**
  - Benchmark token consumption against linear conversational baselines: empirically validated **70.4% overall token reduction** and **70.9% cost reduction**, confirming ADR-002's 65%–80% reduction hypothesis.
  - Validate and calibrate provisional model confidence thresholds ($\ge 0.85$, $< 0.85$) against versioned synthetic test callsets (`v2026.11-v1`): ECE, Brier score, and threshold sensitivity curves demonstrating optimal $\tau = 0.85$ operating cutoff.
  - Implemented comparative benchmark runner and CLI subcommand `ocagents benchmark` (aliases: `eval`, `bench`).
  - Published empirical benchmark results in `docs/eval-benchmarks.md` before making official project claims.
  - Added 12 unit tests in `tests/test_evaluation_benchmark.py` (PR #88, Closes #61).

---

## Epic 5: Milestone v2.1 — Multi-VCS & Enterprise Forge Adapters (Complete)

* **Objective:** Decouple Open Cloud Agents from GitHub-specific assumptions and deliver native code review, merge gating, and artifact reporting across GitLab, Azure DevOps, Bitbucket, and Gitea/Forgejo according to [ADR-003](./adr-003-multi-vcs-provider-adapters.md).
* **Target Milestone:** `v2.1`
* **Prerequisite:** Epic 4 merged into `main`.

- [x] **TASK-5.1: Core `VCSProvider` Interface & Auto-Detection Engine (`src/ocagents/vcs/`)**
  - Implement abstract base class `VCSProvider` in `src/ocagents/vcs/base.py` with standard methods: `detect_context()`, `get_diff()`, `post_pr_summary()`, `post_inline_annotations()`, `set_commit_status()`, `export_native_artifacts()`.
  - Implement dynamic forge auto-detector in `src/ocagents/vcs/detector.py` inspecting CI environment variables (`GITLAB_CI`, `TF_BUILD`, `BITBUCKET_BUILD_NUMBER`, `GITEA_ACTIONS`, `GITHUB_ACTIONS`) and Git remotes.
  - Implement `LocalGitAdapter` fallback for offline developer workstations.
- [x] **TASK-5.2: GitLab SaaS & Self-Managed Adapter (`src/ocagents/vcs/gitlab.py`)**
  - Implement GitLab REST v4 API client using `GITLAB_TOKEN` or `CI_JOB_TOKEN`.
  - Implement Merge Request discussion thread annotations for line-anchored findings.
  - Export native GitLab Code Quality artifact (`gl-code-quality-report.json`) for seamless MR UI rendering.
  - Publish official `.gitlab-ci.yml` CI/CD template and component.
- [x] **TASK-5.3: Azure DevOps Pipelines Adapter & Extension (`src/ocagents/vcs/azure_devops.py`)**
  - Implement Azure DevOps REST API 7.x client using `SYSTEM_ACCESSTOKEN`.
  - Map finding severity to ADO Pull Request Status Check policies (`succeeded`, `failed`, `waiting`).
  - Publish inline thread comments on ADO Pull Request iterations.
  - Package an official Azure Pipelines composite task (`azure-pipelines.yml`).
- [x] **TASK-5.4: Bitbucket Cloud & Data Center Adapter (`src/ocagents/vcs/bitbucket.py`)**
  - Implement Bitbucket Cloud & Server REST 2.0 client using `BITBUCKET_TOKEN`.
  - Ingest findings into Bitbucket Code Insights API (`POST /repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{report_key}`).
  - Add inline code annotations to PR diffs.
  - Publish an official Bitbucket Pipe (`bitbucket-pipelines.yml`).
- [x] **TASK-5.5: Gitea & Forgejo Air-Gapped Adapter (`src/ocagents/vcs/gitea.py`)**
  - Implement Gitea API v1 client for self-hosted sovereign clouds and offline networks.
  - Support strict `--offline` mode with zero external egress.
  - Integrate with Gitea Actions workflows.
- [x] **TASK-5.6: Test Matrix & Mock Forge Test Suite (`tests/test_vcs_adapters.py`)**
  - Comprehensive unit tests mocking REST endpoints for GitLab, ADO, Bitbucket, and Gitea.
  - Verify deterministic fallback to `LocalGitAdapter` when running outside CI.

---

## Epic 6: Milestone v2.2 — Anti-Proliferation, Anti-Swamp & Dynamic Triage

* **Objective:** Address external scaling and proliferation feedback by enforcing strict, risk-tiered agent activation boundaries, anti-swamp blackboard deduplication with TTL invalidation, and bounded execution DAGs with interaction circuit breakers.
* **Target Milestone:** `v2.2`
* **Prerequisite:** Epic 5 merged into `main`.

- [x] **TASK-6.1: Adaptive Change-Set Risk Classifier & Dynamic Agent Invocation Matrix (Closes #102)**
  - Expand blast radius classification from 3 tiers to 4 fine-grained operational tiers:
    - **Tier 0 (No-Op / Documentation):** `*.md`, `docs/**`, `images/**`, `LICENSE`, `.gitignore`, `mkdocs.yml` $\rightarrow$ LLM Bypass (0 tokens spend).
    - **Tier 1 (Low Risk - Scripting & Packaging):** Shell scripts (`*.sh`), utility helpers, packaging manifests (`pyproject.toml`, `requirements*.txt`, `Formula/`) $\rightarrow$ activates `devsecops-engineer`.
    - **Tier 2 (Medium Risk - Workflows & Core Runtime):** CI/CD workflows (`.github/workflows/`, templates), core CLI runtime (`src/ocagents/**`) $\rightarrow$ activates `security-compliance-commander` and `devsecops-reviewer`.
    - **Tier 3 (High Risk - IaC, IAM, Cloud Topology & DB):** Terraform (`*.tf`), Kubernetes manifests, IAM policies, database migrations $\rightarrow$ activates full Master Suite specialists.
  - Implement dynamic invocation matrix module (`src/ocagents/triage/matrix.py`) mapping risk tier to activated specialists, skipped specialists, token ceiling estimates, and gating behavior.
  - Screen for high-risk AST diff triggers: IAM wildcards (`*:*`, `AdministratorAccess`), database destruction (`DROP TABLE`, `TRUNCATE`, unbounded `DELETE`), network exposure (`0.0.0.0/0`, `::/0`), private keys, and `force_destroy`.
  - CLI subcommand and action `ocagents triage classify-diff [--base main] [--json]`.
  - Wire changeset risk tier into `.github/workflows/autonomous-gatekeeper.yml` to skip heavy multi-agent handoff simulation jobs on Tier 0 pull requests.
  - Added unit test suite in `tests/test_risk_classifier.py` and updated `tests/test_triage_classifier.py` (28 tests).

- [x] **TASK-6.2: Anti-Swamp Governance: Deduplication, TTL Expiry & Evidence Ranking (Issue #101)**
  - Canonical SHA-256 fingerprinting for findings (`sha256(rule_id:resource_id:canonical_path:normalized_fact)`).
  - Finding lifecycle state machine: `OPEN` $\rightarrow$ `CORROBORATED` $\rightarrow$ `TRIAGED` $\rightarrow$ `RESOLVED` | `SUPERSEDED` | `EXPIRED`.
  - Git diff refactoring hook (`invalidate_by_diff`) invalidating findings when underlying source ranges are refactored.
  - Signal-to-noise evidence ranking: $Priority = SeverityScore \times Confidence \times CorroborationFactor$ with top-$K$ context pruning.
  - SQLite WAL blackboard store schema evolution, deduplication upserts, and TTL compaction (`ocagents blackboard prune --ttl 14d`).
  - Added unit test suite in `tests/test_blackboard_governance.py` (23 tests, 481 total tests passing).

- [x] **TASK-6.3: Bounded Execution DAG & Anti-Proliferation Interaction Circuit Breaker (Issue #100)**
  - Declarative DAG specification schema (`schemas/v1/orchestration_dag.json`) with strict schema validation.
  - Bounded DAG execution engine (`src/ocagents/orchestration/dag.py`) with topological sort, cycle detection, phase ordering constraints, and canonical 4-phase review flow (`get_canonical_dag()`).
  - Interaction circuit breaker (`src/ocagents/orchestration/circuit_breaker.py`) enforcing token ceilings (per-agent and cumulative workflow), max 2 corroboration hops, ping-pong cycle breaking, and blackboard-mediated decoupling.
  - Backward compatibility shims in `src/ocagents/orchestrator/`.
  - Wire circuit breaker and DAG validation into `BlackboardRunner` and add CLI commands `ocagents dag validate` and `ocagents dag plan`.
  - Added unit test suite in `tests/test_bounded_dag.py` (26 tests, 507 total tests passing).

---

## Epic 7: Milestone v2.3 — Empirical Evaluation, Model Calibration & Live Benchmarks

* **Objective:** Conduct rigorous empirical evaluation across live model providers (Anthropic, OpenAI, Google Gemini), curate a versioned ground-truth multi-cloud PR corpus, calculate Expected Calibration Error (ECE) and Brier scores to optimize human triage routing thresholds ($\tau$), and enforce token/cost regression CI gates.
* **Target Milestone:** `v2.3`
* **Prerequisite:** Epic 6 merged into `main` and Release `v2.2.0` published.

- [ ] **TASK-7.1: Multi-Provider Live API Token & Cost Evaluation Matrix (Issue #128)**
  - Establish a reproducible, multi-provider empirical evaluation matrix measuring token consumption, API latency, and cost per review run across Anthropic (Claude 3.5 Sonnet / Haiku), OpenAI (GPT-4o / GPT-4o-mini), and Google Gemini (Gemini 1.5 Pro / Flash) under both constrained decoding and TOON prompt projection vs. linear conversational multi-agent baselines.
  - Record prompt tokens, completion tokens, cached tokens, wall-clock latency, and dollar cost using standardized provider pricing models.
  - Empirically quantify token savings of SQLite WAL blackboard + TOON projection against linear conversational multi-agent transcripts across Tier 1, Tier 2, and Tier 3 diff sizes.
  - Extend CLI: `ocagents benchmark --provider <all|anthropic|openai|gemini> --matrix --output <json|markdown>`.
  - Update and publish findings in `docs/eval-benchmarks.md`.

- [ ] **TASK-7.2: Versioned Ground-Truth Multi-Cloud PR Benchmark Corpus (Issue #129)**
  - Curate and version a canonical ground-truth multi-cloud evaluation corpus (`v2026.11-corpus-v1`) spanning AWS (Terraform/IAM), Azure (ARM/Bicep), GCP (Workload Identity/Storage), and Kubernetes manifests with human-verified true positives and intentional distractors.
  - Map each test fixture to canonical finding JSON schema with verified line anchors, rule IDs, and expected severity.
  - Implement evaluation metric harness in `src/ocagents/benchmark/metrics.py` computing Precision, Recall, and F1 across deterministic linters and model assertion specialists.
  - CLI subcommand `ocagents benchmark corpus validate`.

- [ ] **TASK-7.3: Empirical Confidence Calibration (ECE), Brier Score & Review Routing Threshold (Issue #130)**
  - Implement Expected Calibration Error (ECE) with equal-frequency and equal-width binning in `src/ocagents/benchmark/calibration.py`.
  - Implement Brier Score and Brier Skill Score (BSS) relative to baseline uniform priors.
  - Generate reliability diagrams (observed accuracy vs. model mean confidence) and evaluate threshold sweeps ($\tau \in [0.50, 0.99]$) against human review escalation costs.
  - Establish empirically optimal routing boundaries for P0 Critical Escalation, P1 Standard Review, and Low-Confidence suppression.
  - CLI subcommand `ocagents benchmark calibrate --corpus <path> --output <json|markdown>`.
  - Document calibration curves and empirical findings in `docs/model-calibration.md`.

- [ ] **TASK-7.4: Automated Token Consumption & Cost Regression Gate (Issue #131)**
  - Implement an automated CI token efficiency and cost regression gate (`.github/workflows/benchmark-regression.yml` / `ocagents benchmark --ci-gate`) running on pull requests modifying `src/ocagents/**`, `schemas/**`, or prompts.
  - Define regression policies: token increase $> 15\%$ triggers warning/failure; execution step count increase $> 20\%$ blocks merge.
  - Post non-approving structured summary comments (`event: 'COMMENT'`) with diff breakdown across specialists.
  - CLI subcommand `ocagents benchmark regression --baseline <file|branch> --current <file> --max-regress-pct 15`.

---

## 🎯 Definition of Done (DoD) per Milestone

1. **Deterministic Quality Gates:** All unit and integration tests pass with 100% clean exit codes (`0`).
2. **Repository Hygiene Invariants:** Zero broken Markdown links, zero leaking workstation paths (`/Users/<username>/`), valid SKILL frontmatter, and preserved script executable permissions (`validate_repo.py`).
3. **No Unplanned Destruction:** Zero automated PR approvals by bots; all remediation diffs remain proposal-only previews requiring explicit human maintainer approval.
4. **Transparent Documentation:** Every capability delivered in CLI or CI agrees exactly with documentation and roadmap status.
