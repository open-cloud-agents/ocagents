# CLI Command Reference

Full reference for the `ocagents` CLI (also available as `oca`). For installation and a quick start, see the [project README](https://github.com/open-cloud-agents/ocagents#-installation).

---

## 🌐 Global Flags & Shortcuts

The `ocagents` CLI supports universal global flags and fast developer shortcuts:

| Flag / Shortcut | Description | Example |
|---|---|---|
| `-h`, `--help` | Render rich, contextual subcommand help guides with usage examples | `ocagents preflight -h` |
| `-v`, `--version` | Display framework version, persona catalog status, and license | `ocagents --version` |
| `ocagents -agents list` | Fast alias to list all 7 specialist agents and tool capabilities | `ocagents -agents list` |
| `ocagents -a ls` | Short abbreviation to list the agent registry | `ocagents -a ls` |
| `ocagents -A -format <fmt>` | Fast shortcut to sync all 7 agents in one command | `ocagents -A -format github` |

---

## 📖 Command Reference

Full overview of all available `ocagents` subcommands:

### `ocagents list` (alias: `ls`)
Lists the 7-Agent Master Suite, declared tool boundaries (`read`, `search`, `edit`, `execute`, `web`), prompt token budgets, and linked skills.
```bash
ocagents list
```

### `ocagents sync`
Synchronizes specialist agents and skills into IDE configurations (GitHub Copilot, Claude Code, Cursor Rules, Gemini).
```bash
# Sync DevSecOps Reviewer + specialist skills into .github/:
ocagents sync devsecops-reviewer --format github --target . --sync-skills

# Sync all 7 agents into Cursor Rules (.cursor/rules/*.mdc):
ocagents sync --all --format cursor --target .

# Sync all 7 agents into Claude Code (.claude/agents/ and .claude/skills/):
ocagents sync --all --format claude --target . --sync-skills
```
* **Flags:** `-A`, `--all`, `-f`, `--format {github,claude,cursor,gemini,raw}`, `-t`, `--target PATH`, `-s`, `--sync-skills`, `--symlink`, `--dry-run`.

### `ocagents validate` (alias: `check`)
Runs local repository hygiene checks, verifying YAML frontmatter on all skills, shell script executable permissions, relative Markdown link integrity, and ensures zero leaking workstation paths or invisible characters.
```bash
ocagents validate
```

### `ocagents preflight` (alias: `gate`)
Executes Stage 1 deterministic pre-flight baseline checks (0 LLM tokens). Enforces fail-closed scanner protocols, signed exceptions, and diff screening.
```bash
# Check working tree changes before commit:
ocagents preflight

# Evaluate pull request unified diff against main:
ocagents preflight --diff

# Strict mode (escalates advisory warnings to exit code 1 in CI):
ocagents preflight --diff --strict --json
```
* **Flags:** `PATHS...`, `--diff [BASE_REF]`, `--strict`, `--json`, `--repo-root PATH`.

### `ocagents triage`
Classifies git changesets into blast radius risk tiers (Stage 2) and evaluates/resolves the `open-cloud-agents/triage-gate` (Stage 6).
```bash
# 1. Classify current changeset into risk tiers (Tier 0: Docs, Tier 1: App, Tier 2: IaC):
ocagents triage

# 2. Evaluate triage-gate status check on findings:
ocagents triage gate --findings findings.json

# 3. Resolve a model finding as authorized CODEOWNER:
ocagents triage accept --id FND-8B1C3E4A9F20 --reason "Approved for dev environment"
ocagents triage dismiss --id FND-8B1C3E4A9F20 --reason "Intentional bastion host configuration"
```
* **Flags:** `--diff [BASE_REF]`, `--gate`, `--findings PATH`, `--db PATH`, `--id FND_ID`, `--resolution {accept,dismiss}`, `--reason TEXT`, `--comment TEXT`, `--actor HANDLE`, `--sha SHA`, `--json`.

### `ocagents findings` (alias: `finding`)
Lists, inspects, triages, exports, and summarizes findings from the Blackboard store. Reads the most recent run by default; use `--run-id` or `--all-runs` to change that, or `--file` to read a findings JSON file instead. With a path and no action, it validates finding JSON documents against `schemas/v1/finding.json`.
```bash
# High and critical findings from the latest run, highest severity first:
ocagents findings list --severity critical,high

# Full detail for one finding: evidence, recommendation, provenance, triage history:
ocagents findings inspect FND-8B1C3E4A9F20

# Record a triage decision (actor must be in CODEOWNERS; --reason is required to dismiss):
ocagents findings triage FND-8B1C3E4A9F20 --action dismiss --reason "Bastion host, approved exception"

# Export for GitHub Code Scanning, a spreadsheet, or a PR comment:
ocagents findings export --format sarif --out ocagents.sarif
ocagents findings export --format csv --all-runs --out findings.csv
ocagents findings export --format markdown --out summary.md

# Counts by severity, status, category, agent, and origin:
ocagents findings stats --json

# Validate finding JSON documents:
ocagents findings validate tests/fixtures/findings/
```
* **Actions:** `list`, `inspect FND_ID`, `triage FND_ID`, `export`, `stats`, `validate [PATH]`.
* **Flags:** `--db PATH`, `--file PATH`, `--run-id ID`, `--all-runs`, `--severity`, `--status`, `--category`, `--agent` (filters are repeatable or comma-separated), `--limit N`, `--json`, `--format {json,sarif,markdown,csv,toon}`, `--out FILE`, `--repo-url URL`, `--action {accept,dismiss}`, `--reason TEXT`, `--actor HANDLE`, `--codeowners PATH`, `--repo-root PATH`.

### `ocagents store`
Inspects, queries, prunes, and exports the SQLite WAL Blackboard findings store.
```bash
# List recent audit runs and recorded findings:
ocagents store list

# Export findings as compact TOON table for model prompts:
ocagents store export --run-id run-019318b4-9a4f-7c1a --format toon

# Export findings as JSON:
ocagents store export --run-id run-019318b4-9a4f-7c1a --format json --out findings.json

# Export findings as SARIF 2.1.0 for GitHub Code Scanning (upload with github/codeql-action/upload-sarif):
ocagents store export --run-id run-019318b4-9a4f-7c1a --format sarif --out ocagents.sarif
```
* **Flags:** `list`, `export`, `prune`, `info`, `--run-id ID`, `--format {json,toon,minified,markdown,sarif}`, `--out FILE`, `--keep N`, `--db PATH`.

### `ocagents report` (aliases: `summary`, `synthesize`)
Synthesizes blackboard findings into clean, actionable, user-facing Markdown review summaries with line anchors and remediation diff previews.
```bash
# Generate Markdown review summary from most recent blackboard run:
ocagents report

# Export report to file with clickable GitHub line links:
ocagents report --out pr_summary.md --repo-url https://github.com/my-org/my-repo
```
* **Flags:** `--run-id ID`, `--file PATH`, `--format {markdown,json}`, `--out FILE`, `--db PATH`, `--repo-url URL`.

### `ocagents benchmark` (aliases: `eval`, `bench`)
Runs reproducible empirical token benchmarks comparing Blackboard Architecture against linear conversational chaining baselines and calibrates model confidence thresholds (ADR-002).
```bash
# Run benchmark and display Markdown summary:
ocagents benchmark

# Export publication Markdown report (docs/eval-benchmarks.md):
ocagents benchmark --export-md docs/eval-benchmarks.md

# Export machine-readable JSON evaluation traces:
ocagents benchmark --export-json .ocagents/benchmark_results.json
```
* **Flags:** `--model MODEL`, `--format {markdown,json}`, `--export-md PATH`, `--export-json PATH`, `--json`.

### `ocagents run` (alias: `simulate`)
Executes an end-to-end multi-agent pipeline review or architectural design task across the 6-stage Master Suite.
```bash
# Run local scripted simulation (zero external network/tokens):
ocagents run --task "Audit Terraform PR in ./terraform/ for state destruction traps"

# Run with local on-device Ollama model:
ocagents run --provider ollama --model llama3 --task "Architect multi-region payment DR failover"

# Run with Claude, Gemini, or OpenAI:
ocagents run --provider anthropic --model claude-3-5-sonnet-20241022 --task "Review IAM policies"
```
* **Flags:** `--task TEXT`, `--provider {simulated,ollama,gemini,anthropic,openai}`, `--model MODEL`, `--export-json FILE`.

### `ocagents sandbox` (aliases: `test-k8s`, `kind`)
Runs isolated, ephemeral KinD Kubernetes sandbox dry-runs and automated incident drills.
```bash
# Ephemeral dry-run on raw Kubernetes manifests:
ocagents sandbox --manifests ./deploy/k8s/

# Test a Helm chart against Kubernetes v1.31:
ocagents sandbox --helm ./charts/billing-api --k8s-version v1.31.0

# Deploy incident scenario and keep cluster running for triage:
ocagents sandbox --scenario scenarios/billing-service-outage/ --keep-cluster
```
* **Flags:** `--manifest PATH`, `--helm PATH`, `--kustomize PATH`, `--scenario PATH`, `--cluster-name NAME`, `--k8s-version TAG`, `--ingress`, `--keep-cluster`.

### `ocagents learn` (aliases: `postmortem`, `ingest`)
Automates the Continual Learning Knowledge Flywheel, codifying edge cases and SRE postmortems into `AGENTS.md`.
```bash
# Ingest single learned fact:
ocagents learn --fact "CoreDNS UDP Throttling: Use ndots: 2 to prevent 5s latency spikes." --category "Kubernetes Networking"

# Ingest from an SRE incident postmortem:
ocagents learn --from-incident postmortems/inc-042.md
```
* **Flags:** `--fact TEXT`, `--category NAME`, `--incident PATH`, `--dry-run`.

### `ocagents info` & `ocagents update`
Displays local catalog paths and runtime metadata, or pulls the latest canonical agent updates.
```bash
ocagents info
ocagents update
```
