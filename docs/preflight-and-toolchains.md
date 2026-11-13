# 🛡️ Deterministic Pre-Flight Gate & Scanner Toolchain Architecture

This document specifies the architecture, scanner catalog, installation options, and exit code protocol for the **Deterministic Pre-Flight Gate** (Pillar 3, [ADR-002](./adr-002-blackboard-findings-and-token-budgets.md)), as well as guidance for managing static analysis dependencies across all installation channels.

---

## 🏛️ Architecture Overview

The Deterministic Pre-Flight Gate enforces strict static analysis and policy screening on changesets **before** LLM tokens are consumed or code changes are merged into upstream repositories. It operates on a **fail-closed scanner availability protocol**:

1. **Target Changeset Resolution:** Resolves modified files from explicit arguments, git diff (`--diff <ref>`), or uncommitted working tree changes.
2. **Scanner Availability Check:** Checks that all scanners required for the specific file types in the changeset are available in the local or CI environment.
3. **Fail-Closed Gate:** If a required scanner is missing and no active cryptographically-signed exception covers the file, execution halts immediately with status `INCOMPLETE_CHECK_FAILED` (exit code `1`).
4. **Advisory Degradation:** If an advisory scanner is missing, coverage is flagged as degraded with status `INCONCLUSIVE_PARTIAL_AUDIT` (exit code `2`), warning the user without blocking standard pre-merge workflows unless `--strict` mode is enabled.
5. **Deterministic Invariant Evaluation:** Runs the DevSecOps diff heuristic screen and OPA institutional policy checks to detect destructive traps, open CIDR blocks, or privilege escalations before specialist AI agents execute.

```
                           ┌─────────────────────────────┐
                           │      Target Changeset       │
                           │ (git diff / explicit paths) │
                           └──────────────┬──────────────┘
                                          │
                                          ▼
                           ┌─────────────────────────────┐
                           │   Scanner Registry Lookup   │
                           │  (Map files to tool catalog)│
                           └──────────────┬──────────────┘
                                          │
                     ┌────────────────────┴────────────────────┐
                     ▼                                         ▼
         [Required Scanners]                       [Advisory Scanners]
       (Checkov, ShellCheck, Ruff)                  (Trivy, CodeQL, OPA)
                     │                                         │
        ┌────────────┴────────────┐               ┌────────────┴────────────┐
        ▼                         ▼               ▼                         ▼
    Installed?                Installed?      Installed?                Installed?
    ├── YES ➔ Execute         ├── YES ➔ Run   ├── YES ➔ Execute         ├── YES ➔ Run
    └── NO  ➔ Signed Exemption?               └── NO  ➔ Flag Degraded
              ├── YES ➔ Waived                          (Exit 2: INCONCLUSIVE)
              └── NO  ➔ Halt Fail-Closed
                        (Exit 1: INCOMPLETE)
```

---

## 📊 Static Scanner Catalog & Classification Matrix

The canonical scanner catalog classifies tools into **Required** (blocking quality gates) and **Advisory** (warning / deep inspection):

| Scanner | Binary | Category | Level | Target Files | Pinned CI Version | Purpose & Invariants |
|---|---|---|---|---|---|---|
| **Checkov** | `checkov` | `iac` | **REQUIRED** | `.tf`, `.tfvars`, `.bicep`, Kubernetes & Helm manifests | `3.2.368` | Static analysis for IaC security, CIS benchmarks, and cloud resource misconfigurations. |
| **ShellCheck** | `shellcheck` | `linter` | **REQUIRED** | `.sh`, `.bash` | `0.10.0` | POSIX/bash shell script linting, quoting defense, and syntax verification. |
| **Ruff** | `ruff` | `linter` | **REQUIRED** | `.py` | `0.17.4` | High-performance Python linter and AST checker enforcing PEP 8, security rules, and code standards. |
| **Trivy** | `trivy` | `vulnerability` | **ADVISORY** | `Dockerfile`, `Containerfile`, `.tf`, `.bicep` | `0.59.1` | Container image vulnerability scanning and misconfiguration detection. |
| **CodeQL** | `codeql` | `sast` | **ADVISORY** | `.py` | GitHub Action `v3` | Semantic Static Application Security Testing (SAST) query engine. Managed via GitHub Action in CI. |
| **OPA / Rego** | `opa` | `policy` | **ADVISORY** | Kubernetes manifests, Helm charts, `.tf` | `0.70.0` | Institutional policy evaluator enforcing organizational guardrails on infrastructure manifests. |

---

## 📦 Installation Channels & Missing-Tool Guidance

Open Cloud Agents supports three primary installation channels. Each channel has distinct scanner provisioning characteristics:

### 1. Homebrew (`brew install ocagents`) — Recommended for macOS & Linux

The official Homebrew formula (`open-cloud-agents/tap/ocagents`) declares required linters as **recommended dependencies**. Homebrew automatically installs them alongside `ocagents`:

```bash
# Tap and install the CLI (automatically provisions python@3.11, shellcheck, and ruff)
brew tap open-cloud-agents/tap
brew install ocagents

# Verify preflight capabilities
ocagents preflight --help
```

To install optional advisory scanners:
```bash
# Optional IaC and vulnerability scanners
brew install checkov
brew install trivy
brew install opa
```

### 2. Standalone Binary (`curl | bash` / `install.ps1`) — Lean Distribution

The standalone precompiled binary is intentionally **lean (~14MB)**. It packages the CLI runtime and core reasoning engine without bundling hundreds of megabytes of third-party scanner binaries.

If a changeset triggers a missing scanner, install the tool via your system package manager:

```bash
# macOS
brew install ruff shellcheck checkov

# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y shellcheck
pip install ruff checkov

# Alpine Linux
apk add shellcheck
pip install ruff checkov

# Windows (winget / choco / pip)
winget install astral-sh.ruff
choco install shellcheck
pip install checkov
```

### 3. Python Package (`pip install open-cloud-agents[preflight]`)

When installing Open Cloud Agents from PyPI or source, use the `preflight` extra to install all Python-based static analysis scanners:

```bash
# Install CLI with pinned Python scanners (ruff and checkov)
pip install "open-cloud-agents[preflight]"

# Or install from requirements-scanners.txt in source checkouts
pip install -r packaging/requirements-scanners.txt
```

> [!NOTE]
> Non-Python scanners (`shellcheck`, `trivy`, `opa`) are native compiled binaries and must be installed via your system package manager or direct binary downloads.

---

## 🚦 Preflight Exit Code & Status Protocol

The preflight engine produces deterministic exit codes designed for both local terminal feedback and automated CI gatekeeping:

| Exit Code | Status Verdict | Condition | Action Required |
|---|---|---|---|
| `0` | **`CLEAN`** | All required and advisory checks passed cleanly. Zero critical or high policy findings. | Changeset is ready for agent synthesis or PR merge. |
| `1` | **`INCOMPLETE_CHECK_FAILED`** | A **required** scanner (`ruff`, `shellcheck`, `checkov`) is missing for modified files without an active signed exception. | Install the missing scanner or generate an authorized exception. |
| `1` | **`INVARIANT_DEFECT`** | A high-risk architectural defect was detected (e.g., `force_destroy = true`, `forces replacement`, `0.0.0.0/0` ingress, `chmod 777`). | Remediate the flagged defect in the changeset. |
| `2` | **`INCONCLUSIVE_PARTIAL_AUDIT`** | An **advisory** scanner (`codeql`, `trivy`, `opa`) is missing from the environment. Audit executed with degraded coverage. | Advisory only. Install missing tools for full coverage. (Escalates to `1` under `--strict`). |
| `2` | **`ADVISORY_WARNINGS`** | Advisory-level policy warnings or medium/low findings detected. | Review advisory notes in report. |

### Strict Enforcement Mode (`--strict`)
In high-security environments or compliance gates, invoke preflight with `--strict`:
```bash
ocagents preflight --diff origin/main --strict
```
Under `--strict`, any missing advisory scanner (`codeql`, `trivy`, `opa`) immediately escalates from exit code `2` to exit code `1`, enforcing 100% complete scanner coverage.

---

## 💡 Architecture Decision: Why Lean Standalone Binaries?

A common question is: *Why doesn't the `ocagents` standalone installer bundle Ruff, Checkov, Trivy, and CodeQL into a single universal binary?*

The Open Cloud Agents project deliberately maintains a **lean standalone binary** for four architectural reasons:

1. **Binary Bloat Prevention:** The `ocagents` standalone executable is ~14MB. Bundling Python runtime dependencies, Checkov (~120MB), Trivy (~80MB), and a Java runtime for CodeQL (~250MB) would produce a 500MB+ monolith, severely slowing download times and CI spin-up.
2. **Security & CVE Maintenance:** Bundled third-party binaries create "zombie dependencies." If a vulnerability is discovered in an embedded scanner, users remain vulnerable until a new `ocagents` release is published. Delegating scanner installations to system package managers (`brew`, `apt`, `pip`) leverages native OS patch distribution.
3. **Cross-Platform Compilation Matrix:** Open Cloud Agents builds across 5 distinct OS/architecture targets (darwin-arm64, darwin-amd64, linux-amd64, linux-arm64, windows-amd64). Bundling native binaries for all five platforms introduces complex cross-compilation and signing burdens.
4. **Licensing & Redistribution Compliance:** Tools like GitHub CodeQL have specific redistribution terms and licensing constraints that prohibit embedding within offline commercial or third-party redistributables.

---

## 🔍 CodeQL Strategy: CI Automation vs. Local Execution

Open Cloud Agents implements a hybrid strategy for semantic SAST queries:

* **In CI (GitHub Actions):** Semantic analysis runs via the official GitHub CodeQL Action (`.github/workflows/codeql.yml`). This provides zero-configuration AST database compilation, automated security alerts in the GitHub Security tab, and zero local developer overhead.
* **Locally:** CodeQL is registered as an **`ADVISORY`** scanner. If the `codeql` CLI is installed and configured locally, `ocagents preflight` executes queries and ingests the resulting SARIF findings. If missing, preflight emits an advisory notice (`INCONCLUSIVE_PARTIAL_AUDIT`, exit `2`) without blocking developer iteration.

---

## 🛡️ Zero-Liability Toolchain Policy: Delegated Package Management

To avoid supply-chain liabilities, corporate proxy failures, and unmanaged host mutations, Open Cloud Agents follows a strict **Zero-Liability Toolchain Policy**:

### The Inviolable Invariant
> **The `ocagents` CLI intentionally avoids acting as a package manager. It never silently or explicitly downloads third-party executables onto developer workstations.**

Preflight is a passive, deterministic gate. It inspects existing files and local tools. Toolchain installation is strictly delegated to native, trusted package managers:

1. **Native OS Package Managers:**
   * **macOS:** `brew install ruff shellcheck checkov trivy opa`
   * **Debian / Ubuntu:** `sudo apt-get install shellcheck` and `pip install ruff checkov`
   * **Windows:** `winget install astral-sh.ruff` and `choco install shellcheck`
2. **Python Ecosystem Extra:**
   * `pip install "open-cloud-agents[preflight]"` automatically provisions pinned Python linters (`ruff==0.17.4`, `checkov==3.2.368`).
3. **Actionable CLI Guidance:**
   * When a scanner is missing from the local environment, `ocagents preflight` halts or warns with a clean, copy-pasteable installation hint tailored to the tool without mutating the user's host environment.

---

## 🔄 Updating Pinned Scanner Versions

To ensure reproducible audits, static scanner versions are pinned in `packaging/requirements-scanners.txt` and `.github/workflows/autonomous-gatekeeper.yml`.

### Step-by-Step Update Protocol:
1. **Update Requirements:** Modify version strings in `packaging/requirements-scanners.txt` and `pyproject.toml` (`[project.optional-dependencies]`).
2. **Verify Multi-Version Compatibility:** Run test matrix across Python 3.9 through 3.13:
   ```bash
   python3 -m unittest tests/test_preflight_channels.py
   ```
3. **Update CI Environment Variables:** Synchronize `RUFF_VERSION` and `CHECKOV_VERSION` in `.github/workflows/autonomous-gatekeeper.yml`.
4. **Update Documentation Matrix:** Update the version table in this document.
5. **Run Verification Diff:** Execute `./bin/ocagents preflight --diff origin/main` to confirm zero false positives or broken rules.

