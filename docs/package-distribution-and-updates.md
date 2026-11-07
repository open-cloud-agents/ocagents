# 📦 Package Distribution & Streamlined Update Channels

This document outlines the multi-platform package distribution architecture, OS package manager alignment, and automated update channeling for the Open Cloud Agents (`ocagents`) standalone CLI.

---

## 🗺️ OS-to-Package-Manager Matrix

Operating systems rely on distinct, native package management ecosystems. To provide zero-friction installation for all developers, Open Cloud Agents supports native channels tailored to each platform:

| Operating System | Primary Native Channels | Secondary / Universal | Update Command |
|---|---|---|---|
| **macOS** (Apple Silicon & Intel) | **Homebrew** (`brew`) | Shell (`curl \| bash`), `pipx` | `brew update && brew upgrade ocagents` |
| **Linux (Ubuntu / Debian)** | **APT** (`apt`), **Snapcraft** (`snap`) | Shell (`curl \| bash`), `pipx` | `apt update && apt install --only-upgrade ocagents` |
| **Linux (Alpine / Docker)** | **APK** (`apk`) | Shell (`curl \| bash`) | `apk update && apk upgrade ocagents` |
| **Linux (Fedora / RHEL)** | **DNF / RPM** (`dnf`) | Homebrew on Linux, `pipx` | `dnf upgrade ocagents` |
| **Windows 11 / 10** | **WinGet** (`winget`), **Chocolatey** (`choco`) | PowerShell (`irm \| iex`), `scoop` | `winget upgrade OpenCloudAgents.ocagents` |
| **Universal (Python 3.9+)** | **PyPI / pipx** (`pipx`) | `pip` | `pipx upgrade open-cloud-agents` |

> [!NOTE]
> **Important Platform Distinction:** Tools like `apt` (Debian/Ubuntu), `apk` (Alpine), `snap` (Ubuntu), and `choco` (Windows) are platform-specific. macOS developers use **Homebrew (`brew`)** or the **universal one-liner (`curl | bash`)**, which provides instant, zero-dependency installation on macOS.

---

## ⚡ The 2-Tier Update Architecture

AI engineering evolves at two different velocities: **agent prompts/skills evolve daily**, whereas **CLI parser binaries evolve monthly**. Open Cloud Agents uses a two-tier update pipeline to ensure users always have access to the latest intelligence without waiting for upstream package repository reviews:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   DEVELOPER REPOSITORY                                 │
│                   Push to 'main' or Release Tag 'v1.3.1' on GitHub                    │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
               ┌────────────────────────────┴───────────────────────────┐
               ▼                                                        ▼
┌──────────────────────────────┐                         ┌──────────────────────────────┐
│  TIER 1: CONTENT & SKILLS    │                         │  TIER 2: CLI ENGINE BINARY   │
│  (Instant Git Catalog Pull)  │                         │ (OS Package Manager Upgrades)│
├──────────────────────────────┤                         ├──────────────────────────────┤
│ • 7 Master Suite Personas    │                         │ • Homebrew Tap (Formula)     │
│ • 377+ 3-Tier Enterprise     │                         │ • PyPI (pipx / pip)          │
│   Execution Skills           │                         │ • WinGet (winget-pkgs)       │
│ • Inviolable Guardrail Rules │                         │ • Chocolatey (community repo)│
│                              │                         │ • Canonical Snap Store       │
│ Command:                     │                         │                              │
│   $ ocagents update          │                         │ Command:                     │
│                              │                         │   $ brew upgrade ocagents    │
│ Velocity: 1.5 Seconds        │                         │   $ winget upgrade ocagents  │
│ Zero Approval Latency        │                         │ Velocity: Standard Packaging │
└──────────────────────────────┘                         └──────────────────────────────┘
```

### Tier 1: In-Place Catalog Auto-Update (`ocagents update`)
* **How it works:** When installed via `install.sh`, `install.ps1`, or git, the canonical catalog resides in `~/.open-cloud-agents`.
* **Execution:** Running `ocagents update` triggers a non-destructive `git pull origin main` in `~/.open-cloud-agents`.
* **User Advantage:** When a new cloud CVE occurs, a new CIS benchmark is released, or a prompt optimization is merged, users receive it **instantly in 1.5 seconds** across macOS, Linux, and Windows.

### Tier 2: Upstream Package Manager Upgrades
* **How it works:** Upgrades the binary launcher and Python packaging metadata when major CLI features or new export formats are added.

---

## 🔄 Automated CI/CD Release Channels

When a new version tag (e.g. `v1.3.1`) is tagged and pushed to GitHub, an automated GitHub Actions release workflow handles cross-platform distribution:

### 1. Homebrew Tap (`Formula/ocagents.rb`)
* **Repository:** `open-cloud-agents/homebrew-tap`
* **Automated Action:** Triggers on `release`, downloads the release tarball, calculates SHA256, and commits the updated formula:
  ```bash
  brew tap open-cloud-agents/tap
  brew install ocagents
  # Later:
  brew upgrade ocagents
  ```

### 2. PyPI & pipx (`pyproject.toml`)
* **Automated Action:** Runs `flit build` or `python -m build`, publishes wheels to PyPI via GitHub OIDC Trusted Publishing.
* **User Experience:**
  ```bash
  pipx install open-cloud-agents
  # Later:
  pipx upgrade open-cloud-agents
  ```

### 3. Windows Package Manager (WinGet)
* **Automated Action:** Uses `winget-create submit` GitHub Action to automatically file a pull request to `microsoft/winget-pkgs`:
  ```powershell
  winget install OpenCloudAgents.ocagents
  # Later:
  winget upgrade OpenCloudAgents.ocagents
  ```

### 4. Chocolatey (`choco`)
* **Automated Action:** Runs `choco pack` and pushes to the Chocolatey Community Repository:
  ```powershell
  choco install ocagents
  # Later:
  choco upgrade ocagents
  ```

### 5. Canonical Snapcraft (`snap`)
* **Automated Action:** Uses the `snapcore/action-build` and `snapcore/action-publish` GitHub Action to release to the `stable` channel.
* **Auto-Update:** Snaps update automatically in the background on Ubuntu systems without user intervention.

---

## 🔒 Cryptographic Supply Chain Security (SLSA Level 3 & Sigstore Attestations)

Every native standalone binary and archive released by Open Cloud Agents is cryptographically signed and attested via GitHub Artifact Attestations (`actions/attest-build-provenance`). This provides verifiable proof of:
- **Build Integrity:** Guarantees the binary was produced directly by GitHub Actions on the official `open-cloud-agents/ocagents` repository.
- **Tamper Resistance:** Proves zero third-party injection or MITM tampering between commit and distribution.
- **Immutable Provenance:** Verifiable against Sigstore's public transparency log (Rekor).

### How to Verify Binary Attestation
Developers and enterprise DevSecOps pipelines can verify downloaded binaries prior to execution using the GitHub CLI:

```bash
gh attestation verify ocagents-darwin-arm64 --owner open-cloud-agents
# or for Linux:
gh attestation verify ocagents-linux-amd64 --owner open-cloud-agents
```

---

## 🔔 Automated Version Update Notifier

To ensure developers are seamlessly informed of newer CLI releases without degrading performance, `ocagents` features an **asynchronous, non-intrusive version update notifier**:

* **Zero Cold-Start Overhead:** Update checks are cached for 24 hours in `~/.cache/ocagents/update_check.json`. Cache expiration triggers a background daemon thread that queries GitHub Releases without blocking or slowing down CLI execution.
* **Safe Output Routing:** Update notices are written strictly to `stderr` and only when attached to an interactive terminal (`sys.stderr.isatty()`). Output redirection (`ocagents list > agents.txt`), piping, and machine-readable output (`--export-json`) are never contaminated.
* **Platform-Aware Guidance:** Automatically detects whether `ocagents` was installed via Homebrew, pipx, WinGet, Alpine APK, or curl, and recommends the exact native command to upgrade.
* **Opt-Out Control:** Users in air-gapped environments or automated scripts can disable the check by setting:
  ```bash
  export OCAGENTS_NO_UPDATE_NOTIFIER=1
  ```
  *(Automated CI runners with `CI=true` or `GITHUB_ACTIONS=true` are automatically exempted).*

---

## 🛡️ Pre-Flight Scanner Dependencies & Lean Distribution Architecture

The standalone executable maintains a lean footprint (~14MB) and delegates static analysis linters (Ruff, ShellCheck, Checkov) to system package managers or Python extras. For complete instructions on managing scanner toolchains across Homebrew, Pip (`open-cloud-agents[preflight]`), and standalone channels, see [Deterministic Pre-Flight Gate & Scanner Toolchains](./preflight-and-toolchains.md).

---

## 🛠️ User Update Cheat Sheet

| Platform | Command to Check Version | Command to Update |
|---|---|---|
| **Any Platform** (Catalog) | `ocagents version` | `ocagents update` |
| **macOS** (Homebrew) | `ocagents -v` | `brew update && brew upgrade ocagents` |
| **macOS / Linux** (Script) | `ocagents info` | `curl -fsSL https://open-cloud-agents.github.io/ocagents/install.sh \| bash` |
| **Windows** (PowerShell) | `ocagents -version` | `irm https://open-cloud-agents.github.io/ocagents/install.ps1 \| iex` |
| **Windows** (WinGet) | `winget list ocagents` | `winget upgrade OpenCloudAgents.ocagents` |
| **Windows** (Chocolatey) | `choco list ocagents` | `choco upgrade ocagents` |
| **Ubuntu / Debian** (APT) | `apt list --installed ocagents` | `sudo apt update && sudo apt install --only-upgrade ocagents` |
| **Alpine Linux** (APK) | `apk info ocagents` | `apk update && apk upgrade ocagents` |
| **Python** (pipx) | `pipx list` | `pipx upgrade open-cloud-agents` |

