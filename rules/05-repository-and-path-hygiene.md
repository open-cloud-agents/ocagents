---
name: Repository & Path Hygiene Standard
severity: CI_BLOCKING
scope: ALL_AGENTS
---

# Rule 05: Repository & Path Hygiene Standard

## Principle
Open Cloud Agents is an open-source, collaborative project designed to run portably across any developer's local machine, cloud workstation, or CI/CD container. All paths, documentation links, and references must be strictly relative and clean.

---

## Inviolable Path Hygiene Rules

### 1. Zero Absolute Local Workstation Paths
- Under no circumstances may an agent or contributor commit paths containing `/Users/<username>/` (macOS) or `/home/<username>/` (Linux).
- All file references must be relative to the repository root or current file location.
- Example:
    - ❌ `file:///Users/<username>/projects/...`
    - ✅ `../skills/devops/kubernetes/k8s-pod-troubleshooting/SKILL.md`

### 2. Relative Markdown Links
- Every link to another document, agent persona, skill, or script must use standard relative Markdown links (e.g. `[Link Text](../path/to/target.md)`).
- Broken links will fail the automated CI pipeline (`scripts/ci/validate_repo.py`).

### 3. File Permissions
- All shell helper scripts (`*.sh`) and executable Python CLI tools in `scripts/` must retain execution bits (`chmod +x`).

### 4. Git Ignore Discipline
- The `ai_brain/` directory, editor state, virtual environments (`.venv`), and temporary scratch logs must remain permanently ignored via `.gitignore`.

### 5. Frontier AI Context & Workspace Ignore Discipline
To maximize agent reasoning quality, prevent token waste, eliminate hallucinations on minified bundles, and protect zero-trust identity boundaries, every workspace must maintain synchronized ignore specifications:
- **Cursor Indexing & Agent Search:** `.cursorignore` and `.cursorindexingignore` exclude generated static sites (`site/`), distribution binaries (`dist/`), virtualenvs, and lockfiles from vector embeddings and `@Codebase` symbol retrieval.
- **Universal Frontier Agent Ignores:** `.agentignore`, `.aiignore`, `.aiexclude`, `.aiderignore`, `.uignore`, `.clineignore`, and `.rooignore` block autonomous agent loops and terminal tools from inspecting binary blobs and mock payloads.
- **RAG & Vector Knowledge Bases:** `.ragignore` shields vector chunking pipelines from ingesting compiled search indices and duplicate documentation artifacts.
- **Claude Code Tool Permissions:** `.claude/settings.json` enforces `permissions.deny` rules blocking unauthorized reads on secret keys, credentials, and bulky build directories.
- **OpenCode & Web IDE Boundaries:** `opencode.json` and `.vscode/settings.json` (`files.exclude`, `search.exclude`, `files.watcherExclude`) keep file trees and background watchers lean.
