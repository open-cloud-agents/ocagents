# 🌐 Multi-VCS & Enterprise Forge Integration Guide

Open Cloud Agents provides native, first-class support for enterprise version control systems and code review platforms according to [ADR-003: Multi-VCS Provider Adapter Engine](./adr-003-multi-vcs-provider-adapters.md).

Specialist agents and deterministic pre-flight gates integrate directly into your forge of choice—publishing findings natively into Merge Request diffs, Code Insights widgets, PR status policies, and security pipelines.

---

## 🏛️ Forge Capabilities & Output Matrix

| Feature / Capability | GitHub | GitLab (SaaS & Self-Managed) | Azure DevOps (ADO) | Bitbucket (Cloud & DC) | Gitea & Forgejo |
|---|---|---|---|---|---|
| **CI Environment Detection** | `GITHUB_ACTIONS=true` | `GITLAB_CI=true` | `TF_BUILD=True` | `BITBUCKET_BUILD_NUMBER` | `GITEA_ACTIONS=true` |
| **Authentication Token** | `GITHUB_TOKEN` | `GITLAB_TOKEN` / `CI_JOB_TOKEN` | `SYSTEM_ACCESSTOKEN` | `BITBUCKET_TOKEN` | `GITEA_TOKEN` |
| **Inline Annotations** | Pull Request Comments & Checks | Merge Request Discussions | PR Thread Annotations | Code Insights Annotations | PR Review Comments |
| **Native Report Artifact** | SARIF v2.1.0 (`ocagents.sarif`) | `gl-code-quality-report.json` | SARIF v2.1.0 (`ocagents.sarif`) | `bitbucket-code-insights.json` | `gitea-quality-report.json` |
| **Quality Gate Status Check** | Commit Status Checks | Commit Status API | PR Status Policy Check | Commit Status API (`/statuses/build`) | Commit Status API (`/statuses/{sha}`) |
| **Air-Gapped Sovereign Cloud** | GitHub Enterprise Server | Self-Managed GitLab | Azure DevOps Server | Bitbucket Data Center | Self-Hosted Gitea / Forgejo |

---

## 🦊 1. GitLab Integration (SaaS & Self-Managed)

Open Cloud Agents ingests findings directly into GitLab's native **Code Quality** widget on Merge Requests.

### Pipeline Configuration (`.gitlab-ci.yml`)

Include the official pipeline template from `templates/gitlab-ci.yml` or reference it directly in your project:

```yaml
stages:
  - test

include:
  - remote: 'https://raw.githubusercontent.com/open-cloud-agents/ocagents/main/templates/gitlab-ci.yml'

ocagents-governance-gate:
  stage: test
  image: python:3.11-slim
  script:
    - pip install --no-cache-dir open-cloud-agents
    - ocagents preflight || true
    - ocagents triage gate --sha "$CI_COMMIT_SHA" --dry-run || true
    - ocagents findings export --format gitlab-quality --out gl-code-quality-report.json || true
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
    paths:
      - gl-code-quality-report.json
```

---

## 🔷 2. Azure DevOps Integration (Azure Repos & Pipelines)

Integrates into Azure Pipelines and enforces Pull Request Status Checks and thread annotations.

### Pipeline Configuration (`azure-pipelines.yml`)

```yaml
trigger:
  branches:
    include:
      - main
pr:
  branches:
    include:
      - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'
    displayName: "Set up Python runtime"

  - script: |
      python -m pip install --no-cache-dir --upgrade pip
      python -m pip install --no-cache-dir open-cloud-agents
    displayName: "Install open-cloud-agents"

  - script: |
      echo "🔍 Running Deterministic Pre-Flight Gate..."
      ocagents preflight || true
      if [ -n "$SYSTEM_PULLREQUEST_PULLREQUESTID" ]; then
        ocagents triage gate --sha "$BUILD_SOURCEVERSION" --dry-run || true
      fi
      mkdir -p "$(Build.ArtifactStagingDirectory)/reports"
      ocagents findings export --format sarif --out "$(Build.ArtifactStagingDirectory)/reports/ocagents.sarif" || true
    displayName: "Execute Open Cloud Agents Gate"
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)/reports'
      ArtifactName: 'CodeAnalysisLogs'
      publishLocation: 'Container'
    displayName: "Publish SARIF Code Analysis Artifacts"
    condition: always()
```

---

## 🪣 3. Bitbucket Integration (Cloud & Data Center)

Open Cloud Agents publishes structured **Code Insights Reports** with batched line annotations directly into Bitbucket pull requests.

### Pipeline Configuration (`bitbucket-pipelines.yml`)

```yaml
image: python:3.11-slim

pipelines:
  pull-requests:
    '**':
      - step:
          name: "Open Cloud Agents Governance Gate"
          caches:
            - pip
          script:
            - pip install --no-cache-dir open-cloud-agents
            - echo "🔍 Running Deterministic Pre-Flight Gate..."
            - ocagents preflight || true
            - echo "🛡️ Evaluating Changeset Blast Radius & Model Findings..."
            - ocagents triage gate --sha "$BITBUCKET_COMMIT" || true
            - ocagents findings export --format bitbucket-insights --out bitbucket-code-insights.json || true
            - ocagents findings export --format sarif --out ocagents.sarif || true
          artifacts:
            - bitbucket-code-insights.json
            - ocagents.sarif
```

---

## 🍵 4. Gitea & Forgejo (Air-Gapped Sovereign Cloud)

For sovereign cloud environments, air-gapped defense networks, and privacy-first self-hosted clusters.

### Workflow Configuration (`.gitea/workflows/ocagents.yml`)

```yaml
name: "Open Cloud Agents Governance Gate"

on:
  pull_request:
    branches:
      - main
  push:
    branches:
      - main

jobs:
  governance-gate:
    name: "Autonomous Pre-Flight & Triage Check"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 50

      - name: Set up Python Runtime
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Open Cloud Agents
        run: |
          python -m pip install --no-cache-dir open-cloud-agents

      - name: Deterministic Pre-Flight Gate (Offline Mode)
        run: |
          echo "🔍 Running Open Cloud Agents Deterministic Pre-Flight Gate..."
          ocagents preflight --offline || true

      - name: Triage Evaluation & Artifact Export
        env:
          GITEA_TOKEN: ${{ secrets.GITEA_TOKEN || secrets.GITHUB_TOKEN }}
          GITEA_SERVER_URL: ${{ gitea.server_url || github.server_url }}
        run: |
          mkdir -p reports
          ocagents findings export --format gitea-quality --out reports/gitea-quality-report.json || true
          ocagents findings export --format sarif --out reports/ocagents.sarif || true

      - name: Upload Quality Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ocagents-governance-reports
          path: reports/
```

---

## 🔒 5. Air-Gapped & Sovereign Cloud Compliance

When operating in isolated environments (AWS GovCloud, Azure Government, private datacenters):

1. **Strict Offline Mode (`--offline`):**
   ```bash
   ocagents --offline
   ocagents preflight --offline
   ```
   Completely suppresses remote package version checks and telephone telemetry.
2. **Local Model Endpoints:**
   Set standard base URL environment variables pointing to internal inference gateways:
   ```bash
   export OPENAI_BASE_URL="http://vllm.internal.corp:8000/v1"
   export OLLAMA_HOST="http://ollama.internal.corp:11434"
   ```
3. **Zero Hardcoded Secrets:**
   All CI adapters authenticate via short-lived ephemeral runner tokens (`CI_JOB_TOKEN`, `SYSTEM_ACCESSTOKEN`, `GITEA_TOKEN`).

---

## 💻 6. Local Developer Workstation Usage

Outside of CI pipelines, Open Cloud Agents automatically activates the `LocalGitAdapter`:
- Zero external network requests or tokens required.
- Inspects your local git branch (`git diff`) and outputs findings cleanly in terminal or local JSON.
