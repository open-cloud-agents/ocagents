# Security Policy: Open Cloud Agents

Open Cloud Agents takes the security and operational integrity of cloud architectures, automation runbooks, and agent workflows seriously. We appreciate the responsible disclosure of vulnerabilities by security researchers, contributors, and platform users.

---

## 🔒 Supported Versions

Only the current stable release line and active milestone branches receive security patches and backports:

| Version | Status | Supported |
|---|---|---|
| **2.0.x** | Current Stable GA Release | :white_check_mark: |
| **1.6.x** | Previous Stable LTS Release | :white_check_mark: |
| **< 1.6** | Legacy Releases | :x: |

---

## 🚨 Reporting a Vulnerability

**Please DO NOT report security vulnerabilities via public GitHub issues, discussions, or pull requests.**

### Preferred Method: GitHub Private Vulnerability Reporting
Submit a confidential vulnerability report directly through GitHub Security Advisories:
👉 **[Report a Security Vulnerability](https://github.com/open-cloud-agents/ocagents/security/advisories/new)**

### Alternative Email Channel
If you cannot use GitHub Advisories or prefer direct maintainer communication, email:
- **Contact:** `ibrahimng@users.noreply.github.com`
- **Subject:** `[SECURITY] Open Cloud Agents Vulnerability Report: <Brief Summary>`

Please include in your report:
1. Description of the vulnerability and its potential security impact.
2. Steps to reproduce the issue, including environment, CLI version, and minimal reproducible example.
3. Proof-of-concept (PoC) code or configuration diff (if applicable).
4. Any proposed remediations or mitigations.

---

## ⏱️ Response Timelines & SLA

When you submit a private report, our maintainers commit to:
1. **Initial Acknowledgment:** Within **48 hours** confirming receipt of the report.
2. **Triage & Assessment:** Within **5 business days** with preliminary severity rating (CVSS v3.1) and reproduction status.
3. **Coordinated Disclosure:** We adhere to a standard **90-day Coordinated Vulnerability Disclosure (CVD)** window, or until an official patch and advisory are published.
4. **Credit & Attribution:** Public credit in release notes and security advisories (unless requested to remain anonymous).

---

## 🎯 Scope & Boundaries

### In-Scope
* **Core CLI (`ocagents`):** Argument injection, arbitrary command execution, unsafe deserialization, or credential exfiltration.
* **Deterministic Pre-Flight Gatekeeper:** Bypasses in `scripts/ci/validate_repo.py`, `scripts/ci/audit_pr_diff.py`, or OPA policy evaluations.
* **Findings Blackboard & Store:** SQL injection, path traversal in evidence locators (`repo:`, `diff:`), or corruption of append-only audit records.
* **Agent Specifications & Runbooks:** Malicious instructions or prompt injection vectors embedded in official personas or core skills.

### Out-of-Scope
* Vulnerabilities in upstream third-party CSP documentation mirrors (`skills/csp/*`).
* Attacks requiring physical access to a developer's workstation or local KinD cluster.
* Speculative model outputs in offline simulation mode without host tool execution privileges.
