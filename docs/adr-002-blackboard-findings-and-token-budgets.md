# ADR-002: Shared Structured Findings Store & Token-Budgeted Blackboard Architecture

* **Status:** Accepted (Target: Open Cloud Agents v2.0)
* **Date:** 2026-11-04
* **Deciders:** Principal Cloud Architect, DevSecOps Reviewer, SRE Reliability Engineer
* **Consulted:** Founding Architect, Community Contributors
* **Supersedes / Extends:** [Architecture MVP Spec](./architecture-mvp-spec.md), [Token Optimization Architecture](./token-optimization-architecture.md), [Engineering Standards](./engineering-standards.md)

---

## 1. Context & Problem Statement

In early iterations of multi-agent engineering frameworks (including Open Cloud Agents v1.x), agent collaboration relies predominantly on **sequential narrative handoffs**:

```text
[Architect Agent] ──(1,200 tok narrative)──► [Security Agent] ──(2,500 tok narrative)──► [FinOps / SRE Agent]
```

While effective for isolated demonstrations, this pattern suffers from three systemic failure modes at enterprise scale:

1. **Compounding Token Inflation ($O(N^2)$ Context Growth):**
   As each specialist agent adds observations, the accumulated conversational transcript saturates model context windows. Downstream agents spend 70% of their token budget re-reading earlier narrative prose rather than evaluating cloud resources.
2. **"Telephone Game" Information Degradation:**
   Conversational prose introduces subjective drift (*"I believe this architecture might..."*). Downstream agents build arguments upon subjective impressions rather than verifiable infrastructure facts, increasing hallucination rates.
3. **Expensive LLM Evaluation of Deterministic Rules:**
   Invoking high-parameter foundation models to check boolean conditions (e.g., `kms_key_id == null` or missing `prevent_destroy`) burns millions of tokens on questions that static analysis or policy-as-code engines answer in 2 milliseconds for free.

---

## 2. Decision Drivers

* **Predictable Token Economics:** Token consumption must be an architectural SLA, not an operational afterthought.
* **Deterministic Baseline Guardrails:** 100% of static, syntactic, and policy rules must execute prior to LLM invocation.
* **Auditability & Provenance:** Every finding must trace to a concrete source line, rule identifier, and confidence score.
* **Reduced False-Positive Fatigue:** High-severity findings with low model confidence must route to human maintainers rather than failing CI/CD pipelines.

---

## 3. Considered Alternatives

| Pattern | Description | Pros | Cons / Why Rejected |
|---|---|---|---|
| **A. Linear Conversational Chaining** | Agents converse in a shared chat thread. | Intuitive to implement; natural language flexibility. | Context explosion, cumulative drift, high token cost. |
| **B. Centralized Orchestrator Routing** | Single "Manager Agent" breaks tasks and calls specialists. | Clear hierarchy. | The Manager becomes a token bottleneck and single point of failure; prone to instruction loss. |
| **C. Blackboard Architecture (Shared Findings Store)** | Specialist agents independently read infrastructure state and publish structured findings to an append-only store. | Sub-linear token scaling, verifiable schemas, decoupled agents. | **Selected as canonical target.** |

---

## 4. Architectural Specification

```mermaid
flowchart TD
    Change["Pull Request / Cloud Workspace State"] --> Funnel["Stage 1: Deterministic Engine (AST / Rego)<br/>0 LLM Tokens"]
    
    Funnel -->|Fails Invariant Rule| HardBlock["Instant Deterministic CI Block"]
    Funnel -->|Passes Invariants| Classifier["Stage 2: Risk-Based Classifier<br/>Fast SLM / Heuristic Classifier"]
    
    Classifier -->|Low Risk (Docs / Non-Infra)| SecOnly["Security Linter Only"]
    Classifier -->|High Risk (IAM / VPC / DB / K8s)| Blackboard["Stage 3: Shared Findings Store (Blackboard)"]
    
    subgraph Specialists["Parallel Specialist Agent Execution"]
        Blackboard <-->|Subscribe State / Publish Finding| AgentArch["Principal Cloud Architect"]
        Blackboard <-->|Subscribe State / Publish Finding| AgentSec["Security Compliance Commander"]
        Blackboard <-->|Subscribe State / Publish Finding| AgentFin["FinOps Cost Optimizer"]
        Blackboard <-->|Subscribe State / Publish Finding| AgentSRE["SRE Reliability Engineer"]
    end
    
    Blackboard --> Synthesis["Stage 4: Automated Synthesis & Routing"]
    Synthesis --> Decision{"Confidence & Severity Gate"}
    Decision -->|High Severity + High Conf| BlockPR["Automated CI Gate Block / Auto-Fix PR"]
    Decision -->|High Severity + Low Conf| HumanGate["Escalate to Human Architect Review"]
    Decision -->|Clean / Low Severity| AutoApprove["Non-Approving Verification Summary"]
```

---

### Pillar 1: The Canonical Finding Schema

Specialist agents are strictly forbidden from communicating in free-form narrative prose. All evaluations must emit valid JSON complying with the **Open Cloud Agents Finding Schema**:

```json
{
  "$schema": "https://open-cloud-agents.github.io/schemas/v1/finding.json",
  "id": "SEC-AZ-042",
  "agent": "security-compliance-commander",
  "rule_id": "rules/02-secrets-and-identity.md",
  "category": "Zero-Trust Secrets",
  "resource": "azurerm_key_vault.prod",
  "fact": "Key Vault public network access enabled without virtual network subnet restrictions",
  "evidence": "terraform/keyvault.tf#L24-L26",
  "recommendation": "Set public_network_access_enabled = false and attach private_endpoint",
  "severity": "high",
  "confidence": 0.94,
  "remediation": {
    "patch_available": true,
    "diff_preview": "- public_network_access_enabled = true\n+ public_network_access_enabled = false"
  }
}
```

#### Fact / Evidence / Recommendation Invariant
Every finding must cleanly separate:
1. **Fact:** Verifiable ground truth regarding the resource state (AST or configuration value).
2. **Evidence:** Explicit file path, line numbers, or cloud resource ARN.
3. **Recommendation:** Prescriptive remediation action without conversational pleasantries.

---

### Pillar 2: First-Class Token Budgeting as Architecture

Every agent specification in `agents/7-agent-master-suite/` must declare immutable token ceilings in its YAML frontmatter:

```yaml
---
name: security-compliance-commander
role: Security Compliance & Cyber Defense Commander
token_budget:
  max_context_tokens: 4500
  max_output_tokens: 600
handoff_contract:
  input_schema: schemas/v1/resource_state.json
  output_schema: schemas/v1/security_finding.json
  max_payload_tokens: 350
tools: [read, search, execute, web]
---
```

* **Build-Time Verification:** `agent_pipeline.py --validate` checks agent declared system prompt token budgets as structural estimates (calibrated to actual tokenizer metrics during runtime).
* **Runtime Enforcement (Rejection over Truncation):** If an agent's output exceeds `max_output_tokens` or emits invalid JSON, the runtime **must not truncate** the payload (which turns valid structured data into corrupt syntax). Instead, the runtime rejects the malformed output, triggers a bounded retry strategy with schema error feedback, or routes the raw attempt to human maintainer review.

---

### Pillar 3: Deterministic Pre-Flight Gate (The Cost-Reduction Funnel)

To protect model budgets, the pipeline evaluates changes in three sequential stages:

1. **Stage 1: Deterministic Engine (0 LLM Tokens):**
   * Static analysis (`semgrep`, `checkov`, `trivy`, `shellcheck`).
   * Repository hygiene (`validate_repo.py`).
   * If a change violates an inviolable rule (e.g., plaintext AWS secret or unquoted runner variable), the pipeline fails immediately without invoking an LLM.
2. **Stage 2: Risk-Based Triage Classifier:**
   * Evaluates the blast radius of the Git diff:
     * **Tier 0 (No Impact):** Documentation, formatting, image assets $\rightarrow$ bypass specialist agents entirely.
     * **Tier 1 (Application Logic):** Application source code without IaC $\rightarrow$ DevSecOps Reviewer only.
     * **Tier 2 (High Blast Radius):** Terraform, CloudFormation, Kubernetes manifests, IAM policies, network routing $\rightarrow$ activate full Master Suite blackboard.
3. **Stage 3: Specialist Agent Blackboard Execution:**
   * Agents execute against the parsed diff and publish atomic findings to the shared store.

---

### Pillar 4: Confidence Scoring & Human-in-the-Loop Routing

To prevent alert fatigue and eliminate false-positive blockers in enterprise CI/CD pipelines, every finding carries a confidence metric $[0.00, 1.00]$. The routing engine enforces complete coverage across all severity and confidence ranges without gaps:

| Severity | Confidence | Routing Action | Enforcement Invariant |
|---|---|---|---|
| **Critical / High** | $\ge 0.85$ | **Automated CI Gate Block** | High confidence in high-risk defect; blocks automated verification. |
| **Critical / High** | $< 0.85$ | **Human Escalation Queue** | High risk, but model uncertainty is elevated; **never suppressed**; flagged for mandatory human maintainer review. |
| **Medium / Low** | $\ge 0.75$ | **Advisory PR Comment** | Structured non-approving verification comment posted for author review. |
| **Medium / Low** | $< 0.75$ | **Diagnostic Audit Log** | Retained in the run execution log for audit traceability; does not clutter PR discussions. |

> **Strict Non-Approval Invariant:** Automated verification workflows running under automated bots post structured verification summaries strictly as non-approving review comments (`event: 'COMMENT'`). Formal pull request approval (`event: 'APPROVE'`) is reserved exclusively for human maintainers.

---

## 5. Consequences & Architectural Hypotheses

### Positive & Expected Capabilities
* **Hypothesized Token Efficiency:** Multi-agent pipeline token consumption is hypothesized to drop by **65% to 80%**, as downstream agents consume structured findings rather than concatenated narrative transcripts. *(Note: This is an architectural hypothesis subject to empirical verification on a versioned evaluation benchmark before becoming an official project claim.)*
* **Enhanced Schema Traceability:** Replacing unstructured prose with strict JSON schemas guarantees field completeness, rule provenance, and machine readability. *(Note: Structured schemas prevent parse errors and format drift, but do not guarantee that model-generated assertions are factually true. Independent tool and human verification remain essential.)*
* **Enterprise CI/CD Predictability:** Clean separation between deterministic AST failures and probabilistic LLM trade-off analyses.
* **Audit Trail Compliance:** Every finding in the shared store serves as structured compliance evidence for SOC 2 and ISO 42001 audits.

### Trade-Offs & Mitigations
* **Schema Rigidity:** Requires strict adherence to JSON schema validation on model outputs; models with poor instruction-following must be handled via bounded retry strategies, not raw truncation.
* **Staged Implementation:** The current CLI simulation does not yet implement the live findings blackboard; transition must proceed through staged releases ([v2.0 Roadmap](./roadmap.md)).

---

## 6. Implementation Milestones

Detailed release milestones, exit criteria, and testing boundaries are formalized in the **[Open Cloud Agents v2.0 Roadmap](./roadmap.md)**:
* **v1.x:** Establish trustworthy baseline, accurate documentation, and transparent simulation status.
* **v1.4:** Structured findings contracts (`schemas/v1/finding.json`).
* **v1.5:** Deterministic pre-flight checks and tool result normalization.
* **v1.6:** Risk-based triage classifier and local append-only findings store.
* **v2.0:** Integrated shared findings workflow, provider integrations, and policy routing.

