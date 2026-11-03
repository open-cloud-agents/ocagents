### 100% Complete Coverage Across All Cloud Pillars

Every formal pillar of the **AWS, Google Cloud, and Azure Well-Architected Frameworks** is now mapped to a dedicated specialist agent:

```
                                  1. STRATEGY & HIGH-LEVEL DESIGN
                              ┌──────────────────────────────────────┐
                              │    Principal Cloud Architect         │
                              │    • Strategic HLD & System Topology │
                              │    • Architecture Decisions (ADRs)   │
                              │    • Multi-Region DR (RTO / RPO)     │
                              └──────────────────┬───────────────────┘
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        ▼                                                 ▼
             GOVERNANCE & COMPLIANCE                              COST & CLOUD ECONOMICS
     ┌─────────────────────────────────────┐              ┌─────────────────────────────────────┐
     │ Security Compliance Commander       │              │ FinOps & Cloud Cost Optimizer       │
     │ • SOC 2 / ISO 27001 / NIST / CIS    │              │ • Rightsizing & Waste Elimination   │
     │ • Cloud Security Command Centers    │              │ • S3 / Storage Lifecycle Tiering    │
     │ • WAF Telemetry & OWASP Top 10 Loop │              │ • NAT / Egress Cost Elimination     │
     └──────────────────┬──────────────────┘              └──────────────────┬──────────────────┘
                        │ Policies & Directives                              │ Cost Targets
                        ▼                                                    ▼
             2. CODE AUDIT & THREAT MODEL                          3. SURGICAL IMPLEMENTATION
     ┌─────────────────────────────────────┐              ┌─────────────────────────────────────┐
     │ DevSecOps Reviewer                  │ ───────────► │ DevSecOps Engineer                  │
     │ • Pre-merge PR & IaC code reviews   │   Task Plan  │ • Surgical code & pipeline fixes    │
     │ • Data loss traps & forced replaces │   Handoff    │ • Non-destructive local tests       │
     │ • Outputs Next-Agent Implementation │              │ • Conventional Commit generator     │
     └─────────────────────────────────────┘              └──────────────────┬──────────────────┘
                                                                             │ Merged / Tagged
                                                                             ▼
                                                                   4. CONTINUOUS DELIVERY
                                                          ┌─────────────────────────────────────┐
                                                          │ GitOps Release Manager              │
                                                          │ • Dev ➔ UAT ➔ Prod Promotion        │
                                                          │ • ArgoCD / Kargo / Flux / Harness   │
                                                          │ • Mandatory Human Sign-Off for Prod │
                                                          │ • Progressive Canary & Rollbacks    │
                                                          └──────────────────┬──────────────────┘
                                                                             │ Production Traffic
                                                                             ▼
                                                                   5. RUNTIME RELIABILITY & SRE
                                                          ┌─────────────────────────────────────┐
                                                          │ SRE & Reliability Incident Engineer │
                                                          │ • Four Golden Signals & SLI/SLO/SLA │
                                                          │ • Client Endpoint RCA (502/503/504) │
                                                          │ • Instant Downtime Containment      │
                                                          │ • Blameless Postmortems (PIR)       │
                                                          └─────────────────────────────────────┘
```

---

### The Complete 7-Agent Master Suite

| Well-Architected Pillar | Agent File | Primary Persona | Core Tools |
|---|---|---|---|
| **Pillar 1: Strategic Architecture** | [`principal-cloud-architect.md`](./7-agent-master-suite/principal-cloud-architect.md) | **Technical Fellow & Systems Architect** | High-Level Design (HLD), ADRs, Domain-Driven Design (DDD), Multi-Region Active-Active, RTO/RPO disaster recovery models. |
| **Pillar 2: Security & Compliance** | [`security-compliance-commander.md`](./7-agent-master-suite/security-compliance-commander.md) | **CISO & Enterprise Cyber Defense Commander** | Security Command Centers (AWS Hub, GCP SCC, Azure), SOC 2 Type II, ISO 27001, OWASP Top 10, continuous WAF traffic analysis loops. |
| **Pillar 3: Code & Pipeline Security** | [`devsecops-reviewer.md`](./7-agent-master-suite/devsecops-reviewer.md) | **Defensive Auditor & Threat Modeler** | Pre-merge PR audits, state destruction prevention (`forces replacement`), threat paths, executive summaries, machine-readable task handoffs. |
| **Pillar 4: Operational Excellence** | [`devsecops-engineer.md`](./7-agent-master-suite/devsecops-engineer.md) | **Surgical Implementer & Hardening Engineer** | Ingests task plans, applies zero-scope-creep fixes, executes composite validation tests, safe self-healing rollbacks, conventional commits. |
| **Pillar 5: Continuous Delivery** | [`gitops-release-manager.md`](./7-agent-master-suite/gitops-release-manager.md) | **Release & GitOps Delivery Specialist** | Multi-environment promotion (`dev` ➔ `uat` ➔ `prod`) via ArgoCD/Kargo/Flux/Harness, progressive Canary rollouts, mandatory human sign-off gates. |
| **Pillar 6: Reliability & Performance** | [`sre-reliability-engineer.md`](./7-agent-master-suite/sre-reliability-engineer.md) | **Site Reliability & Incident Commander** | Four Golden Signals, SLI/SLO/SLA burn-rate alerting, client endpoint RCA (`502/503/504`), instant downtime containment, blameless PIRs. |
| **Pillar 7: Cost Optimization (FinOps)** | [`finops-cloud-cost-optimizer.md`](./7-agent-master-suite/finops-cloud-cost-optimizer.md) | **Cloud Financial Engineer (FinOps)** | Idle waste elimination, container/VM rightsizing, storage tiering lifecycles (S3/Glacier), NAT gateway cost traps, Savings Plans/Spot modeling. |

---

### 🔄 Multi-Agent Orchestration Pipeline

> [!TIP]
> For a complete guide to BYO-LLM execution (Ollama, Gemini, Claude, OpenAI), continual learning ingestion (`ocagents learn`), and SRE incident triage, see the [**How to Use Agents Runbook**](../docs/how-to-use-agents.md).

The 7 agents operate as an integrated delivery pipeline with structured handoffs. You can execute or simulate this pipeline locally and in CI:

#### 1. Local CLI Pipeline Runner
Execute the 6-stage handoff simulation on any architectural task:
```bash
# Validate all agent contracts, frontmatter, and token limits:
python3 scripts/agents/agent_pipeline.py --validate

# Run end-to-end multi-agent handoff pipeline:
python3 scripts/agents/agent_pipeline.py --simulate

# Run with a custom architectural scenario:
python3 scripts/agents/agent_pipeline.py --task "Architect zero-downtime payments failover with Aurora Global Database"
```

#### 2. Automated GitHub Actions Pipeline (`.github/workflows/autonomous-gatekeeper.yml`)
- **Agent Contract Validation:** Ensures every persona has explicit tool boundaries, clear non-goals, and fits within an 8,000-token context budget.
- **Handoff Chain Simulation:** Validates that upstream outputs (ADRs, threat models, task plans) satisfy downstream agent inputs.
- **Automated PR Auditor:** Analyzes incoming pull request diffs using the **DevSecOps Reviewer** persona to detect state-destruction traps and open ingress rules.
