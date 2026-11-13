# Open Cloud Agents: Evaluation Benchmark & Token Calibration Report

- **Benchmark Version:** `2026.11-v1`
- **Evaluation Model Baseline:** `claude-3-5-sonnet`
- **Timestamp (UTC):** `2026-11-13T09:02:10Z`
- **Total Scenarios Evaluated:** 5

## 1. Executive Summary & ADR-002 Hypothesis Validation

In [ADR-002](./adr-002-blackboard-findings-and-token-budgets.md), the multi-agent pipeline token consumption was hypothesized to decrease by **65% to 80%** when transitioning from **Linear Conversational Chaining** to a **Token-Budgeted Blackboard Architecture**.

> **Hypothesis Status:** **VERIFIED**  
> The empirical evaluation measured an overall token reduction of **70.4%** across representative pull request workloads, matching the predicted 65% to 80% reduction envelope.

| Metric | Linear Conversational Baseline | Open Cloud Agents Blackboard | Savings / Improvement |
|---|---|---|---|
| **Total Token Consumption** | 152,726 tokens | 45,233 tokens | **70.4% reduction** |
| **Estimated LLM API Cost** | $0.6766 USD | $0.1969 USD | **$0.4797 saved (70.9%)** |

---

## 2. Scenario-by-Scenario Token & Latency Breakdown

| Scenario ID | Name | Risk Tier | Baseline Tokens | Blackboard Tokens | Token Reduction | Latency Speedup |
|---|---|---|---|---|---|---|
| `SCN-01-DOCS` | Documentation & Non-Code Assets Update | Tier 0 | 26,691 | 0 | **100.0%** | 816.7x |
| `SCN-02-APP-LOGIC` | Microservice API Route & Handler Refactoring | Tier 1 | 29,071 | 2,673 | **90.8%** | 8.8x |
| `SCN-03-MULTIREGION-DR` | Multi-Region Aurora Global Database & VPC Peering | Tier 2 | 35,651 | 16,565 | **53.5%** | 8.8x |
| `SCN-04-SECURITY-CRITICAL` | Critical IAM Permission & Public S3 Bucket Exposure | Tier 2 | 31,178 | 13,370 | **57.1%** | 8.8x |
| `SCN-05-FINOPS-WASTE` | Idle Cloud NAT Gateways & Unattached EBS Volumes | Tier 2 | 30,135 | 12,625 | **58.1%** | 8.8x |

### Architectural Insights by Risk Tier
- **Tier 0 (Documentation & Non-Code Assets):** Stage 2 triage completely bypasses LLM invocation, achieving **100% token elimination** ($0.00 cost) while maintaining full static repository hygiene.
- **Tier 1 (Application Code Only):** Restricts execution to a single scoped reviewer agent (`devsecops-reviewer`), cutting token consumption by **~90%** compared to cascading 7 sequential agents.
- **Tier 2 (High Blast Radius Infrastructure):** Runs only relevant specialist agents in parallel with compact structured findings (TOON/JSON), achieving **50% to 60%** token reduction on dense infrastructure diffs while eliminating quadratic narrative transcript compounding.

---

## 3. Model Confidence Calibration & Threshold Sensitivity

ADR-002 specifies that model assertions emit probabilistic confidence scores used strictly to prioritize human maintainer review queues (P0 urgent vs. P1 standard).

### Empirical Calibration Metrics
- **Expected Calibration Error (ECE):** `0.2400` (POORLY_CALIBRATED)
- **Max Calibration Error (MCE):** `0.7250`
- **Brier Score (Mean Squared Error):** `0.1330` (lower is better, 0.0 is perfect)
- **Recommended Operating Threshold:** `tau >= 0.85`

### Threshold Sensitivity Analysis (Operating Characteristic Curve)

| Threshold (tau) | True Positives (TP) | False Positives (FP) | Precision | Recall | F1-Score | Queue Escalation Rate |
|---|---|---|---|---|---|---|
| `0.70` | 11 | 2 | 84.6% | 100.0% | **0.917** | 86.7% |
| `0.75` | 11 | 0 | 100.0% | 100.0% | **1.000** | 73.3% |
| `0.80` | 11 | 0 | 100.0% | 100.0% | **1.000** | 73.3% |
| `0.85` **(Recommended)** | 11 | 0 | 100.0% | 100.0% | **1.000** | 73.3% |
| `0.90` | 7 | 0 | 100.0% | 63.6% | **0.778** | 46.7% |
| `0.95` | 4 | 0 | 100.0% | 36.4% | **0.533** | 26.7% |

### Calibration Conclusion
The threshold `tau = 0.85` establishes the optimal empirical operating point:
- **Zero False Escalations:** Filters out speculative or uncorroborated suggestions, preventing alert fatigue.
- **100% Critical Recall:** Successfully escalates all verified infrastructure vulnerabilities and compliance defects to maintainers.
- **Strict Guardrail Invariant:** In accordance with ADR-002, model confidence is strictly a human review routing signal and **never** autonomously blocks CI on model opinion alone.

---

## 4. Reproducibility Instructions

Run the benchmark locally using the canonical `ocagents` CLI:

```bash
# Run benchmark comparison against default foundation model pricing (Claude 3.5 Sonnet)
ocagents benchmark

# Export updated Markdown publication report
ocagents benchmark --export-md docs/eval-benchmarks.md

# Export machine-readable JSON evaluation traces
ocagents benchmark --export-json .ocagents/benchmark_results.json
```
