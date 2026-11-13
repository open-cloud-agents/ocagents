"""
Open Cloud Agents: Baseline vs. Blackboard Simulation Engine (TASK-4.6).

Simulates token consumption, execution latency, and cost modeling for:
1. Linear Conversational Chaining Baseline (O(N^2) quadratic compounding across 7 agents).
2. Blackboard Architecture (Stage 1 deterministic pre-flight + Stage 2 triage + structured findings).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ocagents.benchmark.callsets import BenchmarkScenario
from ocagents.benchmark.metrics import (
    ExecutionMetrics,
    calculate_cost_usd,
    estimate_tokens,
)

# Canonical 7 agents in standard sequential handoff order
SEQUENTIAL_BASELINE_AGENTS = [
    "principal-cloud-architect",
    "security-compliance-commander",
    "finops-cloud-cost-optimizer",
    "devsecops-reviewer",
    "devsecops-engineer",
    "gitops-release-manager",
    "sre-reliability-engineer",
]

# Average system prompt tokens per agent persona definition
SYSTEM_PROMPT_TOKENS_PER_AGENT = 750

# Average conversational output tokens generated per agent in sequential chat
BASELINE_NARRATIVE_OUTPUT_TOKENS = 520

# Simulated latency per agent call (milliseconds)
BASELINE_AGENT_LATENCY_MS = 1400.0
BLACKBOARD_AGENT_LATENCY_MS = 950.0
DETERMINISTIC_STAGE_LATENCY_MS = 12.0


def simulate_linear_baseline(
    scenario: BenchmarkScenario,
    model: str = "claude-3-5-sonnet",
) -> ExecutionMetrics:
    """
    Simulates token consumption under the Linear Conversational Chaining pattern.

    Under sequential chaining:
    - Every agent runs regardless of risk tier (no triage bypass).
    - In turn k (1 to 7), agent k receives:
        Prompt_k = System_k + PR_Context + Sum_{j=1}^{k-1} Output_j
    - Each agent produces narrative conversational commentary (~520 tokens).
    - Context compounds quadratically as downstream agents re-read prior conversational prose.
    """
    # Base PR context: diff tokens + file list tokens
    diff_text = f"diff --git files: {', '.join(scenario.files_changed)}\n" + ("x" * scenario.diff_hunk_bytes)
    pr_context_tokens = estimate_tokens(diff_text)

    accumulated_narrative_tokens = 0
    total_prompt_tokens = 0
    total_completion_tokens = 0
    total_latency_ms = 0.0

    for _ in SEQUENTIAL_BASELINE_AGENTS:
        # Prompt = agent system prompt + PR context + all accumulated narrative so far
        turn_prompt = SYSTEM_PROMPT_TOKENS_PER_AGENT + pr_context_tokens + accumulated_narrative_tokens
        turn_completion = BASELINE_NARRATIVE_OUTPUT_TOKENS

        total_prompt_tokens += turn_prompt
        total_completion_tokens += turn_completion
        accumulated_narrative_tokens += turn_completion
        total_latency_ms += BASELINE_AGENT_LATENCY_MS

    total_tokens = total_prompt_tokens + total_completion_tokens
    cost_usd = calculate_cost_usd(total_prompt_tokens, total_completion_tokens, model=model)

    return ExecutionMetrics(
        prompt_tokens=total_prompt_tokens,
        completion_tokens=total_completion_tokens,
        total_tokens=total_tokens,
        cost_usd=cost_usd,
        latency_ms=total_latency_ms,
        activated_agents=list(SEQUENTIAL_BASELINE_AGENTS),
        findings_produced=len(scenario.ground_truth_findings),
        extra_metadata={
            "architecture": "linear_conversational_chaining",
            "compounding_narrative_tokens": accumulated_narrative_tokens,
        },
    )


def simulate_blackboard_execution(
    scenario: BenchmarkScenario,
    model: str = "claude-3-5-sonnet",
) -> ExecutionMetrics:
    """
    Simulates token consumption under the Open Cloud Agents Blackboard Architecture.

    Under Blackboard execution (ADR-002):
    - Stage 1 Deterministic Baseline: AST & hygiene run at 0 LLM tokens.
    - Stage 2 Risk Triage:
        * Tier 0 (Docs/Assets): LLM agents bypassed entirely (0 tokens, 100% savings).
        * Tier 1 (App Logic): Only DevSecOps Reviewer invoked with bounded prompt.
        * Tier 2 (High Blast Radius): Only relevant specialists invoked concurrently.
    - Structured findings format (JSON/TOON): Downstream agents consume compact
      structured finding records rather than conversational prose, eliminating quadratic compounding.
    - Concurrency: Specialists run in parallel, reducing latency to max(agent_latency) + stage overhead.
    """
    # Tier 0: Complete LLM bypass
    if scenario.risk_tier == 0:
        return ExecutionMetrics(
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            cost_usd=0.0,
            latency_ms=DETERMINISTIC_STAGE_LATENCY_MS,
            activated_agents=[],
            findings_produced=0,
            extra_metadata={
                "architecture": "blackboard_shared_store",
                "triage_action": "bypass_llm_tier_0",
            },
        )

    # Base PR diff context
    diff_text = f"diff --git files: {', '.join(scenario.files_changed)}\n" + ("x" * scenario.diff_hunk_bytes)
    pr_diff_tokens = estimate_tokens(diff_text)

    activated_agents = scenario.expected_blackboard_agents
    if not activated_agents:
        # Fallback to devsecops-reviewer if not specified
        activated_agents = ["devsecops-reviewer"]

    total_prompt_tokens = 0
    total_completion_tokens = 0

    # Structured finding output: ~180 tokens per finding schema record (Fact + Evidence + Recommendation)
    # Plus ~120 tokens JSON envelope overhead
    findings_count = len(scenario.ground_truth_findings)
    findings_per_agent = max(1, (findings_count + len(activated_agents) - 1) // len(activated_agents)) if findings_count > 0 else 0

    for _ in activated_agents:
        # Bounded prompt: system instructions + diff context (bounded by max_context_tokens frontmatter budget)
        # Specialist agents only read infrastructure state and compact shared blackboard findings
        agent_prompt = min(4500, SYSTEM_PROMPT_TOKENS_PER_AGENT + pr_diff_tokens)
        agent_completion = min(600, 120 + (findings_per_agent * 180)) if findings_count > 0 else 120

        total_prompt_tokens += agent_prompt
        total_completion_tokens += agent_completion

    total_tokens = total_prompt_tokens + total_completion_tokens
    cost_usd = calculate_cost_usd(total_prompt_tokens, total_completion_tokens, model=model)

    # Concurrency latency: parallel execution means wall-clock time is bounded by single agent latency
    # plus deterministic stage and synthesis
    wall_clock_latency_ms = DETERMINISTIC_STAGE_LATENCY_MS + BLACKBOARD_AGENT_LATENCY_MS + 150.0

    return ExecutionMetrics(
        prompt_tokens=total_prompt_tokens,
        completion_tokens=total_completion_tokens,
        total_tokens=total_tokens,
        cost_usd=cost_usd,
        latency_ms=wall_clock_latency_ms,
        activated_agents=list(activated_agents),
        findings_produced=findings_count,
        extra_metadata={
            "architecture": "blackboard_shared_store",
            "triage_tier": scenario.risk_tier,
            "concurrency": "parallel_specialists",
        },
    )
