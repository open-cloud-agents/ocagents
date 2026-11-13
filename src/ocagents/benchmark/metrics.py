"""
Open Cloud Agents: Benchmark Execution Metrics & Pricing Models (TASK-4.6).

Computes token consumption, latency benchmarks, and cloud provider LLM cost modeling.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Standard foundation model pricing per 1M tokens (USD)
# [Prompt Price / 1M, Completion Price / 1M]
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-opus": (15.00, 75.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gemini-1-5-pro": (3.50, 10.50),
    "gemini-1-5-flash": (0.075, 0.30),
    "default": (3.00, 15.00),
}


def estimate_tokens(text: str) -> int:
    """
    Estimates token count for plain text using standard 4 chars/token heuristic.
    Guarantees at least 1 token for non-empty text.
    """
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


def calculate_cost_usd(
    prompt_tokens: int,
    completion_tokens: int,
    model: str = "default",
) -> float:
    """
    Calculates execution cost in USD based on model pricing per million tokens.
    """
    model_key = model.lower()
    prompt_rate, completion_rate = MODEL_PRICING.get(
        model_key, MODEL_PRICING["default"]
    )
    prompt_cost = (prompt_tokens / 1_000_000.0) * prompt_rate
    completion_cost = (completion_tokens / 1_000_000.0) * completion_rate
    return round(prompt_cost + completion_cost, 6)


@dataclass
class ExecutionMetrics:
    """Telemetry metrics captured during a single benchmark run."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    activated_agents: list[str] = field(default_factory=list)
    findings_produced: int = 0
    extra_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.total_tokens == 0:
            self.total_tokens = self.prompt_tokens + self.completion_tokens

    def to_dict(self) -> dict[str, Any]:
        """Converts execution metrics to dictionary."""
        return asdict(self)
