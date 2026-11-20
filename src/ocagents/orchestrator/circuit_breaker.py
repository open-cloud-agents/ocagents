"""
Open Cloud Agents: Orchestrator Circuit Breaker Compatibility Shim.
"""

from __future__ import annotations

from ocagents.orchestration.circuit_breaker import (
    CircuitBreakerError,
    CircuitBreakerPolicy,
    CircuitBreakerStatus,
    InteractionCircuitBreaker,
    InteractionCycleError,
    MaxHopsExceededError,
    PeerToPeerProhibitedError,
    TokenCeilingExceededError,
)

__all__ = [
    "CircuitBreakerError",
    "CircuitBreakerPolicy",
    "CircuitBreakerStatus",
    "InteractionCircuitBreaker",
    "InteractionCycleError",
    "MaxHopsExceededError",
    "PeerToPeerProhibitedError",
    "TokenCeilingExceededError",
]
