"""
Open Cloud Agents: Orchestrator Compatibility Shim.

Provides backward-compatible aliases for ocagents.orchestration modules.
"""

from __future__ import annotations

from ocagents.orchestration import (
    TIER_2_SPECIALISTS,
    BlackboardRunner,
    BlackboardRunSummary,
    SpecialistExecutionResult,
    SpecialistMetadata,
    load_specialist_metadata,
    resolve_agents_dir,
)
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
from ocagents.orchestration.dag import (
    DAGCycleError,
    DAGError,
    DAGPhase,
    DAGPhaseOrderError,
    DAGStage,
    DAGStageNotFoundError,
    DAGValidationError,
    ExecutionDAG,
    get_canonical_dag,
)

__all__ = [
    "TIER_2_SPECIALISTS",
    "BlackboardRunSummary",
    "BlackboardRunner",
    "CircuitBreakerError",
    "CircuitBreakerPolicy",
    "CircuitBreakerStatus",
    "DAGCycleError",
    "DAGError",
    "DAGPhase",
    "DAGPhaseOrderError",
    "DAGStage",
    "DAGStageNotFoundError",
    "DAGValidationError",
    "ExecutionDAG",
    "InteractionCircuitBreaker",
    "InteractionCycleError",
    "MaxHopsExceededError",
    "PeerToPeerProhibitedError",
    "SpecialistExecutionResult",
    "SpecialistMetadata",
    "TokenCeilingExceededError",
    "get_canonical_dag",
    "load_specialist_metadata",
    "resolve_agents_dir",
]
