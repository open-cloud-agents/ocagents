"""
Open Cloud Agents: Anti-Proliferation Interaction Circuit Breaker (Milestone v2.2 - Issue #100).

Prevents quadratic agent proliferation, recursive ping-ponging, and token exhaustion:
  - Enforces hard token ceilings (per-agent and cumulative workflow)
  - Limits corroboration hops per finding cluster (max 2 rounds)
  - Detects and breaks cyclic agent-to-agent interactions
  - Enforces Blackboard-Mediated Decoupling (prohibiting pairwise conversational chat)
"""

from __future__ import annotations

import datetime
import enum
import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("ocagents.orchestration.circuit_breaker")


class CircuitBreakerStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    TRIPPED = "TRIPPED"
    HALTED = "HALTED"


class CircuitBreakerError(Exception):
    """Raised when an execution violates bounded DAG constraints or trips a circuit breaker."""


class TokenCeilingExceededError(CircuitBreakerError):
    """Raised when an individual agent or cumulative workflow token ceiling is exceeded."""


class MaxHopsExceededError(CircuitBreakerError):
    """Raised when review/corroboration rounds on a finding cluster exceed bounded limits."""


class PeerToPeerProhibitedError(CircuitBreakerError):
    """Raised when an agent attempts conversational pairwise delegation instead of Blackboard findings."""


class InteractionCycleError(CircuitBreakerError):
    """Raised when a recursive ping-pong cycle is detected between agent pairs."""


@dataclass
class CircuitBreakerPolicy:
    """Configurable limits for the interaction circuit breaker."""

    max_corroboration_hops: int = 2
    max_total_workflow_tokens: int = 50000
    max_per_agent_tokens: int = 12000
    fail_closed: bool = True
    prohibit_peer_to_peer: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CircuitBreakerPolicy:
        return cls(
            max_corroboration_hops=int(data.get("max_corroboration_hops", 2)),
            max_total_workflow_tokens=int(data.get("max_total_workflow_tokens", 50000)),
            max_per_agent_tokens=int(data.get("max_per_agent_tokens", 12000)),
            fail_closed=bool(data.get("fail_closed_on_trip", True)),
            prohibit_peer_to_peer=bool(data.get("prohibit_peer_to_peer", True)),
        )


class InteractionCircuitBreaker:
    """
    Stateful circuit breaker tracking token consumption, corroboration hops,
    and agent interaction graph edges across an execution DAG run.
    """

    def __init__(self, policy: CircuitBreakerPolicy | None = None) -> None:
        self.policy = policy or CircuitBreakerPolicy()
        self.status = CircuitBreakerStatus.ACTIVE
        self.total_tokens: int = 0
        self.agent_tokens: dict[str, int] = {}
        self.finding_hops: dict[str, int] = {}
        self.agent_transitions: dict[tuple[str, str], int] = {}
        self.trip_reason: str | None = None
        self.tripped_at_utc: str | None = None
        self.violations: list[str] = []

    def record_token_spend(self, agent_id: str, prompt_tokens: int, completion_tokens: int) -> None:
        """
        Records tokens consumed by a specialist and checks against both per-agent
        and cumulative workflow ceilings.
        """
        spend = prompt_tokens + completion_tokens
        self.agent_tokens[agent_id] = self.agent_tokens.get(agent_id, 0) + spend
        self.total_tokens += spend

        # 1. Per-agent ceiling check
        if self.agent_tokens[agent_id] > self.policy.max_per_agent_tokens:
            reason = (
                f"Agent '{agent_id}' exceeded session token ceiling: "
                f"{self.agent_tokens[agent_id]} tokens consumed (limit: {self.policy.max_per_agent_tokens})."
            )
            self._trip(reason)
            if self.policy.fail_closed:
                raise TokenCeilingExceededError(reason)

        # 2. Cumulative workflow ceiling check
        if self.total_tokens > self.policy.max_total_workflow_tokens:
            reason = (
                f"Workflow exceeded cumulative token ceiling: "
                f"{self.total_tokens} total tokens consumed (limit: {self.policy.max_total_workflow_tokens})."
            )
            self._trip(reason)
            if self.policy.fail_closed:
                raise TokenCeilingExceededError(reason)

    def record_finding_corroboration(
        self,
        finding_id: str,
        acting_agent: str,
        prior_agent: str | None = None,
    ) -> None:
        """
        Tracks corroboration hops on an individual finding cluster and enforces
        bounded recursion limits to prevent agent ping-pong loops.
        """
        current_hops = self.finding_hops.get(finding_id, 0) + 1
        self.finding_hops[finding_id] = current_hops

        # Track pairwise agent transitions on this finding
        if prior_agent and prior_agent != acting_agent:
            pair = (prior_agent, acting_agent)
            reverse_pair = (acting_agent, prior_agent)
            self.agent_transitions[pair] = self.agent_transitions.get(pair, 0) + 1

            # Detect ping-pong cycle between same two agents
            cycle_count = self.agent_transitions.get(pair, 0) + self.agent_transitions.get(reverse_pair, 0)
            if cycle_count > self.policy.max_corroboration_hops:
                reason = (
                    f"Recursive interaction cycle detected between '{prior_agent}' and '{acting_agent}' "
                    f"on finding '{finding_id}' ({cycle_count} exchanges). Halting to prevent agent ping-pong."
                )
                self._trip(reason)
                if self.policy.fail_closed:
                    raise InteractionCycleError(reason)

        # Enforce maximum corroboration hops per finding cluster
        if current_hops > self.policy.max_corroboration_hops:
            reason = (
                f"Finding '{finding_id}' exceeded maximum review/corroboration rounds: "
                f"{current_hops} hops recorded (limit: {self.policy.max_corroboration_hops}). "
                f"Escalating to human maintainer triage."
            )
            self._trip(reason)
            if self.policy.fail_closed:
                raise MaxHopsExceededError(reason)

    def audit_agent_output_for_peer_delegation(self, output_text: str, agent_id: str) -> None:
        """
        Scans raw model output to ensure the agent is not attempting direct
        conversational peer-to-peer delegation (agent theater) instead of emitting
        structured Blackboard findings.
        """
        if not self.policy.prohibit_peer_to_peer or not output_text:
            return

        # Patterns indicating conversational chat delegation rather than findings publication
        p2p_patterns = [
            r"(?:hey|hi|hello)\s+@?(?:principal-cloud-architect|security-compliance-commander|finops-cloud-cost-optimizer|devsecops-reviewer|devsecops-engineer|gitops-release-manager|sre-reliability-engineer|[a-z-]+)",
            r"(?:passing|delegating|handing\s+off)\s+.*?\bto\s+@?[a-z-]+",
            r"(?:please\s+)?(?:review|verify|check|re-run|triage)\s+this,\s+@?[a-z-]+",
            r"(?:send|message|forward)\s+.*?\bto\s+@?[a-z-]+",
        ]

        for pat in p2p_patterns:
            if re.search(pat, output_text, re.IGNORECASE):
                reason = (
                    f"Agent '{agent_id}' attempted prohibited peer-to-peer conversational delegation. "
                    "All multi-agent coordination must occur strictly via Blackboard findings contracts, "
                    "never point-to-point chat meshes."
                )
                self._trip(reason)
                if self.policy.fail_closed:
                    raise PeerToPeerProhibitedError(reason)

    def _trip(self, reason: str) -> None:
        """Transitions circuit breaker to TRIPPED state and records reason."""
        self.status = CircuitBreakerStatus.TRIPPED
        self.trip_reason = reason
        self.violations.append(reason)
        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        self.tripped_at_utc = now_utc
        logger.warning("⚡ INTERACTION CIRCUIT BREAKER TRIPPED: %s", reason)

    def is_tripped(self) -> bool:
        """Returns True if the circuit breaker has tripped."""
        return self.status == CircuitBreakerStatus.TRIPPED

    def get_summary(self) -> dict[str, Any]:
        """Returns diagnostic telemetry summary for audit reports."""
        return {
            "status": self.status.value,
            "is_tripped": self.is_tripped(),
            "trip_reason": self.trip_reason,
            "tripped_at_utc": self.tripped_at_utc,
            "violations_count": len(self.violations),
            "violations": self.violations,
            "total_tokens": self.total_tokens,
            "agent_tokens": self.agent_tokens,
            "finding_hops": self.finding_hops,
            "policy": {
                "max_corroboration_hops": self.policy.max_corroboration_hops,
                "max_total_workflow_tokens": self.policy.max_total_workflow_tokens,
                "max_per_agent_tokens": self.policy.max_per_agent_tokens,
                "fail_closed": self.policy.fail_closed,
                "prohibit_peer_to_peer": self.policy.prohibit_peer_to_peer,
            },
        }
