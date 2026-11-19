"""
Open Cloud Agents: Dynamic Agent Invocation Matrix (Milestone v2.0 - Issue #102).

Maps evaluated git diff risk tiers and AST blast radius triggers to minimal,
disciplined specialist agent rosters. Enforces aggressive triage so low-risk
changesets (e.g. documentation, scripts) do not invoke heavy multi-agent suites.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class RiskTier(enum.IntEnum):
    """
    Blast radius risk tiers for adaptive changeset triage:
      - Tier 0: No-Op / Documentation & Non-Code Assets (LLM Bypass, 0 tokens)
      - Tier 1: Low Risk - Scripting, Packaging & Helper Tooling (DevSecOps Engineer)
      - Tier 2: Medium Risk - CI/CD Workflows & Core Runtime (Security Commander + Reviewer)
      - Tier 3: High Risk - IaC, IAM, Cloud Topology, DB & Destructive Operations (Master Suite)
    """
    TIER_0 = 0
    TIER_1 = 1
    TIER_2 = 2
    TIER_3 = 3


ALL_MASTER_AGENTS: list[str] = [
    "principal-cloud-architect",
    "security-compliance-commander",
    "finops-cloud-cost-optimizer",
    "devsecops-reviewer",
    "devsecops-engineer",
    "gitops-release-manager",
    "sre-reliability-engineer",
]

TIER_NAMES: dict[int, str] = {
    RiskTier.TIER_0: "Tier 0: Docs & Non-Code Assets (LLM Bypass)",
    RiskTier.TIER_1: "Tier 1: Low Risk - Scripting, Packaging & Utilities (DevSecOps Engineer)",
    RiskTier.TIER_2: "Tier 2: Medium Risk - Workflows & Core Runtime (Security + Reviewer)",
    RiskTier.TIER_3: "Tier 3: High Risk - IaC, IAM, Cloud Topology & DB (Full Master Suite)",
}

TIER_GATING_BEHAVIORS: dict[int, str] = {
    RiskTier.TIER_0: "fast_track_hygiene_only",
    RiskTier.TIER_1: "deterministic_lint_and_engineer",
    RiskTier.TIER_2: "security_and_reviewer_audit",
    RiskTier.TIER_3: "full_master_suite_blackboard",
}

TIER_TOKEN_CEILINGS: dict[int, int] = {
    RiskTier.TIER_0: 0,
    RiskTier.TIER_1: 3000,
    RiskTier.TIER_2: 8000,
    RiskTier.TIER_3: 25000,
}

TIER_ACTIVATED_AGENTS: dict[int, list[str]] = {
    RiskTier.TIER_0: [],
    RiskTier.TIER_1: ["devsecops-engineer"],
    RiskTier.TIER_2: [
        "security-compliance-commander",
        "devsecops-reviewer",
    ],
    RiskTier.TIER_3: [
        "principal-cloud-architect",
        "security-compliance-commander",
        "finops-cloud-cost-optimizer",
        "sre-reliability-engineer",
        "devsecops-reviewer",
    ],
}

TIER_RATIONALES: dict[int, str] = {
    RiskTier.TIER_0: (
        "Documentation, media assets, or repository metadata changes only. "
        "Specialist LLM review bypassed (0 token spend); fast-tracked through repository hygiene and link checks."
    ),
    RiskTier.TIER_1: (
        "Utility shell scripts, packaging configurations, or helper tooling changes. "
        "Activating DevSecOps Engineer for syntax validation, ShellCheck, and packaging integrity."
    ),
    RiskTier.TIER_2: (
        "CI/CD workflow definitions or core application runtime changes. "
        "Activating Security Compliance Commander and DevSecOps Reviewer for threat modeling, AST security, and invariant audit."
    ),
    RiskTier.TIER_3: (
        "Infrastructure as Code, cloud topology, IAM policies, database migrations, or high-risk AST modifications. "
        "Activating full Master Suite specialists for multi-region DR, compliance, FinOps cost estimation, SLO reliability, and review."
    ),
}

AGENT_SPECIALTIES: dict[str, str] = {
    "principal-cloud-architect": "Multi-region DR, cloud topology, high-level architecture invariants",
    "security-compliance-commander": "Threat modeling, IAM boundaries, encryption, SOC2/CIS compliance",
    "finops-cloud-cost-optimizer": "Resource rightsizing, idle NAT/snapshot waste, cloud billing impact",
    "devsecops-reviewer": "Pre-merge diff auditing, blast radius analysis, code smells",
    "devsecops-engineer": "ShellCheck, script syntax, packaging configs, build automation",
    "gitops-release-manager": "Canary promotions, rollout gates, environment configuration",
    "sre-reliability-engineer": "Four Golden Signals, cascading outage prevention, SLO burn risks",
}


@dataclass
class InvocationPlan:
    """
    Structured dynamic invocation decision produced by the risk matrix.
    Declares activated vs. skipped specialists, token budget ceilings, and gating behavior.
    """
    risk_tier: int
    tier_name: str
    activated_agents: list[str]
    skipped_agents: list[str]
    rationale: str
    gating_behavior: str
    token_ceiling_estimate: int
    agent_reasons: dict[str, str] = field(default_factory=dict)
    high_risk_triggers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serializes the invocation plan to a JSON-compatible dictionary."""
        return {
            "risk_tier": int(self.risk_tier),
            "tier_name": self.tier_name,
            "activated_agents": list(self.activated_agents),
            "skipped_agents": list(self.skipped_agents),
            "rationale": self.rationale,
            "gating_behavior": self.gating_behavior,
            "token_ceiling_estimate": self.token_ceiling_estimate,
            "agent_reasons": dict(self.agent_reasons),
            "high_risk_triggers": list(self.high_risk_triggers),
        }


def resolve_invocation_plan(
    risk_tier: int | RiskTier,
    high_risk_triggers: list[str] | None = None,
) -> InvocationPlan:
    """
    Resolves the canonical invocation plan for a given risk tier and optional high-risk triggers.
    """
    tier_int = int(risk_tier)
    if tier_int not in TIER_NAMES:
        tier_int = int(RiskTier.TIER_3 if tier_int > 3 else RiskTier.TIER_1)

    tier_name = TIER_NAMES[tier_int]
    activated = list(TIER_ACTIVATED_AGENTS.get(tier_int, []))
    skipped = [a for a in ALL_MASTER_AGENTS if a not in activated]
    rationale = TIER_RATIONALES.get(tier_int, "Custom evaluated risk tier.")
    gating = TIER_GATING_BEHAVIORS.get(tier_int, "standard_review")
    token_ceiling = TIER_TOKEN_CEILINGS.get(tier_int, 0)
    triggers = list(high_risk_triggers or [])

    # Compile per-agent reasons
    agent_reasons: dict[str, str] = {}
    for agent in activated:
        desc = AGENT_SPECIALTIES.get(agent, "Domain specialist")
        agent_reasons[agent] = f"ACTIVATED: Required for {tier_name} ({desc})"

    for agent in skipped:
        desc = AGENT_SPECIALTIES.get(agent, "Domain specialist")
        agent_reasons[agent] = f"SKIPPED: Not warranted by blast radius of {tier_name} (Saves tokens; {desc})"

    return InvocationPlan(
        risk_tier=tier_int,
        tier_name=tier_name,
        activated_agents=activated,
        skipped_agents=skipped,
        rationale=rationale,
        gating_behavior=gating,
        token_ceiling_estimate=token_ceiling,
        agent_reasons=agent_reasons,
        high_risk_triggers=triggers,
    )


def get_invocation_matrix() -> dict[int, InvocationPlan]:
    """Returns the complete static invocation matrix across all 4 risk tiers."""
    return {
        int(tier): resolve_invocation_plan(tier)
        for tier in [RiskTier.TIER_0, RiskTier.TIER_1, RiskTier.TIER_2, RiskTier.TIER_3]
    }
