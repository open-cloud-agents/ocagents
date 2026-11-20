"""
Open Cloud Agents: Signal-to-Noise Evidence Ranking & Top-K Pruning Engine (Milestone v2.2 - Issue #101).

Implements evidence prioritization scoring:
  Priority = SeverityScore * Confidence * CorroborationFactor

Where:
  - SeverityScore: Critical (4.0), High (3.0), Medium (2.0), Low (1.0), Info (0.5)
  - Confidence: Nullable Confidence Contract: None -> 1.0 (deterministic proof); float in [0.1, 1.0]
  - CorroborationFactor: 1 observer (1.0), 2 observers (1.25), 3+ / tool_verified (1.5), human_verified (2.0)

Provides top-K highest-signal item projection to prevent specialist context window bloat.
"""

from __future__ import annotations

import copy
from typing import Any

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
    "info": 0.5,
}

CORROBORATION_STATUS_FACTORS: dict[str, float] = {
    "human_verified": 2.0,
    "tool_verified": 1.5,
    "model_corroborated": 1.25,
    "unverified_model_claim": 1.0,
    "syntactically_valid_unverified_resource": 1.0,
    "rejected_false_positive": 0.0,
}


def get_effective_confidence(confidence: float | None) -> float:
    """
    Computes effective confidence under the Nullable Confidence Contract.
    Deterministic linters emit confidence=None (definitive static proof),
    which evaluates to 1.0. Model claims are bounded to [0.1, 1.0].
    """
    if confidence is None:
        return 1.0

    try:
        val = float(confidence)
        return max(0.1, min(1.0, val))
    except (ValueError, TypeError):
        return 1.0


def calculate_corroboration_factor(finding: dict[str, Any]) -> float:
    """
    Calculates the corroboration multiplier based on status and distinct observer count.
    """
    status = str(finding.get("corroboration_status", "")).lower()

    # If false positive, zero out priority
    if status == "rejected_false_positive":
        return 0.0

    # Base factor from status
    base_factor = CORROBORATION_STATUS_FACTORS.get(status, 1.0)

    # Multi-agent corroboration bonus
    corroborating_agents = finding.get("corroborating_agents") or []
    distinct_agent_count = len(corroborating_agents)

    if distinct_agent_count >= 3:
        agent_factor = 1.5
    elif distinct_agent_count == 2:
        agent_factor = 1.25
    else:
        agent_factor = 1.0

    return max(base_factor, agent_factor)


def calculate_priority_score(finding: dict[str, Any]) -> float:
    """
    Calculates the composite priority score for a finding:
      Priority = SeverityScore * Confidence * CorroborationFactor
    """
    sev = str(finding.get("severity", "medium")).lower()
    sev_score = SEVERITY_WEIGHTS.get(sev, 2.0)

    conf = finding.get("confidence")
    eff_conf = get_effective_confidence(conf)

    corrob_factor = calculate_corroboration_factor(finding)

    score = round(sev_score * eff_conf * corrob_factor, 4)
    return score


def rank_findings(
    findings: list[dict[str, Any]],
    limit_top_k: int | None = None,
    min_confidence: float | None = None,
    allowed_severities: set[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Ranks findings by descending composite priority score and filters noise.

    Arguments:
      findings: List of finding dictionaries.
      limit_top_k: If provided, truncates the result to the top-K highest-signal findings.
      min_confidence: If provided, filters out model findings with confidence below this threshold.
                      (Deterministic linters with confidence=None evaluate as 1.0).
      allowed_severities: Optional set of allowed severity strings in lowercase.

    Returns:
      Ranked and pruned list of finding dictionaries with 'priority_score' annotated.
    """
    if not findings:
        return []

    ranked: list[dict[str, Any]] = []

    for item in findings:
        f = copy.deepcopy(item)
        sev = str(f.get("severity", "medium")).lower()

        if allowed_severities and sev not in allowed_severities:
            continue

        conf = f.get("confidence")
        eff_conf = get_effective_confidence(conf)

        if min_confidence is not None and eff_conf < min_confidence:
            continue

        # Reject explicitly rejected false positives
        if str(f.get("corroboration_status")).lower() == "rejected_false_positive":
            continue

        score = calculate_priority_score(f)
        f["priority_score"] = score
        ranked.append(f)

    # Sort deterministically:
    # 1. priority_score descending
    # 2. occurrence_count descending
    # 3. id ascending (stable tie-breaking)
    ranked.sort(
        key=lambda x: (
            -x.get("priority_score", 0.0),
            -x.get("occurrence_count", 1),
            x.get("id", ""),
        )
    )

    if limit_top_k is not None and limit_top_k > 0:
        return ranked[:limit_top_k]

    return ranked
