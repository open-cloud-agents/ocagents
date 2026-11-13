"""
Open Cloud Agents: Deterministic Finding ID & Deduplication Engine (Milestone v1.6 - TASK-3.3).

Implements deterministic composite key derivation and cross-corroboration deduplication:
  - id = "FND-" + sha256(rule_id:resource:evidence)[0:12].upper()
  - Idempotent deduplication across parallel specialist executions and tool retries
  - Corroboration promotion: upgrades "unverified_model_claim" to "tool_verified"
    when independently corroborated by deterministic linters.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any


def derive_finding_id(rule_id: str, resource: str, evidence: str) -> str:
    """
    Derives deterministic finding ID from the canonical composite key:
      FND- + SHA256(rule_id:resource:evidence)[0:12].upper()
    Matches schemas/v1/finding.json pattern ^FND-[A-Z0-9]{12}$.
    """
    composite = f"{rule_id.strip()}:{resource.strip()}:{evidence.strip()}"
    digest = hashlib.sha256(composite.encode("utf-8")).hexdigest()[:12].upper()
    return f"FND-{digest}"


def ensure_finding_id(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Ensures the finding dictionary has a deterministically derived id.
    If missing or inconsistent, computes and injects it.
    """
    rule_id = finding.get("rule_id", "")
    resource = finding.get("resource", "")
    evidence = finding.get("evidence", "")

    if rule_id and resource and evidence:
        expected_id = derive_finding_id(rule_id, resource, evidence)
        if finding.get("id") != expected_id:
            finding["id"] = expected_id

    return finding


def merge_duplicate_findings(
    existing: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    """
    Merges an incoming duplicate finding into an existing finding record:
      - Increments occurrence_count
      - Promotes corroboration_status when verified by deterministic linters
      - Tracks distinct corroborating agents
      - Preserves the most actionable remediation draft
    """
    merged = copy.deepcopy(existing)

    # 1. Increment occurrence count
    merged["occurrence_count"] = merged.get("occurrence_count", 1) + 1

    # 2. Corroborating agents tracking
    agents: list[str] = merged.get("corroborating_agents", [merged.get("agent", "unknown")])
    inc_agent = incoming.get("agent")
    if inc_agent and inc_agent not in agents:
        agents.append(inc_agent)
    merged["corroborating_agents"] = agents

    # 3. Corroboration promotion
    # If a deterministic linter reports a finding previously raised by an LLM model assertion,
    # promote status to 'tool_verified'
    existing_origin = merged.get("origin")
    incoming_origin = incoming.get("origin")

    if incoming_origin == "deterministic_linter":
        if merged.get("corroboration_status") == "unverified_model_claim":
            merged["corroboration_status"] = "tool_verified"
        # Deterministic linters enforce confidence: null per Nullable Confidence Contract
        if existing_origin != "deterministic_linter":
            merged["origin"] = "deterministic_linter"
            merged["confidence"] = None

    elif incoming_origin == "human_triage":
        merged["origin"] = "human_triage"
        merged["corroboration_status"] = incoming.get("corroboration_status", "human_verified")

    # 4. Confidence calibration (if both are model assertions, adopt the maximum confidence)
    if existing_origin == "model_assertion" and incoming_origin == "model_assertion":
        c1 = merged.get("confidence")
        c2 = incoming.get("confidence")
        if isinstance(c1, (int, float)) and isinstance(c2, (int, float)):
            merged["confidence"] = round(max(c1, c2), 4)

    # 5. Severity escalation (critical > high > medium > low)
    severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    curr_sev = severity_order.get(str(merged.get("severity", "low")).lower(), 1)
    inc_sev = severity_order.get(str(incoming.get("severity", "low")).lower(), 1)
    if inc_sev > curr_sev:
        merged["severity"] = incoming["severity"]

    # 6. Remediation draft merging (preserve proposed draft if incoming has it)
    inc_rem = incoming.get("remediation")
    curr_rem = merged.get("remediation")
    if inc_rem and isinstance(inc_rem, dict) and (not curr_rem or not curr_rem.get("proposed_draft_available")):
        merged["remediation"] = copy.deepcopy(inc_rem)

    return merged


class FindingDeduplicator:
    """
    In-memory stateful deduplication accumulator for findings streamed
    from multiple parallel agents and deterministic linters.
    """

    def __init__(self) -> None:
        self._findings: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []

    def ingest(self, finding: dict[str, Any]) -> str:
        """
        Ingests a finding, ensures deterministic id, and merges duplicates.
        Returns the finding ID.
        """
        item = copy.deepcopy(finding)
        ensure_finding_id(item)
        fid = item.get("id")
        if not fid:
            # Fallback if rule_id/resource/evidence incomplete
            fid = f"FND-UNKNOWN{len(self._order):04d}"
            item["id"] = fid

        if fid in self._findings:
            self._findings[fid] = merge_duplicate_findings(self._findings[fid], item)
        else:
            if "occurrence_count" not in item:
                item["occurrence_count"] = 1
            if "corroborating_agents" not in item:
                item["corroborating_agents"] = [item.get("agent", "unknown")]
            self._findings[fid] = item
            self._order.append(fid)

        return fid

    def ingest_many(self, findings: list[dict[str, Any]]) -> list[str]:
        """Ingests a list of findings, returning list of finding IDs."""
        return [self.ingest(f) for f in findings]

    def get_findings(self) -> list[dict[str, Any]]:
        """Returns all deduplicated findings in order of first insertion."""
        return [self._findings[fid] for fid in self._order]

    def get_by_id(self, finding_id: str) -> dict[str, Any] | None:
        """Retrieves finding by deterministic ID."""
        return self._findings.get(finding_id)

    def count(self) -> int:
        """Returns number of unique findings."""
        return len(self._findings)


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Stateless helper that deduplicates a list of findings deterministically.
    """
    dedup = FindingDeduplicator()
    dedup.ingest_many(findings)
    return dedup.get_findings()

