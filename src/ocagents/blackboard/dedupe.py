"""
Open Cloud Agents: Deterministic Finding ID, Canonical Fingerprinting & Deduplication Engine (Issue #101).

Implements deterministic fingerprint derivation, canonical composite keying, and cross-corroboration:
  - Canonical SHA-256 fingerprint: sha256(rule_id:resource_id:canonical_path:normalized_fact)
  - Canonical ID: "FND-" + sha256(rule_id:resource:evidence)[0:12].upper()
  - Idempotent deduplication across parallel specialist executions and tool retries
  - Corroboration promotion: upgrades "unverified_model_claim" to "tool_verified"
    when independently corroborated by deterministic linters.
  - Multi-agent corroboration tracking and occurrence accounting.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import re
from typing import Any


def extract_canonical_path(evidence: str) -> str:
    """
    Extracts the normalized canonical file path or cloud locator from an evidence URI.
    Handles 'diff:<path>#L<lines>', 'repo:<path>#L<lines>', and 'cloud:<provider>:<id>'.
    """
    if not evidence:
        return ""

    s = evidence.strip()

    # Strip URI scheme prefixes
    if s.startswith(("diff:", "repo:")):
        s = s[5:]
    elif s.startswith("cloud:"):
        s = s[6:]

    # Strip line range fragment (#L10-L20 or #L42)
    if "#" in s:
        s = s.split("#", 1)[0]

    # Normalize directory separators
    s = s.replace("\\", "/").strip()
    return s


def normalize_fact(fact: str) -> str:
    """
    Normalizes a factual claim for deterministic fingerprinting by:
      - Stripping leading and trailing whitespace
      - Collapsing multiple whitespace, tab, and newline sequences to a single space
      - Converting to lowercase
    """
    if not fact:
        return ""
    # Collapse whitespace
    collapsed = re.sub(r"\s+", " ", fact.strip())
    return collapsed.lower()


def derive_fingerprint(
    rule_id: str,
    resource_id: str,
    canonical_path: str,
    normalized_fact: str,
) -> str:
    """
    Derives canonical 64-character SHA-256 fingerprint for a finding:
      sha256(rule_id:resource_id:canonical_path:normalized_fact)
    Guarantees deterministic identity across runs, commits, and varying line offsets.
    """
    r_id = rule_id.strip()
    res = resource_id.strip()
    c_path = canonical_path.strip()
    n_fact = normalized_fact.strip()

    composite = f"{r_id}:{res}:{c_path}:{n_fact}"
    return hashlib.sha256(composite.encode("utf-8")).hexdigest()


def compute_finding_fingerprint(finding: dict[str, Any]) -> str:
    """
    Convenience function that extracts fields from a finding dictionary and derives
    its canonical SHA-256 fingerprint.
    """
    rule_id = finding.get("rule_id", "")
    resource = finding.get("resource", "")
    evidence = finding.get("evidence", "")
    fact = finding.get("fact", "")

    canonical_path = extract_canonical_path(evidence)
    normalized = normalize_fact(fact)

    return derive_fingerprint(rule_id, resource, canonical_path, normalized)


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
    Ensures the finding dictionary has a deterministically derived id and fingerprint.
    If missing or inconsistent, computes and injects them.
    """
    rule_id = finding.get("rule_id", "")
    resource = finding.get("resource", "")
    evidence = finding.get("evidence", "")

    if rule_id and resource and evidence:
        expected_id = derive_finding_id(rule_id, resource, evidence)
        if finding.get("id") != expected_id:
            finding["id"] = expected_id

    # Compute and inject canonical fingerprint
    if not finding.get("fingerprint"):
        finding["fingerprint"] = compute_finding_fingerprint(finding)

    return finding


def merge_duplicate_findings(
    existing: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    """
    Merges an incoming duplicate finding into an existing finding record:
      - Increments occurrence_count
      - Updates corroboration_count and tracks distinct corroborating agents
      - Updates last_seen_utc timestamp
      - Promotes corroboration_status when verified by deterministic linters
      - Calibrates confidence and escalates severity
      - Preserves the most actionable remediation draft
    """
    merged = copy.deepcopy(existing)

    # 1. Occurrence count
    merged["occurrence_count"] = merged.get("occurrence_count", 1) + 1

    # 2. Corroborating agents tracking
    agents: list[str] = list(merged.get("corroborating_agents") or [merged.get("agent", "unknown")])
    inc_agent = incoming.get("agent")
    if inc_agent and inc_agent not in agents:
        agents.append(inc_agent)
    merged["corroborating_agents"] = agents
    merged["corroboration_count"] = len(agents)

    # 3. Canonical Fingerprint preservation
    if not merged.get("fingerprint"):
        merged["fingerprint"] = incoming.get("fingerprint") or compute_finding_fingerprint(merged)

    # 4. Corroboration promotion
    existing_origin = merged.get("origin")
    incoming_origin = incoming.get("origin")

    if incoming_origin == "deterministic_linter":
        if merged.get("corroboration_status") in ("unverified_model_claim", "OPEN"):
            merged["corroboration_status"] = "tool_verified"
        # Deterministic linters enforce confidence: null per Nullable Confidence Contract
        if existing_origin != "deterministic_linter":
            merged["origin"] = "deterministic_linter"
            merged["confidence"] = None

    elif incoming_origin == "human_triage":
        merged["origin"] = "human_triage"
        merged["corroboration_status"] = incoming.get("corroboration_status", "human_verified")

    elif len(agents) > 1 and merged.get("corroboration_status") == "unverified_model_claim":
        # Multiple model agents corroborating the same finding
        merged["corroboration_status"] = "model_corroborated"

    # 5. Confidence calibration (if both are model assertions, adopt the maximum confidence)
    if existing_origin == "model_assertion" and incoming_origin == "model_assertion":
        c1 = merged.get("confidence")
        c2 = incoming.get("confidence")
        if isinstance(c1, (int, float)) and isinstance(c2, (int, float)):
            merged["confidence"] = round(max(c1, c2), 4)

    # 6. Severity escalation (critical > high > medium > low > info)
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    curr_sev = severity_order.get(str(merged.get("severity", "low")).lower(), 1)
    inc_sev = severity_order.get(str(incoming.get("severity", "low")).lower(), 1)
    if inc_sev > curr_sev:
        merged["severity"] = incoming["severity"]

    # 7. Remediation draft merging (preserve proposed draft if incoming has it)
    inc_rem = incoming.get("remediation")
    curr_rem = merged.get("remediation")
    if inc_rem and isinstance(inc_rem, dict) and (not curr_rem or not curr_rem.get("proposed_draft_available")):
        merged["remediation"] = copy.deepcopy(inc_rem)

    # 8. Timestamp updates
    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    merged["last_seen_utc"] = now_utc
    merged["updated_at"] = now_utc

    return merged


class FindingDeduplicator:
    """
    In-memory stateful deduplication accumulator for findings streamed
    from multiple parallel agents and deterministic linters.
    Deduplicates using both canonical ID and SHA-256 fingerprint.
    """

    def __init__(self) -> None:
        self._findings_by_id: dict[str, dict[str, Any]] = {}
        self._id_by_fingerprint: dict[str, str] = {}
        self._order: list[str] = []

    def ingest(self, finding: dict[str, Any]) -> str:
        """
        Ingests a finding, ensures deterministic id and fingerprint, and merges duplicates.
        Returns the finding ID.
        """
        item = copy.deepcopy(finding)
        ensure_finding_id(item)
        fid = item.get("id")
        fp = item.get("fingerprint") or compute_finding_fingerprint(item)
        item["fingerprint"] = fp

        if not fid:
            fid = f"FND-UNKNOWN{len(self._order):04d}"
            item["id"] = fid

        # Check deduplication by fingerprint or id
        target_id: str | None = None
        if fp and fp in self._id_by_fingerprint:
            target_id = self._id_by_fingerprint[fp]
        elif fid in self._findings_by_id:
            target_id = fid

        if target_id and target_id in self._findings_by_id:
            self._findings_by_id[target_id] = merge_duplicate_findings(self._findings_by_id[target_id], item)
            return target_id

        # New finding
        if "occurrence_count" not in item:
            item["occurrence_count"] = 1
        if "corroborating_agents" not in item:
            item["corroborating_agents"] = [item.get("agent", "unknown")]
        item["corroboration_count"] = len(item["corroborating_agents"])

        now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        item.setdefault("created_at", now_utc)
        item.setdefault("updated_at", now_utc)
        item.setdefault("last_seen_utc", now_utc)

        self._findings_by_id[fid] = item
        if fp:
            self._id_by_fingerprint[fp] = fid
        self._order.append(fid)

        return fid

    def ingest_many(self, findings: list[dict[str, Any]]) -> list[str]:
        """Ingests a list of findings, returning list of finding IDs."""
        return [self.ingest(f) for f in findings]

    def get_findings(self) -> list[dict[str, Any]]:
        """Returns all deduplicated findings in order of first insertion."""
        return [self._findings_by_id[fid] for fid in self._order]

    def get_by_id(self, finding_id: str) -> dict[str, Any] | None:
        """Retrieves finding by deterministic ID."""
        return self._findings_by_id.get(finding_id)

    def get_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        """Retrieves finding by canonical SHA-256 fingerprint."""
        fid = self._id_by_fingerprint.get(fingerprint)
        if fid:
            return self._findings_by_id.get(fid)
        return None

    def count(self) -> int:
        """Returns number of unique findings."""
        return len(self._findings_by_id)


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Stateless helper that deduplicates a list of findings deterministically.
    """
    dedup = FindingDeduplicator()
    dedup.ingest_many(findings)
    return dedup.get_findings()
