"""
Open Cloud Agents: Deterministic Finding ID & Deduplication Engine (Backward Compatibility Shim).

Re-exports all deduplication and fingerprinting capabilities from dedupe.py (Milestone v2.2 - Issue #101).
"""

from __future__ import annotations

from ocagents.blackboard.dedupe import (
    FindingDeduplicator,
    compute_finding_fingerprint,
    deduplicate_findings,
    derive_finding_id,
    derive_fingerprint,
    ensure_finding_id,
    extract_canonical_path,
    merge_duplicate_findings,
    normalize_fact,
)

__all__ = [
    "FindingDeduplicator",
    "compute_finding_fingerprint",
    "deduplicate_findings",
    "derive_finding_id",
    "derive_fingerprint",
    "ensure_finding_id",
    "extract_canonical_path",
    "merge_duplicate_findings",
    "normalize_fact",
]
