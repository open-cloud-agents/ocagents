"""
Open Cloud Agents: GitLab Code Quality Report Formatter (ADR-003, Phase 2).

Converts canonical findings (schemas/v1/finding.json) into GitLab's native Code
Quality report artifact schema (gl-code-quality-report.json) so the GitLab MR
widget can display expandable code quality diffs without external plugins.

GitLab Code Quality Schema Specification:
https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool

Each issue object in the report array contains:
  - description: human-readable summary of the issue
  - check_name: unique name of the rule or static check
  - fingerprint: unique, deterministic hash of the issue instance
  - severity: "info" | "minor" | "major" | "critical" | "blocker"
  - location: { path: str, lines: { begin: int, end?: int } }
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

# GitLab Code Quality severity levels
GITLAB_SEVERITIES: tuple[str, ...] = ("info", "minor", "major", "critical", "blocker")

# Mapping from canonical Open Cloud Agents finding severities to GitLab Code Quality severities
SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "major",
    "medium": "minor",
    "low": "info",
    "info": "info",
    # Pass-through if already in GitLab format
    "blocker": "blocker",
    "major": "major",
    "minor": "minor",
}

# Mapping from severity to priority display tag (P0-P4)
SEVERITY_TO_PRIORITY: dict[str, str] = {
    "critical": "P0",
    "blocker": "P0",
    "high": "P1",
    "major": "P1",
    "medium": "P2",
    "minor": "P2",
    "low": "P3",
    "info": "P4",
}

_EVIDENCE_PATTERN = re.compile(
    r"^(?:diff|repo):(?P<path>[^#\s]+)#L(?P<start>\d+)(?:-L(?P<end>\d+))?$"
)
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_PRIORITY_PREFIX = re.compile(r"^\(P[0-4]\)\s*")


def _clean_str(value: Any) -> str:
    """Sanitizes text by removing non-printable control characters."""
    return _CONTROL_CHARS.sub("", str(value or "")).strip()


def _clean_path(path: str) -> str:
    """Normalizes repository-relative path with forward slashes and drops traversal tokens."""
    parts = [p for p in path.replace("\\", "/").split("/") if p and p not in (".", "..")]
    return "/".join(parts) or "unknown"


def _extract_location(finding: dict[str, Any]) -> dict[str, Any]:
    """Extracts path and line bounds from finding evidence or resource."""
    evidence = str(finding.get("evidence") or "").strip()
    match = _EVIDENCE_PATTERN.match(evidence)
    if match:
        path = _clean_path(match.group("path"))
        start_line = max(1, int(match.group("start")))
        end_str = match.group("end")
        lines_obj: dict[str, int] = {"begin": start_line}
        if end_str:
            end_line = max(start_line, int(end_str))
            if end_line > start_line:
                lines_obj["end"] = end_line
        return {"path": path, "lines": lines_obj}

    # Fallback to resource if it resembles a file path
    resource = str(finding.get("resource") or "").strip()
    if resource and ("/" in resource or resource.endswith((".tf", ".yaml", ".yml", ".json", ".py", ".sh", ".go", ".ts", ".js"))):
        # Look for possible line in resource (e.g. main.tf:42)
        if ":" in resource:
            r_path, _, r_line = resource.partition(":")
            if r_line.isdigit():
                return {"path": _clean_path(r_path), "lines": {"begin": max(1, int(r_line))}}
        return {"path": _clean_path(resource), "lines": {"begin": 1}}

    return {"path": "unknown", "lines": {"begin": 1}}


def _extract_check_name(finding: dict[str, Any]) -> str:
    """Extracts a concise, deterministic check name from finding rule_id or metadata."""
    # Check metadata check_id or sarif_rule_id first
    meta = finding.get("metadata")
    if isinstance(meta, dict):
        for key in ("check_id", "rule_id", "sarif_rule_id"):
            val = meta.get(key)
            if val:
                return _clean_str(val)

    rule_id = str(finding.get("rule_id") or "").strip()
    if rule_id:
        if "#" in rule_id:
            fragment = rule_id.split("#", 1)[1].strip()
            if fragment:
                return _clean_str(fragment)
        stem = rule_id.rsplit("/", 1)[-1].removesuffix(".md")
        if stem:
            return _clean_str(stem)

    category = finding.get("category")
    if category:
        return _clean_str(category).upper()

    return "OCAGENTS_CHECK"


def _build_fingerprint(finding: dict[str, Any], path: str, line: int) -> str:
    """Derives a stable, unique 64-character SHA-256 fingerprint for GitLab tracking."""
    finding_id = str(finding.get("id") or "").strip()
    rule_id = str(finding.get("rule_id") or "").strip()
    fact = str(finding.get("fact") or "").strip()
    raw_key = f"{finding_id}:{rule_id}:{path}:{line}:{fact}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _format_description(finding: dict[str, Any], severity: str) -> str:
    """Formats description with priority code prefix matching GitLab MR conventions."""
    fact = _clean_str(finding.get("fact") or finding.get("title") or "Code quality issue detected")
    # If already prefixed with (P0)-(P4), avoid duplicating
    if _PRIORITY_PREFIX.match(fact):
        return fact
    priority = SEVERITY_TO_PRIORITY.get(severity, "P2")
    return f"({priority}) {fact}"


def finding_to_gitlab_issue(
    finding: dict[str, Any],
    *,
    include_suppressed: bool = False,
) -> dict[str, Any] | None:
    """Converts a single finding dict into a GitLab Code Quality issue object.

    Returns None if the finding is malformed or marked as a rejected false positive.
    """
    if not isinstance(finding, dict):
        return None

    # Filter out false positives unless explicitly included
    if not include_suppressed and finding.get("corroboration_status") == "rejected_false_positive":
        return None

    raw_severity = str(finding.get("severity") or "").lower().strip()
    gitlab_severity = SEVERITY_MAP.get(raw_severity, "minor")

    location = _extract_location(finding)
    path = location["path"]
    begin_line = location["lines"]["begin"]

    check_name = _extract_check_name(finding)
    fingerprint = _build_fingerprint(finding, path, begin_line)
    description = _format_description(finding, raw_severity)

    return {
        "description": description,
        "check_name": check_name,
        "fingerprint": fingerprint,
        "severity": gitlab_severity,
        "location": location,
    }


def findings_to_gitlab_code_quality(
    findings: Iterable[dict[str, Any]],
    *,
    include_suppressed: bool = False,
) -> list[dict[str, Any]]:
    """Transforms a collection of findings into the GitLab Code Quality array schema."""
    issues: list[dict[str, Any]] = []
    seen_fingerprints: set[str] = set()

    for finding in findings or []:
        issue = finding_to_gitlab_issue(finding, include_suppressed=include_suppressed)
        if issue is None:
            continue
        fp = issue["fingerprint"]
        if fp in seen_fingerprints:
            continue
        seen_fingerprints.add(fp)
        issues.append(issue)

    return issues


def findings_to_gitlab_code_quality_json(
    findings: Iterable[dict[str, Any]],
    *,
    indent: int = 2,
    include_suppressed: bool = False,
) -> str:
    """Serializes findings into a JSON string conforming to gl-code-quality-report.json."""
    issues = findings_to_gitlab_code_quality(findings, include_suppressed=include_suppressed)
    return json.dumps(issues, indent=indent, ensure_ascii=False) + "\n"
