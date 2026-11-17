"""
Open Cloud Agents: SARIF 2.1.0 Exporter (#103).

Converts canonical findings (schemas/v1/finding.json) into a SARIF 2.1.0 log that
GitHub Code Scanning (github/codeql-action/upload-sarif), the VS Code SARIF Viewer
and SonarQube can import.

Mapping:
  - evidence ``diff:``/``repo:<path>#L<start>[-L<end>]`` -> physical location + region
  - evidence ``cloud:<provider>:<resource>``              -> logical location
  - severity critical/high/medium/low/info                -> level error/warning/note,
    plus a numeric ``security-severity`` that GitHub uses for alert severity labels
  - finding ``id``                                        -> stable partial fingerprint
  - ``rejected_false_positive``                           -> external suppression
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from ocagents import __version__

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "Open Cloud Agents"
TOOL_INFORMATION_URI = "https://github.com/open-cloud-agents/ocagents"
SRCROOT = "%SRCROOT%"
FINGERPRINT_KEY = "ocagentsFindingId/v1"
UNKNOWN_RULE_ID = "rules/unknown.md"

SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# GitHub Code Scanning labels alerts from this score:
# >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
SEVERITY_TO_SECURITY_SCORE: dict[str, str] = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "2.0",
    "info": "0.0",
}

_FILE_EVIDENCE = re.compile(r"^(?:diff|repo):(?P<path>[^#\s]+)#L(?P<start>\d+)(?:-L(?P<end>\d+))?$")
_CLOUD_EVIDENCE = re.compile(r"^cloud:(?P<target>.+)$")


def _severity(finding: dict[str, Any]) -> str:
    value = str(finding.get("severity") or "").lower().strip()
    return value if value in SEVERITY_TO_LEVEL else "info"


def _clean_path(path: str) -> str | None:
    """Repository-relative path with forward slashes; drops '.' and '..' segments."""
    parts = [p for p in path.replace("\\", "/").split("/") if p and p not in (".", "..")]
    return "/".join(parts) or None


def _location(evidence: str) -> dict[str, Any] | None:
    """Builds a SARIF location from an evidence locator, or None if it has none."""
    match = _FILE_EVIDENCE.match(evidence)
    if match:
        uri = _clean_path(match.group("path"))
        if uri is None:
            return None
        physical: dict[str, Any] = {"artifactLocation": {"uri": uri, "uriBaseId": SRCROOT}}
        start = int(match.group("start"))
        if start >= 1:  # SARIF line numbers start at 1
            region: dict[str, Any] = {"startLine": start}
            end = int(match.group("end") or start)
            if end > start:
                region["endLine"] = end
            physical["region"] = region
        return {"physicalLocation": physical}

    match = _CLOUD_EVIDENCE.match(evidence)
    if match:
        return {"logicalLocations": [{"fullyQualifiedName": match.group("target"), "kind": "resource"}]}
    return None


def _message(finding: dict[str, Any]) -> str:
    fact = str(finding.get("fact") or "").strip() or "No description provided"
    recommendation = str(finding.get("recommendation") or "").strip()
    return f"{fact}\n\nRecommendation: {recommendation}" if recommendation else fact


def _rule_help_uri(rule_id: str) -> str:
    # rule_id points at the canonical rules/ catalog of the Open Cloud Agents repository.
    return f"{TOOL_INFORMATION_URI}/blob/main/{rule_id}"


def _rule_name(rule_id: str) -> str:
    stem = rule_id.split("#", 1)[0].rsplit("/", 1)[-1].removesuffix(".md")
    words = [w for w in re.split(r"[-_]+", stem) if w and not w.isdigit()]
    return "".join(w.capitalize() for w in words) or "UnknownRule"


def _result(finding: dict[str, Any], rule_index: int) -> dict[str, Any]:
    severity = _severity(finding)
    evidence = str(finding.get("evidence") or "")
    result: dict[str, Any] = {
        "ruleId": str(finding.get("rule_id") or UNKNOWN_RULE_ID),
        "ruleIndex": rule_index,
        "level": SEVERITY_TO_LEVEL[severity],
        "message": {"text": _message(finding)},
    }

    location = _location(evidence)
    if location is not None:
        result["locations"] = [location]

    finding_id = finding.get("id")
    if finding_id:
        result["partialFingerprints"] = {FINGERPRINT_KEY: str(finding_id)}

    if finding.get("corroboration_status") == "rejected_false_positive":
        result["suppressions"] = [
            {"kind": "external", "status": "accepted", "justification": "Rejected as a false positive during triage."}
        ]

    properties: dict[str, Any] = {"severity": severity}
    for key, prop in (
        ("id", "findingId"),
        ("agent", "agent"),
        ("origin", "origin"),
        ("category", "category"),
        ("resource", "resource"),
        ("confidence", "confidence"),
        ("corroboration_status", "corroborationStatus"),
    ):
        if finding.get(key) is not None:
            properties[prop] = finding[key]
    if evidence:
        properties["evidence"] = evidence
    remediation = finding.get("remediation")
    if isinstance(remediation, dict) and remediation.get("diff_preview"):
        properties["remediationPreview"] = remediation["diff_preview"]
    result["properties"] = properties
    return result


def build_sarif_log(
    findings: Iterable[dict[str, Any]],
    *,
    tool_version: str = __version__,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Builds a SARIF 2.1.0 log (as a dict) with a single run for the findings.

    Non-dict entries are skipped and missing fields fall back to safe defaults,
    so a partially invalid findings list still produces a valid log.

    ``run_id`` is stored in ``run.properties`` rather than ``automationDetails``:
    GitHub treats ``automationDetails.id`` as the analysis category, and a new
    category on every run would stop earlier alerts from ever being closed.
    """
    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    rule_categories: dict[str, list[str]] = {}
    rule_severity: dict[str, str] = {}
    results: list[dict[str, Any]] = []

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id") or UNKNOWN_RULE_ID)
        severity = _severity(finding)

        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rule_categories[rule_id] = []
            rule_severity[rule_id] = severity
            rules.append({"id": rule_id})
        elif SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(rule_severity[rule_id]):
            rule_severity[rule_id] = severity

        category = finding.get("category")
        if category and category not in rule_categories[rule_id]:
            rule_categories[rule_id].append(str(category))

        results.append(_result(finding, rule_index[rule_id]))

    # A rule can cover findings of several severities; it reports the highest one.
    for rule in rules:
        rule_id = rule["id"]
        severity = rule_severity[rule_id]
        rule.update(
            {
                "name": _rule_name(rule_id),
                "shortDescription": {"text": f"Open Cloud Agents rule {rule_id}"},
                "helpUri": _rule_help_uri(rule_id),
                "defaultConfiguration": {"level": SEVERITY_TO_LEVEL[severity]},
                "properties": {
                    "tags": rule_categories[rule_id],
                    "security-severity": SEVERITY_TO_SECURITY_SCORE[severity],
                },
            }
        )

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": str(tool_version),
                "informationUri": TOOL_INFORMATION_URI,
                "rules": rules,
            }
        },
        "results": results,
    }
    if run_id:
        run["properties"] = {"ocagentsRunId": str(run_id)}

    return {"version": SARIF_VERSION, "$schema": SARIF_SCHEMA_URI, "runs": [run]}


def findings_to_sarif_json(
    findings: Iterable[dict[str, Any]],
    *,
    tool_version: str = __version__,
    run_id: str | None = None,
    indent: int | None = 2,
) -> str:
    """Serializes findings as a SARIF 2.1.0 JSON document."""
    log = build_sarif_log(findings, tool_version=tool_version, run_id=run_id)
    return json.dumps(log, indent=indent, ensure_ascii=False) + "\n"
