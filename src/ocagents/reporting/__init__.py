"""
Open Cloud Agents: Reporting & Synthesis Engine.

Compiles machine-readable findings and execution telemetry into clean,
user-facing Markdown and JSON review reports.
"""

from __future__ import annotations

from ocagents.reporting.synthesis import (
    CORROBORATION_BADGES,
    SEVERITY_BADGES,
    SEVERITY_ORDER,
    calculate_verdict,
    count_findings_by_severity,
    format_evidence_link,
    format_rule_link,
    generate_markdown_report,
    sanitize_github_url,
)

__all__ = [
    "CORROBORATION_BADGES",
    "SEVERITY_BADGES",
    "SEVERITY_ORDER",
    "calculate_verdict",
    "count_findings_by_severity",
    "format_evidence_link",
    "format_rule_link",
    "generate_markdown_report",
    "sanitize_github_url",
]
