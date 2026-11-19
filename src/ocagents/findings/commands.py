"""
Open Cloud Agents: First-class findings CLI (`ocagents findings ...`).

Subcommands that work on findings recorded in the Blackboard store
(or, for read-only commands, a findings JSON file):

  list     Table of findings, highest severity first
  inspect  Full detail for one finding: evidence, recommendation, provenance, triage
  triage   Record a human accept/dismiss decision in the Blackboard store
  export   Write findings as json, sarif, markdown, csv or toon
  stats    Counts by severity, status, category, agent and origin

`list`, `export` and `stats` accept --severity/--status/--category/--agent
filters (repeatable). Text that may come from model output is stripped of
terminal control characters before printing, and CSV cells are guarded
against spreadsheet formula injection.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

FINDINGS_ACTIONS = ("list", "inspect", "triage", "export", "stats")
EXPORT_FORMATS = (
    "json",
    "sarif",
    "markdown",
    "md",
    "csv",
    "toon",
    "gitlab-quality",
    "gitlab",
    "gl-code-quality",
    "bitbucket-insights",
    "bitbucket",
    "bb-insights",
)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {sev: rank for rank, sev in enumerate(SEVERITY_ORDER)}

CSV_COLUMNS = (
    "id",
    "severity",
    "corroboration_status",
    "category",
    "rule_id",
    "resource",
    "evidence",
    "agent",
    "origin",
    "confidence",
    "occurrence_count",
    "fact",
    "recommendation",
)

# C0/C1 control characters except tab and newline (ESC, CSI, BEL, ...).
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_SEVERITY_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[37m",
}
_RESET = "\033[0m"


class FindingsCommandError(Exception):
    """User-facing error raised by a findings subcommand."""


# --- Pure helpers ---------------------------------------------------------


def clean_text(value: Any) -> str:
    """Returns value as text with terminal control characters removed."""
    if value is None:
        return ""
    return _CONTROL_CHARS.sub("", str(value))


def _one_line(value: Any, width: int | None = None) -> str:
    text = " ".join(clean_text(value).split())
    if width and len(text) > width:
        return text[: width - 1] + "…"
    return text


def _normalize_filter(values: list[str] | str | None) -> set[str] | None:
    if not values:
        return None
    if isinstance(values, str):
        values = [values]
    items = {part.strip().lower() for value in values for part in value.split(",") if part.strip()}
    return items or None


def filter_findings(
    findings: list[dict[str, Any]],
    severity: list[str] | str | None = None,
    status: list[str] | str | None = None,
    category: list[str] | str | None = None,
    agent: list[str] | str | None = None,
) -> list[dict[str, Any]]:
    """
    Filters findings. Each filter accepts one value, a list, or a
    comma-separated string; matching is case-insensitive and values within
    one filter are OR-ed, while different filters are AND-ed.
    """
    criteria = {
        "severity": _normalize_filter(severity),
        "corroboration_status": _normalize_filter(status),
        "category": _normalize_filter(category),
        "agent": _normalize_filter(agent),
    }
    result = []
    for finding in findings:
        if all(
            wanted is None or str(finding.get(field, "")).lower() in wanted
            for field, wanted in criteria.items()
        ):
            result.append(finding)
    return result


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Orders findings by severity (critical first), then by ID."""
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), len(SEVERITY_ORDER)),
            str(f.get("id", "")),
        ),
    )


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts findings by severity, status, category, agent and origin."""

    def count(field: str) -> dict[str, int]:
        counter = Counter(str(f.get(field) or "unknown") for f in findings)
        return dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))

    by_severity = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = str(f.get("severity") or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_status": count("corroboration_status"),
        "by_category": count("category"),
        "by_agent": count("agent"),
        "by_origin": count("origin"),
    }


def _csv_cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, str):
        value = clean_text(value)
        if value.startswith(_CSV_FORMULA_PREFIXES):
            return "'" + value
    return value


def findings_to_csv(findings: list[dict[str, Any]]) -> str:
    """Serializes findings as CSV with a fixed column set."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        writer.writerow([_csv_cell(f.get(col)) for col in CSV_COLUMNS])
    return buffer.getvalue()


def _colorize(severity: str, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_SEVERITY_COLORS.get(severity, '')}{text}{_RESET}"


def render_findings_table(findings: list[dict[str, Any]], use_color: bool = False) -> str:
    """Renders a fixed-width text table of findings."""
    headers = ("ID", "SEVERITY", "STATUS", "RULE", "RESOURCE")
    widths = (16, 8, 24, 40, 40)
    rows = [
        (
            _one_line(f.get("id"), widths[0]),
            _one_line(f.get("severity"), widths[1]).lower(),
            _one_line(f.get("corroboration_status"), widths[2]),
            _one_line(f.get("rule_id"), widths[3]),
            _one_line(f.get("resource"), widths[4]),
        )
        for f in findings
    ]

    def fmt(cells: tuple[str, ...], color: bool = False) -> str:
        padded = [cell.ljust(width) for cell, width in zip(cells, widths)]
        if color:
            padded[1] = _colorize(cells[1], padded[1], True)
        return "  ".join(padded).rstrip()

    lines = [fmt(headers), fmt(tuple("-" * w for w in widths))]
    lines += [fmt(row, color=use_color) for row in rows]
    return "\n".join(lines)


def render_finding_detail(finding: dict[str, Any]) -> str:
    """Renders a human-readable detail view of one finding."""
    confidence = finding.get("confidence")
    fields = [
        ("ID", finding.get("id")),
        ("Severity", finding.get("severity")),
        ("Status", finding.get("corroboration_status")),
        ("Confidence", "n/a" if confidence is None else confidence),
        ("Rule", finding.get("rule_id")),
        ("Category", finding.get("category")),
        ("Resource", finding.get("resource")),
        ("Evidence", finding.get("evidence")),
    ]
    lines = [f"{label + ':':<12} {_one_line(value)}" for label, value in fields]

    lines += ["", "Fact:", f"  {clean_text(finding.get('fact')).strip()}"]
    lines += ["", "Recommendation:", f"  {clean_text(finding.get('recommendation')).strip()}"]

    remediation = finding.get("remediation")
    if isinstance(remediation, dict) and remediation:
        lines += ["", "Remediation:"]
        for key, value in remediation.items():
            text = clean_text(value if isinstance(value, str) else json.dumps(value))
            lines.append(f"  {clean_text(key)}:")
            lines += [f"    {line}" for line in text.splitlines() or [""]]

    agents = finding.get("corroborating_agents") or [finding.get("agent")]
    lines += [
        "",
        "Provenance:",
        f"  Origin:      {_one_line(finding.get('origin'))}",
        f"  Agent:       {_one_line(finding.get('agent'))}",
        f"  Seen by:     {_one_line(', '.join(str(a) for a in agents if a))}",
        f"  Occurrences: {_one_line(finding.get('occurrence_count', 1))}",
    ]

    metadata = finding.get("metadata")
    resolution = metadata.get("resolution") if isinstance(metadata, dict) else None
    if isinstance(resolution, dict):
        lines += [
            "",
            "Triage:",
            f"  Action:      {_one_line(resolution.get('action'))}",
            f"  By:          {_one_line(resolution.get('resolved_by'))}",
            f"  At:          {_one_line(resolution.get('resolved_at'))}",
            f"  Reason:      {_one_line(resolution.get('reason'))}",
        ]
        if resolution.get("previous_status"):
            lines.append(f"  Was:         {_one_line(resolution.get('previous_status'))}")

    return "\n".join(lines)


def render_stats(stats: dict[str, Any]) -> str:
    """Renders summarize_findings() output as text."""
    lines = [f"Total findings: {stats['total']}"]
    sections = (
        ("Severity", "by_severity"),
        ("Status", "by_status"),
        ("Category", "by_category"),
        ("Agent", "by_agent"),
        ("Origin", "by_origin"),
    )
    for title, key in sections:
        counts = stats.get(key) or {}
        if not counts:
            continue
        lines += ["", f"{title}:"]
        lines += [f"  {_one_line(name, 40):<40} {value:>5}" for name, value in counts.items()]
    return "\n".join(lines)


# --- Data access ----------------------------------------------------------


def _open_store(db_path: str | Path | None):
    from ocagents.blackboard.store import DEFAULT_DB_PATH, BlackboardStore

    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    if not path.is_file():
        raise FindingsCommandError(
            f"No Blackboard database found at {path}. Run a review first, or pass --db PATH."
        )
    return BlackboardStore(path)


def _load_from_file(file_path: str) -> list[dict[str, Any]]:
    from ocagents.triage.gate import load_findings_source

    path = Path(file_path)
    if not path.exists():
        raise FindingsCommandError(f"Findings file not found: {path}")
    return load_findings_source(findings_file=path)


def load_findings(args: Any) -> tuple[list[dict[str, Any]], str | None]:
    """
    Loads findings for list/export/stats. Returns (findings, run_id).

    Source order: --file, then the Blackboard store. In the store, --run-id
    selects a run, --all-runs selects every run, and the default is the most
    recent run.
    """
    file_path = getattr(args, "file", None)
    if file_path:
        return _load_from_file(file_path), None

    with _open_store(getattr(args, "db", None)) as store:
        if getattr(args, "all_runs", False):
            return store.get_findings(), None
        run_id = getattr(args, "run_id", None)
        if not run_id:
            runs = store.list_runs(limit=1)
            if not runs:
                return [], None
            run_id = runs[0].get("run_id")
        return store.get_findings(run_id=run_id), run_id


def find_finding(args: Any, finding_id: str) -> dict[str, Any] | None:
    """Looks up one finding by ID in --file or the Blackboard store."""
    file_path = getattr(args, "file", None)
    if file_path:
        for finding in _load_from_file(file_path):
            if str(finding.get("id", "")).upper() == finding_id:
                return finding
        return None
    with _open_store(getattr(args, "db", None)) as store:
        return store.get_finding(finding_id)


# --- Subcommands ----------------------------------------------------------


def _use_color() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _filtered(args: Any, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return filter_findings(
        findings,
        severity=getattr(args, "severity", None),
        status=getattr(args, "status", None),
        category=getattr(args, "category", None),
        agent=getattr(args, "agent", None),
    )


def _require_id(args: Any, action: str) -> str:
    finding_id = getattr(args, "target", None)
    if not finding_id:
        raise FindingsCommandError(f"Usage: ocagents findings {action} <FND-ID>")
    return str(finding_id).strip().upper()


def _cmd_list(args: Any) -> int:
    findings, run_id = load_findings(args)
    findings = sort_findings(_filtered(args, findings))
    limit = getattr(args, "limit", None)
    if limit is not None and limit >= 0:
        findings = findings[:limit]

    if getattr(args, "json", False):
        print(json.dumps(findings, indent=2))
        return 0

    if getattr(args, "file", None):
        scope = f"file {args.file}"
    elif run_id:
        scope = f"run {run_id}"
    else:
        scope = "all runs"
    print(f"{len(findings)} finding(s) ({clean_text(scope)})")
    if findings:
        print()
        print(render_findings_table(findings, use_color=_use_color()))
    return 0


def _cmd_inspect(args: Any) -> int:
    finding_id = _require_id(args, "inspect")
    finding = find_finding(args, finding_id)
    if finding is None:
        raise FindingsCommandError(f"Finding {finding_id} not found.")
    if getattr(args, "json", False):
        print(json.dumps(finding, indent=2))
    else:
        print(render_finding_detail(finding))
    return 0


def _cmd_triage(args: Any) -> int:
    from ocagents.blackboard.store import DEFAULT_DB_PATH
    from ocagents.triage.resolution import (
        FINDING_ID_PATTERN,
        ResolutionAction,
        is_authorized_maintainer,
        resolve_finding_in_store,
    )

    finding_id = _require_id(args, "triage")
    if not FINDING_ID_PATTERN.match(finding_id):
        raise FindingsCommandError(f"Invalid finding ID: {clean_text(finding_id)} (expected FND- followed by 12 characters)")
    if getattr(args, "file", None):
        raise FindingsCommandError(
            "findings triage records decisions in the Blackboard store. "
            "For a findings JSON file use: ocagents triage accept|dismiss <FND-ID> --findings FILE"
        )

    action_name = (getattr(args, "triage_action", None) or "").lower()
    if action_name not in ("accept", "dismiss"):
        raise FindingsCommandError("--action accept|dismiss is required")
    action = ResolutionAction(action_name)

    reason = getattr(args, "reason", None)
    if action == ResolutionAction.DISMISS and not (reason and reason.strip()):
        raise FindingsCommandError("--reason is required when dismissing a finding")

    actor = (
        getattr(args, "actor", None)
        or os.environ.get("GITHUB_ACTOR")
        or os.environ.get("USER")
        or os.environ.get("USERNAME")
        or ""
    ).lstrip("@")
    repo_root = getattr(args, "repo_root", None) or os.getcwd()
    if not is_authorized_maintainer(actor, codeowners_path=getattr(args, "codeowners", None), repo_root=repo_root):
        raise FindingsCommandError(
            f"Authorization denied: '@{clean_text(actor)}' is not listed in CODEOWNERS. "
            "Pass --actor or --codeowners if this is wrong."
        )

    db_path = Path(getattr(args, "db", None) or DEFAULT_DB_PATH)
    if not db_path.is_file():
        raise FindingsCommandError(f"No Blackboard database found at {db_path}. Pass --db PATH.")
    if not resolve_finding_in_store(db_path, finding_id, action, actor, reason):
        raise FindingsCommandError(f"Finding {finding_id} not found in {db_path}.")

    with _open_store(db_path) as store:
        updated = store.get_finding(finding_id) or {}

    if getattr(args, "json", False):
        print(json.dumps(updated, indent=2))
    else:
        print(
            f"✔ {finding_id} marked {updated.get('corroboration_status')} by @{clean_text(actor)}"
        )
    return 0


def _cmd_export(args: Any) -> int:
    fmt = (getattr(args, "format", None) or "json").lower()
    if fmt not in EXPORT_FORMATS:
        raise FindingsCommandError(f"Unsupported export format: {fmt} (choose from {', '.join(EXPORT_FORMATS)})")

    findings, run_id = load_findings(args)
    findings = sort_findings(_filtered(args, findings))

    if fmt == "json":
        content = json.dumps(findings, indent=2)
    elif fmt == "sarif":
        from ocagents.blackboard.sarif_exporter import findings_to_sarif_json

        content = findings_to_sarif_json(findings, run_id=run_id)
    elif fmt in ("markdown", "md"):
        from ocagents.reporting.synthesis import generate_markdown_report

        content = generate_markdown_report(findings=findings, repo_url=getattr(args, "repo_url", None))
    elif fmt == "csv":
        content = findings_to_csv(findings)
    elif fmt in ("gitlab-quality", "gitlab", "gl-code-quality"):
        from ocagents.vcs.gitlab_quality import findings_to_gitlab_code_quality_json

        content = findings_to_gitlab_code_quality_json(findings)
    elif fmt in ("bitbucket-insights", "bitbucket", "bb-insights"):
        from ocagents.vcs.bitbucket import findings_to_bitbucket_insights_json

        content = findings_to_bitbucket_insights_json(findings)
    else:
        from ocagents.blackboard.projections import project_findings_toon

        content = project_findings_toon(findings)

    out_file = getattr(args, "out", None)
    if out_file:
        path = Path(out_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        print(f"✔ Exported {len(findings)} finding(s) to {path} (format: {fmt})")
    else:
        sys.stdout.write(content if content.endswith("\n") else content + "\n")
    return 0


def _cmd_stats(args: Any) -> int:
    findings, run_id = load_findings(args)
    stats = summarize_findings(_filtered(args, findings))
    if run_id:
        stats["run_id"] = run_id
    if getattr(args, "json", False):
        print(json.dumps(stats, indent=2))
    else:
        if run_id:
            print(f"Run: {clean_text(run_id)}")
        print(render_stats(stats))
    return 0


_HANDLERS = {
    "list": _cmd_list,
    "inspect": _cmd_inspect,
    "triage": _cmd_triage,
    "export": _cmd_export,
    "stats": _cmd_stats,
}


def run_findings_command(action: str, args: Any) -> int:
    """Dispatches `ocagents findings <action>`; returns a process exit code."""
    handler = _HANDLERS.get(action)
    if handler is None:
        print(f"✖ Unknown findings action: {clean_text(action)}", file=sys.stderr)
        return 2
    try:
        return handler(args)
    except FindingsCommandError as err:
        print(f"✖ {err}", file=sys.stderr)
        return 1
