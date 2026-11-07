"""
Open Cloud Agents: TOON / Compact Tabular Prompt Projection Serializer (Milestone v1.6 - TASK-3.5).

Projects blackboard findings into compact, Token-Oriented Object Notation (TOON) tables
for specialist agent prompt contexts, cutting repeated JSON syntactic overhead by 30% to 50%.
"""

from __future__ import annotations

import json
from typing import Any

DEFAULT_TOON_COLUMNS = [
    "id",
    "severity",
    "status",
    "rule",
    "resource",
    "evidence",
    "fact",
    "recommendation",
]

# Domain relevance mappings by agent role
AGENT_RULE_PREFERENCES: dict[str, set[str]] = {
    "security-compliance-commander": {
        "rules/01-destructive-actions.md",
        "rules/02-secrets-and-identity.md",
        "rules/04-cloud-well-architected-invariants.md",
    },
    "finops-cloud-cost-optimizer": {
        "rules/04-cloud-well-architected-invariants.md",
    },
    "sre-reliability-engineer": {
        "rules/01-destructive-actions.md",
        "rules/04-cloud-well-architected-invariants.md",
    },
    "devsecops-reviewer": set(),  # Reviews all rules
    "principal-cloud-architect": set(),  # Reviews all rules
}


def estimate_token_count(text: str) -> int:
    """
    Computes structural token approximation (~4 chars per token)
    per ADR-002 and token optimization standards.
    """
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


def _sanitize_cell(value: Any) -> str:
    """Sanitizes text value for tabular representation by escaping newlines and pipes."""
    if value is None:
        return "-"
    s = str(value).strip().replace("\r\n", " ").replace("\n", " ").replace("|", "\\|")
    return s if s else "-"


def project_findings_toon(
    findings: list[dict[str, Any]],
    columns: list[str] | None = None,
    max_tokens: int | None = None,
) -> str:
    """
    Serializes a list of findings into compact TOON (Token-Oriented Object Notation) tabular text.
    Respects token budgets by truncating at whole-row boundaries if max_tokens is exceeded.
    """
    if not findings:
        return "[FINDINGS_TABLE: count=0]\n(No findings recorded)\n[/FINDINGS_TABLE]"

    cols = columns or DEFAULT_TOON_COLUMNS
    header_line = " | ".join(c.upper() for c in cols)
    lines: list[str] = [
        f"[FINDINGS_TABLE: count={len(findings)}]",
        header_line,
    ]

    for f in findings:
        row_cells: list[str] = []
        for col in cols:
            if col == "id":
                val = f.get("id", "-")
            elif col == "severity":
                sev = f.get("severity", "medium")
                conf = f.get("confidence")
                if conf is not None:
                    val = f"{sev} ({conf:.2f})"
                else:
                    val = f"{sev} (tool)"
            elif col == "status":
                val = f.get("corroboration_status", "unverified")
            elif col == "rule":
                val = f.get("rule_id", "-")
            elif col == "resource":
                val = f.get("resource", "-")
            elif col == "evidence":
                val = f.get("evidence", "-")
            elif col == "fact":
                val = f.get("fact", "-")
            elif col == "recommendation":
                val = f.get("recommendation", "-")
            elif col == "agent":
                val = f.get("agent", "-")
            elif col == "category":
                val = f.get("category", "-")
            else:
                val = f.get(col, "-")

            row_cells.append(_sanitize_cell(val))

        row_str = " | ".join(row_cells)

        # Token ceiling check
        if max_tokens is not None:
            candidate_text = "\n".join(lines + [row_str, "[/FINDINGS_TABLE]"])
            if estimate_token_count(candidate_text) > max_tokens:
                lines.append(f"... [Truncated at token limit: remaining {len(findings) - len(lines) + 2} findings omitted]")
                break

        lines.append(row_str)

    lines.append("[/FINDINGS_TABLE]")
    return "\n".join(lines)


def project_findings_minified_json(
    findings: list[dict[str, Any]],
    max_tokens: int | None = None,
) -> str:
    """
    Serializes findings as compact minified JSON without whitespace.
    """
    if not findings:
        return "[]"

    if max_tokens is None:
        return json.dumps(findings, separators=(",", ":"))

    # Bounded insertion under token ceiling
    selected: list[dict[str, Any]] = []
    for f in findings:
        selected.append(f)
        text = json.dumps(selected, separators=(",", ":"))
        if estimate_token_count(text) > max_tokens:
            selected.pop()
            break

    return json.dumps(selected, separators=(",", ":"))


def filter_findings_for_agent(
    findings: list[dict[str, Any]],
    agent_name: str,
) -> list[dict[str, Any]]:
    """
    Filters blackboard findings to those strictly relevant to a specialist agent's domain mandate.
    """
    preferred_rules = AGENT_RULE_PREFERENCES.get(agent_name)
    if not preferred_rules:
        # Agent reviews all findings
        return list(findings)

    filtered: list[dict[str, Any]] = []
    for f in findings:
        rule_id = f.get("rule_id", "")
        if rule_id in preferred_rules:
            filtered.append(f)
        elif f.get("severity") in ("critical", "high"):
            # High blast radius issues always surface to all specialists
            filtered.append(f)

    return filtered


def measure_projection_efficiency(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Benchmarks token and character efficiency of TOON tabular projection
    compared to formatted JSON array and minified JSON.
    """
    if not findings:
        return {
            "findings_count": 0,
            "raw_json_tokens": 0,
            "minified_json_tokens": 0,
            "toon_tokens": 0,
            "token_reduction_vs_raw_percent": 0.0,
            "token_reduction_vs_minified_percent": 0.0,
        }

    raw_json = json.dumps(findings, indent=2)
    minified_json = json.dumps(findings, separators=(",", ":"))
    toon = project_findings_toon(findings)

    raw_tokens = estimate_token_count(raw_json)
    min_tokens = estimate_token_count(minified_json)
    toon_tokens = estimate_token_count(toon)

    red_raw = round(((raw_tokens - toon_tokens) / max(raw_tokens, 1)) * 100.0, 1)
    red_min = round(((min_tokens - toon_tokens) / max(min_tokens, 1)) * 100.0, 1)

    return {
        "findings_count": len(findings),
        "raw_json_chars": len(raw_json),
        "raw_json_tokens": raw_tokens,
        "minified_json_chars": len(minified_json),
        "minified_json_tokens": min_tokens,
        "toon_chars": len(toon),
        "toon_tokens": toon_tokens,
        "token_reduction_vs_raw_percent": red_raw,
        "token_reduction_vs_minified_percent": red_min,
    }
