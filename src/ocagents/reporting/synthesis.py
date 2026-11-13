"""
Open Cloud Agents: Stage 5 User-Facing Markdown Synthesis Reporter (Milestone v2.0 - TASK-4.3).

Synthesizes structured blackboard findings, risk triage classifications, and agent execution
telemetry into clean, actionable, user-facing PR review Markdown reports.
"""

from __future__ import annotations

import re
from typing import Any

from ocagents.blackboard.envelope import RunEnvelope
from ocagents.orchestration.blackboard_runner import BlackboardRunSummary

# Severity hierarchy for ordering and grouping
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_BADGES = {
    "critical": "🚨 Critical",
    "high": "⚠️ High",
    "medium": "🟡 Medium",
    "low": "ℹ️ Low",
    "info": "📝 Info",
}

CORROBORATION_BADGES = {
    "tool_verified": "🛡️ Tool-Verified",
    "unverified_model_claim": "🤖 Model Assertion (Unverified)",
    "human_verified": "👤 Human-Verified",
    "rejected_false_positive": "❌ Dismissed (False Positive)",
}


def sanitize_github_url(raw_url: str | None) -> str | None:
    """Normalizes SSH/HTTPS GitHub URLs to a canonical HTTPS web URL."""
    if not raw_url:
        return None
    url = raw_url.strip()
    if url.endswith(".git"):
        url = url[:-4]
    if url.startswith("git@github.com:"):
        repo_part = url[len("git@github.com:"):]
        return f"https://github.com/{repo_part}"
    if url.startswith("https://github.com/"):
        return url
    if "/" in url and not url.startswith("http"):
        return f"https://github.com/{url}"
    return url


def format_evidence_link(
    evidence: str,
    repo_url: str | None = None,
    commit_sha: str | None = None,
) -> str:
    """
    Formats canonical evidence URI (diff:..., repo:..., cloud:...) into a clickable
    Markdown link or safe relative code span. Strips local workstation paths.
    """
    if not evidence:
        return "`unknown`"

    # Remove any stray absolute local paths
    clean_ev = re.sub(r"/Users/[^/]+/", "", evidence)
    clean_ev = re.sub(r"[a-zA-Z]:\\[^\\]+\\", "", clean_ev)

    gh_base = sanitize_github_url(repo_url)
    ref = commit_sha or "main"

    # Match diff:<path>#L<lines> or repo:<path>#L<lines>
    match = re.match(r"^(?:diff|repo):([^#]+)(?:#(L\d+(?:-L\d+)?))?$", clean_ev)
    if match:
        filepath = match.group(1).lstrip("/")
        line_ref = match.group(2) or ""
        display_text = f"{filepath}#{line_ref}" if line_ref else filepath

        if gh_base:
            anchor = f"#{line_ref}" if line_ref else ""
            url = f"{gh_base}/blob/{ref}/{filepath}{anchor}"
            return f"[`{display_text}`]({url})"
        return f"`{display_text}`"

    # Match cloud:<resource_id>
    if clean_ev.startswith("cloud:"):
        resource_id = clean_ev[len("cloud:"):]
        return f"`cloud:{resource_id}`"

    return f"`{clean_ev}`"


def format_rule_link(rule_id: str, repo_url: str | None = None, commit_sha: str | None = None) -> str:
    """Formats a rule ID into a clickable Markdown link if repo_url is available."""
    if not rule_id:
        return "`rules/unknown.md`"

    rule_clean = rule_id.lstrip("/")
    gh_base = sanitize_github_url(repo_url)
    if gh_base:
        ref = commit_sha or "main"
        url = f"{gh_base}/blob/{ref}/{rule_clean}"
        return f"[`{rule_clean}`]({url})"
    return f"`{rule_clean}`"


def calculate_verdict(findings: list[dict[str, Any]]) -> tuple[str, str, str]:
    """
    Computes gate verdict based on the highest severity active finding.
    Returns (verdict_badge, verdict_title, verdict_description).
    """
    active_findings = [
        f for f in findings
        if f.get("corroboration_status") != "rejected_false_positive"
    ]

    has_critical = any(f.get("severity", "").lower() == "critical" for f in active_findings)
    has_high = any(f.get("severity", "").lower() == "high" for f in active_findings)
    has_medium = any(f.get("severity", "").lower() == "medium" for f in active_findings)
    has_low_or_info = any(f.get("severity", "").lower() in ("low", "info") for f in active_findings)

    if has_critical or has_high:
        return (
            "🚨 ACTION REQUIRED",
            "P0/P1 Architectural or Security Defects Intercepted",
            "One or more Critical or High severity findings require human maintainer review or remediation prior to merging.",
        )
    if has_medium:
        return (
            "⚠️ ADVISORY REVIEW",
            "Medium-Severity Advisory Findings Reported",
            "Architectural or compliance warnings identified. Non-blocking; maintainer sign-off recommended.",
        )
    if has_low_or_info:
        return (
            "ℹ️ INFORMATIONAL",
            "Low-Severity Suggestions Reported",
            "Minor hygiene or style suggestions identified. Non-blocking.",
        )
    return (
        "✅ CLEAN",
        "All Pre-Merge Quality Gates Passed",
        "Zero architectural defects or compliance violations detected in changeset.",
    )


def count_findings_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Tallies findings grouped by canonical severity level."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = str(f.get("severity", "medium")).lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["medium"] += 1
    return counts


def generate_markdown_report(
    findings: list[dict[str, Any]],
    run_envelope: RunEnvelope | dict[str, Any] | None = None,
    run_summary: BlackboardRunSummary | dict[str, Any] | None = None,
    repo_url: str | None = None,
    pr_number: int | None = None,
) -> str:
    """
    Generates a full GitHub Flavored Markdown PR review verification summary report.
    """
    # 1. Resolve Envelope & Metadata
    env_data: dict[str, Any] = {}
    if isinstance(run_envelope, RunEnvelope):
        env_data = run_envelope.to_dict()
    elif isinstance(run_envelope, dict):
        env_data = dict(run_envelope)

    resolved_repo_url = repo_url or env_data.get("repo_url")
    commit_sha = env_data.get("commit_sha")
    short_sha = commit_sha[:8] if commit_sha else "unknown"
    run_id = env_data.get("run_id") or (
        run_summary.run_id if isinstance(run_summary, BlackboardRunSummary)
        else run_summary.get("run_id") if isinstance(run_summary, dict)
        else "local-run"
    )
    risk_tier = env_data.get("risk_tier", 2)

    # 2. Compute Verdict and Counts
    verdict_badge, verdict_title, verdict_desc = calculate_verdict(findings)
    counts = count_findings_by_severity(findings)
    total_findings = len(findings)

    # 3. Assemble Header & Verdict Callout
    lines: list[str] = [
        "## 🛡️ Open Cloud Agents: Pre-Merge Verification Summary",
        "",
        f"### {verdict_badge}: {verdict_title}",
        "",
        f"{verdict_desc}",
        "",
        "| Severity Breakdown | Count |",
        "|---|---|",
        f"| 🚨 **Critical** | {counts['critical']} |",
        f"| ⚠️ **High** | {counts['high']} |",
        f"| 🟡 **Medium** | {counts['medium']} |",
        f"| ℹ️ **Low** | {counts['low']} |",
        f"| 📝 **Info** | {counts['info']} |",
        f"| **Total Findings** | **{total_findings}** |",
        "",
    ]

    # 4. Findings Sections (Grouped by Severity)
    if total_findings == 0:
        lines.extend([
            "---",
            "",
            "### ✨ Clean Changeset",
            "No architectural risks, compliance gaps, or Well-Architected violations were identified.",
            "",
        ])
    else:
        lines.extend([
            "---",
            "",
            "## 📋 Detailed Findings Catalog",
            "",
        ])

        # Group findings by severity
        grouped: dict[str, list[dict[str, Any]]] = {s: [] for s in SEVERITY_ORDER}
        for f in findings:
            sev = str(f.get("severity", "medium")).lower()
            if sev in grouped:
                grouped[sev].append(f)
            else:
                grouped["medium"].append(f)

        for sev in SEVERITY_ORDER:
            sev_findings = grouped[sev]
            if not sev_findings:
                continue

            sev_badge = SEVERITY_BADGES.get(sev, sev.title())
            lines.append(f"### {sev_badge} ({len(sev_findings)})")
            lines.append("")

            for f in sev_findings:
                fid = f.get("id", "FND-UNKNOWN")
                rule_id = f.get("rule_id", "rules/unknown.md")
                resource = f.get("resource", "unknown")
                evidence = f.get("evidence", "")
                fact = f.get("fact", "No fact provided")
                rec = f.get("recommendation", "No recommendation provided")
                agent = f.get("agent", "unknown")
                status = f.get("corroboration_status", "unverified_model_claim")
                origin = f.get("origin", "model_assertion")
                confidence = f.get("confidence")
                occurrence_count = f.get("occurrence_count", 1)
                corroborating = f.get("corroborating_agents", [agent])

                status_label = CORROBORATION_BADGES.get(status, status)
                ev_link = format_evidence_link(evidence, repo_url=resolved_repo_url, commit_sha=commit_sha)
                rule_link = format_rule_link(rule_id, repo_url=resolved_repo_url, commit_sha=commit_sha)

                lines.append(f"#### `{fid}`: {fact}")
                lines.append("")
                lines.append(f"- **Rule**: {rule_link}")
                lines.append(f"- **Resource**: `{resource}`")
                lines.append(f"- **Location**: {ev_link}")
                lines.append(f"- **Origin**: `{origin}` ({status_label})")
                lines.append(f"- **Reporting Specialist**: `{agent}`")

                if occurrence_count > 1 or len(corroborating) > 1:
                    agents_str = ", ".join(f"`{a}`" for a in set(corroborating))
                    lines.append(f"- **Corroborating Specialists**: {agents_str} ({occurrence_count} independent reports)")

                if confidence is not None:
                    try:
                        conf_pct = f"{float(confidence) * 100:.0f}%"
                        lines.append(f"- **Confidence Score**: {conf_pct}")
                    except (ValueError, TypeError):
                        pass

                lines.append("")
                lines.append(f"**Recommendation:** {rec}")
                lines.append("")

                # Remediation Diff Preview (if provided)
                remediation = f.get("remediation")
                if isinstance(remediation, dict):
                    diff_preview = remediation.get("diff_preview", "").strip()
                    if diff_preview:
                        lines.append("> [!TIP]")
                        lines.append("> **Proposed Remediation Preview (Advisory Proposal Only):**")
                        lines.append("> Remediation diffs are draft proposals and are **never** automatically merged.")
                        lines.append("")
                        lines.append("```diff")
                        lines.append(diff_preview)
                        lines.append("```")
                        lines.append("")

                lines.append("---")
                lines.append("")

    # 5. Maintainer Review & Triage Directives Section
    lines.extend([
        "## 🛠️ Maintainer Triage & Resolution Directives",
        "",
        "Maintainers can triage findings by leaving a comment on this pull request:",
        "",
        "- `/ocagents triage <finding-id> accept` - Confirm defect and mandate remediation prior to merge.",
        "- `/ocagents triage <finding-id> dismiss --reason \"<justification>\"` - Dismiss as accepted risk or false positive.",
        "",
    ])

    # 6. Telemetry & Execution Audit Section
    lines.extend([
        "<details>",
        "<summary><b>🔍 Run Telemetry & Execution Audit</b></summary>",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| **Run ID** | `{run_id}` |",
        f"| **Commit SHA** | `{short_sha}` |",
        f"| **Risk Tier** | Tier {risk_tier} |",
    ])

    if isinstance(run_summary, BlackboardRunSummary):
        lines.append(f"| **Activated Specialists** | {', '.join(f'`{a}`' for a in run_summary.agents_activated) or 'None (LLM Bypass)'} |")
        lines.append(f"| **Total Tokens Consumed** | {run_summary.total_tokens_consumed:,} |")
        lines.append(f"| **Execution Duration** | {run_summary.execution_time_seconds:.2f}s |")
        if run_summary.errors:
            lines.append(f"| **Execution Errors** | {len(run_summary.errors)} error(s) |")

        if run_summary.agent_results:
            lines.extend([
                "",
                "#### Specialist Execution Breakdown",
                "",
                "| Specialist | Status | Findings | Tokens | Duration |",
                "|---|---|---|---|---|",
            ])
            for aid, res in run_summary.agent_results.items():
                dur_s = f"{res.duration_ms / 1000:.2f}s" if res.duration_ms else "-"
                tok = f"{res.total_tokens:,}" if res.total_tokens else "0"
                lines.append(f"| `{aid}` | `{res.status}` | {len(res.findings)} | {tok} | {dur_s} |")

    elif isinstance(run_summary, dict):
        agents_act = run_summary.get("agents_activated", [])
        total_tok = run_summary.get("total_tokens_consumed", 0)
        dur = run_summary.get("execution_time_seconds", 0.0)
        lines.append(f"| **Activated Specialists** | {', '.join(f'`{a}`' for a in agents_act) or 'None'} |")
        lines.append(f"| **Total Tokens Consumed** | {total_tok:,} |")
        lines.append(f"| **Execution Duration** | {dur:.2f}s |")

        agent_results = run_summary.get("agent_results", {})
        if agent_results:
            lines.extend([
                "",
                "#### Specialist Execution Breakdown",
                "",
                "| Specialist | Status | Findings | Tokens | Duration |",
                "|---|---|---|---|---|",
            ])
            for aid, r in agent_results.items():
                dur_s = f"{r.get('duration_ms', 0) / 1000:.2f}s"
                tok = f"{r.get('total_tokens', 0):,}"
                lines.append(f"| `{aid}` | `{r.get('status')}` | {r.get('findings_count', 0)} | {tok} | {dur_s} |")

    lines.extend([
        "",
        "</details>",
        "",
        "---",
        "",
        "> [!NOTE]",
        "> Automated verification by **Open Cloud Agents**. Automated reviews assist reviewers; formal pull request approval requires a human maintainer.",
        "",
    ])

    return "\n".join(lines)
