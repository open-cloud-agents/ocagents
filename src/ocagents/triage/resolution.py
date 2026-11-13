"""
Open Cloud Agents: Human Triage Resolution Directives (Milestone v2.0 - TASK-4.5).

Handles maintainer triage resolution commands in PR comments and PR review approvals:
  - Parses slash directives:
      /ocagents triage FND-XXX accept [--reason "..."]
      /ocagents triage FND-XXX dismiss --reason "..."
  - Enforces repository CODEOWNERS authorization checks
  - Updates finding corroboration_status:
      accept  -> "human_verified"
      dismiss -> "rejected_false_positive"
  - Automatically transitions open-cloud-agents/triage-gate status check to SUCCESS
    when all P0/P1 claims are resolved or upon human maintainer review approval.
"""

from __future__ import annotations

import enum
import json
import os
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ocagents.triage.gate import (
    TRIAGE_GATE_CONTEXT,
    TRIAGE_GATE_LABEL,
    TriageGateResult,
    TriageGateStatus,
    evaluate_triage_gate,
    parse_codeowners,
    sync_triage_gate_github,
)

# Regex matching valid deterministic finding IDs (FND- + 12 alphanumeric uppercase)
FINDING_ID_PATTERN = re.compile(r"^FND-[A-Z0-9]{12}$")

# Directive command regex matching both syntax orders:
#   /ocagents triage FND-XXX accept [--reason "..."]
#   /ocagents triage accept FND-XXX [--reason "..."]
DIRECTIVE_PATTERN = re.compile(
    r"^/ocagents\s+triage\s+(?:(?P<action1>accept|dismiss)\s+(?P<id1>FND-[A-Z0-9]{12})|(?P<id2>FND-[A-Z0-9]{12})\s+(?P<action2>accept|dismiss))"
    r"(?:\s+--reason\s+(?:\"(?P<reason_d>[^\"]+)\"|'(?P<reason_s>[^']+)'|(?P<reason_b>\S+)))?",
    re.IGNORECASE | re.MULTILINE,
)


class ResolutionAction(str, enum.Enum):
    """Supported human triage resolution actions."""
    ACCEPT = "accept"
    DISMISS = "dismiss"


@dataclass
class TriageDirective:
    """Structured representation of a parsed /ocagents triage directive."""

    finding_id: str
    action: ResolutionAction
    reason: str | None = None
    raw_command: str = ""
    author: str | None = None
    line_number: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Converts directive to dictionary."""
        d = asdict(self)
        d["action"] = self.action.value
        return d


@dataclass
class TriageResolutionResult:
    """Outcome of processing triage directives or review approvals."""

    success: bool
    directives_parsed: list[TriageDirective] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)
    failed_directives: list[tuple[str, str]] = field(default_factory=list)
    authorized: bool = True
    actor: str = "unknown"
    gate_result: TriageGateResult | None = None
    github_sync: dict[str, Any] | None = None
    response_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Converts result to clean dictionary."""
        return {
            "success": self.success,
            "authorized": self.authorized,
            "actor": self.actor,
            "directives_count": len(self.directives_parsed),
            "resolved_count": len(self.resolved_findings),
            "resolved_findings": self.resolved_findings,
            "failed_directives": self.failed_directives,
            "gate_status": self.gate_result.status.value if self.gate_result else None,
            "is_blocking": self.gate_result.is_blocking if self.gate_result else False,
            "response_message": self.response_message,
            "github_sync": self.github_sync,
        }


def parse_triage_directives(text: str, author: str | None = None) -> list[TriageDirective]:
    """
    Parses one or more /ocagents triage slash directives from comment text.
    
    Supports:
      /ocagents triage FND-8B1C3E4A9F20 accept
      /ocagents triage FND-8B1C3E4A9F20 accept --reason "Security compliance verified"
      /ocagents triage FND-8B1C3E4A9F20 dismiss --reason 'Staging exception active'
      /ocagents triage accept FND-8B1C3E4A9F20
    """
    directives: list[TriageDirective] = []
    if not text:
        return directives

    clean_author = author.lstrip("@") if author else None

    for line_idx, line in enumerate(text.splitlines(), start=1):
        line_clean = line.strip()
        if not line_clean.startswith("/ocagents"):
            continue

        match = DIRECTIVE_PATTERN.search(line_clean)
        if not match:
            continue

        action_str = (match.group("action1") or match.group("action2") or "").lower()
        f_id = (match.group("id1") or match.group("id2") or "").upper()
        reason = match.group("reason_d") or match.group("reason_s") or match.group("reason_b")

        if not FINDING_ID_PATTERN.match(f_id):
            continue

        action = ResolutionAction.ACCEPT if action_str == "accept" else ResolutionAction.DISMISS

        directives.append(
            TriageDirective(
                finding_id=f_id,
                action=action,
                reason=reason.strip() if reason else None,
                raw_command=line_clean,
                author=clean_author,
                line_number=line_idx,
            )
        )

    return directives


def is_authorized_maintainer(
    author: str,
    codeowners_path: Path | str | None = None,
    repo_root: Path | str | None = None,
) -> bool:
    """
    Verifies that the directive author is an authorized repository CODEOWNER.
    Returns True if author handle matches any reviewer in CODEOWNERS.
    """
    if not author:
        return False

    clean_author = author.lstrip("@").lower()
    reviewers, team_reviewers = parse_codeowners(codeowners_path=codeowners_path, repo_root=repo_root)

    for r in reviewers:
        if r.lower() == clean_author:
            return True

    for t in team_reviewers:
        if t.lower() == clean_author:
            return True

    return False


def apply_directive(
    directive: TriageDirective,
    findings: list[dict[str, Any]],
    actor: str,
) -> tuple[dict[str, Any] | None, bool, str]:
    """
    Applies a single triage directive to a list of finding dictionaries in-place.
    
    Returns:
        (updated_finding, success, message)
    """
    target: dict[str, Any] | None = None
    for f in findings:
        if f.get("id") == directive.finding_id:
            target = f
            break

    if target is None:
        return None, False, f"Finding '{directive.finding_id}' not found in active findings collection."

    new_status = (
        "human_verified"
        if directive.action == ResolutionAction.ACCEPT
        else "rejected_false_positive"
    )
    old_status = target.get("corroboration_status", "unverified_model_claim")
    target["corroboration_status"] = new_status

    # Ensure metadata structure exists and append resolution audit entry
    metadata = target.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        target["metadata"] = metadata

    default_reason = (
        "Accepted and verified by human maintainer"
        if directive.action == ResolutionAction.ACCEPT
        else "Dismissed as false positive or acceptable risk"
    )

    metadata["resolution"] = {
        "action": directive.action.value,
        "corroboration_status": new_status,
        "previous_status": old_status,
        "resolved_by": actor,
        "resolved_at": datetime.now(timezone.utc).isoformat(),
        "reason": directive.reason or default_reason,
    }

    msg = (
        f"Finding {directive.finding_id} transitioned from '{old_status}' "
        f"to '{new_status}' by @{actor}."
    )
    return target, True, msg


def resolve_finding_in_store(
    db_path: Path | str,
    finding_id: str,
    action: ResolutionAction,
    actor: str,
    reason: str | None = None,
) -> bool:
    """
    Persists a triage resolution directly into an SQLite Blackboard database.
    Updates corroboration_status and appends resolution audit entry to metadata JSON.
    """
    p = Path(db_path)
    if not p.is_file():
        return False

    new_status = (
        "human_verified"
        if action == ResolutionAction.ACCEPT
        else "rejected_false_positive"
    )

    try:
        conn = sqlite3.connect(str(p), timeout=5.0)
        conn.execute("PRAGMA busy_timeout = 5000;")
        cursor = conn.cursor()

        # Fetch current record
        cursor.execute("SELECT metadata FROM findings WHERE id = ?", (finding_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return False

        raw_meta = row[0]
        meta: dict[str, Any] = {}
        if raw_meta:
            try:
                meta = json.loads(raw_meta)
            except json.JSONDecodeError:
                meta = {}

        meta["resolution"] = {
            "action": action.value,
            "corroboration_status": new_status,
            "resolved_by": actor,
            "resolved_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason or ("Accepted" if action == ResolutionAction.ACCEPT else "Dismissed"),
        }

        cursor.execute(
            "UPDATE findings SET corroboration_status = ?, metadata = ? WHERE id = ?",
            (new_status, json.dumps(meta), finding_id),
        )
        conn.commit()
        conn.close()
        return True
    except (sqlite3.Error, OSError):
        return False


def apply_maintainer_approval(
    findings: list[dict[str, Any]],
    reviewer: str,
    reason: str | None = None,
) -> tuple[int, list[str]]:
    """
    Transitions all pending unverified model claims to 'human_verified' upon
    human maintainer PR approval (event: 'APPROVE').
    """
    resolved_ids: list[str] = []
    clean_reviewer = reviewer.lstrip("@")
    effective_reason = reason or "Approved via repository CODEOWNER pull request review"

    for f in findings:
        status = f.get("corroboration_status")
        if status in ("unverified_model_claim", None):
            f["corroboration_status"] = "human_verified"
            metadata = f.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}
                f["metadata"] = metadata
            metadata["resolution"] = {
                "action": "pr_approval",
                "corroboration_status": "human_verified",
                "previous_status": status or "unverified_model_claim",
                "resolved_by": clean_reviewer,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "reason": effective_reason,
            }
            f_id = f.get("id", "UNKNOWN")
            resolved_ids.append(f_id)

    return len(resolved_ids), resolved_ids


def execute_triage_directives(
    comment_body: str,
    actor: str,
    findings: list[dict[str, Any]],
    db_path: Path | str | None = None,
    codeowners_path: Path | str | None = None,
    repo_root: Path | str | None = None,
    commit_sha: str | None = None,
    repo: str | None = None,
    pr_number: int | None = None,
    github_token: str | None = None,
    dry_run: bool = False,
) -> TriageResolutionResult:
    """
    End-to-end dispatcher for PR comment directives:
      1. Parses directives from comment text.
      2. Validates author authorization against CODEOWNERS.
      3. Applies resolutions in-memory and to Blackboard database (if provided).
      4. Re-evaluates open-cloud-agents/triage-gate status.
      5. Synchronizes commit status check and PR label with GitHub.
      6. Formats response markdown comment for PR thread.
    """
    clean_actor = actor.lstrip("@")
    directives = parse_triage_directives(comment_body, author=clean_actor)

    if not directives:
        return TriageResolutionResult(
            success=False,
            authorized=True,
            actor=clean_actor,
            response_message="No valid `/ocagents triage` directives found in comment.",
        )

    # Enforce CODEOWNERS authorization
    authorized = is_authorized_maintainer(
        author=clean_actor,
        codeowners_path=codeowners_path,
        repo_root=repo_root,
    )

    if not authorized:
        msg = (
            f"⛔ **Authorization Denied:** User `@{clean_actor}` is not listed in `CODEOWNERS`.\n\n"
            "> Triage resolution directives (`/ocagents triage accept|dismiss`) require maintainer permissions."
        )
        return TriageResolutionResult(
            success=False,
            directives_parsed=directives,
            authorized=False,
            actor=clean_actor,
            response_message=msg,
        )

    resolved: list[str] = []
    failed: list[tuple[str, str]] = []
    audit_messages: list[str] = []

    for d in directives:
        target, ok, message = apply_directive(d, findings, actor=clean_actor)
        if ok and target:
            resolved.append(d.finding_id)
            audit_messages.append(f"- ✅ **{d.finding_id}:** {message}")
            if db_path:
                resolve_finding_in_store(
                    db_path=db_path,
                    finding_id=d.finding_id,
                    action=d.action,
                    actor=clean_actor,
                    reason=d.reason,
                )
        else:
            failed.append((d.finding_id, message))
            audit_messages.append(f"- ❌ **{d.finding_id}:** {message}")

    # Re-evaluate triage gate
    gate_res = evaluate_triage_gate(
        findings=findings,
        codeowners_path=codeowners_path,
        repo_root=repo_root,
    )

    sync_log: dict[str, Any] | None = None
    if commit_sha and repo:
        sync_log = sync_triage_gate_github(
            repo=repo,
            commit_sha=commit_sha,
            gate_result=gate_res,
            pr_number=pr_number,
            github_token=github_token,
            dry_run=dry_run,
        )

    # Format response markdown comment
    response_lines = [
        "### 🛡️ Open Cloud Agents: Triage Directive Processed",
        "",
        f"**Authorized Maintainer:** `@{clean_actor}`",
        "",
        "#### Resolution Summary:",
        "\n".join(audit_messages),
        "",
    ]

    if gate_res.is_blocking:
        response_lines.extend([
            f"**Triage Gate State:** `⏳ PENDING` ({gate_res.description})",
            f"> Status check `{TRIAGE_GATE_CONTEXT}` remains in `PENDING` awaiting resolution of remaining P0/P1 claims.",
        ])
    else:
        response_lines.extend([
            f"**Triage Gate State:** `✅ SUCCESS` ({gate_res.description})",
            f"> Status check `{TRIAGE_GATE_CONTEXT}` released to `SUCCESS`. Label `{TRIAGE_GATE_LABEL}` removed.",
        ])

    return TriageResolutionResult(
        success=len(resolved) > 0,
        directives_parsed=directives,
        resolved_findings=resolved,
        failed_directives=failed,
        authorized=True,
        actor=clean_actor,
        gate_result=gate_res,
        github_sync=sync_log,
        response_message="\n".join(response_lines),
    )
