"""
Open Cloud Agents: Dedicated CI Status Check: open-cloud-agents/triage-gate (Milestone v2.0 - TASK-4.4).

Manages the Model Findings Triage Gate context (open-cloud-agents/triage-gate):
  - When P0/P1 unverified model assertions exist:
      - Sets status check state to 'pending'
      - Sets description: 'Unresolved P0/P1 model assertions ({p0} critical, {p1} high) require human maintainer sign-off'
      - Applies PR label: 'needs-security-review'
      - Requests review from CODEOWNERS
  - When all findings are clean or resolved:
      - Sets status check state to 'success'
      - Sets description: 'Triage gate passed: zero unresolved P0/P1 findings'
      - Removes PR label: 'needs-security-review' (if present)
"""

from __future__ import annotations

import enum
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# Canonical status check context name enforced in ADR-002
TRIAGE_GATE_CONTEXT = "open-cloud-agents/triage-gate"

# Canonical PR label applied when P0/P1 model claims require human review
TRIAGE_GATE_LABEL = "needs-security-review"


class TriageGateStatus(str, enum.Enum):
    """Status check states for GitHub commit statuses."""
    PENDING = "pending"
    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"


@dataclass
class TriageGateResult:
    """Outcome of evaluating the model findings triage gate."""

    status: TriageGateStatus
    description: str
    context: str = TRIAGE_GATE_CONTEXT
    total_findings: int = 0
    p0_count: int = 0  # Critical severity unverified model claims
    p1_count: int = 0  # High severity unverified model claims
    p2_count: int = 0  # Medium/Low severity unverified model claims
    p3_count: int = 0  # Low/Info or uncertain claims
    tool_verified_count: int = 0
    human_verified_count: int = 0
    dismissed_count: int = 0
    unresolved_findings: list[dict[str, Any]] = field(default_factory=list)
    codeowners: list[str] = field(default_factory=list)
    labels_to_add: list[str] = field(default_factory=list)
    labels_to_remove: list[str] = field(default_factory=list)
    target_url: str | None = None

    @property
    def is_blocking(self) -> bool:
        """True if the triage gate is holding the commit in PENDING."""
        return self.status == TriageGateStatus.PENDING

    @property
    def unresolved_p0_p1_count(self) -> int:
        """Count of blocking P0/P1 findings requiring human triage."""
        return self.p0_count + self.p1_count

    def to_dict(self) -> dict[str, Any]:
        """Converts result to a clean dictionary."""
        d = asdict(self)
        d["status"] = self.status.value
        d["is_blocking"] = self.is_blocking
        d["unresolved_p0_p1_count"] = self.unresolved_p0_p1_count
        return d

    def to_markdown_summary(self) -> str:
        """Renders an executive summary of the triage gate status for PR reviews."""
        lines = [
            f"### 🛡️ Triage Gate Status: `{self.context}`",
            "",
            f"**Gate State:** `{'⏳ PENDING (Awaiting Human Maintainer Sign-off)' if self.is_blocking else '✅ SUCCESS (Passed)'}`",
            f"**Description:** {self.description}",
            "",
            "| Metric | Count | Governance Action |",
            "|---|---|---|",
            f"| **P0 (Critical Model Claims)** | {self.p0_count} | {'🛑 Blocks merge (PENDING)' if self.p0_count > 0 else '✅ None'} |",
            f"| **P1 (High Model Claims)** | {self.p1_count} | {'🛑 Blocks merge (PENDING)' if self.p1_count > 0 else '✅ None'} |",
            f"| **P2 (Medium/Low Claims)** | {self.p2_count} | Advisory review |",
            f"| **P3 (Informational Claims)** | {self.p3_count} | Diagnostic log |",
            f"| **Human-Verified Findings** | {self.human_verified_count} | ✅ Resolved |",
            f"| **Dismissed (False Positive)** | {self.dismissed_count} | ✅ Resolved |",
            f"| **Tool-Verified Findings** | {self.tool_verified_count} | Deterministic gate check |",
            f"| **Total Processed** | {self.total_findings} | - |",
        ]

        if self.is_blocking and self.unresolved_findings:
            lines.extend([
                "",
                "#### ⚠️ Unresolved P0/P1 Model Findings Requiring Sign-Off:",
                "",
                "| Finding ID | Severity | Category | Resource | Summary Fact |",
                "|---|---|---|---|---|",
            ])
            for f in self.unresolved_findings[:15]:
                f_id = f.get("id", "UNKNOWN")
                sev = f.get("severity", "unknown").upper()
                cat = f.get("category", "General")
                res = f.get("resource", "Unknown")
                fact = f.get("fact", "")
                fact_preview = (fact[:75] + "...") if len(fact) > 75 else fact
                lines.append(f"| `{f_id}` | **{sev}** | {cat} | `{res}` | {fact_preview} |")

            if len(self.unresolved_findings) > 15:
                lines.append(f"\n*... and {len(self.unresolved_findings) - 15} additional finding(s) in blackboard store.*")

            if self.codeowners:
                owners_str = ", ".join(self.codeowners)
                lines.extend([
                    "",
                    f"> **CODEOWNERS Review Required:** Assigned to {owners_str} via `{TRIAGE_GATE_LABEL}` label.",
                    "> Use `/ocagents triage FND-XXX accept` or `/ocagents triage FND-XXX dismiss --reason \"...\"` to resolve.",
                ])

        return "\n".join(lines)


def parse_codeowners(codeowners_path: Path | str | None = None, repo_root: Path | str | None = None) -> tuple[list[str], list[str]]:
    """
    Parses repository CODEOWNERS to extract individual user handles and team handles.
    
    Returns:
        (reviewers, team_reviewers) where reviewers are user logins without '@'
        and team_reviewers are team slugs without '@org/'.
    """
    candidates: list[Path] = []
    root = Path(repo_root) if repo_root else Path.cwd()

    if codeowners_path:
        candidates.append(Path(codeowners_path))
    else:
        candidates.extend([
            root / ".github" / "CODEOWNERS",
            root / "CODEOWNERS",
            root / "docs" / "CODEOWNERS",
        ])

    target_file: Path | None = None
    for c in candidates:
        if c.is_file():
            target_file = c
            break

    if not target_file:
        return [], []

    reviewers: list[str] = []
    team_reviewers: list[str] = []

    try:
        content = target_file.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            parts = clean.split()
            # First item is pattern, following items are owners
            for owner in parts[1:]:
                if not owner.startswith("@"):
                    continue
                handle = owner[1:]
                if "/" in handle:
                    # @org/team-slug -> team-slug
                    _, team_slug = handle.split("/", 1)
                    if team_slug and team_slug not in team_reviewers:
                        team_reviewers.append(team_slug)
                else:
                    if handle and handle not in reviewers:
                        reviewers.append(handle)
    except OSError:
        pass

    return reviewers, team_reviewers


def evaluate_triage_gate(
    findings: list[dict[str, Any]] | None = None,
    codeowners_path: Path | str | None = None,
    repo_root: Path | str | None = None,
    target_url: str | None = None,
) -> TriageGateResult:
    """
    Evaluates findings against the open-cloud-agents/triage-gate governance policy.
    
    P0/P1 model assertions (critical/high severity, origin=model_assertion,
    corroboration_status=unverified_model_claim) hold the gate in PENDING.
    """
    items = findings or []
    p0_count = 0
    p1_count = 0
    p2_count = 0
    p3_count = 0
    tool_verified_count = 0
    human_verified_count = 0
    dismissed_count = 0
    unresolved_p0_p1: list[dict[str, Any]] = []

    for f in items:
        origin = f.get("origin")
        status = f.get("corroboration_status")
        sev = str(f.get("severity", "medium")).lower()

        # Check resolution states first
        if status == "human_verified":
            human_verified_count += 1
            continue
        if status == "rejected_false_positive":
            dismissed_count += 1
            continue

        # Check tool-verified findings
        if status == "tool_verified" or origin == "deterministic_linter":
            tool_verified_count += 1
            continue

        # Evaluate model assertions
        if origin == "model_assertion" or status == "unverified_model_claim":
            if sev == "critical":
                p0_count += 1
                unresolved_p0_p1.append(f)
            elif sev == "high":
                p1_count += 1
                unresolved_p0_p1.append(f)
            elif sev in ("medium", "low"):
                conf = f.get("confidence")
                if conf is not None and conf < 0.85:
                    p3_count += 1
                else:
                    p2_count += 1
            else:
                p3_count += 1
        else:
            # Other unclassified assertions
            if sev in ("critical", "high"):
                p1_count += 1
                unresolved_p0_p1.append(f)
            else:
                p2_count += 1

    reviewers, team_reviewers = parse_codeowners(codeowners_path=codeowners_path, repo_root=repo_root)
    all_owners = [f"@{r}" for r in reviewers] + [f"@{t}" for t in team_reviewers]

    if p0_count + p1_count > 0:
        gate_status = TriageGateStatus.PENDING
        description = (
            f"Unresolved P0/P1 model assertions ({p0_count} critical, {p1_count} high) "
            f"require human maintainer sign-off"
        )
        labels_to_add = [TRIAGE_GATE_LABEL]
        labels_to_remove = []
    else:
        gate_status = TriageGateStatus.SUCCESS
        description = "Triage gate passed: zero unresolved P0/P1 findings"
        labels_to_add = []
        labels_to_remove = [TRIAGE_GATE_LABEL]

    return TriageGateResult(
        status=gate_status,
        description=description,
        context=TRIAGE_GATE_CONTEXT,
        total_findings=len(items),
        p0_count=p0_count,
        p1_count=p1_count,
        p2_count=p2_count,
        p3_count=p3_count,
        tool_verified_count=tool_verified_count,
        human_verified_count=human_verified_count,
        dismissed_count=dismissed_count,
        unresolved_findings=unresolved_p0_p1,
        codeowners=all_owners,
        labels_to_add=labels_to_add,
        labels_to_remove=labels_to_remove,
        target_url=target_url,
    )


def load_findings_source(
    findings_file: Path | str | None = None,
    db_path: Path | str | None = None,
    run_id: str | None = None,
) -> list[dict[str, Any]]:
    """Loads findings from a JSON file, JSON directory, or SQLite Blackboard store."""
    if findings_file:
        p = Path(findings_file)
        if not p.exists():
            return []
        if p.is_file():
            content = p.read_text(encoding="utf-8", errors="replace").strip()
            if not content:
                return []
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    return [item for item in data if isinstance(item, dict)]
                if isinstance(data, dict):
                    if "findings" in data and isinstance(data["findings"], list):
                        return [item for item in data["findings"] if isinstance(item, dict)]
                    return [data]
            except json.JSONDecodeError:
                return []
        elif p.is_dir():
            results: list[dict[str, Any]] = []
            for f in sorted(p.glob("*.json")):
                try:
                    data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                    if isinstance(data, list):
                        results.extend([x for x in data if isinstance(x, dict)])
                    elif isinstance(data, dict):
                        results.append(data)
                except (OSError, json.JSONDecodeError):
                    continue
            return results

    if db_path:
        db = Path(db_path)
        if db.is_file():
            try:
                from ocagents.blackboard.store import BlackboardStore
                store = BlackboardStore(db)
                return store.query(run_id=run_id)
            except Exception:
                return []

    return []


def sync_triage_gate_github(
    repo: str,
    commit_sha: str,
    gate_result: TriageGateResult,
    pr_number: int | None = None,
    pr_author: str | None = None,
    github_token: str | None = None,
    api_base_url: str = "https://api.github.com",
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Synchronizes the triage gate status to GitHub:
      1. Creates/updates commit status: context='open-cloud-agents/triage-gate'
      2. If PR number provided: applies/removes 'needs-security-review' label
      3. If PENDING: requests review from CODEOWNERS (excluding PR author)
    """
    token = github_token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    audit_log: dict[str, Any] = {
        "repo": repo,
        "commit_sha": commit_sha,
        "pr_number": pr_number,
        "dry_run": dry_run,
        "status_payload": {
            "state": gate_result.status.value,
            "context": gate_result.context,
            "description": gate_result.description[:140],
            "target_url": gate_result.target_url,
        },
        "labels_added": [],
        "labels_removed": [],
        "reviewers_requested": [],
        "errors": [],
    }

    if dry_run or not token:
        if not token and not dry_run:
            audit_log["errors"].append("Missing GITHUB_TOKEN; skipping live GitHub API synchronization.")
        if gate_result.labels_to_add:
            audit_log["labels_added"].extend(gate_result.labels_to_add)
        if gate_result.labels_to_remove:
            audit_log["labels_removed"].extend(gate_result.labels_to_remove)
        return audit_log

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "OpenCloudAgents-TriageGate/2.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # 1. Post Commit Status (open-cloud-agents/triage-gate)
    status_url = f"{api_base_url.rstrip('/')}/repos/{repo}/statuses/{commit_sha}"
    status_body = json.dumps({
        "state": gate_result.status.value,
        "context": gate_result.context,
        "description": gate_result.description[:140],
        "target_url": gate_result.target_url or "",
    }).encode("utf-8")

    try:
        req = urllib.request.Request(status_url, data=status_body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            audit_log["commit_status_response_code"] = resp.status
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
        audit_log["errors"].append(f"Failed to post commit status to {status_url}: {e}")

    # 2. PR Label Management & Review Requests (if pr_number available)
    if pr_number:
        # 2a. Add labels if needed
        if gate_result.labels_to_add:
            labels_url = f"{api_base_url.rstrip('/')}/repos/{repo}/issues/{pr_number}/labels"
            labels_body = json.dumps({"labels": gate_result.labels_to_add}).encode("utf-8")
            try:
                req = urllib.request.Request(labels_url, data=labels_body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=15) as resp:
                    audit_log["labels_added"].extend(gate_result.labels_to_add)
            except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
                audit_log["errors"].append(f"Failed to add PR labels: {e}")

        # 2b. Remove labels if resolved
        if gate_result.labels_to_remove:
            for label in gate_result.labels_to_remove:
                label_encoded = urllib.parse.quote(label)
                delete_url = f"{api_base_url.rstrip('/')}/repos/{repo}/issues/{pr_number}/labels/{label_encoded}"
                try:
                    req = urllib.request.Request(delete_url, headers=headers, method="DELETE")
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        audit_log["labels_removed"].append(label)
                except urllib.error.HTTPError as e:
                    # HTTP 404 is normal if label was not present
                    if e.code != 404:
                        audit_log["errors"].append(f"Failed to remove label {label}: {e}")
                except (urllib.error.URLError, OSError) as e:
                    audit_log["errors"].append(f"Network error removing label {label}: {e}")

        # 2c. Request review from CODEOWNERS if PENDING
        if gate_result.status == TriageGateStatus.PENDING and gate_result.codeowners:
            reviewers: list[str] = []
            team_reviewers: list[str] = []
            clean_author = (pr_author or "").lstrip("@").lower()

            for owner in gate_result.codeowners:
                handle = owner.lstrip("@")
                if "/" in handle:
                    _, team_slug = handle.split("/", 1)
                    if team_slug and team_slug not in team_reviewers:
                        team_reviewers.append(team_slug)
                else:
                    if handle and handle.lower() != clean_author and handle not in reviewers:
                        reviewers.append(handle)

            if reviewers or team_reviewers:
                reviewers_url = f"{api_base_url.rstrip('/')}/repos/{repo}/pulls/{pr_number}/requested_reviewers"
                payload: dict[str, Any] = {}
                if reviewers:
                    payload["reviewers"] = reviewers
                if team_reviewers:
                    payload["team_reviewers"] = team_reviewers

                req_body = json.dumps(payload).encode("utf-8")
                try:
                    req = urllib.request.Request(reviewers_url, data=req_body, headers=headers, method="POST")
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        audit_log["reviewers_requested"] = reviewers + team_reviewers
                except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
                    audit_log["errors"].append(f"Failed to request review from CODEOWNERS: {e}")

    return audit_log
