"""
Open Cloud Agents: Local Git Adapter (ADR-003, Multi-VCS Phase 1).

Pure CLI fallback used when no forge is detected (a developer shell, or an
air-gapped runner). It reads diffs with the local ``git`` binary and writes
review output to the terminal. It never calls a remote API.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, TextIO

from ocagents.vcs.base import DEFAULT_STATUS_CONTEXT, VALID_COMMIT_STATES, VCSProvider

GIT_TIMEOUT_SECONDS = 60
NATIVE_ARTIFACT_NAME = "ocagents-findings.json"

# Control characters except tab and newline. Finding text can come from model
# output, so escape sequences are removed before anything reaches the terminal.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# A git ref must not start with "-" (it would be read as an option) or contain
# whitespace or control characters.
_SAFE_REF = re.compile(r"^[^\s\x00-\x1f\x7f-][^\s\x00-\x1f\x7f]*$")


def _clean(text: Any) -> str:
    return _CONTROL_CHARS.sub("", str(text))


def _validate_ref(ref: str) -> str:
    if not isinstance(ref, str) or not _SAFE_REF.match(ref):
        raise ValueError(f"Invalid git reference: {ref!r}")
    return ref


class LocalGitAdapter(VCSProvider):
    """Offline adapter that formats review results for the terminal."""

    def __init__(self, repo_root: str | Path | None = None, stream: TextIO | None = None) -> None:
        self.repo_root = Path(repo_root) if repo_root is not None else Path.cwd()
        self.stream = stream

    @property
    def _out(self) -> TextIO:
        # Resolved at write time so redirected or captured stdout is respected.
        return self.stream if self.stream is not None else sys.stdout

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )

    def detect_context(self) -> bool:
        """Matches whenever the working directory is inside a Git work tree."""
        try:
            proc = self._git("rev-parse", "--is-inside-work-tree")
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0 and proc.stdout.strip() == "true"

    def get_diff(self, base_ref: str, head_ref: str) -> str:
        """Returns ``git diff base...head`` (falling back to ``base..head``).

        Raises ValueError for unsafe refs and RuntimeError if git fails.
        """
        base = _validate_ref(base_ref)
        head = _validate_ref(head_ref)
        proc = self._git("diff", f"{base}...{head}", "--")
        if proc.returncode != 0:
            proc = self._git("diff", f"{base}..{head}", "--")
        if proc.returncode != 0:
            err = proc.stderr.strip() or f"Failed to compute git diff between {base} and {head}"
            raise RuntimeError(f"Git diff failed (exit {proc.returncode}): {err}")
        return proc.stdout

    def post_pr_summary(self, pr_id: str, summary_markdown: str) -> bool:
        """Prints the review summary to the terminal."""
        out = self._out
        out.write(f"\n=== Open Cloud Agents review summary ({_clean(pr_id) or 'local'}) ===\n")
        out.write(_clean(summary_markdown).rstrip("\n") + "\n")
        out.flush()
        return True

    def post_inline_annotations(self, pr_id: str, findings: list[dict[str, Any]]) -> int:
        """Prints one line per finding and returns how many were printed."""
        out = self._out
        count = 0
        for finding in findings or []:
            if not isinstance(finding, dict):
                continue
            severity = _clean(finding.get("severity", "info")).upper()
            location = _clean(finding.get("evidence") or finding.get("resource") or "unknown")
            message = _clean(finding.get("fact") or finding.get("title") or "No description provided")
            fid = _clean(finding.get("id", "FND-UNKNOWN"))
            out.write(f"[{severity}] {location}: {message} ({fid})\n")
            count += 1
        out.flush()
        return count

    def set_commit_status(
        self,
        sha: str,
        state: str,
        description: str,
        context: str = DEFAULT_STATUS_CONTEXT,
        target_url: str | None = None,
    ) -> bool:
        """Prints the status line; there is no remote check to update locally."""
        if state not in VALID_COMMIT_STATES:
            raise ValueError(f"state must be one of {', '.join(VALID_COMMIT_STATES)}; got {state!r}")
        line = f"[{_clean(context)}] {state}: {_clean(description)} ({_clean(sha)[:12]})"
        if target_url:
            line += f" {_clean(target_url)}"
        self._out.write(line + "\n")
        self._out.flush()
        return True

    def export_native_artifacts(self, findings: list[dict[str, Any]], output_dir: Path) -> list[Path]:
        """Writes the findings as JSON, the local equivalent of a forge report."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / NATIVE_ARTIFACT_NAME
        path.write_text(json.dumps(list(findings or []), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return [path]
