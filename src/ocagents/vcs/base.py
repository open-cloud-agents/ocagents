"""
Open Cloud Agents: Core VCSProvider Interface (ADR-003, Multi-VCS Phase 1).

Every forge integration (GitHub, GitLab, Azure DevOps, Bitbucket, Gitea/Forgejo,
and the local Git fallback) implements this contract, so the deterministic engine
and the findings blackboard never depend on a specific forge.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

# Commit status states shared by all adapters. Each adapter maps them to its
# forge's own vocabulary (for example GitLab uses "failed", GitHub uses "failure").
VALID_COMMIT_STATES: tuple[str, ...] = ("success", "failed", "pending")

DEFAULT_STATUS_CONTEXT = "ocagents/quality-gate"


class VCSProvider(ABC):
    """Abstract base contract for version control and code review forges."""

    @abstractmethod
    def detect_context(self) -> bool:
        """Returns True if the current runtime or git repository matches this forge."""

    @abstractmethod
    def get_diff(self, base_ref: str, head_ref: str) -> str:
        """Retrieves the unified git diff between base and head references."""

    @abstractmethod
    def post_pr_summary(self, pr_id: str, summary_markdown: str) -> bool:
        """Publishes or updates the high-level review summary comment on the PR/MR."""

    @abstractmethod
    def post_inline_annotations(self, pr_id: str, findings: list[dict[str, Any]]) -> int:
        """Publishes line-level annotations/discussions on changed code files."""

    @abstractmethod
    def set_commit_status(
        self,
        sha: str,
        state: str,
        description: str,
        context: str = DEFAULT_STATUS_CONTEXT,
        target_url: str | None = None,
    ) -> bool:
        """Sets the platform commit status or build check result.

        ``state`` is one of :data:`VALID_COMMIT_STATES`.
        """

    @abstractmethod
    def export_native_artifacts(self, findings: list[dict[str, Any]], output_dir: Path) -> list[Path]:
        """Exports platform-native artifacts (e.g. gl-code-quality-report.json, sarif)."""
