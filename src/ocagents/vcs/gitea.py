"""
Open Cloud Agents: Gitea & Forgejo Air-Gapped Adapter (ADR-003, Phase 5).

Implements the VCSProvider interface for self-hosted, air-gapped, and sovereign cloud
deployments using Gitea and Forgejo REST API v1.
Supports authentication with GITEA_TOKEN / API tokens, PR diff fetching, review
summary threading, line-level code review comments, commit status check updates,
strict offline / air-gapped execution mode, and native artifact generation.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, TextIO

from ocagents import __version__
from ocagents.blackboard.sarif_exporter import findings_to_sarif_json
from ocagents.vcs.base import DEFAULT_STATUS_CONTEXT, VALID_COMMIT_STATES, VCSProvider
from ocagents.vcs.detector import Forge, detect_forge
from ocagents.vcs.local import LocalGitAdapter

logger = logging.getLogger(__name__)

GT_ARTIFACT_NAME = "gitea-quality-report.json"
SUMMARY_MARKER = "<!-- ocagents-review-summary -->"

_EVIDENCE_REGEX = re.compile(
    r"^(?:diff|repo):(?P<path>[^#\s]+)#L(?P<start>\d+)(?:-L(?P<end>\d+))?$"
)

# Mapping from VCSProvider commit states to Gitea commit status states
GT_STATUS_STATE_MAP: dict[str, str] = {
    "success": "success",
    "failed": "failure",
    "pending": "pending",
}

GITEA_API_EXCEPTIONS = (
    urllib.error.URLError,
    urllib.error.HTTPError,
    OSError,
    ValueError,
    KeyError,
    RuntimeError,
)


def findings_to_gitea_quality(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Transforms canonical finding documents into Gitea / Forgejo quality report structure."""
    total = len(findings)
    critical = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
    high = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    medium = sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium")
    low = sum(1 for f in findings if str(f.get("severity", "")).lower() in ("low", "info"))
    has_blocking = (critical + high) > 0

    return {
        "status": "failure" if has_blocking else "success",
        "summary": {
            "total_findings": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "blocking_count": critical + high,
        },
        "findings": findings,
    }


def findings_to_gitea_quality_json(findings: list[dict[str, Any]], indent: int = 2) -> str:
    """Serializes findings as formatted Gitea quality JSON."""
    return json.dumps(findings_to_gitea_quality(findings), indent=indent, ensure_ascii=False)


class GiteaAdapter(VCSProvider):
    """VCSProvider adapter for Gitea and Forgejo in self-hosted and air-gapped environments."""

    def __init__(
        self,
        base_url: str | None = None,
        owner: str | None = None,
        repo: str | None = None,
        token: str | None = None,
        pr_id: str | int | None = None,
        commit_sha: str | None = None,
        repo_root: str | Path | None = None,
        timeout: int = 30,
        offline: bool = False,
        stream: TextIO | None = None,
    ) -> None:
        raw_url = (
            base_url
            or os.environ.get("GITEA_SERVER_URL")
            or os.environ.get("GITEA_URL")
            or os.environ.get("FORGEJO_URL")
            or os.environ.get("GITHUB_SERVER_URL")
            or "https://gitea.com"
        )
        norm_url = raw_url.rstrip("/")
        if not norm_url.endswith("/api/v1"):
            norm_url = f"{norm_url}/api/v1"
        self.base_url = norm_url

        full_repo = (
            os.environ.get("GITEA_REPOSITORY")
            or os.environ.get("FORGEJO_REPOSITORY")
            or os.environ.get("GITHUB_REPOSITORY")
        )
        env_owner, env_repo = (
            full_repo.split("/", 1) if full_repo and "/" in full_repo else (None, None)
        )

        self.owner = (
            owner
            or os.environ.get("GITEA_OWNER")
            or os.environ.get("GITHUB_REPOSITORY_OWNER")
            or env_owner
        )
        self.repo = repo or os.environ.get("GITEA_REPO") or env_repo

        env_ref = os.environ.get("GITHUB_REF") or os.environ.get("GITEA_REF", "")
        ref_match = re.search(r"refs/pull/(\d+)", env_ref)
        env_pr_id = ref_match.group(1) if ref_match else None

        self.pr_id = (
            pr_id
            or os.environ.get("GITEA_PR_INDEX")
            or os.environ.get("GITEA_PR_ID")
            or env_pr_id
        )
        self.commit_sha = (
            commit_sha or os.environ.get("GITEA_COMMIT") or os.environ.get("GITHUB_SHA")
        )
        self.repo_root = Path(repo_root) if repo_root is not None else Path.cwd()
        self.timeout = timeout
        self.stream = stream

        # Air-gapped / offline operation flag
        self.offline = offline or (
            os.environ.get("OCAGENTS_OFFLINE", "").lower() in ("1", "true", "yes")
            or os.environ.get("OFFLINE", "").lower() in ("1", "true", "yes")
            or os.environ.get("GITEA_OFFLINE", "").lower() in ("1", "true", "yes")
        )

        env_token = (
            os.environ.get("GITEA_TOKEN")
            or os.environ.get("FORGEJO_TOKEN")
            or os.environ.get("GITEA_API_TOKEN")
            or os.environ.get("GITHUB_TOKEN")
        )
        self.token = (token or env_token or "").strip() or None

        self._local_fallback = LocalGitAdapter(
            repo_root=self.repo_root, stream=self.stream
        )

    @property
    def encoded_owner(self) -> str:
        """Returns the URL-encoded owner handle."""
        if not self.owner:
            raise ValueError(
                "Gitea owner is not set. Provide owner or set GITEA_OWNER / GITHUB_REPOSITORY."
            )
        return urllib.parse.quote(str(self.owner), safe="")

    @property
    def encoded_repo(self) -> str:
        """Returns the URL-encoded repository name."""
        if not self.repo:
            raise ValueError(
                "Gitea repo is not set. Provide repo or set GITEA_REPO / GITHUB_REPOSITORY."
            )
        return urllib.parse.quote(str(self.repo), safe="")

    def _headers(self) -> dict[str, str]:
        """Constructs HTTP headers including authorization and user agent."""
        headers = {
            "User-Agent": f"OpenCloudAgents/{__version__}",
            "Accept": "application/json",
        }
        if self.token:
            # Gitea accepts `token <token>` or `Bearer <token>`
            headers["Authorization"] = f"token {self.token}"
        return headers

    def _build_repo_url(self, endpoint: str) -> str:
        """Constructs full repository-scoped Gitea REST v1 URL."""
        path = endpoint.lstrip("/")
        return f"{self.base_url}/repos/{self.encoded_owner}/{self.encoded_repo}/{path}"

    def _api_request(
        self,
        endpoint: str,
        method: str = "GET",
        data: dict[str, Any] | list[Any] | None = None,
        params: dict[str, Any] | None = None,
        accept: str = "application/json",
    ) -> Any:
        """Executes an authenticated HTTP request against Gitea / Forgejo REST v1 API."""
        if self.offline:
            logger.debug(
                "GiteaAdapter in offline mode; suppressing external API call to %s",
                endpoint,
            )
            return {} if "application/json" in accept else ""

        url = self._build_repo_url(endpoint)
        if params:
            query = urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not None}
            )
            if query:
                url = f"{url}?{query}"

        body: bytes | None = None
        headers = self._headers()
        headers["Accept"] = accept

        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                content = response.read().decode("utf-8")
                if "application/json" in accept and content.strip():
                    return json.loads(content)
                return content
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Gitea API {method} {url} failed ({exc.code}): {err_body}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Gitea API {method} {url} connection failed: {exc.reason}"
            ) from exc

    def detect_context(self) -> bool:
        """Returns True if running in Gitea Actions / Forgejo or against a Gitea remote."""
        if os.environ.get("GITEA_ACTIONS") or os.environ.get("FORGEJO_ACTIONS"):
            return True
        if os.environ.get("GITEA_SERVER_URL") or os.environ.get("FORGEJO_URL"):
            return True
        if os.environ.get("GITEA_TOKEN") or os.environ.get("FORGEJO_TOKEN"):
            return True
        detection = detect_forge(repo_root=self.repo_root)
        return detection.forge == Forge.GITEA

    def get_diff(self, base_ref: str, head_ref: str) -> str:
        """Retrieves raw unified git diff from Gitea PR diff API, falling back to local git."""
        if (
            not self.offline
            and self.pr_id
            and self.owner
            and self.repo
            and self.token
        ):
            try:
                diff_text = self._api_request(
                    f"pulls/{self.pr_id}.diff",
                    accept="text/plain",
                )
                if isinstance(diff_text, str) and diff_text.strip():
                    return diff_text
            except GITEA_API_EXCEPTIONS as exc:
                logger.debug("Failed to fetch PR diff from Gitea API: %s", exc)

        return self._local_fallback.get_diff(base_ref, head_ref)

    def post_pr_summary(self, pr_id: str, summary_markdown: str) -> bool:
        """Publishes or updates the high-level review summary comment on the Gitea PR."""
        target_pr = pr_id or self.pr_id
        if not target_pr:
            raise ValueError("pr_id is required to post a review summary.")
        if self.offline or not self.token or not self.owner or not self.repo:
            return self._local_fallback.post_pr_summary(str(target_pr), summary_markdown)

        content_with_marker = f"{summary_markdown.rstrip()}\n\n{SUMMARY_MARKER}"

        # 1. Search existing issue comments for summary marker to update in place
        try:
            comments = self._api_request(f"issues/{target_pr}/comments")
            if isinstance(comments, list):
                for comment in comments:
                    raw_text = comment.get("body", "")
                    if SUMMARY_MARKER in raw_text:
                        comment_id = comment.get("id")
                        if comment_id is not None:
                            self._api_request(
                                f"issues/comments/{comment_id}",
                                method="PATCH",
                                data={"body": content_with_marker},
                            )
                            return True
        except GITEA_API_EXCEPTIONS as exc:
            logger.debug("Failed to search/update existing Gitea PR comment: %s", exc)

        # 2. Post new top-level comment
        payload = {"body": content_with_marker}
        self._api_request(
            f"issues/{target_pr}/comments",
            method="POST",
            data=payload,
        )
        return True

    def post_inline_annotations(
        self, pr_id: str, findings: list[dict[str, Any]]
    ) -> int:
        """Publishes line-level review comments on changed files in the Gitea PR."""
        target_pr = pr_id or self.pr_id
        if not target_pr:
            raise ValueError("pr_id is required to post inline annotations.")
        if self.offline or not self.token or not self.owner or not self.repo:
            return self._local_fallback.post_inline_annotations(
                str(target_pr), findings
            )

        review_comments: list[dict[str, Any]] = []

        for finding in findings or []:
            if not isinstance(finding, dict):
                continue
            if finding.get("corroboration_status") == "rejected_false_positive":
                continue

            evidence = str(finding.get("evidence") or "").strip()
            match = _EVIDENCE_REGEX.match(evidence)

            severity = str(finding.get("severity") or "info").upper()
            fid = finding.get("id", "FND-UNKNOWN")
            rule_id = finding.get("rule_id", "rules/unknown.md")
            fact = finding.get("fact") or "Code defect identified."
            recommendation = finding.get("recommendation", "")

            body = (
                f"### 🛡️ Open Cloud Agents: [{severity}]\n"
                f"**Rule:** `{rule_id}` ({fid})\n"
                f"**Finding:** {fact}"
            )
            if recommendation:
                body += f"\n\n**Remediation:** {recommendation}"

            path = match.group("path") if match else (finding.get("resource") or "")
            line = int(match.group("start")) if match else 1

            if path:
                review_comments.append(
                    {
                        "path": path.replace("\\", "/").strip("/"),
                        "new_position": max(1, line),
                        "body": body,
                    }
                )

        if not review_comments:
            return 0

        # Try submitting as a consolidated PR Review
        try:
            self._api_request(
                f"pulls/{target_pr}/reviews",
                method="POST",
                data={
                    "body": f"Open Cloud Agents Governance Review: {len(review_comments)} finding(s) identified.",
                    "event": "COMMENT",
                    "comments": review_comments,
                },
            )
            return len(review_comments)
        except GITEA_API_EXCEPTIONS as exc:
            logger.debug("Consolidated Gitea review failed, falling back to individual comments: %s", exc)

        # Fallback to posting individual line comments
        posted_count = 0
        target_commit = self.commit_sha
        for rc in review_comments:
            comment_payload: dict[str, Any] = {
                "body": rc["body"],
                "path": rc["path"],
                "new_position": rc["new_position"],
            }
            if target_commit:
                comment_payload["commit_id"] = target_commit
            try:
                self._api_request(
                    f"pulls/{target_pr}/comments",
                    method="POST",
                    data=comment_payload,
                )
                posted_count += 1
            except GITEA_API_EXCEPTIONS as exc:
                logger.debug("Failed to post individual Gitea line comment: %s", exc)

        return posted_count

    def set_commit_status(
        self,
        sha: str,
        state: str,
        description: str,
        context: str = DEFAULT_STATUS_CONTEXT,
        target_url: str | None = None,
    ) -> bool:
        """Sets the Gitea commit build status check."""
        if state not in VALID_COMMIT_STATES:
            raise ValueError(
                f"state must be one of {', '.join(VALID_COMMIT_STATES)}; got {state!r}"
            )

        if self.offline or not self.token or not self.owner or not self.repo:
            return self._local_fallback.set_commit_status(
                sha, state, description, context, target_url
            )

        gt_state = GT_STATUS_STATE_MAP.get(state, "pending")
        payload: dict[str, Any] = {
            "state": gt_state,
            "context": context,
            "description": description[:255] if description else "",
        }
        if target_url:
            payload["target_url"] = target_url

        try:
            self._api_request(
                f"statuses/{sha}",
                method="POST",
                data=payload,
            )
            return True
        except GITEA_API_EXCEPTIONS as exc:
            raise RuntimeError(
                f"Failed to set Gitea commit status for {sha[:8]}: {exc}"
            ) from exc

    def export_native_artifacts(
        self, findings: list[dict[str, Any]], output_dir: Path
    ) -> list[Path]:
        """Generates native Gitea Quality JSON and SARIF reports."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        report_path = out_dir / GT_ARTIFACT_NAME
        report_path.write_text(
            findings_to_gitea_quality_json(findings) + "\n", encoding="utf-8"
        )

        # Also generate standard SARIF 2.1.0 log
        sarif_path = out_dir / "ocagents.sarif"
        sarif_path.write_text(findings_to_sarif_json(findings), encoding="utf-8")

        return [report_path, sarif_path]
