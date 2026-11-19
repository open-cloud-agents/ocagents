"""
Open Cloud Agents: GitLab SaaS & Self-Managed Adapter (ADR-003, Phase 2).

Implements the VCSProvider interface for GitLab using the GitLab REST v4 API.
Supports authentication with GITLAB_TOKEN or pipeline CI_JOB_TOKEN, Merge Request
diff retrieval, inline MR discussion threads, commit pipeline statuses, and native
GitLab Code Quality artifact generation (gl-code-quality-report.json).
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
from ocagents.vcs.base import DEFAULT_STATUS_CONTEXT, VALID_COMMIT_STATES, VCSProvider
from ocagents.vcs.detector import Forge, detect_forge
from ocagents.vcs.gitlab_quality import findings_to_gitlab_code_quality_json
from ocagents.vcs.local import LocalGitAdapter

logger = logging.getLogger(__name__)
GL_ARTIFACT_NAME = "gl-code-quality-report.json"
SUMMARY_MARKER = "<!-- ocagents-review-summary -->"
_EVIDENCE_REGEX = re.compile(
    r"^(?:diff|repo):(?P<path>[^#\s]+)#L(?P<start>\d+)(?:-L(?P<end>\d+))?$"
)
GITLAB_API_EXCEPTIONS = (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, KeyError)


class GitLabAdapter(VCSProvider):
    """VCSProvider adapter for GitLab SaaS and Self-Managed instances."""

    def __init__(
        self,
        base_url: str | None = None,
        project_id: str | int | None = None,
        token: str | None = None,
        token_type: str | None = None,
        mr_iid: str | int | None = None,
        repo_root: str | Path | None = None,
        timeout: int = 30,
        stream: TextIO | None = None,
    ) -> None:
        raw_url = base_url or os.environ.get("CI_SERVER_URL") or os.environ.get("GITLAB_URL") or "https://gitlab.com"
        self.base_url = raw_url.rstrip("/")

        self.project_id = project_id or os.environ.get("CI_PROJECT_ID") or os.environ.get("CI_PROJECT_PATH")
        self.mr_iid = mr_iid or os.environ.get("CI_MERGE_REQUEST_IID")
        self.repo_root = Path(repo_root) if repo_root is not None else Path.cwd()
        self.timeout = timeout
        self.stream = stream

        # Token resolution and header type
        env_gitlab_token = os.environ.get("GITLAB_TOKEN")
        env_job_token = os.environ.get("CI_JOB_TOKEN")
        if token is not None:
            self.token = token.strip()
            self.token_type = token_type or ("job" if token == env_job_token and not env_gitlab_token else "private")
        elif env_gitlab_token:
            self.token = env_gitlab_token.strip()
            self.token_type = token_type or "private"
        elif env_job_token:
            self.token = env_job_token.strip()
            self.token_type = token_type or "job"
        else:
            self.token = None
            self.token_type = None

        self._local_fallback = LocalGitAdapter(repo_root=self.repo_root, stream=self.stream)

    @property
    def encoded_project_id(self) -> str:
        """Returns the URL-encoded project identifier."""
        if not self.project_id:
            raise ValueError("GitLab project_id is not set. Provide project_id or set CI_PROJECT_ID.")
        return urllib.parse.quote(str(self.project_id), safe="")

    def _headers(self) -> dict[str, str]:
        """Constructs HTTP request headers including auth and user-agent."""
        headers = {
            "User-Agent": f"OpenCloudAgents/{__version__}",
            "Accept": "application/json",
        }
        if self.token:
            if self.token_type == "job":
                headers["JOB-TOKEN"] = self.token
            elif self.token_type == "bearer":
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                headers["PRIVATE-TOKEN"] = self.token
        return headers

    def _api_request(
        self,
        endpoint: str,
        method: str = "GET",
        data: dict[str, Any] | list[Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Performs an authenticated HTTP request to the GitLab REST v4 API."""
        url = f"{self.base_url}/api/v4/{endpoint.lstrip('/')}"
        if params:
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
            if query:
                url = f"{url}?{query}"

        body: bytes | None = None
        headers = self._headers()
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                content = response.read().decode("utf-8")
                return json.loads(content) if content.strip() else {}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitLab API {method} {url} failed ({exc.code}): {err_body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitLab API {method} {url} connection failed: {exc.reason}") from exc

    def detect_context(self) -> bool:
        """Returns True if running inside a GitLab CI pipeline or against a GitLab repository."""
        if os.environ.get("GITLAB_CI", "").strip().lower() == "true":
            return True
        if os.environ.get("CI_SERVER_URL") and os.environ.get("CI_PROJECT_ID"):
            return True
        detection = detect_forge(repo_root=self.repo_root)
        return detection.forge == Forge.GITLAB

    def get_diff(self, base_ref: str, head_ref: str) -> str:
        """Retrieves unified git diff between refs via GitLab API, falling back to local git."""
        # 1. Try Merge Request diffs endpoint if mr_iid is available
        if self.mr_iid and self.project_id and self.token:
            try:
                diffs_data = self._api_request(
                    f"projects/{self.encoded_project_id}/merge_requests/{self.mr_iid}/diffs"
                )
                if isinstance(diffs_data, list):
                    return self._format_diff_list(diffs_data)
            except GITLAB_API_EXCEPTIONS as exc:
                logger.debug("Failed to fetch MR diffs via GitLab API: %s", exc)

        # 2. Try repository compare endpoint if project_id and token are set
        if self.project_id and self.token:
            try:
                compare_data = self._api_request(
                    f"projects/{self.encoded_project_id}/repository/compare",
                    params={"from": base_ref, "to": head_ref},
                )
                if isinstance(compare_data, dict) and "diffs" in compare_data:
                    return self._format_diff_list(compare_data["diffs"])
            except GITLAB_API_EXCEPTIONS as exc:
                logger.debug("Failed to compare repository refs via GitLab API: %s", exc)

        # 3. Fallback to local Git repository execution
        return self._local_fallback.get_diff(base_ref, head_ref)

    def _format_diff_list(self, diffs: list[dict[str, Any]]) -> str:
        """Transforms a list of GitLab API diff objects into standard unified diff format."""
        chunks: list[str] = []
        for item in diffs:
            old_path = item.get("old_path", "")
            new_path = item.get("new_path", "")
            diff_text = item.get("diff", "")
            header = f"diff --git a/{old_path} b/{new_path}\n--- a/{old_path}\n+++ b/{new_path}\n"
            chunks.append(header + diff_text)
        return "\n".join(chunks)

    def post_pr_summary(self, pr_id: str, summary_markdown: str) -> bool:
        """Publishes or updates the top-level review summary comment on the GitLab MR."""
        mr_id = pr_id or self.mr_iid
        if not mr_id:
            raise ValueError("pr_id (Merge Request IID) is required to post a review summary.")
        if not self.project_id or not self.token:
            # Fall back to printing to terminal stream if offline
            return self._local_fallback.post_pr_summary(str(mr_id), summary_markdown)

        body_with_marker = f"{summary_markdown.rstrip()}\n\n{SUMMARY_MARKER}"

        # Check existing notes to update if one was previously posted
        try:
            notes = self._api_request(f"projects/{self.encoded_project_id}/merge_requests/{mr_id}/notes")
            if isinstance(notes, list):
                for note in notes:
                    if SUMMARY_MARKER in str(note.get("body", "")):
                        note_id = note.get("id")
                        if note_id:
                            self._api_request(
                                f"projects/{self.encoded_project_id}/merge_requests/{mr_id}/notes/{note_id}",
                                method="PUT",
                                data={"body": body_with_marker},
                            )
                            return True
        except GITLAB_API_EXCEPTIONS as exc:
            logger.debug("Failed to list or update existing GitLab MR note: %s", exc)

        # Create new note
        self._api_request(
            f"projects/{self.encoded_project_id}/merge_requests/{mr_id}/notes",
            method="POST",
            data={"body": body_with_marker},
        )
        return True

    def _get_mr_diff_refs(self, mr_id: str) -> dict[str, str]:
        """Fetches base_sha, start_sha, and head_sha for inline comment positioning."""
        # Check environment variables first (available in GitLab CI MR pipelines)
        base_sha = os.environ.get("CI_MERGE_REQUEST_DIFF_BASE_SHA")
        head_sha = os.environ.get("CI_COMMIT_SHA")
        if base_sha and head_sha:
            return {"base_sha": base_sha, "start_sha": base_sha, "head_sha": head_sha}

        try:
            mr_info = self._api_request(f"projects/{self.encoded_project_id}/merge_requests/{mr_id}")
            if isinstance(mr_info, dict) and "diff_refs" in mr_info:
                refs = mr_info["diff_refs"]
                if isinstance(refs, dict):
                    return {
                        "base_sha": refs.get("base_sha", ""),
                        "start_sha": refs.get("start_sha", refs.get("base_sha", "")),
                        "head_sha": refs.get("head_sha", ""),
                    }
        except GITLAB_API_EXCEPTIONS as exc:
            logger.debug("Failed to fetch MR diff_refs from GitLab API: %s", exc)
        return {}

    def post_inline_annotations(self, pr_id: str, findings: list[dict[str, Any]]) -> int:
        """Publishes line-anchored discussions on the Merge Request diffs."""
        mr_id = pr_id or self.mr_iid
        if not mr_id:
            raise ValueError("pr_id (Merge Request IID) is required to post inline annotations.")
        if not self.project_id or not self.token:
            return self._local_fallback.post_inline_annotations(str(mr_id), findings)

        diff_refs = self._get_mr_diff_refs(str(mr_id))
        posted_count = 0

        for finding in findings or []:
            if not isinstance(finding, dict):
                continue

            evidence = str(finding.get("evidence") or "").strip()
            match = _EVIDENCE_REGEX.match(evidence)

            severity = str(finding.get("severity") or "info").upper()
            fid = finding.get("id", "FND-UNKNOWN")
            fact = finding.get("fact") or finding.get("title") or "Code defect identified."
            recommendation = finding.get("recommendation", "")
            rule_id = finding.get("rule_id", "rules/unknown.md")

            comment_body = (
                f"### 🛡️ Open Cloud Agents: [{severity}] Finding\n\n"
                f"**Rule:** `{rule_id}` ({fid})\n\n"
                f"**Finding:** {fact}\n"
            )
            if recommendation:
                comment_body += f"\n**Recommendation:** {recommendation}\n"

            # If evidence has file and line and we have diff_refs, try positioned discussion
            if match and diff_refs.get("base_sha") and diff_refs.get("head_sha"):
                path = match.group("path").replace("\\", "/").strip("/")
                line = int(match.group("start"))
                position = {
                    "base_sha": diff_refs["base_sha"],
                    "start_sha": diff_refs.get("start_sha", diff_refs["base_sha"]),
                    "head_sha": diff_refs["head_sha"],
                    "position_type": "text",
                    "new_path": path,
                    "new_line": line,
                }
                try:
                    self._api_request(
                        f"projects/{self.encoded_project_id}/merge_requests/{mr_id}/discussions",
                        method="POST",
                        data={"body": comment_body, "position": position},
                    )
                    posted_count += 1
                    continue
                except GITLAB_API_EXCEPTIONS as exc:
                    logger.debug("Failed to post line-anchored discussion: %s", exc)

            # General note fallback if positioning is unavailable or line not in diff
            try:
                self._api_request(
                    f"projects/{self.encoded_project_id}/merge_requests/{mr_id}/notes",
                    method="POST",
                    data={"body": comment_body},
                )
                posted_count += 1
            except GITLAB_API_EXCEPTIONS as exc:
                logger.debug("Failed to post MR note fallback: %s", exc)

        return posted_count

    def set_commit_status(
        self,
        sha: str,
        state: str,
        description: str,
        context: str = DEFAULT_STATUS_CONTEXT,
        target_url: str | None = None,
    ) -> bool:
        """Sets the GitLab commit pipeline status check via Commit Status API."""
        if state not in VALID_COMMIT_STATES:
            raise ValueError(f"state must be one of {', '.join(VALID_COMMIT_STATES)}; got {state!r}")

        if not self.project_id or not self.token:
            return self._local_fallback.set_commit_status(sha, state, description, context, target_url)

        # GitLab status accepts state: "pending", "running", "success", "failed", "canceled"
        payload: dict[str, Any] = {
            "state": state,
            "name": context,
            "description": description[:1000] if description else "",
        }
        if target_url:
            payload["target_url"] = target_url

        try:
            self._api_request(
                f"projects/{self.encoded_project_id}/statuses/{sha}",
                method="POST",
                data=payload,
            )
            return True
        except Exception as exc:
            raise RuntimeError(f"Failed to set GitLab commit status for {sha[:8]}: {exc}") from exc

    def export_native_artifacts(self, findings: list[dict[str, Any]], output_dir: Path) -> list[Path]:
        """Generates and writes gl-code-quality-report.json to output_dir."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = out_dir / GL_ARTIFACT_NAME
        content = findings_to_gitlab_code_quality_json(findings)
        artifact_path.write_text(content, encoding="utf-8")
        return [artifact_path]
