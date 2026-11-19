"""
Open Cloud Agents: Azure DevOps Pipelines & Repos Adapter (ADR-003, Phase 3).

Implements the VCSProvider interface for Azure DevOps Repos and Azure Pipelines
using the Azure DevOps REST API 7.x.
Supports authentication with SYSTEM_ACCESSTOKEN or Personal Access Tokens (PAT),
PR thread creation, line-anchored threadContext annotations, PR status policies,
commit build statuses, and native SARIF v2.1.0 artifact publishing.
"""

from __future__ import annotations

import base64
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

ADO_ARTIFACT_NAME = "ocagents.sarif"
SUMMARY_MARKER = "<!-- ocagents-review-summary -->"
_EVIDENCE_REGEX = re.compile(
    r"^(?:diff|repo):(?P<path>[^#\s]+)#L(?P<start>\d+)(?:-L(?P<end>\d+))?$"
)

# Mapping from VCSProvider commit states to Azure DevOps status states
ADO_STATUS_STATE_MAP: dict[str, str] = {
    "success": "succeeded",
    "failed": "failed",
    "pending": "pending",
}

ADO_API_EXCEPTIONS = (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, KeyError)


class AzureDevOpsAdapter(VCSProvider):
    """VCSProvider adapter for Azure DevOps Repos and Azure Pipelines."""

    def __init__(
        self,
        collection_uri: str | None = None,
        project: str | None = None,
        repository_id: str | None = None,
        token: str | None = None,
        token_type: str | None = None,
        pr_id: str | int | None = None,
        repo_root: str | Path | None = None,
        api_version: str = "7.1",
        timeout: int = 30,
        stream: TextIO | None = None,
    ) -> None:
        raw_uri = (
            collection_uri
            or os.environ.get("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI")
            or os.environ.get("AZURE_DEVOPS_URL")
            or "https://dev.azure.com"
        )
        self.collection_uri = raw_uri.rstrip("/")
        self.project = project or os.environ.get("SYSTEM_TEAMPROJECT") or os.environ.get("AZURE_DEVOPS_PROJECT")
        self.repository_id = (
            repository_id
            or os.environ.get("BUILD_REPOSITORY_ID")
            or os.environ.get("BUILD_REPOSITORY_NAME")
            or os.environ.get("AZURE_DEVOPS_REPOSITORY")
        )
        self.pr_id = pr_id or os.environ.get("SYSTEM_PULLREQUEST_PULLREQUESTID")
        self.api_version = api_version
        self.repo_root = Path(repo_root) if repo_root is not None else Path.cwd()
        self.timeout = timeout
        self.stream = stream

        # Authentication resolution
        env_access_token = os.environ.get("SYSTEM_ACCESSTOKEN")
        env_pat = os.environ.get("AZURE_DEVOPS_EXT_PAT") or os.environ.get("AZURE_DEVOPS_TOKEN")
        if token is not None:
            self.token = token.strip()
            self.token_type = token_type or ("bearer" if self.token.startswith("eyJ") else "basic")
        elif env_access_token:
            self.token = env_access_token.strip()
            self.token_type = token_type or "bearer"
        elif env_pat:
            self.token = env_pat.strip()
            self.token_type = token_type or "basic"
        else:
            self.token = None
            self.token_type = None

        self._local_fallback = LocalGitAdapter(repo_root=self.repo_root, stream=self.stream)

    @property
    def encoded_project(self) -> str:
        """Returns the URL-encoded project name or identifier."""
        if not self.project:
            raise ValueError("Azure DevOps project is not set. Provide project or set SYSTEM_TEAMPROJECT.")
        return urllib.parse.quote(str(self.project), safe="")

    @property
    def encoded_repository(self) -> str:
        """Returns the URL-encoded repository name or identifier."""
        if not self.repository_id:
            raise ValueError(
                "Azure DevOps repository_id is not set. Provide repository_id or set BUILD_REPOSITORY_ID."
            )
        return urllib.parse.quote(str(self.repository_id), safe="")

    def _headers(self) -> dict[str, str]:
        """Constructs HTTP headers including authorization and user agent."""
        headers = {
            "User-Agent": f"OpenCloudAgents/{__version__}",
            "Accept": "application/json",
        }
        if self.token:
            if self.token_type == "bearer":
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                # Basic authentication with PAT (:token encoded in base64)
                auth_str = f":{self.token}"
                auth_b64 = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")
                headers["Authorization"] = f"Basic {auth_b64}"
        return headers

    def _build_repo_url(self, endpoint: str) -> str:
        """Constructs full repository-level REST endpoint URL."""
        path = endpoint.lstrip("/")
        return f"{self.collection_uri}/{self.encoded_project}/_apis/git/repositories/{self.encoded_repository}/{path}"

    def _api_request(
        self,
        endpoint: str,
        method: str = "GET",
        data: dict[str, Any] | list[Any] | None = None,
        params: dict[str, Any] | None = None,
        full_url: str | None = None,
    ) -> Any:
        """Executes an authenticated HTTP request against Azure DevOps REST 7.x API."""
        url = full_url if full_url else self._build_repo_url(endpoint)

        query_params = {"api-version": self.api_version}
        if params:
            query_params.update({k: v for k, v in params.items() if v is not None})
        encoded_query = urllib.parse.urlencode(query_params)
        url = f"{url}?{encoded_query}" if encoded_query else url

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
            raise RuntimeError(f"Azure DevOps API {method} {url} failed ({exc.code}): {err_body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Azure DevOps API {method} {url} connection failed: {exc.reason}") from exc

    def detect_context(self) -> bool:
        """Returns True if executing inside Azure Pipelines or against an Azure DevOps repository."""
        if os.environ.get("TF_BUILD", "").strip().lower() == "true":
            return True
        if os.environ.get("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"):
            return True
        detection = detect_forge(repo_root=self.repo_root)
        return detection.forge == Forge.AZURE_DEVOPS

    def get_diff(self, base_ref: str, head_ref: str) -> str:
        """Returns unified git diff between references, prioritizing local git execution."""
        return self._local_fallback.get_diff(base_ref, head_ref)

    def post_pr_summary(self, pr_id: str, summary_markdown: str) -> bool:
        """Publishes or updates the top-level review summary comment thread on the PR."""
        target_pr = pr_id or self.pr_id
        if not target_pr:
            raise ValueError("pr_id is required to post a review summary.")
        if not self.token or not self.project or not self.repository_id:
            return self._local_fallback.post_pr_summary(str(target_pr), summary_markdown)

        content_with_marker = f"{summary_markdown.rstrip()}\n\n{SUMMARY_MARKER}"

        # 1. Search existing threads for our summary marker to update in-place
        try:
            threads_resp = self._api_request(f"pullRequests/{target_pr}/threads")
            threads = threads_resp.get("value", []) if isinstance(threads_resp, dict) else []
            for thread in threads:
                comments = thread.get("comments", [])
                if comments and SUMMARY_MARKER in str(comments[0].get("content", "")):
                    thread_id = thread.get("id")
                    comment_id = comments[0].get("id")
                    if thread_id is not None and comment_id is not None:
                        self._api_request(
                            f"pullRequests/{target_pr}/threads/{thread_id}/comments/{comment_id}",
                            method="PATCH",
                            data={"content": content_with_marker},
                        )
                        return True
        except ADO_API_EXCEPTIONS as exc:
            logger.debug("Failed to list or update existing ADO PR thread: %s", exc)

        # 2. If no existing thread found, post a new top-level thread
        new_thread_payload = {
            "comments": [
                {
                    "parentCommentId": 0,
                    "content": content_with_marker,
                    "commentType": 1,  # 1 = Text comment
                }
            ],
            "status": 1,  # 1 = Active
        }
        self._api_request(
            f"pullRequests/{target_pr}/threads",
            method="POST",
            data=new_thread_payload,
        )
        return True

    def post_inline_annotations(self, pr_id: str, findings: list[dict[str, Any]]) -> int:
        """Publishes line-anchored thread comments on the changed files of the pull request."""
        target_pr = pr_id or self.pr_id
        if not target_pr:
            raise ValueError("pr_id is required to post inline annotations.")
        if not self.token or not self.project or not self.repository_id:
            return self._local_fallback.post_inline_annotations(str(target_pr), findings)

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

            # 1. Attempt anchored thread with threadContext if coordinates are present
            if match:
                raw_path = match.group("path").replace("\\", "/").strip("/")
                # Azure DevOps file paths in threadContext must start with a leading slash
                file_path = f"/{raw_path}"
                start_line = max(1, int(match.group("start")))
                end_str = match.group("end")
                end_line = max(start_line, int(end_str)) if end_str else start_line

                thread_payload = {
                    "comments": [
                        {
                            "parentCommentId": 0,
                            "content": comment_body,
                            "commentType": 1,
                        }
                    ],
                    "status": 1,
                    "threadContext": {
                        "filePath": file_path,
                        "rightFileStart": {"line": start_line, "offset": 1},
                        "rightFileEnd": {"line": end_line, "offset": 1},
                    },
                }
                try:
                    self._api_request(
                        f"pullRequests/{target_pr}/threads",
                        method="POST",
                        data=thread_payload,
                    )
                    posted_count += 1
                    continue
                except ADO_API_EXCEPTIONS as exc:
                    logger.debug("Line-anchored ADO thread failed, attempting general comment: %s", exc)

            # 2. General comment thread fallback
            general_payload = {
                "comments": [
                    {
                        "parentCommentId": 0,
                        "content": comment_body,
                        "commentType": 1,
                    }
                ],
                "status": 1,
            }
            try:
                self._api_request(
                    f"pullRequests/{target_pr}/threads",
                    method="POST",
                    data=general_payload,
                )
                posted_count += 1
            except ADO_API_EXCEPTIONS as exc:
                logger.debug("Failed to post general ADO PR thread: %s", exc)

        return posted_count

    def set_commit_status(
        self,
        sha: str,
        state: str,
        description: str,
        context: str = DEFAULT_STATUS_CONTEXT,
        target_url: str | None = None,
    ) -> bool:
        """Sets Azure DevOps PR status policy check or commit status."""
        if state not in VALID_COMMIT_STATES:
            raise ValueError(f"state must be one of {', '.join(VALID_COMMIT_STATES)}; got {state!r}")

        if not self.token or not self.project or not self.repository_id:
            return self._local_fallback.set_commit_status(sha, state, description, context, target_url)

        ado_state = ADO_STATUS_STATE_MAP.get(state, "pending")
        payload: dict[str, Any] = {
            "state": ado_state,
            "description": description[:1000] if description else "",
            "context": {
                "name": context,
                "genre": "open-cloud-agents",
            },
        }
        if target_url:
            payload["targetUrl"] = target_url

        # 1. If pull request ID is active, publish directly to Pull Request Statuses API
        if self.pr_id:
            try:
                self._api_request(
                    f"pullRequests/{self.pr_id}/statuses",
                    method="POST",
                    data=payload,
                )
                return True
            except ADO_API_EXCEPTIONS as exc:
                logger.debug("Failed to set PR status check, falling back to commit status: %s", exc)

        # 2. Commit Statuses API fallback
        try:
            self._api_request(
                f"commits/{sha}/statuses",
                method="POST",
                data=payload,
            )
            return True
        except ADO_API_EXCEPTIONS as exc:
            raise RuntimeError(f"Failed to set Azure DevOps status for {sha[:8]}: {exc}") from exc

    def export_native_artifacts(self, findings: list[dict[str, Any]], output_dir: Path) -> list[Path]:
        """Generates and writes ocagents.sarif log for Azure DevOps SARIF extension."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = out_dir / ADO_ARTIFACT_NAME
        content = findings_to_sarif_json(findings)
        artifact_path.write_text(content, encoding="utf-8")
        return [artifact_path]
