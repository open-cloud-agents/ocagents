"""
Open Cloud Agents: Bitbucket Cloud & Data Center Adapter (ADR-003, Phase 4).

Implements the VCSProvider interface for Bitbucket Cloud and Bitbucket Data Center
using the Bitbucket REST API 2.0.
Supports authentication with BITBUCKET_TOKEN or repository app passwords, PR diff
fetching, Code Insights Reports, Code Insights Annotations batching, pull request
comment threading, commit build statuses, and native artifact generation.
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

BB_REPORT_KEY = "open-cloud-agents"
BB_ARTIFACT_NAME = "bitbucket-code-insights.json"
SUMMARY_MARKER = "<!-- ocagents-review-summary -->"
MAX_ANNOTATIONS_PER_BATCH = 100

_EVIDENCE_REGEX = re.compile(
    r"^(?:diff|repo):(?P<path>[^#\s]+)#L(?P<start>\d+)(?:-L(?P<end>\d+))?$"
)

# Mapping from VCSProvider commit states to Bitbucket commit status states
BB_STATUS_STATE_MAP: dict[str, str] = {
    "success": "SUCCESSFUL",
    "failed": "FAILED",
    "pending": "INPROGRESS",
}

# Mapping from canonical finding severities to Bitbucket Code Insights severities
BB_SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "LOW",
}

# Mapping finding category to Bitbucket annotation type
BB_ANNOTATION_TYPE_MAP: dict[str, str] = {
    "security": "VULNERABILITY",
    "architecture": "BUG",
    "reliability": "BUG",
    "cost": "CODE_SMELL",
    "hygiene": "CODE_SMELL",
}

BITBUCKET_API_EXCEPTIONS = (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, KeyError)


def findings_to_bitbucket_insights(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Transforms canonical finding documents into Bitbucket Code Insights report structure."""
    total = len(findings)
    critical = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
    high = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    medium = sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium")
    has_blocking = (critical + high) > 0

    return {
        "report": {
            "title": "Open Cloud Agents Governance Gate",
            "details": f"Autonomous review completed: {total} finding(s) detected ({critical} critical, {high} high).",
            "report_type": "SECURITY",
            "reporter": "Open Cloud Agents",
            "result": "FAILED" if has_blocking else "PASSED",
            "data": [
                {"title": "Total Findings", "type": "NUMBER", "value": total},
                {"title": "Critical (P0)", "type": "NUMBER", "value": critical},
                {"title": "High (P1)", "type": "NUMBER", "value": high},
                {"title": "Medium (P2)", "type": "NUMBER", "value": medium},
            ],
        },
        "findings": findings,
    }


def findings_to_bitbucket_insights_json(findings: list[dict[str, Any]], indent: int = 2) -> str:
    """Serializes findings as formatted Bitbucket Code Insights JSON."""
    return json.dumps(findings_to_bitbucket_insights(findings), indent=indent, ensure_ascii=False)


class BitbucketAdapter(VCSProvider):
    """VCSProvider adapter for Bitbucket Cloud and Bitbucket Data Center."""

    def __init__(
        self,
        base_url: str | None = None,
        workspace: str | None = None,
        repo_slug: str | None = None,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        pr_id: str | int | None = None,
        commit_sha: str | None = None,
        repo_root: str | Path | None = None,
        timeout: int = 30,
        stream: TextIO | None = None,
    ) -> None:
        raw_url = (
            base_url
            or os.environ.get("BITBUCKET_API_URL")
            or os.environ.get("BITBUCKET_URL")
            or "https://api.bitbucket.org/2.0"
        )
        self.base_url = raw_url.rstrip("/")
        self.workspace = workspace or os.environ.get("BITBUCKET_WORKSPACE")
        self.repo_slug = repo_slug or os.environ.get("BITBUCKET_REPO_SLUG")
        self.pr_id = pr_id or os.environ.get("BITBUCKET_PR_ID")
        self.commit_sha = commit_sha or os.environ.get("BITBUCKET_COMMIT")
        self.repo_root = Path(repo_root) if repo_root is not None else Path.cwd()
        self.timeout = timeout
        self.stream = stream

        # Authentication resolution
        env_token = os.environ.get("BITBUCKET_TOKEN")
        env_user = username or os.environ.get("BITBUCKET_USER") or os.environ.get("BITBUCKET_USERNAME")
        env_pass = (
            password
            or os.environ.get("BITBUCKET_APP_PASSWORD")
            or os.environ.get("BITBUCKET_PASSWORD")
        )

        if token:
            self.token = token.strip()
            self.auth_type = "bearer"
        elif env_token:
            self.token = env_token.strip()
            self.auth_type = "bearer"
        elif env_user and env_pass:
            auth_str = f"{env_user}:{env_pass}"
            self.token = base64.b64encode(auth_str.encode("utf-8")).decode("ascii")
            self.auth_type = "basic"
        else:
            self.token = None
            self.auth_type = None

        self._local_fallback = LocalGitAdapter(repo_root=self.repo_root, stream=self.stream)

    @property
    def encoded_workspace(self) -> str:
        """Returns the URL-encoded workspace slug."""
        if not self.workspace:
            raise ValueError("Bitbucket workspace is not set. Provide workspace or set BITBUCKET_WORKSPACE.")
        return urllib.parse.quote(str(self.workspace), safe="")

    @property
    def encoded_repo_slug(self) -> str:
        """Returns the URL-encoded repository slug."""
        if not self.repo_slug:
            raise ValueError("Bitbucket repo_slug is not set. Provide repo_slug or set BITBUCKET_REPO_SLUG.")
        return urllib.parse.quote(str(self.repo_slug), safe="")

    def _headers(self) -> dict[str, str]:
        """Constructs HTTP headers including authorization and user agent."""
        headers = {
            "User-Agent": f"OpenCloudAgents/{__version__}",
            "Accept": "application/json",
        }
        if self.token:
            if self.auth_type == "bearer":
                headers["Authorization"] = f"Bearer {self.token}"
            elif self.auth_type == "basic":
                headers["Authorization"] = f"Basic {self.token}"
        return headers

    def _build_repo_url(self, endpoint: str) -> str:
        """Constructs full repository-scoped Bitbucket REST 2.0 URL."""
        path = endpoint.lstrip("/")
        return f"{self.base_url}/repositories/{self.encoded_workspace}/{self.encoded_repo_slug}/{path}"

    def _api_request(
        self,
        endpoint: str,
        method: str = "GET",
        data: dict[str, Any] | list[Any] | None = None,
        params: dict[str, Any] | None = None,
        accept: str = "application/json",
    ) -> Any:
        """Executes an authenticated HTTP request against Bitbucket REST 2.0 API."""
        url = self._build_repo_url(endpoint)
        if params:
            query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
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
            raise RuntimeError(f"Bitbucket API {method} {url} failed ({exc.code}): {err_body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Bitbucket API {method} {url} connection failed: {exc.reason}") from exc

    def detect_context(self) -> bool:
        """Returns True if running in Bitbucket Pipelines or against a Bitbucket repository."""
        if os.environ.get("BITBUCKET_BUILD_NUMBER"):
            return True
        if os.environ.get("BITBUCKET_WORKSPACE") and os.environ.get("BITBUCKET_REPO_SLUG"):
            return True
        detection = detect_forge(repo_root=self.repo_root)
        return detection.forge == Forge.BITBUCKET

    def get_diff(self, base_ref: str, head_ref: str) -> str:
        """Retrieves raw unified git diff from Bitbucket PR diff API, falling back to local git."""
        if self.pr_id and self.workspace and self.repo_slug and self.token:
            try:
                diff_text = self._api_request(
                    f"pullrequests/{self.pr_id}/diff",
                    accept="text/plain",
                )
                if isinstance(diff_text, str) and diff_text.strip():
                    return diff_text
            except BITBUCKET_API_EXCEPTIONS as exc:
                logger.debug("Failed to fetch PR diff from Bitbucket API: %s", exc)

        return self._local_fallback.get_diff(base_ref, head_ref)

    def post_pr_summary(self, pr_id: str, summary_markdown: str) -> bool:
        """Publishes or updates the high-level review summary comment on the Bitbucket PR."""
        target_pr = pr_id or self.pr_id
        if not target_pr:
            raise ValueError("pr_id is required to post a review summary.")
        if not self.token or not self.workspace or not self.repo_slug:
            return self._local_fallback.post_pr_summary(str(target_pr), summary_markdown)

        content_with_marker = f"{summary_markdown.rstrip()}\n\n{SUMMARY_MARKER}"

        # 1. Search existing comments for summary marker to update in place
        try:
            resp = self._api_request(f"pullrequests/{target_pr}/comments")
            comments = resp.get("values", []) if isinstance(resp, dict) else []
            for comment in comments:
                raw_text = comment.get("content", {}).get("raw", "")
                if SUMMARY_MARKER in raw_text:
                    comment_id = comment.get("id")
                    if comment_id is not None:
                        self._api_request(
                            f"pullrequests/{target_pr}/comments/{comment_id}",
                            method="PUT",
                            data={"content": {"raw": content_with_marker}},
                        )
                        return True
        except BITBUCKET_API_EXCEPTIONS as exc:
            logger.debug("Failed to search/update existing Bitbucket PR comment: %s", exc)

        # 2. Post new top-level comment
        payload = {"content": {"raw": content_with_marker}}
        self._api_request(
            f"pullrequests/{target_pr}/comments",
            method="POST",
            data=payload,
        )
        return True

    def _create_code_insights_report(
        self,
        commit: str,
        findings: list[dict[str, Any]],
    ) -> bool:
        """Creates or updates the Bitbucket Code Insights Report for the target commit."""
        total = len(findings)
        critical = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
        high = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
        medium = sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium")

        has_blocking = (critical + high) > 0
        result = "FAILED" if has_blocking else "PASSED"

        report_payload = {
            "title": "Open Cloud Agents Governance Gate",
            "details": f"Autonomous review completed: {total} finding(s) detected ({critical} critical, {high} high).",
            "report_type": "SECURITY",
            "reporter": "Open Cloud Agents",
            "result": result,
            "data": [
                {"title": "Total Findings", "type": "NUMBER", "value": total},
                {"title": "Critical (P0)", "type": "NUMBER", "value": critical},
                {"title": "High (P1)", "type": "NUMBER", "value": high},
                {"title": "Medium (P2)", "type": "NUMBER", "value": medium},
            ],
        }

        try:
            self._api_request(
                f"commit/{commit}/reports/{BB_REPORT_KEY}",
                method="PUT",
                data=report_payload,
            )
            return True
        except BITBUCKET_API_EXCEPTIONS as exc:
            logger.debug("Failed to create Bitbucket Code Insights report: %s", exc)
            return False

    def _post_code_insights_annotations(
        self,
        commit: str,
        findings: list[dict[str, Any]],
    ) -> int:
        """Batch-posts line-level annotations to the Bitbucket Code Insights Report."""
        annotations: list[dict[str, Any]] = []

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if finding.get("corroboration_status") == "rejected_false_positive":
                continue

            evidence = str(finding.get("evidence") or "").strip()
            match = _EVIDENCE_REGEX.match(evidence)

            severity = str(finding.get("severity") or "info").lower()
            bb_severity = BB_SEVERITY_MAP.get(severity, "LOW")
            category = str(finding.get("category") or "hygiene").lower()
            anno_type = BB_ANNOTATION_TYPE_MAP.get(category, "CODE_SMELL")

            fid = finding.get("id", "FND-UNKNOWN")
            fact = finding.get("fact") or finding.get("title") or "Code defect identified."
            rule_id = finding.get("rule_id", "rules/unknown.md")
            path = match.group("path") if match else (finding.get("resource") or "unknown")
            line = int(match.group("start")) if match else 1

            summary_text = f"[{severity.upper()}] {fact}"
            recommendation = finding.get("recommendation")
            if recommendation:
                summary_text += f" Remediation: {recommendation}"
            summary_text = summary_text[:450]

            annotations.append(
                {
                    "external_id": fid,
                    "title": f"[{severity.upper()}] {rule_id}"[:255],
                    "annotation_type": anno_type,
                    "summary": summary_text,
                    "severity": bb_severity,
                    "path": path.replace("\\", "/").strip("/"),
                    "line": max(1, line),
                }
            )

        if not annotations:
            return 0

        posted_count = 0
        # Batch in chunks of up to 100 annotations as required by Bitbucket Code Insights API
        for i in range(0, len(annotations), MAX_ANNOTATIONS_PER_BATCH):
            batch = annotations[i : i + MAX_ANNOTATIONS_PER_BATCH]
            try:
                self._api_request(
                    f"commit/{commit}/reports/{BB_REPORT_KEY}/annotations",
                    method="POST",
                    data=batch,
                )
                posted_count += len(batch)
            except BITBUCKET_API_EXCEPTIONS as exc:
                logger.debug("Failed to post Bitbucket Code Insights annotations batch: %s", exc)

        return posted_count

    def post_inline_annotations(self, pr_id: str, findings: list[dict[str, Any]]) -> int:
        """Publishes Code Insights annotations and inline PR comments."""
        target_pr = pr_id or self.pr_id
        if not target_pr:
            raise ValueError("pr_id is required to post inline annotations.")
        if not self.token or not self.workspace or not self.repo_slug:
            return self._local_fallback.post_inline_annotations(str(target_pr), findings)

        target_commit = self.commit_sha
        if not target_commit:
            try:
                pr_info = self._api_request(f"pullrequests/{target_pr}")
                target_commit = pr_info.get("source", {}).get("commit", {}).get("hash")
            except BITBUCKET_API_EXCEPTIONS as exc:
                logger.debug("Failed to resolve PR source commit hash: %s", exc)

        count = 0
        # 1. Publish Code Insights Report & Annotations if commit hash is available
        if target_commit:
            self._create_code_insights_report(target_commit, findings)
            count = self._post_code_insights_annotations(target_commit, findings)

        # 2. If no annotations posted via Insights, post as inline PR comments
        if count == 0:
            for finding in findings or []:
                if not isinstance(finding, dict):
                    continue
                evidence = str(finding.get("evidence") or "").strip()
                match = _EVIDENCE_REGEX.match(evidence)
                severity = str(finding.get("severity") or "info").upper()
                fact = finding.get("fact") or "Code defect identified."
                fid = finding.get("id", "FND-UNKNOWN")
                rule_id = finding.get("rule_id", "rules/unknown.md")

                comment_text = f"### 🛡️ Open Cloud Agents: [{severity}]\n**Rule:** `{rule_id}` ({fid})\n**Finding:** {fact}"
                payload: dict[str, Any] = {"content": {"raw": comment_text}}
                if match:
                    payload["inline"] = {
                        "to": int(match.group("start")),
                        "path": match.group("path").replace("\\", "/").strip("/"),
                    }
                try:
                    self._api_request(
                        f"pullrequests/{target_pr}/comments",
                        method="POST",
                        data=payload,
                    )
                    count += 1
                except BITBUCKET_API_EXCEPTIONS as exc:
                    logger.debug("Failed to post inline PR comment to Bitbucket: %s", exc)

        return count

    def set_commit_status(
        self,
        sha: str,
        state: str,
        description: str,
        context: str = DEFAULT_STATUS_CONTEXT,
        target_url: str | None = None,
    ) -> bool:
        """Sets the Bitbucket commit build status."""
        if state not in VALID_COMMIT_STATES:
            raise ValueError(f"state must be one of {', '.join(VALID_COMMIT_STATES)}; got {state!r}")

        if not self.token or not self.workspace or not self.repo_slug:
            return self._local_fallback.set_commit_status(sha, state, description, context, target_url)

        bb_state = BB_STATUS_STATE_MAP.get(state, "INPROGRESS")
        payload: dict[str, Any] = {
            "state": bb_state,
            "key": context,
            "name": context,
            "description": description[:255] if description else "",
        }
        if target_url:
            payload["url"] = target_url

        try:
            self._api_request(
                f"commit/{sha}/statuses/build",
                method="POST",
                data=payload,
            )
            return True
        except BITBUCKET_API_EXCEPTIONS as exc:
            raise RuntimeError(f"Failed to set Bitbucket build status for {sha[:8]}: {exc}") from exc

    def export_native_artifacts(self, findings: list[dict[str, Any]], output_dir: Path) -> list[Path]:
        """Generates native Bitbucket Code Insights JSON and SARIF reports."""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        insights_path = out_dir / BB_ARTIFACT_NAME
        insights_path.write_text(findings_to_bitbucket_insights_json(findings) + "\n", encoding="utf-8")

        # Also write SARIF 2.1.0 log
        sarif_path = out_dir / "ocagents.sarif"
        sarif_path.write_text(findings_to_sarif_json(findings), encoding="utf-8")

        return [insights_path, sarif_path]
