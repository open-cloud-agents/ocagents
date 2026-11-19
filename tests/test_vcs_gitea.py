"""
Unit tests for Open Cloud Agents: Gitea & Forgejo Air-Gapped Adapter (ADR-003, Issue #110).
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ocagents.vcs import (
    GT_ARTIFACT_NAME,
    Forge,
    GiteaAdapter,
    VCSProvider,
    findings_to_gitea_quality,
    findings_to_gitea_quality_json,
    get_vcs_adapter,
)
from ocagents.vcs.gitea import GT_STATUS_STATE_MAP, SUMMARY_MARKER


def _sample_finding(**kwargs) -> dict:
    base = {
        "$schema": "https://open-cloud-agents.github.io/schemas/v1/finding.json",
        "id": "FND-D4E5F6A1B2C3",
        "agent": "security-compliance-commander",
        "origin": "deterministic_linter",
        "rule_id": "rules/02-secrets-and-identity.md#IAM002",
        "category": "security",
        "resource": "aws_iam_role.workload",
        "fact": "Overly permissive wildcard action 'sts:AssumeRole' without external ID condition.",
        "evidence": "diff:terraform/iam.tf#L12-L16",
        "recommendation": "Restrict AssumeRole trust policy with specific Principal ARN and condition.",
        "severity": "critical",
        "confidence": None,
        "corroboration_status": "tool_verified",
    }
    base.update(kwargs)
    return base


class TestGiteaAdapterConfiguration(unittest.TestCase):
    """Verifies GiteaAdapter initialization, base URL normalization, credentials, and owner/repo parsing."""

    def test_is_vcs_provider(self):
        adapter = GiteaAdapter()
        self.assertIsInstance(adapter, VCSProvider)

    def test_base_url_normalization(self):
        # 1. Default base URL
        a1 = GiteaAdapter()
        self.assertEqual(a1.base_url, "https://gitea.com/api/v1")

        # 2. Appends /api/v1 if missing
        a2 = GiteaAdapter(base_url="https://gitea.corp.internal/")
        self.assertEqual(a2.base_url, "https://gitea.corp.internal/api/v1")

        # 3. Preserves existing /api/v1
        a3 = GiteaAdapter(base_url="https://forgejo.sovereign.cloud/api/v1")
        self.assertEqual(a3.base_url, "https://forgejo.sovereign.cloud/api/v1")

        # 4. Ingests GITEA_SERVER_URL from environment
        with mock.patch.dict("os.environ", {"GITEA_SERVER_URL": "https://git.internal"}):
            a4 = GiteaAdapter()
            self.assertEqual(a4.base_url, "https://git.internal/api/v1")

    def test_authentication_token(self):
        # 1. GITEA_TOKEN
        with mock.patch.dict("os.environ", {"GITEA_TOKEN": "oauth-token-xyz"}, clear=True):
            adapter = GiteaAdapter()
            headers = adapter._headers()
            self.assertEqual(headers["Authorization"], "token oauth-token-xyz")

        # 2. FORGEJO_TOKEN
        with mock.patch.dict("os.environ", {"FORGEJO_TOKEN": "oauth-token-abc"}, clear=True):
            adapter = GiteaAdapter()
            headers = adapter._headers()
            self.assertEqual(headers["Authorization"], "token oauth-token-abc")

    def test_owner_and_repo_parsing(self):
        # From GITHUB_REPOSITORY (in Gitea Actions)
        with mock.patch.dict("os.environ", {"GITHUB_REPOSITORY": "cloud-sec/infra"}):
            adapter = GiteaAdapter()
            self.assertEqual(adapter.owner, "cloud-sec")
            self.assertEqual(adapter.repo, "infra")
            self.assertEqual(adapter.encoded_owner, "cloud-sec")
            self.assertEqual(adapter.encoded_repo, "infra")

        # From explicit parameters with URL encoding
        adapter_custom = GiteaAdapter(owner="Dev Sec Ops", repo="Core Repo/Sub")
        self.assertEqual(adapter_custom.encoded_owner, "Dev%20Sec%20Ops")
        self.assertEqual(adapter_custom.encoded_repo, "Core%20Repo%2FSub")

    def test_offline_mode_flag(self):
        # Explicit parameter
        a1 = GiteaAdapter(offline=True)
        self.assertTrue(a1.offline)

        # Environment variable
        with mock.patch.dict("os.environ", {"OCAGENTS_OFFLINE": "true"}):
            a2 = GiteaAdapter()
            self.assertTrue(a2.offline)


class TestGiteaAdapterDetection(unittest.TestCase):
    """Verifies detect_context under Gitea Actions, Forgejo, and local environments."""

    def test_detect_context_under_gitea_actions(self):
        with mock.patch.dict("os.environ", {"GITEA_ACTIONS": "true"}):
            self.assertTrue(GiteaAdapter().detect_context())

    def test_detect_context_under_forgejo_actions(self):
        with mock.patch.dict("os.environ", {"FORGEJO_ACTIONS": "true"}):
            self.assertTrue(GiteaAdapter().detect_context())

    def test_detect_context_via_server_url(self):
        with mock.patch.dict("os.environ", {"GITEA_SERVER_URL": "https://gitea.local"}):
            self.assertTrue(GiteaAdapter().detect_context())

    def test_detect_context_via_token(self):
        with mock.patch.dict("os.environ", {"GITEA_TOKEN": "token-abc"}):
            self.assertTrue(GiteaAdapter().detect_context())

    def test_detect_context_negative_outside_gitea(self):
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch("ocagents.vcs.gitea.detect_forge") as mock_detect,
        ):
            mock_detect.return_value = mock.MagicMock(forge=Forge.LOCAL)
            self.assertFalse(GiteaAdapter().detect_context())


class TestGiteaAdapterOperations(unittest.TestCase):
    """Verifies PR diffs, review summary comments, line annotations, commit statuses, and artifacts."""

    def setUp(self):
        self.out = io.StringIO()
        self.adapter = GiteaAdapter(
            base_url="https://gitea.example.com",
            owner="my-org",
            repo="cloud-deploy",
            token="test-gitea-token",
            pr_id=12,
            commit_sha="e" * 40,
            stream=self.out,
        )

    def test_get_diff_via_api(self):
        mock_diff = "diff --git a/infra.tf b/infra.tf\n--- a/infra.tf\n+++ b/infra.tf\n"
        with mock.patch.object(self.adapter, "_api_request", return_value=mock_diff) as mock_req:
            diff = self.adapter.get_diff("main", "feature")
            self.assertEqual(diff, mock_diff)
            mock_req.assert_called_once_with("pulls/12.diff", accept="text/plain")

    def test_get_diff_offline_fallback(self):
        adapter = GiteaAdapter(owner="org", repo="repo", offline=True)
        with mock.patch.object(adapter._local_fallback, "get_diff", return_value="local diff") as mock_local:
            diff = adapter.get_diff("main", "feature")
            self.assertEqual(diff, "local diff")
            mock_local.assert_called_once_with("main", "feature")

    def test_post_pr_summary_creates_new_comment(self):
        with mock.patch.object(self.adapter, "_api_request") as mock_req:
            # 1. Search existing comments (empty list), 2. Post new comment
            mock_req.side_effect = [[], {"id": 201}]
            success = self.adapter.post_pr_summary("12", "## Review Summary\nAll clean.")
            self.assertTrue(success)
            self.assertEqual(mock_req.call_count, 2)

            post_call = mock_req.call_args_list[1]
            self.assertEqual(post_call[0][0], "issues/12/comments")
            self.assertEqual(post_call[1]["method"], "POST")
            comment_body = post_call[1]["data"]["body"]
            self.assertIn("## Review Summary", comment_body)
            self.assertIn(SUMMARY_MARKER, comment_body)

    def test_post_pr_summary_updates_existing_comment(self):
        existing_comments = [
            {
                "id": 505,
                "body": f"Old review\n\n{SUMMARY_MARKER}",
            }
        ]
        with mock.patch.object(self.adapter, "_api_request") as mock_req:
            mock_req.side_effect = [existing_comments, {"id": 505}]
            success = self.adapter.post_pr_summary("12", "## Updated Review")
            self.assertTrue(success)
            self.assertEqual(mock_req.call_count, 2)

            patch_call = mock_req.call_args_list[1]
            self.assertEqual(patch_call[0][0], "issues/comments/505")
            self.assertEqual(patch_call[1]["method"], "PATCH")
            self.assertIn("## Updated Review", patch_call[1]["data"]["body"])

    def test_post_inline_annotations_via_pr_review(self):
        findings = [_sample_finding()]
        with mock.patch.object(self.adapter, "_api_request", return_value={"id": 801}) as mock_req:
            posted = self.adapter.post_inline_annotations("12", findings)
            self.assertEqual(posted, 1)

            mock_req.assert_called_once()
            endpoint = mock_req.call_args[0][0]
            self.assertEqual(endpoint, "pulls/12/reviews")
            data = mock_req.call_args[1]["data"]
            self.assertEqual(data["event"], "COMMENT")
            comments = data["comments"]
            self.assertEqual(len(comments), 1)
            self.assertEqual(comments[0]["path"], "terraform/iam.tf")
            self.assertEqual(comments[0]["new_position"], 12)
            self.assertIn("[CRITICAL]", comments[0]["body"])

    def test_post_inline_annotations_fallback_individual_comments(self):
        findings = [_sample_finding()]
        with mock.patch.object(self.adapter, "_api_request") as mock_req:
            # 1. Consolidated review fails, 2. Individual comment succeeds
            mock_req.side_effect = [
                RuntimeError("Reviews endpoint not supported on this version"),
                {"id": 901},
            ]
            posted = self.adapter.post_inline_annotations("12", findings)
            self.assertEqual(posted, 1)
            self.assertEqual(mock_req.call_count, 2)

            post_call = mock_req.call_args_list[1]
            self.assertEqual(post_call[0][0], "pulls/12/comments")
            self.assertEqual(post_call[1]["data"]["path"], "terraform/iam.tf")

    def test_set_commit_status_state_mapping(self):
        for oca_state, gt_state in GT_STATUS_STATE_MAP.items():
            with (
                self.subTest(oca_state=oca_state),
                mock.patch.object(self.adapter, "_api_request", return_value={}) as mock_req,
            ):
                self.adapter.set_commit_status("e" * 40, oca_state, "Quality gate check")
                endpoint = mock_req.call_args[0][0]
                self.assertEqual(endpoint, f"statuses/{'e'*40}")
                payload = mock_req.call_args[1]["data"]
                self.assertEqual(payload["state"], gt_state)

    def test_set_commit_status_rejects_invalid_state(self):
        with self.assertRaises(ValueError):
            self.adapter.set_commit_status("abc", "unrecognized", "desc")

    def test_export_native_artifacts(self):
        findings = [_sample_finding()]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "reports"
            artifacts = self.adapter.export_native_artifacts(findings, out_dir)
            self.assertEqual(len(artifacts), 2)

            report_file, sarif_file = artifacts[0], artifacts[1]
            self.assertEqual(report_file.name, GT_ARTIFACT_NAME)
            self.assertEqual(sarif_file.name, "ocagents.sarif")
            self.assertTrue(report_file.exists())
            self.assertTrue(sarif_file.exists())

            report_data = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(report_data["status"], "failure")  # critical -> failure
            self.assertEqual(report_data["summary"]["critical"], 1)


class TestGiteaFormattingHelpers(unittest.TestCase):
    """Verifies findings_to_gitea_quality transformation helpers."""

    def test_findings_to_gitea_quality(self):
        findings = [
            _sample_finding(severity="critical"),
            _sample_finding(severity="low"),
        ]
        result = findings_to_gitea_quality(findings)
        self.assertEqual(result["status"], "failure")
        self.assertEqual(result["summary"]["total_findings"], 2)
        self.assertEqual(result["summary"]["critical"], 1)
        self.assertEqual(result["summary"]["low"], 1)

        json_str = findings_to_gitea_quality_json(findings)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["status"], "failure")


class TestVCSAdapterFactoryGitea(unittest.TestCase):
    """Verifies get_vcs_adapter factory resolution for Gitea and Forgejo."""

    def test_factory_returns_gitea_adapter(self):
        for variant in (Forge.GITEA, "gitea", "forgejo", "codeberg"):
            with self.subTest(variant=variant):
                adapter = get_vcs_adapter(forge=variant)
                self.assertIsInstance(adapter, GiteaAdapter)


if __name__ == "__main__":
    unittest.main()
