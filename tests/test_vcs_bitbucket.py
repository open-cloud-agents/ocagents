"""
Unit tests for Open Cloud Agents: Bitbucket Cloud & Data Center Adapter (ADR-003, Issue #109).
"""

from __future__ import annotations

import base64
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ocagents.vcs import (
    BB_ARTIFACT_NAME,
    BitbucketAdapter,
    Forge,
    VCSProvider,
    findings_to_bitbucket_insights,
    findings_to_bitbucket_insights_json,
    get_vcs_adapter,
)
from ocagents.vcs.bitbucket import (
    BB_REPORT_KEY,
    BB_STATUS_STATE_MAP,
    MAX_ANNOTATIONS_PER_BATCH,
    SUMMARY_MARKER,
)


def _sample_finding(**kwargs) -> dict:
    base = {
        "$schema": "https://open-cloud-agents.github.io/schemas/v1/finding.json",
        "id": "FND-C3D4E5F6A1B2",
        "agent": "security-compliance-commander",
        "origin": "deterministic_linter",
        "rule_id": "rules/02-secrets-and-identity.md#S3001",
        "category": "security",
        "resource": "aws_s3_bucket.data",
        "fact": "S3 bucket encryption not enforced via KMS envelope key.",
        "evidence": "diff:terraform/storage.tf#L18-L22",
        "recommendation": "Configure server_side_encryption_configuration with aws:kms.",
        "severity": "high",
        "confidence": None,
        "corroboration_status": "tool_verified",
    }
    base.update(kwargs)
    return base


class TestBitbucketAdapterConfiguration(unittest.TestCase):
    """Verifies BitbucketAdapter initialization, credentials, and URL encoding."""

    def test_is_vcs_provider(self):
        adapter = BitbucketAdapter()
        self.assertIsInstance(adapter, VCSProvider)

    def test_base_url_normalization(self):
        a1 = BitbucketAdapter(base_url="https://api.bitbucket.org/2.0/")
        self.assertEqual(a1.base_url, "https://api.bitbucket.org/2.0")

        with mock.patch.dict("os.environ", {"BITBUCKET_API_URL": "https://bitbucket.corp.internal/rest/api/2.0/"}):
            a2 = BitbucketAdapter()
            self.assertEqual(a2.base_url, "https://bitbucket.corp.internal/rest/api/2.0")

    def test_authentication_bearer_token(self):
        with mock.patch.dict("os.environ", {"BITBUCKET_TOKEN": "oauth-token-xyz"}, clear=True):
            adapter = BitbucketAdapter()
            headers = adapter._headers()
            self.assertEqual(headers["Authorization"], "Bearer oauth-token-xyz")
            self.assertEqual(adapter.auth_type, "bearer")

    def test_authentication_basic_app_password(self):
        with mock.patch.dict(
            "os.environ",
            {
                "BITBUCKET_USER": "my-user",
                "BITBUCKET_APP_PASSWORD": "my-app-password-123",
            },
            clear=True,
        ):
            adapter = BitbucketAdapter()
            headers = adapter._headers()
            self.assertEqual(adapter.auth_type, "basic")
            self.assertTrue(headers["Authorization"].startswith("Basic "))
            decoded = base64.b64decode(headers["Authorization"].split(" ")[1]).decode("utf-8")
            self.assertEqual(decoded, "my-user:my-app-password-123")

    def test_workspace_and_repo_slug_url_encoding(self):
        adapter = BitbucketAdapter(
            workspace="Cloud Engineering",
            repo_slug="core infra/repo",
        )
        self.assertEqual(adapter.encoded_workspace, "Cloud%20Engineering")
        self.assertEqual(adapter.encoded_repo_slug, "core%20infra%2Frepo")

    def test_missing_workspace_raises(self):
        adapter = BitbucketAdapter(workspace=None, repo_slug="repo")
        with self.assertRaises(ValueError):
            _ = adapter.encoded_workspace

    def test_missing_repo_slug_raises(self):
        adapter = BitbucketAdapter(workspace="ws", repo_slug=None)
        with self.assertRaises(ValueError):
            _ = adapter.encoded_repo_slug


class TestBitbucketAdapterDetection(unittest.TestCase):
    """Verifies detect_context under Bitbucket Pipelines and local environments."""

    def test_detect_context_under_bitbucket_pipelines(self):
        with mock.patch.dict("os.environ", {"BITBUCKET_BUILD_NUMBER": "42"}):
            self.assertTrue(BitbucketAdapter().detect_context())

    def test_detect_context_via_workspace_and_slug(self):
        with mock.patch.dict("os.environ", {"BITBUCKET_WORKSPACE": "acme", "BITBUCKET_REPO_SLUG": "cloud"}):
            self.assertTrue(BitbucketAdapter().detect_context())

    def test_detect_context_negative_outside_bitbucket(self):
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch("ocagents.vcs.bitbucket.detect_forge") as mock_detect,
        ):
            mock_detect.return_value = mock.MagicMock(forge=Forge.LOCAL)
            self.assertFalse(BitbucketAdapter().detect_context())


class TestBitbucketAdapterOperations(unittest.TestCase):
    """Verifies PR diffs, review summary comments, Code Insights reports, annotations batching, and statuses."""

    def setUp(self):
        self.out = io.StringIO()
        self.adapter = BitbucketAdapter(
            workspace="acme-corp",
            repo_slug="cloud-infra",
            token="test-token",
            pr_id=45,
            commit_sha="c" * 40,
            stream=self.out,
        )

    def test_get_diff_via_api(self):
        mock_diff = "diff --git a/main.tf b/main.tf\n--- a/main.tf\n+++ b/main.tf\n"
        with mock.patch.object(self.adapter, "_api_request", return_value=mock_diff) as mock_req:
            diff = self.adapter.get_diff("main", "feature")
            self.assertEqual(diff, mock_diff)
            mock_req.assert_called_once_with("pullrequests/45/diff", accept="text/plain")

    def test_get_diff_fallback_to_local(self):
        # When token is missing, falls back to local git
        adapter = BitbucketAdapter(workspace="acme", repo_slug="repo", token=None)
        with mock.patch.object(adapter._local_fallback, "get_diff", return_value="local diff") as mock_local:
            diff = adapter.get_diff("main", "feature")
            self.assertEqual(diff, "local diff")
            mock_local.assert_called_once_with("main", "feature")

    def test_post_pr_summary_creates_new_comment(self):
        with mock.patch.object(self.adapter, "_api_request") as mock_req:
            # 1. Search existing comments (empty values), 2. Post new comment
            mock_req.side_effect = [{"values": []}, {"id": 101}]
            success = self.adapter.post_pr_summary("45", "## Review Summary\nAll clean.")
            self.assertTrue(success)
            self.assertEqual(mock_req.call_count, 2)

            post_call = mock_req.call_args_list[1]
            self.assertEqual(post_call[0][0], "pullrequests/45/comments")
            self.assertEqual(post_call[1]["method"], "POST")
            comment_raw = post_call[1]["data"]["content"]["raw"]
            self.assertIn("## Review Summary", comment_raw)
            self.assertIn(SUMMARY_MARKER, comment_raw)

    def test_post_pr_summary_updates_existing_comment(self):
        existing_comments = {
            "values": [
                {
                    "id": 999,
                    "content": {"raw": f"Old review\n\n{SUMMARY_MARKER}"},
                }
            ]
        }
        with mock.patch.object(self.adapter, "_api_request") as mock_req:
            mock_req.side_effect = [existing_comments, {"id": 999}]
            success = self.adapter.post_pr_summary("45", "## Updated Review")
            self.assertTrue(success)
            self.assertEqual(mock_req.call_count, 2)

            put_call = mock_req.call_args_list[1]
            self.assertEqual(put_call[0][0], "pullrequests/45/comments/999")
            self.assertEqual(put_call[1]["method"], "PUT")
            self.assertIn("## Updated Review", put_call[1]["data"]["content"]["raw"])

    def test_create_code_insights_report_passed(self):
        findings = [_sample_finding(severity="low")]
        with mock.patch.object(self.adapter, "_api_request", return_value={}) as mock_req:
            success = self.adapter._create_code_insights_report("c" * 40, findings)
            self.assertTrue(success)
            mock_req.assert_called_once()
            endpoint = mock_req.call_args[0][0]
            self.assertEqual(endpoint, f"commit/{'c'*40}/reports/{BB_REPORT_KEY}")
            self.assertEqual(mock_req.call_args[1]["method"], "PUT")
            data = mock_req.call_args[1]["data"]
            self.assertEqual(data["result"], "PASSED")
            self.assertEqual(data["report_type"], "SECURITY")

    def test_create_code_insights_report_failed_on_blocking(self):
        findings = [_sample_finding(severity="critical"), _sample_finding(severity="high")]
        with mock.patch.object(self.adapter, "_api_request", return_value={}) as mock_req:
            success = self.adapter._create_code_insights_report("c" * 40, findings)
            self.assertTrue(success)
            data = mock_req.call_args[1]["data"]
            self.assertEqual(data["result"], "FAILED")

    def test_post_code_insights_annotations_batching(self):
        # Generate 150 findings to verify batching (max 100 per batch)
        findings = [_sample_finding(id=f"FND-{i:04d}", severity="medium") for i in range(150)]
        with mock.patch.object(self.adapter, "_api_request", return_value={}) as mock_req:
            posted = self.adapter._post_code_insights_annotations("c" * 40, findings)
            self.assertEqual(posted, 150)
            self.assertEqual(mock_req.call_count, 2)

            # First batch: 100 items
            first_batch = mock_req.call_args_list[0][1]["data"]
            self.assertEqual(len(first_batch), MAX_ANNOTATIONS_PER_BATCH)
            # Second batch: 50 items
            second_batch = mock_req.call_args_list[1][1]["data"]
            self.assertEqual(len(second_batch), 50)

    def test_post_inline_annotations_with_insights(self):
        findings = [_sample_finding()]
        with (
            mock.patch.object(self.adapter, "_create_code_insights_report", return_value=True) as mock_report,
            mock.patch.object(self.adapter, "_post_code_insights_annotations", return_value=1) as mock_anno,
        ):
            posted = self.adapter.post_inline_annotations("45", findings)
            self.assertEqual(posted, 1)
            mock_report.assert_called_once_with("c" * 40, findings)
            mock_anno.assert_called_once_with("c" * 40, findings)

    def test_set_commit_status_state_mapping(self):
        for oca_state, bb_state in BB_STATUS_STATE_MAP.items():
            with (
                self.subTest(oca_state=oca_state),
                mock.patch.object(self.adapter, "_api_request", return_value={}) as mock_req,
            ):
                self.adapter.set_commit_status("c" * 40, oca_state, "Quality gate check")
                endpoint = mock_req.call_args[0][0]
                self.assertEqual(endpoint, f"commit/{'c'*40}/statuses/build")
                payload = mock_req.call_args[1]["data"]
                self.assertEqual(payload["state"], bb_state)

    def test_set_commit_status_rejects_invalid_state(self):
        with self.assertRaises(ValueError):
            self.adapter.set_commit_status("abc", "unrecognized", "desc")

    def test_export_native_artifacts(self):
        findings = [_sample_finding()]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "reports"
            artifacts = self.adapter.export_native_artifacts(findings, out_dir)
            self.assertEqual(len(artifacts), 2)

            insights_file, sarif_file = artifacts[0], artifacts[1]
            self.assertEqual(insights_file.name, BB_ARTIFACT_NAME)
            self.assertEqual(sarif_file.name, "ocagents.sarif")
            self.assertTrue(insights_file.exists())
            self.assertTrue(sarif_file.exists())

            insights_content = json.loads(insights_file.read_text(encoding="utf-8"))
            self.assertEqual(insights_content["report"]["title"], "Open Cloud Agents Governance Gate")
            self.assertEqual(insights_content["report"]["result"], "FAILED")  # critical/high -> FAILED
            self.assertEqual(len(insights_content["findings"]), 1)


class TestBitbucketFormattingHelpers(unittest.TestCase):
    """Verifies findings_to_bitbucket_insights transformation helpers."""

    def test_findings_to_bitbucket_insights(self):
        findings = [
            _sample_finding(severity="critical"),
            _sample_finding(severity="low"),
        ]
        result = findings_to_bitbucket_insights(findings)
        rep = result["report"]
        self.assertEqual(rep["result"], "FAILED")
        self.assertEqual(rep["report_type"], "SECURITY")
        self.assertEqual(len(result["findings"]), 2)

        json_str = findings_to_bitbucket_insights_json(findings)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["report"]["result"], "FAILED")


class TestVCSAdapterFactoryBitbucket(unittest.TestCase):
    """Verifies get_vcs_adapter factory resolution for Bitbucket."""

    def test_factory_returns_bitbucket_adapter(self):
        for variant in (Forge.BITBUCKET, "bitbucket", "bb", "bitbucket-cloud", "bitbucket-server"):
            with self.subTest(variant=variant):
                adapter = get_vcs_adapter(forge=variant)
                self.assertIsInstance(adapter, BitbucketAdapter)


if __name__ == "__main__":
    unittest.main()
