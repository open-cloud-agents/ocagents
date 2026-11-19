"""
Unit tests for Open Cloud Agents: GitLab SaaS & Self-Managed Adapter (ADR-003, Issue #107).
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ocagents.vcs import (
    GL_ARTIFACT_NAME,
    Forge,
    GitLabAdapter,
    LocalGitAdapter,
    VCSProvider,
    findings_to_gitlab_code_quality_json,
    get_vcs_adapter,
)
from ocagents.vcs.gitlab import SUMMARY_MARKER
from ocagents.vcs.gitlab_quality import finding_to_gitlab_issue


def _sample_finding(**kwargs) -> dict:
    base = {
        "$schema": "https://open-cloud-agents.github.io/schemas/v1/finding.json",
        "id": "FND-A1B2C3D4E5F6",
        "agent": "security-compliance-commander",
        "origin": "deterministic_linter",
        "rule_id": "rules/02-secrets-and-identity.md#SECRET001",
        "category": "security",
        "resource": "aws_db_instance.main",
        "fact": "Plaintext database master password detected in configuration.",
        "evidence": "diff:terraform/rds.tf#L42-L45",
        "recommendation": "Migrate secret to AWS Secrets Manager using dynamic references.",
        "severity": "critical",
        "confidence": None,
        "corroboration_status": "tool_verified",
    }
    base.update(kwargs)
    return base


class TestGitLabCodeQualityFormatter(unittest.TestCase):
    """Verifies schema conformance of gl-code-quality-report.json."""

    def test_single_finding_schema_conformance(self):
        finding = _sample_finding()
        issue = finding_to_gitlab_issue(finding)
        self.assertIsNotNone(issue)
        self.assertIn("description", issue)
        self.assertIn("check_name", issue)
        self.assertIn("fingerprint", issue)
        self.assertIn("severity", issue)
        self.assertIn("location", issue)

        self.assertEqual(issue["check_name"], "SECRET001")
        self.assertEqual(issue["severity"], "critical")
        self.assertEqual(issue["location"]["path"], "terraform/rds.tf")
        self.assertEqual(issue["location"]["lines"]["begin"], 42)
        self.assertEqual(issue["location"]["lines"]["end"], 45)
        self.assertTrue(issue["description"].startswith("(P0)"))
        self.assertEqual(len(issue["fingerprint"]), 64)  # 64-char sha256 hex string

    def test_severity_mapping_matrix(self):
        expected_mappings = {
            "critical": ("critical", "P0"),
            "high": ("major", "P1"),
            "medium": ("minor", "P2"),
            "low": ("info", "P3"),
            "info": ("info", "P4"),
        }
        for oca_sev, (gl_sev, priority) in expected_mappings.items():
            with self.subTest(oca_severity=oca_sev):
                finding = _sample_finding(severity=oca_sev)
                issue = finding_to_gitlab_issue(finding)
                self.assertIsNotNone(issue)
                self.assertEqual(issue["severity"], gl_sev)
                self.assertTrue(issue["description"].startswith(f"({priority})"))

    def test_fingerprint_deterministic_and_unique(self):
        f1 = _sample_finding(id="FND-111111111111")
        f2 = _sample_finding(id="FND-222222222222")
        issue1 = finding_to_gitlab_issue(f1)
        issue2 = finding_to_gitlab_issue(f2)
        issue1_repeat = finding_to_gitlab_issue(f1)

        self.assertEqual(issue1["fingerprint"], issue1_repeat["fingerprint"])
        self.assertNotEqual(issue1["fingerprint"], issue2["fingerprint"])

    def test_rejected_false_positives_filtered_by_default(self):
        finding = _sample_finding(corroboration_status="rejected_false_positive")
        self.assertIsNone(finding_to_gitlab_issue(finding, include_suppressed=False))
        self.assertIsNotNone(finding_to_gitlab_issue(finding, include_suppressed=True))

    def test_malformed_findings_handled_safely(self):
        for bad in (None, "string", 123, []):
            with self.subTest(bad=bad):
                self.assertIsNone(finding_to_gitlab_issue(bad))

    def test_json_serialization(self):
        findings = [_sample_finding(), _sample_finding(id="FND-999999999999", severity="high")]
        json_output = findings_to_gitlab_code_quality_json(findings)
        parsed = json.loads(json_output)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["severity"], "critical")
        self.assertEqual(parsed[1]["severity"], "major")


class TestGitLabAdapterConfiguration(unittest.TestCase):
    """Verifies GitLabAdapter initialization, URL parsing, and token resolution."""

    def test_is_vcs_provider(self):
        adapter = GitLabAdapter()
        self.assertIsInstance(adapter, VCSProvider)

    def test_base_url_normalization(self):
        a1 = GitLabAdapter(base_url="https://gitlab.example.com/")
        self.assertEqual(a1.base_url, "https://gitlab.example.com")

        with mock.patch.dict("os.environ", {"CI_SERVER_URL": "https://gitlab.corp.internal/"}):
            a2 = GitLabAdapter()
            self.assertEqual(a2.base_url, "https://gitlab.corp.internal")

    def test_token_and_header_selection(self):
        # 1. Private token preference
        with mock.patch.dict("os.environ", {"GITLAB_TOKEN": "glpat-test1234"}):
            adapter = GitLabAdapter()
            self.assertEqual(adapter.token, "glpat-test1234")
            self.assertEqual(adapter._headers()["PRIVATE-TOKEN"], "glpat-test1234")
            self.assertNotIn("JOB-TOKEN", adapter._headers())

        # 2. CI Job Token fallback
        with mock.patch.dict("os.environ", {"CI_JOB_TOKEN": "gljob-5678"}, clear=True):
            adapter = GitLabAdapter()
            self.assertEqual(adapter.token, "gljob-5678")
            self.assertEqual(adapter._headers()["JOB-TOKEN"], "gljob-5678")
            self.assertNotIn("PRIVATE-TOKEN", adapter._headers())

        # 3. Explicit Bearer token
        adapter = GitLabAdapter(token="bearer-token-123", token_type="bearer")
        self.assertEqual(adapter._headers()["Authorization"], "Bearer bearer-token-123")

    def test_project_id_encoding(self):
        adapter = GitLabAdapter(project_id="open-cloud-agents/infrastructure/core")
        self.assertEqual(adapter.encoded_project_id, "open-cloud-agents%2Finfrastructure%2Fcore")

        numeric_adapter = GitLabAdapter(project_id=12345)
        self.assertEqual(numeric_adapter.encoded_project_id, "12345")


class TestGitLabAdapterDetection(unittest.TestCase):
    """Verifies detect_context under GitLab CI and non-CI environments."""

    def test_detect_context_under_gitlab_ci(self):
        with mock.patch.dict("os.environ", {"GITLAB_CI": "true"}):
            self.assertTrue(GitLabAdapter().detect_context())

    def test_detect_context_via_ci_server_and_project_id(self):
        with mock.patch.dict("os.environ", {"CI_SERVER_URL": "https://gitlab.com", "CI_PROJECT_ID": "42"}):
            self.assertTrue(GitLabAdapter().detect_context())

    def test_detect_context_negative_outside_gitlab(self):
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch("ocagents.vcs.gitlab.detect_forge") as mock_detect,
        ):
            mock_detect.return_value = mock.MagicMock(forge=Forge.LOCAL)
            self.assertFalse(GitLabAdapter().detect_context())


class TestGitLabAdapterOperations(unittest.TestCase):
    """Verifies diff fetching, summary notes, inline discussions, and commit status."""

    def setUp(self):
        self.out = io.StringIO()
        self.adapter = GitLabAdapter(
            base_url="https://gitlab.example.com",
            project_id="test/repo",
            token="glpat-token",
            mr_iid=42,
            stream=self.out,
        )

    def test_get_diff_via_mr_diffs_api(self):
        sample_diffs = [
            {
                "old_path": "terraform/rds.tf",
                "new_path": "terraform/rds.tf",
                "diff": "@@ -1,3 +1,4 @@\n resource \"aws_db_instance\" \"main\" {\n+  password = \"admin123\"\n }\n",
            }
        ]
        with mock.patch.object(self.adapter, "_api_request", return_value=sample_diffs) as mock_req:
            diff = self.adapter.get_diff("base", "head")
            mock_req.assert_called_once_with("projects/test%2Frepo/merge_requests/42/diffs")
            self.assertIn("diff --git a/terraform/rds.tf b/terraform/rds.tf", diff)
            self.assertIn("+  password = \"admin123\"", diff)

    def test_post_pr_summary_creates_new_note(self):
        with mock.patch.object(self.adapter, "_api_request") as mock_req:
            # First call lists notes (empty), second call creates note
            mock_req.side_effect = [[], {"id": 101, "body": "Summary"}]
            result = self.adapter.post_pr_summary("42", "## Review Summary\nAll clean.")
            self.assertTrue(result)
            self.assertEqual(mock_req.call_count, 2)
            create_call = mock_req.call_args_list[1]
            self.assertEqual(create_call[0][0], "projects/test%2Frepo/merge_requests/42/notes")
            self.assertEqual(create_call[1]["method"], "POST")
            self.assertIn("## Review Summary", create_call[1]["data"]["body"])
            self.assertIn(SUMMARY_MARKER, create_call[1]["data"]["body"])

    def test_post_pr_summary_updates_existing_note(self):
        existing_notes = [
            {"id": 999, "body": f"Old summary\n\n{SUMMARY_MARKER}"}
        ]
        with mock.patch.object(self.adapter, "_api_request") as mock_req:
            mock_req.side_effect = [existing_notes, {"id": 999, "body": "Updated"}]
            result = self.adapter.post_pr_summary("42", "## New Review Summary")
            self.assertTrue(result)
            self.assertEqual(mock_req.call_count, 2)
            update_call = mock_req.call_args_list[1]
            self.assertEqual(update_call[0][0], "projects/test%2Frepo/merge_requests/42/notes/999")
            self.assertEqual(update_call[1]["method"], "PUT")
            self.assertIn("## New Review Summary", update_call[1]["data"]["body"])

    def test_post_inline_annotations_with_positioning(self):
        mr_details = {
            "diff_refs": {
                "base_sha": "base12345678",
                "start_sha": "base12345678",
                "head_sha": "head12345678",
            }
        }
        with mock.patch.object(self.adapter, "_api_request") as mock_req:
            # 1. Fetch MR details for diff_refs, 2. Post discussion
            mock_req.side_effect = [mr_details, {"id": 501}]
            findings = [_sample_finding()]
            posted = self.adapter.post_inline_annotations("42", findings)
            self.assertEqual(posted, 1)

            discussion_call = mock_req.call_args_list[1]
            self.assertEqual(discussion_call[0][0], "projects/test%2Frepo/merge_requests/42/discussions")
            pos = discussion_call[1]["data"]["position"]
            self.assertEqual(pos["new_path"], "terraform/rds.tf")
            self.assertEqual(pos["new_line"], 42)
            self.assertEqual(pos["base_sha"], "base12345678")

    def test_set_commit_status(self):
        with mock.patch.object(self.adapter, "_api_request", return_value={"status": "success"}) as mock_req:
            success = self.adapter.set_commit_status(
                sha="a" * 40,
                state="success",
                description="Checks passed",
                context="ocagents/quality-gate",
            )
            self.assertTrue(success)
            mock_req.assert_called_once_with(
                f"projects/test%2Frepo/statuses/{'a'*40}",
                method="POST",
                data={
                    "state": "success",
                    "name": "ocagents/quality-gate",
                    "description": "Checks passed",
                },
            )

    def test_set_commit_status_rejects_invalid_state(self):
        with self.assertRaises(ValueError):
            self.adapter.set_commit_status("abc", "invalid_state", "desc")

    def test_export_native_artifacts_writes_gl_code_quality(self):
        findings = [_sample_finding()]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "reports"
            artifacts = self.adapter.export_native_artifacts(findings, out_dir)
            self.assertEqual(len(artifacts), 1)
            report_file = artifacts[0]
            self.assertEqual(report_file.name, GL_ARTIFACT_NAME)
            self.assertTrue(report_file.exists())

            content = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(len(content), 1)
            self.assertEqual(content[0]["severity"], "critical")


class TestVCSAdapterFactory(unittest.TestCase):
    """Verifies get_vcs_adapter factory method."""

    def test_factory_returns_gitlab_adapter(self):
        adapter = get_vcs_adapter(forge=Forge.GITLAB)
        self.assertIsInstance(adapter, GitLabAdapter)

        adapter_str = get_vcs_adapter(forge="gitlab")
        self.assertIsInstance(adapter_str, GitLabAdapter)

    def test_factory_returns_local_git_adapter(self):
        adapter = get_vcs_adapter(forge=Forge.LOCAL)
        self.assertIsInstance(adapter, LocalGitAdapter)

        adapter_str = get_vcs_adapter(forge="local")
        self.assertIsInstance(adapter_str, LocalGitAdapter)


if __name__ == "__main__":
    unittest.main()
