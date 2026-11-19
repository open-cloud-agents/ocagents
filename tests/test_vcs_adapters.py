"""
Open Cloud Agents: Multi-VCS Adapter Contract & Integration Test Matrix (ADR-003, Task 5.6).

Verifies forge-agnostic contract compliance, factory resolution, commit status
state mappings, deterministic offline fallback, and native artifact exports across
all supported platforms (GitLab, Azure DevOps, Bitbucket, Gitea/Forgejo, Local).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ocagents.vcs import (
    ADO_ARTIFACT_NAME,
    BB_ARTIFACT_NAME,
    GL_ARTIFACT_NAME,
    GT_ARTIFACT_NAME,
    AzureDevOpsAdapter,
    BitbucketAdapter,
    Forge,
    GiteaAdapter,
    GitLabAdapter,
    LocalGitAdapter,
    VCSProvider,
    findings_to_bitbucket_insights,
    findings_to_bitbucket_insights_json,
    findings_to_gitea_quality,
    findings_to_gitea_quality_json,
    findings_to_gitlab_code_quality,
    findings_to_gitlab_code_quality_json,
    get_vcs_adapter,
)
from ocagents.vcs.base import VALID_COMMIT_STATES


def _sample_finding(**kwargs) -> dict:
    base = {
        "$schema": "https://open-cloud-agents.github.io/schemas/v1/finding.json",
        "id": "FND-A1B2C3D4E5F6",
        "agent": "security-compliance-commander",
        "origin": "deterministic_linter",
        "rule_id": "rules/02-secrets-and-identity.md#SEC001",
        "category": "security",
        "resource": "google_storage_bucket.audit",
        "fact": "Public bucket access enabled via allUsers IAM member binding.",
        "evidence": "diff:terraform/storage.tf#L10-L15",
        "recommendation": "Remove allUsers binding and enforce uniform bucket-level access.",
        "severity": "critical",
        "confidence": None,
        "corroboration_status": "tool_verified",
    }
    base.update(kwargs)
    return base


ALL_ADAPTER_CLASSES = (
    GitLabAdapter,
    AzureDevOpsAdapter,
    BitbucketAdapter,
    GiteaAdapter,
    LocalGitAdapter,
)


class TestVCSAdapterContractMatrix(unittest.TestCase):
    """Verifies that all concrete forge adapters implement the VCSProvider abstract interface."""

    def test_all_adapters_inherit_from_vcs_provider(self):
        for adapter_cls in ALL_ADAPTER_CLASSES:
            with self.subTest(adapter=adapter_cls.__name__):
                self.assertTrue(issubclass(adapter_cls, VCSProvider))

    def test_all_required_methods_exist_and_callable(self):
        required_methods = (
            "detect_context",
            "get_diff",
            "post_pr_summary",
            "post_inline_annotations",
            "set_commit_status",
            "export_native_artifacts",
        )
        for adapter_cls in ALL_ADAPTER_CLASSES:
            for method_name in required_methods:
                with self.subTest(adapter=adapter_cls.__name__, method=method_name):
                    self.assertTrue(hasattr(adapter_cls, method_name))
                    self.assertTrue(callable(getattr(adapter_cls, method_name)))


class TestVCSFactoryAndFallbackMatrix(unittest.TestCase):
    """Verifies get_vcs_adapter resolution across forge enums, string aliases, and local fallback."""

    def test_factory_forge_enum_resolution(self):
        cases = [
            (Forge.GITLAB, GitLabAdapter),
            (Forge.AZURE_DEVOPS, AzureDevOpsAdapter),
            (Forge.BITBUCKET, BitbucketAdapter),
            (Forge.GITEA, GiteaAdapter),
            (Forge.LOCAL, LocalGitAdapter),
        ]
        for forge_enum, expected_cls in cases:
            with self.subTest(forge=forge_enum.value):
                adapter = get_vcs_adapter(forge=forge_enum)
                self.assertIsInstance(adapter, expected_cls)

    def test_factory_string_aliases_resolution(self):
        alias_cases = [
            ("gitlab", GitLabAdapter),
            ("GITLAB", GitLabAdapter),
            ("ado", AzureDevOpsAdapter),
            ("azure-devops", AzureDevOpsAdapter),
            ("azure_devops", AzureDevOpsAdapter),
            ("azure", AzureDevOpsAdapter),
            ("bitbucket", BitbucketAdapter),
            ("bb", BitbucketAdapter),
            ("bitbucket-cloud", BitbucketAdapter),
            ("bitbucket-server", BitbucketAdapter),
            ("gitea", GiteaAdapter),
            ("forgejo", GiteaAdapter),
            ("codeberg", GiteaAdapter),
            ("local", LocalGitAdapter),
            ("unrecognized-custom-forge", LocalGitAdapter),
        ]
        for alias, expected_cls in alias_cases:
            with self.subTest(alias=alias):
                adapter = get_vcs_adapter(forge=alias)
                self.assertIsInstance(adapter, expected_cls)

    def test_deterministic_fallback_to_local_git_adapter(self):
        """When running outside CI and without recognized remotes, defaults to LocalGitAdapter."""
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch("ocagents.vcs.detector.get_origin_remote_url", return_value=None),
        ):
            adapter = get_vcs_adapter()
            self.assertIsInstance(adapter, LocalGitAdapter)


class TestVCSCommitStatusMappingMatrix(unittest.TestCase):
    """Verifies that all adapters adhere to VALID_COMMIT_STATES ('success', 'failed', 'pending')."""

    def test_all_adapters_accept_valid_commit_states(self):
        adapters = [
            GitLabAdapter(project_id="123", token="mock-token"),
            AzureDevOpsAdapter(
                collection_uri="https://dev.azure.com/org",
                project="proj",
                repository_id="repo",
                token="mock-token",
                pr_id=1,
            ),
            BitbucketAdapter(workspace="ws", repo_slug="repo", token="mock-token"),
            GiteaAdapter(owner="owner", repo="repo", token="mock-token"),
        ]
        for adapter in adapters:
            for state in VALID_COMMIT_STATES:
                with (
                    self.subTest(adapter=adapter.__class__.__name__, state=state),
                    mock.patch.object(adapter, "_api_request", return_value={}) as mock_req,
                ):
                    success = adapter.set_commit_status("f" * 40, state, "Quality Check")
                    self.assertTrue(success)
                    mock_req.assert_called_once()

    def test_all_adapters_reject_invalid_commit_states(self):
        adapters = [
            GitLabAdapter(),
            AzureDevOpsAdapter(),
            BitbucketAdapter(),
            GiteaAdapter(),
            LocalGitAdapter(),
        ]
        for adapter in adapters:
            with (
                self.subTest(adapter=adapter.__class__.__name__),
                self.assertRaises(ValueError),
            ):
                adapter.set_commit_status("f" * 40, "invalid_state_xyz", "Description")


class TestVCSArtifactExportMatrix(unittest.TestCase):
    """Verifies native artifact generation across all adapters and formats."""

    def test_gitlab_artifacts_export(self):
        adapter = GitLabAdapter()
        findings = [_sample_finding()]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "gl"
            artifacts = adapter.export_native_artifacts(findings, out_dir)
            names = [a.name for a in artifacts]
            self.assertIn(GL_ARTIFACT_NAME, names)
            self.assertEqual(len(artifacts), 1)

    def test_azure_devops_artifacts_export(self):
        adapter = AzureDevOpsAdapter()
        findings = [_sample_finding()]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "ado"
            artifacts = adapter.export_native_artifacts(findings, out_dir)
            names = [a.name for a in artifacts]
            self.assertIn(ADO_ARTIFACT_NAME, names)
            self.assertEqual(len(artifacts), 1)

    def test_bitbucket_artifacts_export(self):
        adapter = BitbucketAdapter()
        findings = [_sample_finding()]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "bb"
            artifacts = adapter.export_native_artifacts(findings, out_dir)
            names = [a.name for a in artifacts]
            self.assertIn(BB_ARTIFACT_NAME, names)
            self.assertIn("ocagents.sarif", names)
            self.assertEqual(len(artifacts), 2)

    def test_gitea_artifacts_export(self):
        adapter = GiteaAdapter()
        findings = [_sample_finding()]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "gt"
            artifacts = adapter.export_native_artifacts(findings, out_dir)
            names = [a.name for a in artifacts]
            self.assertIn(GT_ARTIFACT_NAME, names)
            self.assertIn("ocagents.sarif", names)
            self.assertEqual(len(artifacts), 2)

    def test_local_git_adapter_artifacts_export(self):
        adapter = LocalGitAdapter()
        findings = [_sample_finding()]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "local"
            artifacts = adapter.export_native_artifacts(findings, out_dir)
            names = [a.name for a in artifacts]
            self.assertIn("ocagents-findings.json", names)
            self.assertEqual(len(artifacts), 1)


class TestVCSUnifiedFindingSerialization(unittest.TestCase):
    """Verifies that all native finding transformation helpers produce valid JSON and structures."""

    def setUp(self):
        self.findings = [
            _sample_finding(severity="critical"),
            _sample_finding(id="FND-2", severity="high"),
            _sample_finding(id="FND-3", severity="medium"),
            _sample_finding(id="FND-4", severity="low"),
        ]

    def test_gitlab_code_quality_serialization(self):
        gl_list = findings_to_gitlab_code_quality(self.findings)
        self.assertEqual(len(gl_list), 4)
        gl_json = findings_to_gitlab_code_quality_json(self.findings)
        parsed = json.loads(gl_json)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 4)

    def test_bitbucket_insights_serialization(self):
        bb_data = findings_to_bitbucket_insights(self.findings)
        self.assertEqual(bb_data["report"]["result"], "FAILED")  # critical/high -> FAILED
        self.assertEqual(bb_data["report"]["data"][0]["value"], 4)
        bb_json = findings_to_bitbucket_insights_json(self.findings)
        parsed = json.loads(bb_json)
        self.assertIn("report", parsed)
        self.assertIn("findings", parsed)

    def test_gitea_quality_serialization(self):
        gt_data = findings_to_gitea_quality(self.findings)
        self.assertEqual(gt_data["status"], "failure")
        self.assertEqual(gt_data["summary"]["blocking_count"], 2)
        gt_json = findings_to_gitea_quality_json(self.findings)
        parsed = json.loads(gt_json)
        self.assertEqual(parsed["status"], "failure")


if __name__ == "__main__":
    unittest.main()
