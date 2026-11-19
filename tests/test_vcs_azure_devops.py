"""
Unit tests for Open Cloud Agents: Azure DevOps Pipelines & Repos Adapter (ADR-003, Issue #108).
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ocagents.vcs import (
    ADO_ARTIFACT_NAME,
    AzureDevOpsAdapter,
    Forge,
    VCSProvider,
    get_vcs_adapter,
)
from ocagents.vcs.azure_devops import ADO_STATUS_STATE_MAP, SUMMARY_MARKER


def _sample_finding(**kwargs) -> dict:
    base = {
        "$schema": "https://open-cloud-agents.github.io/schemas/v1/finding.json",
        "id": "FND-B2C3D4E5F6A1",
        "agent": "security-compliance-commander",
        "origin": "deterministic_linter",
        "rule_id": "rules/02-secrets-and-identity.md#KV001",
        "category": "security",
        "resource": "azurerm_key_vault.main",
        "fact": "Key Vault public network access enabled without subnet bypass restrictions.",
        "evidence": "diff:terraform/keyvault.tf#L24-L26",
        "recommendation": "Configure network_acls with default_action 'Deny' and virtual_network_subnet_ids.",
        "severity": "critical",
        "confidence": None,
        "corroboration_status": "tool_verified",
    }
    base.update(kwargs)
    return base


class TestAzureDevOpsAdapterConfiguration(unittest.TestCase):
    """Verifies AzureDevOpsAdapter initialization, credentials, and URL encoding."""

    def test_is_vcs_provider(self):
        adapter = AzureDevOpsAdapter()
        self.assertIsInstance(adapter, VCSProvider)

    def test_collection_uri_normalization(self):
        a1 = AzureDevOpsAdapter(collection_uri="https://dev.azure.com/my-org/")
        self.assertEqual(a1.collection_uri, "https://dev.azure.com/my-org")

        with mock.patch.dict("os.environ", {"SYSTEM_TEAMFOUNDATIONCOLLECTIONURI": "https://dev.azure.com/corp-org/"}):
            a2 = AzureDevOpsAdapter()
            self.assertEqual(a2.collection_uri, "https://dev.azure.com/corp-org")

    def test_authentication_headers(self):
        # 1. Bearer token (SYSTEM_ACCESSTOKEN)
        with mock.patch.dict("os.environ", {"SYSTEM_ACCESSTOKEN": "oauth-token-12345"}, clear=True):
            adapter = AzureDevOpsAdapter()
            headers = adapter._headers()
            self.assertEqual(headers["Authorization"], "Bearer oauth-token-12345")

        # 2. Basic token with PAT
        with mock.patch.dict("os.environ", {"AZURE_DEVOPS_EXT_PAT": "my-secret-pat"}, clear=True):
            adapter = AzureDevOpsAdapter()
            headers = adapter._headers()
            self.assertTrue(headers["Authorization"].startswith("Basic "))

        # 3. Explicit token and token_type
        adapter_custom = AzureDevOpsAdapter(token="custom-token", token_type="bearer")
        self.assertEqual(adapter_custom._headers()["Authorization"], "Bearer custom-token")

    def test_identifier_url_encoding(self):
        adapter = AzureDevOpsAdapter(
            project="Core Platform/Infrastructure",
            repository_id="core repo/sub",
        )
        self.assertEqual(adapter.encoded_project, "Core%20Platform%2FInfrastructure")
        self.assertEqual(adapter.encoded_repository, "core%20repo%2Fsub")


class TestAzureDevOpsAdapterDetection(unittest.TestCase):
    """Verifies detect_context under Azure Pipelines and local environments."""

    def test_detect_context_under_azure_pipelines(self):
        with mock.patch.dict("os.environ", {"TF_BUILD": "True"}):
            self.assertTrue(AzureDevOpsAdapter().detect_context())

    def test_detect_context_via_collection_uri(self):
        with mock.patch.dict("os.environ", {"SYSTEM_TEAMFOUNDATIONCOLLECTIONURI": "https://dev.azure.com/org"}):
            self.assertTrue(AzureDevOpsAdapter().detect_context())

    def test_detect_context_negative_outside_azure_devops(self):
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch("ocagents.vcs.azure_devops.detect_forge") as mock_detect,
        ):
            mock_detect.return_value = mock.MagicMock(forge=Forge.LOCAL)
            self.assertFalse(AzureDevOpsAdapter().detect_context())


class TestAzureDevOpsAdapterOperations(unittest.TestCase):
    """Verifies threads, inline threadContext annotations, status policies, and artifacts."""

    def setUp(self):
        self.out = io.StringIO()
        self.adapter = AzureDevOpsAdapter(
            collection_uri="https://dev.azure.com/myorg",
            project="MyProject",
            repository_id="MyRepo",
            token="test-access-token",
            pr_id=77,
            stream=self.out,
        )

    def test_post_pr_summary_creates_new_thread(self):
        with mock.patch.object(self.adapter, "_api_request") as mock_req:
            # 1. Search existing threads (empty value list), 2. Create thread
            mock_req.side_effect = [{"value": []}, {"id": 1001}]
            success = self.adapter.post_pr_summary("77", "## Summary\nAll checks clean.")
            self.assertTrue(success)
            self.assertEqual(mock_req.call_count, 2)

            post_call = mock_req.call_args_list[1]
            self.assertEqual(post_call[0][0], "pullRequests/77/threads")
            self.assertEqual(post_call[1]["method"], "POST")
            comment_content = post_call[1]["data"]["comments"][0]["content"]
            self.assertIn("## Summary", comment_content)
            self.assertIn(SUMMARY_MARKER, comment_content)

    def test_post_pr_summary_updates_existing_thread(self):
        existing_threads = {
            "value": [
                {
                    "id": 555,
                    "comments": [
                        {"id": 1, "content": f"Old summary\n\n{SUMMARY_MARKER}"}
                    ],
                }
            ]
        }
        with mock.patch.object(self.adapter, "_api_request") as mock_req:
            mock_req.side_effect = [existing_threads, {"id": 1}]
            success = self.adapter.post_pr_summary("77", "## Updated Summary")
            self.assertTrue(success)
            self.assertEqual(mock_req.call_count, 2)

            patch_call = mock_req.call_args_list[1]
            self.assertEqual(patch_call[0][0], "pullRequests/77/threads/555/comments/1")
            self.assertEqual(patch_call[1]["method"], "PATCH")
            self.assertIn("## Updated Summary", patch_call[1]["data"]["content"])

    def test_post_inline_annotations_with_thread_context(self):
        with mock.patch.object(self.adapter, "_api_request", return_value={"id": 888}) as mock_req:
            findings = [_sample_finding()]
            posted = self.adapter.post_inline_annotations("77", findings)
            self.assertEqual(posted, 1)

            mock_req.assert_called_once()
            endpoint = mock_req.call_args[0][0]
            self.assertEqual(endpoint, "pullRequests/77/threads")
            data = mock_req.call_args[1]["data"]
            self.assertIn("threadContext", data)
            tc = data["threadContext"]
            # Azure DevOps requires leading slash
            self.assertEqual(tc["filePath"], "/terraform/keyvault.tf")
            self.assertEqual(tc["rightFileStart"]["line"], 24)
            self.assertEqual(tc["rightFileEnd"]["line"], 26)

    def test_set_commit_status_pr_policy(self):
        with mock.patch.object(self.adapter, "_api_request", return_value={"status": "succeeded"}) as mock_req:
            success = self.adapter.set_commit_status(
                sha="a" * 40,
                state="success",
                description="All checks passed",
                context="ocagents/quality-gate",
            )
            self.assertTrue(success)
            mock_req.assert_called_once_with(
                "pullRequests/77/statuses",
                method="POST",
                data={
                    "state": "succeeded",
                    "description": "All checks passed",
                    "context": {
                        "name": "ocagents/quality-gate",
                        "genre": "open-cloud-agents",
                    },
                },
            )

    def test_set_commit_status_state_mapping(self):
        for oca_state, ado_state in ADO_STATUS_STATE_MAP.items():
            with (
                self.subTest(oca_state=oca_state),
                mock.patch.object(self.adapter, "_api_request", return_value={}) as mock_req,
            ):
                self.adapter.set_commit_status("a" * 40, oca_state, "Test state")
                payload = mock_req.call_args[1]["data"]
                self.assertEqual(payload["state"], ado_state)

    def test_set_commit_status_rejects_invalid_state(self):
        with self.assertRaises(ValueError):
            self.adapter.set_commit_status("abc", "unrecognized", "desc")

    def test_export_native_artifacts_writes_sarif(self):
        findings = [_sample_finding()]
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "reports"
            artifacts = self.adapter.export_native_artifacts(findings, out_dir)
            self.assertEqual(len(artifacts), 1)
            sarif_file = artifacts[0]
            self.assertEqual(sarif_file.name, ADO_ARTIFACT_NAME)
            self.assertTrue(sarif_file.exists())

            content = json.loads(sarif_file.read_text(encoding="utf-8"))
            self.assertEqual(content["version"], "2.1.0")
            self.assertEqual(len(content["runs"][0]["results"]), 1)


class TestVCSAdapterFactoryAzureDevOps(unittest.TestCase):
    """Verifies get_vcs_adapter factory resolution for Azure DevOps."""

    def test_factory_returns_azure_devops_adapter(self):
        for variant in (Forge.AZURE_DEVOPS, "azure_devops", "ado", "azure-devops"):
            with self.subTest(variant=variant):
                adapter = get_vcs_adapter(forge=variant)
                self.assertIsInstance(adapter, AzureDevOpsAdapter)


if __name__ == "__main__":
    unittest.main()
