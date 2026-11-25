"""
tests/test_cli_sync.py
=============================================================================
Unit tests for targeted CSP synchronization, auto-detection, and pruning.
=============================================================================
"""

import argparse
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
_src_dir = _repo_root / "src"
if str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))

from ocagents.cli import (
    cmd_sync,
    detect_workspace_clouds,
    filter_skills_for_cloud,
    get_skills_target_dir,
    provision_workspace_hygiene,
    prune_irrelevant_skills,
)
from ocagents.scanner.preflight import get_effective_ignored_dirs


class TestCliSyncTargeting(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.workspace = Path(self.temp_dir) / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_workspace_clouds_empty(self):
        """Verifies an empty workspace detects no cloud providers."""
        detected = detect_workspace_clouds(self.workspace)
        self.assertEqual(detected, [])

    def test_detect_workspace_clouds_aws_marker(self):
        """Verifies AWS detection via cdk.json root marker."""
        (self.workspace / "cdk.json").write_text("{}", encoding="utf-8")
        detected = detect_workspace_clouds(self.workspace)
        self.assertEqual(detected, ["aws"])

    def test_detect_workspace_clouds_azure_marker(self):
        """Verifies Azure detection via azure-pipelines.yml root marker."""
        (self.workspace / "azure-pipelines.yml").write_text("steps: []", encoding="utf-8")
        detected = detect_workspace_clouds(self.workspace)
        self.assertEqual(detected, ["azure"])

    def test_detect_workspace_clouds_gcp_marker(self):
        """Verifies GCP detection via cloudbuild.yaml root marker."""
        (self.workspace / "cloudbuild.yaml").write_text("steps: []", encoding="utf-8")
        detected = detect_workspace_clouds(self.workspace)
        self.assertEqual(detected, ["gcp"])

    def test_detect_workspace_clouds_terraform_aws(self):
        """Verifies AWS detection via Terraform resource definitions."""
        tf_file = self.workspace / "main.tf"
        tf_file.write_text('resource "aws_s3_bucket" "b" {}', encoding="utf-8")
        detected = detect_workspace_clouds(self.workspace)
        self.assertEqual(detected, ["aws"])

    def test_detect_workspace_clouds_terraform_multi(self):
        """Verifies multi-cloud detection across AWS and GCP in Terraform."""
        (self.workspace / "aws.tf").write_text('provider "aws" { region = "us-east-1" }', encoding="utf-8")
        (self.workspace / "gcp.tf").write_text('provider "google" { project = "test" }', encoding="utf-8")
        detected = detect_workspace_clouds(self.workspace)
        self.assertEqual(detected, ["aws", "gcp"])

    def test_filter_skills_for_cloud_aws(self):
        """Verifies skill filtering for AWS scope keeps AWS and core, prunes others."""
        declared = [
            "devops/iac/terraform-infrastructure-planner",
            "security/cis-complete-audit",
            "csp/aws",
            "csp/azure",
            "csp/gcp",
            "devops/iac/aws-terraform-implementation",
            "devops/iac/azure-terraform-implementation",
        ]
        filtered = filter_skills_for_cloud(declared, {"aws"})
        self.assertIn("devops/iac/terraform-infrastructure-planner", filtered)
        self.assertIn("security/cis-complete-audit", filtered)
        self.assertIn("csp/aws", filtered)
        self.assertIn("devops/iac/aws-terraform-implementation", filtered)
        self.assertNotIn("csp/azure", filtered)
        self.assertNotIn("csp/gcp", filtered)
        self.assertNotIn("devops/iac/azure-terraform-implementation", filtered)

    def test_filter_skills_for_cloud_agnostic(self):
        """Verifies skill filtering for agnostic scope strips all CSP skills."""
        declared = [
            "devops/kubernetes/helm-chart-scaffold",
            "csp/aws",
            "csp/azure",
            "csp/gcp",
            "devops/iac/aws-terraform-implementation",
        ]
        filtered = filter_skills_for_cloud(declared, {"agnostic"})
        self.assertEqual(filtered, ["devops/kubernetes/helm-chart-scaffold"])

    def test_filter_skills_for_cloud_all(self):
        """Verifies skill filtering for all scope preserves full list."""
        declared = ["csp/aws", "csp/azure", "csp/gcp"]
        filtered = filter_skills_for_cloud(declared, {"all"})
        self.assertEqual(filtered, declared)

    def test_get_skills_target_dir(self):
        """Verifies target skills directory calculation across IDE formats."""
        self.assertEqual(get_skills_target_dir(self.workspace, "claude"), self.workspace / ".claude" / "skills")
        self.assertEqual(get_skills_target_dir(self.workspace, "cursor"), self.workspace / ".cursor" / "skills")
        self.assertEqual(get_skills_target_dir(self.workspace, "github"), self.workspace / ".github" / "skills")
        self.assertEqual(get_skills_target_dir(self.workspace, "gemini"), self.workspace / ".gemini" / "skills")
        self.assertEqual(get_skills_target_dir(self.workspace, "raw"), self.workspace / "skills")

    def test_prune_irrelevant_skills(self):
        """Verifies pruning removes unselected CSP folders."""
        skills_dir = self.workspace / ".claude" / "skills"
        aws_dir = skills_dir / "csp" / "aws"
        azure_dir = skills_dir / "csp" / "azure"
        gcp_dir = skills_dir / "csp" / "gcp"
        aws_dir.mkdir(parents=True, exist_ok=True)
        azure_dir.mkdir(parents=True, exist_ok=True)
        gcp_dir.mkdir(parents=True, exist_ok=True)

        pruned = prune_irrelevant_skills(skills_dir, {"aws"}, dry_run=False)
        self.assertEqual(pruned, 2)
        self.assertTrue(aws_dir.exists())
        self.assertFalse(azure_dir.exists())
        self.assertFalse(gcp_dir.exists())

    def test_cmd_sync_targeted_aws_claude(self):
        """End-to-end sync for Claude format with --cloud aws."""
        repo_root = Path(__file__).resolve().parent.parent
        args = argparse.Namespace(
            agent="principal-cloud-architect",
            all=False,
            format="claude",
            target=str(self.workspace),
            sync_skills=True,
            cloud="aws",
            prune=True,
            symlink=False,
            dry_run=False,
        )

        rc = cmd_sync(args, repo_root)
        self.assertEqual(rc, 0)

        # Agent file created
        agent_file = self.workspace / ".claude" / "agents" / "principal-cloud-architect.md"
        self.assertTrue(agent_file.exists())

        # AWS skills synced, Azure/GCP pruned
        skills_base = self.workspace / ".claude" / "skills"
        self.assertTrue((skills_base / "csp" / "aws").exists())
        self.assertFalse((skills_base / "csp" / "azure").exists())
        self.assertFalse((skills_base / "csp" / "gcp").exists())

    def test_provision_workspace_hygiene_cursor(self):
        """Verifies cursor format provisions .cursorignore, .cursorindexingignore, and .agentignore."""
        provisioned = provision_workspace_hygiene(self.workspace, fmt="cursor")
        self.assertIn(".cursorignore", provisioned)
        self.assertIn(".cursorindexingignore", provisioned)
        self.assertIn(".agentignore", provisioned)
        self.assertTrue((self.workspace / ".cursorignore").is_file())
        self.assertTrue((self.workspace / ".cursorindexingignore").is_file())
        self.assertTrue((self.workspace / ".agentignore").is_file())

    def test_provision_workspace_hygiene_claude(self):
        """Verifies claude format provisions .claude/settings.json, .agentignore, and .aiignore."""
        provisioned = provision_workspace_hygiene(self.workspace, fmt="claude")
        self.assertIn(".claude/settings.json", provisioned)
        self.assertIn(".agentignore", provisioned)
        self.assertIn(".aiignore", provisioned)
        self.assertTrue((self.workspace / ".claude" / "settings.json").is_file())
        self.assertTrue((self.workspace / ".agentignore").is_file())

    def test_provision_workspace_hygiene_preserves_existing(self):
        """Verifies existing hygiene files are preserved and not overwritten unless force=True."""
        ignore_file = self.workspace / ".cursorignore"
        ignore_file.write_text("# Custom User Ignore\nmy-custom-folder/\n", encoding="utf-8")

        provisioned = provision_workspace_hygiene(self.workspace, fmt="cursor", force=False)
        self.assertNotIn(".cursorignore", provisioned)
        content = ignore_file.read_text(encoding="utf-8")
        self.assertIn("my-custom-folder/", content)

    def test_provision_workspace_hygiene_force_overwrites(self):
        """Verifies force=True overwrites existing hygiene files."""
        ignore_file = self.workspace / ".cursorignore"
        ignore_file.write_text("# Custom User Ignore\n", encoding="utf-8")

        provisioned = provision_workspace_hygiene(self.workspace, fmt="cursor", force=True)
        self.assertIn(".cursorignore", provisioned)
        content = ignore_file.read_text(encoding="utf-8")
        self.assertIn("Open Cloud Agents: Frontier AI Context", content)

    def test_sync_auto_provisions_hygiene(self):
        """Verifies cmd_sync automatically scaffolds hygiene files in target workspace."""
        repo_root = Path(__file__).resolve().parent.parent
        args = argparse.Namespace(
            agent="principal-cloud-architect",
            all=False,
            format="cursor",
            target=str(self.workspace),
            sync_skills=False,
            cloud="aws",
            prune=False,
            hygiene=True,
            force_hygiene=False,
            symlink=False,
            dry_run=False,
        )
        rc = cmd_sync(args, repo_root)
        self.assertEqual(rc, 0)
        self.assertTrue((self.workspace / ".cursorignore").is_file())
        self.assertTrue((self.workspace / ".agentignore").is_file())

    def test_sync_no_hygiene_skips_scaffolding(self):
        """Verifies cmd_sync with hygiene=False skips scaffolding."""
        repo_root = Path(__file__).resolve().parent.parent
        args = argparse.Namespace(
            agent="principal-cloud-architect",
            all=False,
            format="cursor",
            target=str(self.workspace),
            sync_skills=False,
            cloud="aws",
            prune=False,
            hygiene=False,
            force_hygiene=False,
            symlink=False,
            dry_run=False,
        )
        rc = cmd_sync(args, repo_root)
        self.assertEqual(rc, 0)
        self.assertFalse((self.workspace / ".cursorignore").exists())

    def test_get_effective_ignored_dirs_with_agentignore(self):
        """Verifies preflight's get_effective_ignored_dirs dynamically parses .agentignore."""
        (self.workspace / ".agentignore").write_text("custom_vendor/\nlegacy_scratch/\n", encoding="utf-8")
        effective = get_effective_ignored_dirs(self.workspace)
        self.assertIn("custom_vendor", effective)
        self.assertIn("legacy_scratch", effective)
        self.assertIn("node_modules", effective)
        self.assertIn("site", effective)


if __name__ == "__main__":
    unittest.main()
