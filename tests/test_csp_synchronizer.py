"""
tests/test_csp_synchronizer.py
=============================================================================
Unit tests for Automated Cloud Service Provider (CSP) Skills Content Synchronizer.
=============================================================================
"""

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.ci.sync_csp_content import (
    load_config,
    save_config,
    enforce_script_permissions,
    generate_markdown_summary,
    sync_provider,
)


class TestCspSynchronizer(unittest.TestCase):

    def test_upstream_sync_config_structure(self):
        """Verify production upstream-sync.json contains valid structure, providers, and mappings."""
        repo_root = Path(__file__).resolve().parent.parent
        config_path = repo_root / "skills" / "csp" / "upstream-sync.json"
        self.assertTrue(config_path.exists(), "skills/csp/upstream-sync.json must exist")

        config = load_config(config_path)
        self.assertEqual(config.get("version"), "1.0.0")
        providers = config.get("providers", {})
        self.assertIn("aws", providers)
        self.assertIn("azure", providers)
        self.assertIn("gcp", providers)

        for key, pdata in providers.items():
            self.assertIn("name", pdata)
            self.assertIn("repository", pdata)
            self.assertIn("target_dir", pdata)
            self.assertIn("sync_mappings", pdata)
            self.assertGreater(len(pdata["sync_mappings"]), 0)
            self.assertIn("preserve_files", pdata)
            self.assertIn("README.md", pdata["preserve_files"])
            for mapping in pdata["sync_mappings"]:
                self.assertIn("source", mapping)
                self.assertIn("target", mapping)

    def test_enforce_script_permissions(self):
        """Verify enforce_script_permissions sets executable bit (0o755) on shell scripts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_workspace = Path(tmpdir)
            scripts_dir = temp_workspace / "scripts"
            scripts_dir.mkdir(parents=True)

            non_exec_sh = scripts_dir / "test_run.sh"
            non_exec_sh.write_text("#!/bin/sh\necho hello\n")
            non_exec_sh.chmod(0o644)

            other_file = scripts_dir / "notes.txt"
            other_file.write_text("just text\n")
            other_file.chmod(0o644)

            self.assertFalse(bool(non_exec_sh.stat().st_mode & stat.S_IXUSR))

            count = enforce_script_permissions(temp_workspace)
            self.assertEqual(count, 1)
            self.assertTrue(bool(non_exec_sh.stat().st_mode & stat.S_IXUSR))
            self.assertFalse(bool(other_file.stat().st_mode & stat.S_IXUSR))

    def test_markdown_summary_generation(self):
        """Verify generate_markdown_summary produces formatted table and hygiene checklist."""
        results = [
            {
                "name": "Amazon Web Services (AWS)",
                "repository": "aws/agent-toolkit-for-aws",
                "target_dir": "skills/csp/aws",
                "status": "SYNCHRONIZED",
                "latest_sha": "174379354c7c93f9e80249265f3fffa67a42f0c1",
                "commit_message": "feat: add quantum computing skills",
                "diff_summary": {
                    "has_changes": True,
                    "added_count": 5,
                    "modified_count": 2,
                    "deleted_count": 0,
                    "sample_files": ["skills/csp/aws/skills/amazon-braket/SKILL.md"],
                    "total_changed": 7,
                },
            },
            {
                "name": "Microsoft Azure",
                "repository": "MicrosoftDocs/Agent-Skills",
                "target_dir": "skills/csp/azure",
                "status": "UP_TO_DATE",
                "latest_sha": "6ecdaf59cde880d0ef3d1715357b6c0b0c6696d8",
                "commit_message": "docs: update azure skills",
                "diff_summary": {"has_changes": False},
            },
        ]

        summary = generate_markdown_summary(
            results,
            run_date="2026-11-04 22:00:00 UTC",
            validation_ok=True,
            validation_output="All clean",
        )

        self.assertIn("## 🌐 Open Cloud Agents - Upstream CSP Skills Synchronization", summary)
        self.assertIn("Amazon Web Services (AWS)", summary)
        self.assertIn("Microsoft Azure", summary)
        self.assertIn("17437935", summary)
        self.assertIn("All Repository Hygiene Checks Passed (`scripts/ci/validate_repo.py`)", summary)

    @patch("scripts.ci.sync_csp_content.fetch_upstream_commit")
    def test_sync_provider_up_to_date_skipped(self, mock_fetch):
        """Verify sync_provider skips downloading when baseline SHA matches upstream."""
        provider_data = {
            "name": "Mock Provider",
            "repository": "mock/repo",
            "branch": "main",
            "target_dir": "skills/csp/mock",
            "last_synced_commit": "abcdef1234567890",
            "last_synced_date": "2026-11-04T00:00:00Z",
            "sync_mappings": [{"source": "skills", "target": "skills"}],
            "preserve_files": ["README.md"],
        }

        mock_fetch.return_value = {
            "sha": "abcdef1234567890",
            "commit": {"message": "noop", "committer": {"date": "2026-11-04T00:00:00Z"}},
        }

        res = sync_provider("mock", provider_data, force=False, dry_run=False)
        self.assertEqual(res["status"], "UP_TO_DATE")
        self.assertFalse(res["drift"])
        self.assertFalse(res["synced"])

    @patch("scripts.ci.sync_csp_content.save_config")
    @patch("scripts.ci.sync_csp_content.run_repo_validation", return_value=(True, "Clean"))
    @patch("scripts.ci.sync_csp_content.sync_provider")
    @patch("scripts.ci.sync_csp_content.load_config")
    @patch("sys.argv", ["sync_csp_content.py", "--provider", "aws"])
    def test_main_exit_zero_on_successful_sync(self, mock_load, mock_sync, mock_val, mock_save):
        """Verify main exits with 0 (not 2) when upstream changes are successfully synchronized."""
        from scripts.ci.sync_csp_content import main

        mock_load.return_value = {
            "version": "1.0.0",
            "providers": {"aws": {"name": "AWS", "repository": "aws/repo"}},
        }
        mock_sync.return_value = {
            "name": "AWS",
            "repository": "aws/repo",
            "target_dir": "skills/csp/aws",
            "status": "SYNCHRONIZED",
            "synced": True,
            "latest_sha": "c48a8a8b",
            "latest_date": "2026-11-13T00:00:00Z",
            "diff_summary": {"has_changes": True, "total_changed": 17},
        }

        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 0)

    @patch("scripts.ci.sync_csp_content.sync_provider")
    @patch("scripts.ci.sync_csp_content.load_config")
    @patch("sys.argv", ["sync_csp_content.py", "--provider", "aws", "--dry-run"])
    def test_main_exit_two_on_dry_run_drift(self, mock_load, mock_sync):
        """Verify main exits with 2 when dry-run detects upstream drift."""
        from scripts.ci.sync_csp_content import main

        mock_load.return_value = {
            "version": "1.0.0",
            "providers": {"aws": {"name": "AWS", "repository": "aws/repo"}},
        }
        mock_sync.return_value = {
            "name": "AWS",
            "repository": "aws/repo",
            "target_dir": "skills/csp/aws",
            "status": "DRIFT_DETECTED",
            "drift": True,
            "synced": False,
        }

        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 2)

    @patch("scripts.ci.sync_csp_content.sync_provider")
    @patch("scripts.ci.sync_csp_content.load_config")
    @patch("sys.argv", ["sync_csp_content.py", "--provider", "aws"])
    def test_main_exit_one_on_failure(self, mock_load, mock_sync):
        """Verify main exits with 1 when provider sync fails."""
        from scripts.ci.sync_csp_content import main

        mock_load.return_value = {
            "version": "1.0.0",
            "providers": {"aws": {"name": "AWS", "repository": "aws/repo"}},
        }
        mock_sync.return_value = {
            "name": "AWS",
            "repository": "aws/repo",
            "target_dir": "skills/csp/aws",
            "status": "CLONE_FAILED",
            "synced": False,
            "error": "Network timeout",
        }

        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)

    @patch("scripts.ci.sync_csp_content.sync_provider")
    @patch("scripts.ci.sync_csp_content.load_config")
    @patch("sys.argv", ["sync_csp_content.py", "--provider", "aws"])
    def test_main_exit_zero_when_up_to_date(self, mock_load, mock_sync):
        """Verify main exits with 0 when all skills are already up to date."""
        from scripts.ci.sync_csp_content import main

        mock_load.return_value = {
            "version": "1.0.0",
            "providers": {"aws": {"name": "AWS", "repository": "aws/repo"}},
        }
        mock_sync.return_value = {
            "name": "AWS",
            "repository": "aws/repo",
            "target_dir": "skills/csp/aws",
            "status": "UP_TO_DATE",
            "drift": False,
            "synced": False,
        }

        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
