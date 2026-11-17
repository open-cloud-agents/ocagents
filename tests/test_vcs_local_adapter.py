"""
Unit tests for Open Cloud Agents: Local Git Adapter (ADR-003, Multi-VCS Phase 1).
"""

import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ocagents.vcs import LocalGitAdapter, VCSProvider

HAS_GIT = shutil.which("git") is not None


def _git(repo, *args):
    subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


class TestLocalGitAdapterOutput(unittest.TestCase):
    """Terminal output, status validation and artifacts (no git needed)."""

    def setUp(self):
        self.out = io.StringIO()
        self.adapter = LocalGitAdapter(repo_root=".", stream=self.out)

    def test_is_a_vcs_provider(self):
        self.assertIsInstance(self.adapter, VCSProvider)

    def test_post_pr_summary_prints_markdown(self):
        self.assertTrue(self.adapter.post_pr_summary("42", "## Verdict\nApprove"))
        text = self.out.getvalue()
        self.assertIn("review summary (42)", text)
        self.assertIn("## Verdict\nApprove", text)

    def test_post_inline_annotations_counts_and_formats(self):
        findings = [
            {"id": "FND-1", "severity": "high", "evidence": "main.tf:12", "fact": "Bucket is public"},
            {"id": "FND-2", "severity": "low", "resource": "aws_s3_bucket.logs", "fact": "Missing tags"},
            "not-a-dict",
        ]
        self.assertEqual(self.adapter.post_inline_annotations("1", findings), 2)
        lines = self.out.getvalue().splitlines()
        self.assertEqual(lines[0], "[HIGH] main.tf:12: Bucket is public (FND-1)")
        self.assertEqual(lines[1], "[LOW] aws_s3_bucket.logs: Missing tags (FND-2)")

    def test_post_inline_annotations_handles_empty_input(self):
        self.assertEqual(self.adapter.post_inline_annotations("1", []), 0)
        self.assertEqual(self.adapter.post_inline_annotations("1", None), 0)

    def test_terminal_control_characters_are_stripped(self):
        """Model-generated text must not inject terminal escape sequences."""
        findings = [{"id": "FND-1", "severity": "high", "evidence": "a.tf:1", "fact": "x\x1b[2J\x1b]0;pwned\x07y"}]
        self.adapter.post_inline_annotations("1", findings)
        self.adapter.post_pr_summary("1", "safe\x1b[31mred\x1b[0m")
        text = self.out.getvalue()
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        # Only the invisible control bytes are removed; the printable text stays readable.
        self.assertIn("x[2J]0;pwnedy", text)
        self.assertIn("safe[31mred[0m", text)

    def test_set_commit_status_valid_states(self):
        for state in ("success", "failed", "pending"):
            with self.subTest(state=state):
                self.assertTrue(self.adapter.set_commit_status("a" * 40, state, "All checks done"))
        self.assertIn("[ocagents/quality-gate] success: All checks done (aaaaaaaaaaaa)", self.out.getvalue())

    def test_set_commit_status_rejects_unknown_state(self):
        with self.assertRaises(ValueError):
            self.adapter.set_commit_status("abc", "failure", "GitHub vocabulary is not the shared contract")

    def test_export_native_artifacts_writes_json(self):
        findings = [{"id": "FND-1", "severity": "high", "fact": "Ünïcode ok"}]
        with tempfile.TemporaryDirectory() as tmp:
            paths = self.adapter.export_native_artifacts(findings, Path(tmp) / "out")
            self.assertEqual(len(paths), 1)
            self.assertEqual(json.loads(paths[0].read_text(encoding="utf-8")), findings)


@unittest.skipUnless(HAS_GIT, "git is not installed")
class TestLocalGitAdapterGit(unittest.TestCase):
    """Diff and context detection against a real temporary repository."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "main.tf").write_text('resource "x" "y" {}\n', encoding="utf-8")
        _git(self.repo, "add", "main.tf")
        _git(self.repo, "commit", "-q", "-m", "first")
        _git(self.repo, "tag", "base")
        (self.repo / "main.tf").write_text('resource "x" "y" {\n  public = true\n}\n', encoding="utf-8")
        _git(self.repo, "commit", "-q", "-am", "second")
        self.adapter = LocalGitAdapter(repo_root=self.repo, stream=io.StringIO())

    def tearDown(self):
        self._tmp.cleanup()

    def test_detect_context_inside_repository(self):
        self.assertTrue(self.adapter.detect_context())

    def test_detect_context_outside_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / "plain"
            plain.mkdir()
            env_guard = {"GIT_CEILING_DIRECTORIES": tmp}
            with mock.patch.dict("os.environ", env_guard):
                self.assertFalse(LocalGitAdapter(repo_root=plain).detect_context())

    def test_get_diff_returns_unified_diff(self):
        diff = self.adapter.get_diff("base", "HEAD")
        self.assertIn("diff --git a/main.tf b/main.tf", diff)
        self.assertIn("+  public = true", diff)

    def test_get_diff_unknown_ref_raises_runtime_error(self):
        with self.assertRaises(RuntimeError):
            self.adapter.get_diff("does-not-exist", "HEAD")

    def test_get_diff_rejects_option_injection(self):
        for bad in ("--output=/tmp/x", "-p", "", "main branch", "ref\x00null"):
            with self.subTest(ref=bad):
                with self.assertRaises(ValueError):
                    self.adapter.get_diff(bad, "HEAD")
                with self.assertRaises(ValueError):
                    self.adapter.get_diff("base", bad)


if __name__ == "__main__":
    unittest.main()
