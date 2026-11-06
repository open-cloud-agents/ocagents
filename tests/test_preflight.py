"""Unit and integration tests for deterministic pre-flight gatekeeper and CLI preflight command (v1.5 TASK-2.6).

Verifies:
- ocagents preflight [--diff] [--strict] [--json]
- Changeset resolution from explicit paths, git diffs, and patch files
- Fail-closed scanner availability protocol (exit 0 on clean pass, 1 on required failure, 2 on advisory warnings)
- Strict mode escalation of advisory warnings to exit code 1
- OPA and DevSecOps heuristic diff screen integration
- Machine-readable JSON reporting and colorized terminal summary
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from ocagents.scanner.availability import AvailabilityStatus
from ocagents.scanner.exceptions import ExceptionsManifest
from ocagents.scanner.preflight import (
    PreflightEngine,
    PreflightResult,
    audit_diff_heuristics,
    parse_diff_target_files,
    run_preflight,
)
from ocagents.scanner.registry import get_default_registry

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
EXCEPTIONS_FIXTURE = FIXTURES_DIR / "exceptions" / "valid_exceptions.json"
TF_DESTRUCTIVE_FIXTURE = FIXTURES_DIR / "terraform" / "tfplan_destructive.json"
K8S_INSECURE_FIXTURE = FIXTURES_DIR / "kubernetes" / "deployment_insecure.yaml"

# Fixed reference time for deterministic exception expiry: 2026-11-15T12:00:00Z
FIXED_REF_TIME = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)


class TestPreflightEngine(unittest.TestCase):
    """Test suite for deterministic pre-flight gatekeeper engine and invariants."""

    def setUp(self) -> None:
        self.registry = get_default_registry()
        self.manifest = ExceptionsManifest(manifest_path=EXCEPTIONS_FIXTURE)
        self.empty_manifest = ExceptionsManifest(records=[])

    def test_preflight_clean_pass_exit_0(self) -> None:
        """When all required and advisory scanners are available and no violations exist, status is CLEAN (exit 0)."""
        mock_which = lambda cmd: f"/usr/local/bin/{cmd}"
        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        changeset = ["infra/main.tf", "scripts/deploy.sh"]
        result = engine.run(changeset=changeset, strict=False, reference_time=FIXED_REF_TIME)

        self.assertEqual(result.status, AvailabilityStatus.CLEAN)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.is_clean)
        self.assertFalse(result.is_failed)
        self.assertEqual(len(result.skipped_scanners), 0)

    def test_preflight_missing_required_scanner_exit_1(self) -> None:
        """When a required scanner is missing without exception, halt with INCOMPLETE_CHECK_FAILED (exit 1)."""
        # checkov is missing
        def mock_which(cmd: str) -> str | None:
            if cmd == "checkov":
                return None
            return f"/usr/local/bin/{cmd}"

        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        changeset = ["infra/vpc.tf"]  # requires checkov
        result = engine.run(changeset=changeset, strict=False, reference_time=FIXED_REF_TIME)

        self.assertEqual(result.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(result.exit_code, 1)
        self.assertTrue(result.is_failed)
        req_skipped = [s for s in result.skipped_scanners if s["level"] == "REQUIRED"]
        self.assertEqual(len(req_skipped), 1)
        self.assertEqual(req_skipped[0]["name"], "checkov")

    def test_preflight_missing_required_with_valid_exception_passes_exit_0(self) -> None:
        """When a required scanner is missing but covered by signed exception, gate proceeds (exit 0)."""
        mock_which = lambda cmd: None if cmd == "checkov" else f"/usr/local/bin/{cmd}"
        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.manifest,  # exempts checkov on infra/legacy/**
            which_fn=mock_which,
        )

        changeset = ["infra/legacy/vpc.tf"]
        result = engine.run(changeset=changeset, strict=False, reference_time=FIXED_REF_TIME)

        self.assertEqual(result.status, AvailabilityStatus.CLEAN)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.is_clean)
        self.assertEqual(len(result.exemptions_applied), 1)
        self.assertEqual(result.exemptions_applied[0]["scanner"], "checkov")

    def test_preflight_missing_advisory_scanner_exit_2(self) -> None:
        """When an advisory scanner is missing without exception, mark INCONCLUSIVE_PARTIAL_AUDIT (exit 2)."""
        # trivy is missing, but checkov is available
        def mock_which(cmd: str) -> str | None:
            if cmd == "trivy":
                return None
            return f"/usr/local/bin/{cmd}"

        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        changeset = ["infra/vpc.tf"]
        result = engine.run(changeset=changeset, strict=False, reference_time=FIXED_REF_TIME)

        self.assertEqual(result.status, AvailabilityStatus.INCONCLUSIVE_PARTIAL_AUDIT)
        self.assertEqual(result.exit_code, 2)
        self.assertTrue(result.is_inconclusive)
        adv_skipped = [s for s in result.skipped_scanners if s["level"] == "ADVISORY"]
        self.assertEqual(len(adv_skipped), 1)
        self.assertEqual(adv_skipped[0]["name"], "trivy")

    def test_preflight_strict_mode_escalates_advisory_exit_1(self) -> None:
        """In strict mode (--strict), missing advisory scanner escalates to failure (exit 1)."""
        def mock_which(cmd: str) -> str | None:
            if cmd == "trivy":
                return None
            return f"/usr/local/bin/{cmd}"

        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        changeset = ["infra/vpc.tf"]
        result = engine.run(changeset=changeset, strict=True, reference_time=FIXED_REF_TIME)

        self.assertEqual(result.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(result.exit_code, 1)
        self.assertTrue(result.is_failed)
        self.assertTrue(result.strict)
        self.assertTrue(any("Strict mode" in d for d in result.diagnostics))

    def test_preflight_destructive_diff_heuristic_fails_exit_1(self) -> None:
        """Diff heuristic flagging force_destroy = true triggers high invariant violation (exit 1)."""
        mock_which = lambda cmd: f"/usr/local/bin/{cmd}"
        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        diff_sample = """diff --git a/infra/storage.tf b/infra/storage.tf
index 1111111..2222222 100644
--- a/infra/storage.tf
+++ b/infra/storage.tf
@@ -10,3 +10,4 @@
 resource "aws_s3_bucket" "prod_data" {
   bucket = "customer-archive-prod"
+  force_destroy = true
 }
"""
        changeset = ["infra/storage.tf"]
        result = engine.run(
            changeset=changeset,
            diff_text=diff_sample,
            strict=False,
            reference_time=FIXED_REF_TIME,
        )

        self.assertEqual(result.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(result.exit_code, 1)
        self.assertTrue(result.is_failed)
        self.assertGreaterEqual(result.findings_by_severity.get("high", 0), 1)
        self.assertIn("diff_screen", result.executed_scanners)

    def test_preflight_open_ingress_diff_heuristic_fails_exit_1(self) -> None:
        """Diff heuristic flagging 0.0.0.0/0 ingress triggers high invariant violation (exit 1)."""
        mock_which = lambda cmd: f"/usr/local/bin/{cmd}"
        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        diff_sample = """diff --git a/infra/sg.tf b/infra/sg.tf
index 1111111..2222222 100644
--- a/infra/sg.tf
+++ b/infra/sg.tf
@@ -5,3 +5,4 @@
 resource "aws_security_group_rule" "inbound" {
   type = "ingress"
+  cidr_blocks = ["0.0.0.0/0"]
 }
"""
        changeset = ["infra/sg.tf"]
        result = engine.run(
            changeset=changeset,
            diff_text=diff_sample,
            strict=False,
            reference_time=FIXED_REF_TIME,
        )

        self.assertEqual(result.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(result.exit_code, 1)
        self.assertGreaterEqual(result.findings_by_severity.get("high", 0), 1)

    def test_preflight_json_serialization(self) -> None:
        """PreflightResult.to_dict() returns a valid JSON-serializable structure with all summary fields."""
        mock_which = lambda cmd: f"/usr/local/bin/{cmd}"
        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        result = engine.run(changeset=["infra/main.tf"], strict=False, reference_time=FIXED_REF_TIME)
        payload = result.to_dict()

        self.assertEqual(payload["status"], "CLEAN")
        self.assertEqual(payload["exit_code"], 0)
        self.assertIn("summary", payload)
        self.assertEqual(payload["summary"]["changeset_size"], 1)
        self.assertIn("findings_by_severity", payload["summary"])

        # Must cleanly serialize to JSON string without errors
        serialized = json.dumps(payload)
        self.assertIn('"status": "CLEAN"', serialized)
        self.assertIn('"exit_code": 0', serialized)

    def test_preflight_terminal_summary_formatting(self) -> None:
        """format_terminal_summary generates structured readable text without ANSI escapes when use_color=False."""
        mock_which = lambda cmd: f"/usr/local/bin/{cmd}"
        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        result = engine.run(changeset=["infra/main.tf"], strict=False, reference_time=FIXED_REF_TIME)
        summary = result.format_terminal_summary(use_color=False)

        self.assertIn("Open Cloud Agents: Deterministic Pre-Flight Gate", summary)
        self.assertIn("VERDICT: CLEAN (Exit Code 0)", summary)
        self.assertIn("Findings Breakdown:", summary)
        self.assertNotIn("\033[", summary)

    def test_parse_diff_target_files_helper(self) -> None:
        """parse_diff_target_files correctly extracts distinct modified paths from unified diff."""
        diff_sample = """diff --git a/infra/vpc.tf b/infra/vpc.tf
index 1234..5678 100644
--- a/infra/vpc.tf
+++ b/infra/vpc.tf
@@ -1 +1 @@
-old
+new
diff --git a/k8s/deployment.yaml b/k8s/deployment.yaml
new file mode 100644
--- /dev/null
+++ b/k8s/deployment.yaml
@@ -0,0 +1 @@
+apiVersion: apps/v1
"""
        files = parse_diff_target_files(diff_sample)
        self.assertEqual(files, ["infra/vpc.tf", "k8s/deployment.yaml"])

    def test_resolve_changeset_from_diff_file(self) -> None:
        """resolve_changeset reads from a physical unified diff file path."""
        engine = PreflightEngine(registry=self.registry)
        diff_content = """diff --git a/infra/cluster.tf b/infra/cluster.tf
--- a/infra/cluster.tf
+++ b/infra/cluster.tf
@@ -1 +1 @@
+resource "aws_eks_cluster" "main" {}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False) as tf:
            tf.write(diff_content)
            tf_path = tf.name

        try:
            files, diff_text = engine.resolve_changeset(diff_target=tf_path)
            self.assertEqual(files, ["infra/cluster.tf"])
            self.assertIsNotNone(diff_text)
            self.assertIn("aws_eks_cluster", diff_text)
        finally:
            Path(tf_path).unlink(missing_ok=True)

    def test_convenience_run_preflight_helper(self) -> None:
        """Functional run_preflight helper executes and returns PreflightResult."""
        result = run_preflight(paths=["README.md"], reference_time=FIXED_REF_TIME)
        self.assertIsInstance(result, PreflightResult)
        self.assertEqual(result.status, AvailabilityStatus.CLEAN)
        self.assertEqual(result.exit_code, 0)


class TestCliPreflightSubcommand(unittest.TestCase):
    """Test suite for ocagents preflight CLI entrypoint."""

    def test_cli_preflight_json_flag(self) -> None:
        """CLI invocation with --json outputs valid JSON payload and expected exit code."""
        from ocagents.cli import cmd_preflight

        args = argparse.Namespace(
            paths=["README.md"],
            diff=None,
            strict=False,
            json=True,
            repo_root=None,
        )

        with patch("sys.stdout.write") as mock_stdout, patch("builtins.print") as mock_print:
            exit_code = cmd_preflight(args, asset_root=Path(__file__).resolve().parent.parent)

        self.assertEqual(exit_code, 0)
        # Verify print was called with JSON
        self.assertTrue(mock_print.called)
        printed_arg = mock_print.call_args[0][0]
        parsed_json = json.loads(printed_arg)
        self.assertEqual(parsed_json["status"], "CLEAN")
        self.assertEqual(parsed_json["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
