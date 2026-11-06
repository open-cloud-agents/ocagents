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
import subprocess
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
        self.clean_runner = lambda cmd, **kwargs: subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="[]",
            stderr="",
        )

    def test_preflight_clean_pass_exit_0(self) -> None:
        """When all required and advisory scanners are available and no violations exist, status is CLEAN (exit 0)."""
        mock_which = lambda cmd: f"/usr/local/bin/{cmd}"
        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
            runner_fn=self.clean_runner,
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
            runner_fn=self.clean_runner,
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
            runner_fn=self.clean_runner,
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
            runner_fn=self.clean_runner,
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
            runner_fn=self.clean_runner,
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
            runner_fn=self.clean_runner,
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
            runner_fn=self.clean_runner,
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
            runner_fn=self.clean_runner,
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
            runner_fn=self.clean_runner,
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

    def test_preflight_executes_checkov_and_aggregates_findings(self) -> None:
        """When checkov is available, it is actually invoked, its output parsed and findings aggregated."""
        checkov_output = json.dumps({
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "bc_check_id": None,
                        "check_name": "Ensure S3 bucket has an ACL defined",
                        "check_result": {"result": "FAILED"},
                        "file_path": "infra/main.tf",
                        "file_line_range": [10, 20],
                        "resource": "aws_s3_bucket.data",
                        "severity": "HIGH",
                    }
                ]
            }
        })

        def runner(cmd, **kwargs):
            if "checkov" in cmd[0]:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=checkov_output, stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[]", stderr="")

        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=lambda c: f"/usr/local/bin/{c}",
            runner_fn=runner,
        )

        result = engine.run(changeset=["infra/main.tf"], reference_time=FIXED_REF_TIME)

        self.assertIn("checkov", result.executed_scanners)
        self.assertEqual(result.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0]["metadata"]["check_id"], "CKV_AWS_20")

    def test_preflight_executes_shellcheck_and_ruff(self) -> None:
        """When shellcheck and ruff are available, both are invoked and their findings aggregated."""
        shellcheck_output = json.dumps([
            {
                "file": "scripts/deploy.sh",
                "line": 15,
                "endLine": 15,
                "column": 5,
                "endColumn": 12,
                "level": "warning",
                "code": 2086,
                "message": "Double quote to prevent globbing and word splitting.",
            }
        ])
        ruff_output = json.dumps([
            {
                "code": "F401",
                "message": "'os' imported but unused",
                "filename": "src/module.py",
                "location": {"row": 5, "column": 1},
                "end_location": {"row": 5, "column": 10},
            }
        ])

        def runner(cmd, **kwargs):
            if "shellcheck" in cmd[0]:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=shellcheck_output, stderr="")
            if "ruff" in cmd[0]:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=ruff_output, stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[]", stderr="")

        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=lambda c: f"/usr/local/bin/{c}",
            runner_fn=runner,
        )

        result = engine.run(changeset=["scripts/deploy.sh", "src/module.py"], reference_time=FIXED_REF_TIME)

        self.assertIn("shellcheck", result.executed_scanners)
        self.assertIn("ruff", result.executed_scanners)
        self.assertEqual(len(result.findings), 2)
        rule_ids = {f["rule_id"] for f in result.findings}
        self.assertIn("shellcheck/SC2086", rule_ids)
        self.assertIn("ruff/F401", rule_ids)

    def test_preflight_scanner_execution_crash_fails_closed(self) -> None:
        """When an available required scanner process crashes or errors out, preflight fails closed (exit 1)."""
        def crashing_runner(cmd, **kwargs):
            if "checkov" in cmd[0]:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=2,
                    stdout="",
                    stderr="SyntaxError: invalid syntax in configuration",
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[]", stderr="")

        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=lambda c: f"/usr/local/bin/{c}",
            runner_fn=crashing_runner,
        )

        result = engine.run(changeset=["infra/main.tf"], reference_time=FIXED_REF_TIME)

        self.assertEqual(result.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(result.exit_code, 1)
        self.assertTrue(result.is_failed)
        self.assertTrue(any("FAIL-CLOSED: Execution failed for required scanner(s): checkov" in d for d in result.diagnostics))

    def test_resolve_changeset_explicit_diff_target_fails_closed(self) -> None:
        """Explicit diff target fails closed without falling back to working-tree changes."""
        engine = PreflightEngine(registry=self.registry)

        # 1. Non-existent patch file raises FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            engine.resolve_changeset(diff_target="nonexistent_patch_file.patch")

        # 2. Unresolvable git ref raises ValueError
        def failing_git_runner(cmd, **kwargs):
            return subprocess.CompletedProcess(args=cmd, returncode=128, stdout="", stderr="fatal: bad revision")

        engine_with_failing_git = PreflightEngine(
            registry=self.registry,
            runner_fn=failing_git_runner,
        )
        with self.assertRaises(ValueError):
            engine_with_failing_git.resolve_changeset(diff_target="nonexistent-branch-or-ref")

        # 3. run_preflight convenience helper captures failure and returns exit code 1
        res = run_preflight(diff_target="missing.patch", repo_root=Path(__file__).resolve().parent.parent)
        self.assertEqual(res.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(res.exit_code, 1)
        self.assertTrue(any("FAIL-CLOSED" in d for d in res.diagnostics))

    def test_preflight_advisory_warnings_status_is_advisory_not_clean(self) -> None:
        """When medium or low advisory findings exist and --strict is false, status is ADVISORY_WARNINGS (exit 2)."""
        shellcheck_warning = json.dumps([
            {
                "file": "scripts/build.sh",
                "line": 10,
                "endLine": 10,
                "column": 5,
                "endColumn": 12,
                "level": "warning",
                "code": 2086,
                "message": "Double quote to prevent globbing and word splitting.",
            }
        ])

        def runner(cmd, **kwargs):
            if "shellcheck" in cmd[0]:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=shellcheck_warning, stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[]", stderr="")

        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=lambda c: f"/usr/local/bin/{c}",
            runner_fn=runner,
        )

        result = engine.run(changeset=["scripts/build.sh"], strict=False, reference_time=FIXED_REF_TIME)

        # Status must be ADVISORY_WARNINGS with exit code 2, NEVER CLEAN!
        self.assertEqual(result.status, AvailabilityStatus.ADVISORY_WARNINGS)
        self.assertEqual(result.exit_code, 2)
        self.assertFalse(result.is_clean)
        self.assertTrue(result.is_inconclusive)
        self.assertTrue(result.has_advisories)

        # Verify summary output formatting
        summary = result.format_terminal_summary(use_color=False)
        self.assertIn("VERDICT: ADVISORY_WARNINGS (Exit Code 2)", summary)
        self.assertNotIn("VERDICT: CLEAN", summary)

        # Verify JSON representation
        data = result.to_dict()
        self.assertEqual(data["status"], "ADVISORY_WARNINGS")
        self.assertEqual(data["exit_code"], 2)

    def test_preflight_tampered_or_unsigned_exceptions_rejected(self) -> None:
        """Unsigned or tampered exceptions in manifest are rejected and fail closed when required scanner missing."""
        unsigned_manifest_path = FIXTURES_DIR / "exceptions" / "unsigned_exceptions.json"
        unsigned_manifest = ExceptionsManifest(manifest_path=unsigned_manifest_path, require_signature=True)

        engine = PreflightEngine(
            registry=self.registry,
            exceptions_manifest=unsigned_manifest,
            which_fn=lambda c: None if c == "checkov" else f"/usr/local/bin/{c}",
            runner_fn=self.clean_runner,
        )

        # infra/legacy/vpc.tf should NOT be exempt because exception signature was missing
        result = engine.run(changeset=["infra/legacy/vpc.tf"], reference_time=FIXED_REF_TIME)

        self.assertEqual(result.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(result.exit_code, 1)
        self.assertTrue(result.is_failed)
        self.assertEqual(len(result.exemptions_applied), 0)
        self.assertTrue(any("unsigned" in d.lower() or "rejected" in d.lower() for d in result.diagnostics))


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
