"""Channel Availability & Dependency Smoke Tests for Deterministic Pre-Flight Gate.

Verifies:
- Pip optional-dependencies extra 'preflight' in pyproject.toml
- requirements-scanners.txt pinning and synchronization
- Homebrew formula dependency declarations (:recommended vs optional)
- Accurate reporting of missing tools (never claiming execution when missing)
- Fail-closed exit codes (1 for missing required, 2 for missing advisory)
- Strict mode escalation (exit 2 -> exit 1)
- Zero false-clean invariant across all distribution channels
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from ocagents.scanner.availability import AvailabilityStatus
from ocagents.scanner.exceptions import ExceptionsManifest
from ocagents.scanner.preflight import PreflightEngine
from ocagents.scanner.registry import get_default_registry


class TestPreflightChannelsAndPackaging(unittest.TestCase):
    """Smoke tests for packaging metadata, dependency declarations, and channel availability."""

    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parent.parent
        self.registry = get_default_registry()
        self.empty_manifest = ExceptionsManifest(records=[])

    def test_pyproject_preflight_extra_metadata(self) -> None:
        """Verifies pyproject.toml declares [project.optional-dependencies].preflight with pinned versions."""
        pyproject_path = self.repo_root / "pyproject.toml"
        self.assertTrue(pyproject_path.exists(), "pyproject.toml must exist in repo root")

        content = pyproject_path.read_text(encoding="utf-8")
        self.assertIn("[project.optional-dependencies]", content)
        self.assertIn("preflight = [", content)
        self.assertIn("ruff==", content)
        self.assertIn("checkov==", content)

    def test_requirements_scanners_file_sync(self) -> None:
        """Verifies packaging/requirements-scanners.txt exists, is pinned, and documents update protocol."""
        req_path = self.repo_root / "packaging" / "requirements-scanners.txt"
        self.assertTrue(req_path.exists(), "packaging/requirements-scanners.txt must exist")

        lines = [line.strip() for line in req_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        pins = {line.split("==")[0]: line.split("==")[1] for line in lines if "==" in line}

        self.assertIn("ruff", pins)
        self.assertIn("checkov", pins)
        self.assertEqual(pins["ruff"], "0.17.4")
        self.assertEqual(pins["checkov"], "3.2.368")

    def test_homebrew_formula_dependencies(self) -> None:
        """Verifies Homebrew formula declares linters as :recommended dependencies."""
        formula_path = self.repo_root / "Formula" / "ocagents.rb"
        self.assertTrue(formula_path.exists(), "Formula/ocagents.rb must exist")

        content = formula_path.read_text(encoding="utf-8")
        self.assertIn('depends_on "python@3.11" => :recommended', content)
        self.assertIn('depends_on "shellcheck" => :recommended', content)
        self.assertIn('depends_on "ruff" => :recommended', content)

    def test_missing_required_python_linter_reports_failure_without_execution(self) -> None:
        """Verifies that missing required 'ruff' fails closed (exit 1) and is NOT claimed as executed."""
        def mock_which(cmd: str) -> str | None:
            if cmd in ("python3", "python"):
                return "/usr/bin/python3"
            return None  # ruff missing

        engine = PreflightEngine(
            repo_root=self.repo_root,
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        result = engine.run(changeset=["src/app.py"])

        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        # Invariant: ruff was missing, so it must NEVER appear in executed_scanners
        self.assertNotIn("ruff", result.executed_scanners)
        # It must be recorded in skipped_scanners with level == 'REQUIRED'
        skipped_names = [s.get("name") for s in result.skipped_scanners]
        self.assertIn("ruff", skipped_names)
        ruff_skip = next(s for s in result.skipped_scanners if s.get("name") == "ruff")
        self.assertEqual(ruff_skip.get("level"), "REQUIRED")

    def test_missing_required_iac_scanner_reports_failure_without_execution(self) -> None:
        """Verifies that missing required 'checkov' for .tf files fails closed (exit 1)."""
        def mock_which(cmd: str) -> str | None:
            if cmd in ("python3", "python"):
                return "/usr/bin/python3"
            return None  # checkov missing

        engine = PreflightEngine(
            repo_root=self.repo_root,
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        result = engine.run(changeset=["terraform/main.tf"])

        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertNotIn("checkov", result.executed_scanners)
        skipped_names = [s.get("name") for s in result.skipped_scanners]
        self.assertIn("checkov", skipped_names)
        checkov_skip = next(s for s in result.skipped_scanners if s.get("name") == "checkov")
        self.assertEqual(checkov_skip.get("level"), "REQUIRED")

    def test_missing_advisory_scanner_reports_inconclusive_without_execution(self) -> None:
        """Verifies that missing advisory 'codeql' yields exit 2 with degraded coverage."""
        def mock_which(cmd: str) -> str | None:
            if cmd == "ruff":
                return "/opt/bin/ruff"
            if cmd in ("python3", "python"):
                return "/usr/bin/python3"
            return None  # codeql missing

        def mock_runner(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[]", stderr="")

        engine = PreflightEngine(
            repo_root=self.repo_root,
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
            runner_fn=mock_runner,
        )

        result = engine.run(changeset=["src/app.py"])

        self.assertEqual(result.exit_code, 2)
        self.assertEqual(result.status, AvailabilityStatus.INCONCLUSIVE_PARTIAL_AUDIT)
        # ruff executed cleanly
        self.assertIn("ruff", result.executed_scanners)
        # codeql was missing and must NOT be in executed_scanners
        self.assertNotIn("codeql", result.executed_scanners)
        # codeql must be listed in skipped_scanners
        skipped_names = [s.get("name") for s in result.skipped_scanners]
        self.assertIn("codeql", skipped_names)
        codeql_skip = next(s for s in result.skipped_scanners if s.get("name") == "codeql")
        self.assertEqual(codeql_skip.get("level"), "ADVISORY")

    def test_strict_mode_escalates_missing_advisory_to_failure(self) -> None:
        """Verifies that --strict mode escalates missing advisory scanners to exit code 1."""
        def mock_which(cmd: str) -> str | None:
            if cmd == "ruff":
                return "/opt/bin/ruff"
            if cmd in ("python3", "python"):
                return "/usr/bin/python3"
            return None  # codeql missing

        def mock_runner(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[]", stderr="")

        engine = PreflightEngine(
            repo_root=self.repo_root,
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
            runner_fn=mock_runner,
        )

        result = engine.run(changeset=["src/app.py"], strict=True)

        self.assertEqual(result.exit_code, 1)
        self.assertEqual(result.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertTrue(result.strict)

    def test_zero_false_clean_invariant(self) -> None:
        """Verifies that uninspected or unavailable required scanners can never produce CLEAN (exit 0)."""
        def mock_which_none(cmd: str) -> str | None:
            return None

        engine = PreflightEngine(
            repo_root=self.repo_root,
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which_none,
        )

        for sample_file in ("main.tf", "script.sh", "server.py"):
            with self.subTest(file=sample_file):
                result = engine.run(changeset=[sample_file])
                self.assertNotEqual(result.exit_code, 0, f"Uninspected file {sample_file} must never return exit 0")
                self.assertNotEqual(result.status, AvailabilityStatus.CLEAN)


if __name__ == "__main__":
    unittest.main()
