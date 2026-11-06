"""Unit tests for fail-closed scanner availability protocol and signed exceptions engine.

Validates that missing required scanners halt execution with INCOMPLETE_CHECK_FAILED (exit 1),
missing advisory scanners mark runs as INCONCLUSIVE_PARTIAL_AUDIT (exit 2),
and signed exceptions in .ocagents/exceptions.json are enforced with strict 90-day lifespans.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from ocagents.scanner.availability import (
    AvailabilityReport,
    AvailabilityStatus,
    ScannerAvailabilityProtocol,
)
from ocagents.scanner.exceptions import (
    ExceptionRecord,
    ExceptionsManifest,
    parse_iso_timestamp,
)
from ocagents.scanner.registry import get_default_registry

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "exceptions"
VALID_EXCEPTIONS_FIXTURE = FIXTURES_DIR / "valid_exceptions.json"
EXPIRED_EXCEPTIONS_FIXTURE = FIXTURES_DIR / "expired_exceptions.json"
EXCEEDS_90_DAYS_FIXTURE = FIXTURES_DIR / "exceeds_90_days.json"
MISSING_FIELDS_FIXTURE = FIXTURES_DIR / "missing_fields.json"

# Fixed reference time for deterministic testing: 2026-11-15T12:00:00Z
FIXED_REF_TIME = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)


class TestExceptionsManifest(unittest.TestCase):
    """Test suite for .ocagents/exceptions.json parser and 90-day boundary validation."""

    def test_load_valid_exceptions(self) -> None:
        """Valid exceptions load successfully and match active reference windows."""
        manifest = ExceptionsManifest(manifest_path=VALID_EXCEPTIONS_FIXTURE)
        self.assertEqual(manifest.total_count, 2)
        self.assertEqual(len(manifest.invalid_records), 0)

        active = manifest.active_exceptions(reference_time=FIXED_REF_TIME)
        self.assertEqual(len(active), 2)

    def test_is_exempt_matching(self) -> None:
        """Glob pattern and rule matching correctly identifies exempt target files."""
        manifest = ExceptionsManifest(manifest_path=VALID_EXCEPTIONS_FIXTURE)

        # Match checkov exception on infra/legacy/**
        self.assertTrue(manifest.is_exempt("checkov", "infra/legacy/vpc.tf", reference_time=FIXED_REF_TIME))
        self.assertTrue(manifest.is_exempt("checkov", "infra/legacy/sub/db.tf", reference_time=FIXED_REF_TIME))
        self.assertFalse(manifest.is_exempt("checkov", "infra/prod/vpc.tf", reference_time=FIXED_REF_TIME))

        # Match rule_id exception on infra/sandbox/*.tf
        self.assertTrue(manifest.is_exempt("rules/01-destructive-actions.md", "infra/sandbox/test.tf", reference_time=FIXED_REF_TIME))
        self.assertFalse(manifest.is_exempt("rules/01-destructive-actions.md", "infra/prod/main.tf", reference_time=FIXED_REF_TIME))

    def test_expired_exception_rejected(self) -> None:
        """Exceptions with expires_at in the past are rejected and do not grant exemption."""
        manifest = ExceptionsManifest(manifest_path=EXPIRED_EXCEPTIONS_FIXTURE)
        self.assertEqual(manifest.total_count, 1)

        # In 2026, the 2023 exception is expired
        self.assertEqual(len(manifest.active_exceptions(reference_time=FIXED_REF_TIME)), 0)
        self.assertEqual(len(manifest.expired_exceptions(reference_time=FIXED_REF_TIME)), 1)
        self.assertFalse(manifest.is_exempt("checkov", "infra/legacy/vpc.tf", reference_time=FIXED_REF_TIME))

    def test_exceeds_90_days_rejected(self) -> None:
        """Exceptions exceeding 90-day maximum lifespan are invalid and rejected on load."""
        manifest = ExceptionsManifest(manifest_path=EXCEEDS_90_DAYS_FIXTURE)
        self.assertEqual(manifest.total_count, 0)
        self.assertEqual(len(manifest.invalid_records), 1)
        self.assertIn("90 days", manifest.invalid_records[0][1])

    def test_missing_mandatory_fields_rejected(self) -> None:
        """Exceptions missing required justification, owner, or timestamps are rejected."""
        manifest = ExceptionsManifest(manifest_path=MISSING_FIELDS_FIXTURE)
        self.assertEqual(manifest.total_count, 0)
        self.assertEqual(len(manifest.invalid_records), 1)

    def test_empty_or_missing_manifest_handled_gracefully(self) -> None:
        """A non-existent manifest path returns an empty manifest without throwing errors."""
        manifest = ExceptionsManifest(manifest_path=FIXTURES_DIR / "nonexistent.json")
        self.assertEqual(manifest.total_count, 0)
        self.assertFalse(manifest.is_exempt("checkov", "infra/main.tf"))


class TestScannerAvailabilityProtocol(unittest.TestCase):
    """Test suite for fail-closed scanner availability protocol and exit codes."""

    def setUp(self) -> None:
        self.registry = get_default_registry()
        self.empty_manifest = ExceptionsManifest(records=[])
        self.valid_manifest = ExceptionsManifest(manifest_path=VALID_EXCEPTIONS_FIXTURE)

    def test_all_scanners_available_returns_clean(self) -> None:
        """When all required and advisory scanners are installed, status is CLEAN (exit 0)."""
        # Mock which_fn returning an executable path for all tool names
        mock_which = lambda cmd: f"/usr/local/bin/{cmd}"
        protocol = ScannerAvailabilityProtocol(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        changeset = ["infra/vpc.tf", "scripts/deploy.sh"]
        report = protocol.check_changeset(changeset, reference_time=FIXED_REF_TIME)

        self.assertEqual(report.status, AvailabilityStatus.CLEAN)
        self.assertEqual(report.exit_code, 0)
        self.assertTrue(report.is_clean)
        self.assertEqual(len(report.missing_required), 0)
        self.assertEqual(len(report.missing_advisory), 0)

    def test_missing_required_scanner_halts_with_exit_code_1(self) -> None:
        """When a required scanner is missing without exception, emit INCOMPLETE_CHECK_FAILED (exit 1)."""
        # checkov is missing
        def mock_which(cmd: str) -> str | None:
            if cmd == "checkov":
                return None
            return f"/usr/local/bin/{cmd}"

        protocol = ScannerAvailabilityProtocol(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        changeset = ["infra/vpc.tf"]  # .tf requires checkov
        report = protocol.check_changeset(changeset, reference_time=FIXED_REF_TIME)

        self.assertEqual(report.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(report.exit_code, 1)
        self.assertTrue(report.is_failed)
        self.assertIn("checkov", report.missing_required)
        self.assertIn("FAIL-CLOSED", report.diagnostics[0])

    def test_missing_required_scanner_with_valid_exception_passes_clean(self) -> None:
        """When a missing required scanner has an active signed exception, audit proceeds (exit 0)."""
        # checkov is missing
        def mock_which(cmd: str) -> str | None:
            if cmd == "checkov":
                return None
            return f"/usr/local/bin/{cmd}"

        protocol = ScannerAvailabilityProtocol(
            registry=self.registry,
            exceptions_manifest=self.valid_manifest,
            which_fn=mock_which,
        )

        # infra/legacy/** is covered by valid_exceptions.json
        changeset = ["infra/legacy/vpc.tf"]
        report = protocol.check_changeset(changeset, reference_time=FIXED_REF_TIME)

        self.assertEqual(report.status, AvailabilityStatus.CLEAN)
        self.assertEqual(report.exit_code, 0)
        self.assertTrue(report.is_clean)
        self.assertEqual(len(report.missing_required), 0)
        self.assertEqual(len(report.exemptions_applied), 1)
        self.assertEqual(report.exemptions_applied[0]["scanner"], "checkov")

    def test_missing_required_scanner_with_expired_exception_halts(self) -> None:
        """When an exception for a missing scanner is expired, fail-closed gate is restored (exit 1)."""
        expired_manifest = ExceptionsManifest(manifest_path=EXPIRED_EXCEPTIONS_FIXTURE)
        mock_which = lambda cmd: None if cmd == "checkov" else f"/usr/local/bin/{cmd}"

        protocol = ScannerAvailabilityProtocol(
            registry=self.registry,
            exceptions_manifest=expired_manifest,
            which_fn=mock_which,
        )

        changeset = ["infra/legacy/vpc.tf"]
        report = protocol.check_changeset(changeset, reference_time=FIXED_REF_TIME)

        self.assertEqual(report.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(report.exit_code, 1)
        self.assertIn("checkov", report.missing_required)

    def test_missing_advisory_scanner_marks_inconclusive_exit_code_2(self) -> None:
        """When an advisory scanner is missing without exception, mark INCONCLUSIVE_PARTIAL_AUDIT (exit 2)."""
        # checkov is available, but trivy (advisory on .tf) is missing
        def mock_which(cmd: str) -> str | None:
            if cmd == "trivy":
                return None
            return f"/usr/local/bin/{cmd}"

        protocol = ScannerAvailabilityProtocol(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=mock_which,
        )

        changeset = ["infra/vpc.tf"]
        report = protocol.check_changeset(changeset, reference_time=FIXED_REF_TIME)

        self.assertEqual(report.status, AvailabilityStatus.INCONCLUSIVE_PARTIAL_AUDIT)
        self.assertEqual(report.exit_code, 2)
        self.assertTrue(report.is_inconclusive)
        self.assertIn("trivy", report.missing_advisory)
        self.assertEqual(len(report.missing_required), 0)
        self.assertIn("DEGRADED COVERAGE", report.diagnostics[0])

    def test_empty_changeset_returns_clean(self) -> None:
        """An empty changeset requires no scanners and returns CLEAN."""
        protocol = ScannerAvailabilityProtocol(
            registry=self.registry,
            exceptions_manifest=self.empty_manifest,
            which_fn=lambda cmd: None,  # Even with zero tools installed
        )
        report = protocol.check_changeset([])
        self.assertEqual(report.status, AvailabilityStatus.CLEAN)
        self.assertEqual(report.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
