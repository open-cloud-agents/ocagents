"""Unit tests for fail-closed scanner availability protocol and signed exceptions engine.

Validates that missing required scanners halt execution with INCOMPLETE_CHECK_FAILED (exit 1),
missing advisory scanners mark runs as INCONCLUSIVE_PARTIAL_AUDIT (exit 2),
and signed exceptions in .ocagents/exceptions.json are enforced with strict 90-day lifespans.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

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
TAMPERED_EXCEPTIONS_FIXTURE = FIXTURES_DIR / "tampered_exceptions.json"
UNSIGNED_EXCEPTIONS_FIXTURE = FIXTURES_DIR / "unsigned_exceptions.json"
UNKEYED_EXCEPTIONS_FIXTURE = FIXTURES_DIR / "unkeyed_exceptions.json"

# Fixed reference time for deterministic testing: 2026-11-15T12:00:00Z
FIXED_REF_TIME = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
TEST_SIGNING_KEY = "ocagents-governance-secret-v1"


class TestExceptionsManifest(unittest.TestCase):
    """Test suite for .ocagents/exceptions.json parser and 90-day boundary validation."""

    def setUp(self) -> None:
        self.env_patcher = patch.dict(os.environ, {"OCAGENTS_SIGNATURE_KEY": TEST_SIGNING_KEY})
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)

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

    def test_unsigned_exception_rejected_when_signature_required(self) -> None:
        """Exception records without a cryptographic signature are rejected when signatures are required."""
        manifest = ExceptionsManifest(manifest_path=UNSIGNED_EXCEPTIONS_FIXTURE, require_signature=True)
        self.assertEqual(manifest.total_count, 0)
        self.assertEqual(len(manifest.invalid_records), 1)
        self.assertIn("signature", manifest.invalid_records[0][1].lower())

    def test_tampered_signature_rejected(self) -> None:
        """Exception records with modified content or mismatched signature fail verification."""
        manifest = ExceptionsManifest(manifest_path=TAMPERED_EXCEPTIONS_FIXTURE, require_signature=True)
        self.assertEqual(manifest.total_count, 0)
        self.assertEqual(len(manifest.invalid_records), 1)
        self.assertIn("signature verification failed", manifest.invalid_records[0][1].lower())

    def test_unkeyed_digest_rejected_as_signature(self) -> None:
        """Unkeyed plain SHA-256 digests are strictly rejected and cannot bypass HMAC verification."""
        manifest = ExceptionsManifest(manifest_path=UNKEYED_EXCEPTIONS_FIXTURE, require_signature=True)
        self.assertEqual(manifest.total_count, 0)
        self.assertEqual(len(manifest.invalid_records), 1)
        self.assertIn("signature verification failed", manifest.invalid_records[0][1].lower())

    def test_absent_signing_key_fails_closed_and_rejects_exceptions(self) -> None:
        """When OCAGENTS_SIGNATURE_KEY is absent and no secret_key provided, signed exceptions fail closed."""
        with patch.dict(os.environ, {}, clear=True):
            manifest = ExceptionsManifest(manifest_path=VALID_EXCEPTIONS_FIXTURE, require_signature=True)
            self.assertEqual(manifest.total_count, 0)
            self.assertEqual(len(manifest.invalid_records), 2)
            for _, err in manifest.invalid_records:
                self.assertIn("signing key is absent", err.lower())
            self.assertFalse(manifest.is_exempt("checkov", "infra/legacy/vpc.tf", reference_time=FIXED_REF_TIME))

    def test_sign_exception_payload_without_key_raises_value_error(self) -> None:
        """sign_exception_payload raises ValueError when neither secret_key nor env key is configured."""
        from ocagents.scanner.exceptions import sign_exception_payload
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError) as ctx:
                sign_exception_payload(
                    rule_id="checkov",
                    resource_pattern="infra/legacy/**",
                    reason="Scheduled migration",
                    risk_owner="security-lead@corp.internal",
                    created_at="2026-11-01T00:00:00Z",
                    expires_at="2026-11-30T00:00:00Z",
                )
            self.assertIn("No HMAC signing key configured", str(ctx.exception))

    def test_sign_exception_payload_and_hmac_verification(self) -> None:
        """Exceptions must be signed with HMAC-SHA256, and reject unkeyed digests or wrong keys."""
        from ocagents.scanner.exceptions import sign_exception_payload

        # Valid default HMAC signature
        sig = sign_exception_payload(
            rule_id="checkov",
            resource_pattern="infra/legacy/**",
            reason="Scheduled migration",
            risk_owner="security-lead@corp.internal",
            created_at="2026-11-01T00:00:00Z",
            expires_at="2026-11-30T00:00:00Z",
        )
        self.assertTrue(sig.startswith("hmac_sha256:"))
        rec = ExceptionRecord(
            rule_id="checkov",
            resource_pattern="infra/legacy/**",
            reason="Scheduled migration",
            risk_owner="security-lead@corp.internal",
            created_at="2026-11-01T00:00:00Z",
            expires_at="2026-11-30T00:00:00Z",
            signature=sig,
        )
        self.assertTrue(rec.is_signature_valid())

        # Unkeyed digest must be rejected
        unkeyed_rec = ExceptionRecord(
            rule_id="checkov",
            resource_pattern="infra/legacy/**",
            reason="Scheduled migration",
            risk_owner="security-lead@corp.internal",
            created_at="2026-11-01T00:00:00Z",
            expires_at="2026-11-30T00:00:00Z",
            signature=f"sha256:{rec.compute_canonical_digest()}",
        )
        self.assertFalse(unkeyed_rec.is_signature_valid())

        # Custom secret key HMAC signature
        custom_key_sig = sign_exception_payload(
            rule_id="checkov",
            resource_pattern="infra/legacy/**",
            reason="Scheduled migration",
            risk_owner="security-lead@corp.internal",
            created_at="2026-11-01T00:00:00Z",
            expires_at="2026-11-30T00:00:00Z",
            secret_key="custom-enterprise-signing-key",
        )
        rec_custom = ExceptionRecord(
            rule_id="checkov",
            resource_pattern="infra/legacy/**",
            reason="Scheduled migration",
            risk_owner="security-lead@corp.internal",
            created_at="2026-11-01T00:00:00Z",
            expires_at="2026-11-30T00:00:00Z",
            signature=custom_key_sig,
        )
        # Matches when matching key is provided
        self.assertTrue(rec_custom.is_signature_valid(secret_key="custom-enterprise-signing-key"))
        # Fails when wrong key is provided
        self.assertFalse(rec_custom.is_signature_valid(secret_key="wrong-key"))
        # Even if OCAGENTS_SIGNATURE_KEY is set, unkeyed digest is still rejected
        import os
        old_env = os.environ.get("OCAGENTS_SIGNATURE_KEY")
        try:
            os.environ["OCAGENTS_SIGNATURE_KEY"] = "custom-enterprise-signing-key"
            self.assertFalse(unkeyed_rec.is_signature_valid())
            self.assertTrue(rec_custom.is_signature_valid())
        finally:
            if old_env is not None:
                os.environ["OCAGENTS_SIGNATURE_KEY"] = old_env
            else:
                os.environ.pop("OCAGENTS_SIGNATURE_KEY", None)


class TestScannerAvailabilityProtocol(unittest.TestCase):
    """Test suite for fail-closed scanner availability protocol and exit codes."""

    def setUp(self) -> None:
        self.env_patcher = patch.dict(os.environ, {"OCAGENTS_SIGNATURE_KEY": TEST_SIGNING_KEY})
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)
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

    def test_missing_required_scanner_with_absent_signing_key_fails_closed(self) -> None:
        """When signing key is absent, exceptions in manifest cannot be authenticated and required scanner halts with exit 1."""
        with patch.dict(os.environ, {}, clear=True):
            unauthenticated_manifest = ExceptionsManifest(manifest_path=VALID_EXCEPTIONS_FIXTURE, require_signature=True)
            def mock_which(cmd: str) -> str | None:
                if cmd == "checkov":
                    return None
                return f"/usr/local/bin/{cmd}"

            protocol = ScannerAvailabilityProtocol(
                registry=self.registry,
                exceptions_manifest=unauthenticated_manifest,
                which_fn=mock_which,
            )

            changeset = ["infra/legacy/vpc.tf"]
            report = protocol.check_changeset(changeset, reference_time=FIXED_REF_TIME)

            self.assertEqual(report.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
            self.assertEqual(report.exit_code, 1)
            self.assertTrue(report.is_failed)
            self.assertIn("checkov", report.missing_required)

    def test_valid_exception_wrong_resource_fails(self) -> None:
        """A valid exception for one resource does not exempt an unmatched resource with missing required scanner."""
        # checkov is missing
        mock_which = lambda cmd: None if cmd == "checkov" else f"/usr/local/bin/{cmd}"
        protocol = ScannerAvailabilityProtocol(
            registry=self.registry,
            exceptions_manifest=self.valid_manifest,  # exempts infra/legacy/** and infra/sandbox/*.tf
            which_fn=mock_which,
        )

        # infra/prod/main.tf is NOT covered by the legacy or sandbox exception
        changeset = ["infra/prod/main.tf"]
        report = protocol.check_changeset(changeset, reference_time=FIXED_REF_TIME)

        self.assertEqual(report.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(report.exit_code, 1)
        self.assertTrue(report.is_failed)
        self.assertIn("checkov", report.missing_required)
        self.assertEqual(len(report.exemptions_applied), 0)

    def test_valid_exception_wrong_scanner_fails(self) -> None:
        """A valid exception for one scanner/rule does not exempt a different missing required scanner on the same resource."""
        # shellcheck is missing, but checkov is available
        def mock_which(cmd: str) -> str | None:
            if cmd == "shellcheck":
                return None
            return f"/usr/local/bin/{cmd}"

        protocol = ScannerAvailabilityProtocol(
            registry=self.registry,
            exceptions_manifest=self.valid_manifest,  # has checkov exception on infra/legacy/**
            which_fn=mock_which,
        )

        # File matches resource_pattern infra/legacy/**, but requires shellcheck which is NOT exempt
        changeset = ["infra/legacy/deploy.sh"]
        report = protocol.check_changeset(changeset, reference_time=FIXED_REF_TIME)

        self.assertEqual(report.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(report.exit_code, 1)
        self.assertTrue(report.is_failed)
        self.assertIn("shellcheck", report.missing_required)
        self.assertEqual(len(report.exemptions_applied), 0)

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

    def test_changeset_to_report_integration_with_matched_and_denied_logging(self) -> None:
        """Integration test: changeset -> availability evaluation -> structured report & JSON serialization."""
        # checkov is missing
        def mock_which(cmd: str) -> str | None:
            if cmd == "checkov":
                return None
            return f"/usr/local/bin/{cmd}"

        protocol = ScannerAvailabilityProtocol(
            registry=self.registry,
            exceptions_manifest=self.valid_manifest,  # exempts checkov on infra/legacy/**
            which_fn=mock_which,
        )

        # Changeset includes one exempt legacy file and one unexempt prod file
        changeset = ["infra/legacy/vpc.tf", "infra/prod/main.tf"]
        report = protocol.check_changeset(changeset, reference_time=FIXED_REF_TIME)

        # Assert fail-closed verdict
        self.assertEqual(report.status, AvailabilityStatus.INCOMPLETE_CHECK_FAILED)
        self.assertEqual(report.exit_code, 1)
        self.assertTrue(report.is_failed)
        self.assertIn("checkov", report.missing_required)

        # Assert matched exception logging
        self.assertEqual(len(report.exemptions_applied), 1)
        self.assertEqual(report.exemptions_applied[0]["resource"], "infra/legacy/vpc.tf")
        self.assertEqual(report.exemptions_applied[0]["scanner"], "checkov")
        matched_diag = [d for d in report.diagnostics if "Exemption matched:" in d]
        self.assertEqual(len(matched_diag), 1)
        self.assertIn("infra/legacy/vpc.tf", matched_diag[0])
        self.assertIn("checkov", matched_diag[0])

        # Assert denied / unexempt resource logging
        denied_diag = [d for d in report.diagnostics if "Resource denied / unexempt:" in d]
        self.assertEqual(len(denied_diag), 1)
        self.assertIn("infra/prod/main.tf", denied_diag[0])
        self.assertIn("checkov", denied_diag[0])

        # Assert report serialization to dict and valid JSON
        report_dict = report.to_dict()
        self.assertEqual(report_dict["status"], "INCOMPLETE_CHECK_FAILED")
        self.assertEqual(report_dict["exit_code"], 1)
        self.assertEqual(report_dict["missing_required"], ["checkov"])
        serialized_json = json.dumps(report_dict)
        self.assertIn('"status": "INCOMPLETE_CHECK_FAILED"', serialized_json)
        self.assertIn('"exit_code": 1', serialized_json)


if __name__ == "__main__":
    unittest.main()

