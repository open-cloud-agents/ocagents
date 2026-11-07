"""
Unit tests for Open Cloud Agents: Run Metadata Envelope Engine (TASK-3.2).
"""

import json
import unittest

from ocagents.blackboard.envelope import (
    RunEnvelope,
    create_run_envelope,
    generate_deterministic_run_id,
    validate_run_envelope,
)


class TestBlackboardEnvelope(unittest.TestCase):
    """Test suite covering the Run Metadata Envelope Engine."""

    def test_generate_deterministic_run_id(self):
        """Identical execution context must produce identical run_id (idempotency)."""
        id1 = generate_deterministic_run_id(
            repo_url="https://github.com/open-cloud-agents/ocagents.git",
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
            pr_number=128,
            timestamp_utc="2026-11-07T12:00:00Z",
        )
        id2 = generate_deterministic_run_id(
            repo_url="https://github.com/open-cloud-agents/ocagents.git",
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
            pr_number=128,
            timestamp_utc="2026-11-07T12:00:00Z",
        )
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("run-"))
        self.assertEqual(len(id1), 4 + 16)

        # Different commit produces different id
        id3 = generate_deterministic_run_id(
            repo_url="https://github.com/open-cloud-agents/ocagents.git",
            commit_sha="9999991234567890abcdef1234567890abcdef12",
            pr_number=128,
            timestamp_utc="2026-11-07T12:00:00Z",
        )
        self.assertNotEqual(id1, id3)

    def test_create_run_envelope_valid(self):
        """Factory creates valid envelope conforming to schema."""
        envelope = create_run_envelope(
            risk_tier=2,
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
            base_sha="1234567890abcdef1234567890abcdef12345678",
            pr_number=42,
            repo="open-cloud-agents/ocagents",
            invoked_by="ci-gatekeeper",
            token_budget_allocated={
                "max_context_tokens": 15000,
                "max_output_tokens": 2000,
                "max_session_total_tokens": 25000,
            },
            agent_manifest={
                "security-compliance-commander": "anthropic/claude-3-5-sonnet-20241022",
            },
            tool_manifest={"checkov": "v3.2.14"},
        )

        d = envelope.to_dict()
        valid, errors = validate_run_envelope(d)
        self.assertTrue(valid, f"Validation failed: {errors}")
        self.assertEqual(envelope.risk_tier, 2)
        self.assertEqual(envelope.pr_number, 42)
        self.assertEqual(envelope.invoked_by, "ci-gatekeeper")

    def test_validate_run_envelope_missing_required(self):
        """Missing required fields must fail validation."""
        d = {
            "$schema": "https://open-cloud-agents.github.io/schemas/v1/run_envelope.json",
            "run_id": "run-1234567890abcdef",
            # missing commit_sha, risk_tier, schema_version, engine_version, timestamp_utc
        }
        valid, errors = validate_run_envelope(d)
        self.assertFalse(valid)
        self.assertTrue(any("Missing required field" in e for e in errors))

    def test_validate_run_envelope_forbidden_extra_keys(self):
        """Extra properties outside the schema specification must be rejected."""
        envelope = create_run_envelope(
            risk_tier=1,
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
        )
        d = envelope.to_dict()
        d["unauthorized_property"] = "malicious_payload"
        valid, errors = validate_run_envelope(d)
        self.assertFalse(valid)
        self.assertTrue(any("Forbidden extra properties found" in e for e in errors))

    def test_validate_run_envelope_invalid_risk_tier(self):
        """Non-integer or out-of-range risk_tier must be rejected."""
        envelope = create_run_envelope(
            risk_tier=1,
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
        )
        d = envelope.to_dict()
        d["risk_tier"] = 3  # Allowed is 0, 1, 2
        valid, errors = validate_run_envelope(d)
        self.assertFalse(valid)
        self.assertTrue(any("Field 'risk_tier' must be integer enum" in e for e in errors))

        # Boolean is rejected
        d["risk_tier"] = True
        valid, errors = validate_run_envelope(d)
        self.assertFalse(valid)

    def test_roundtrip_json_serialization(self):
        """Envelope must cleanly roundtrip through JSON serialization and from_dict."""
        envelope = create_run_envelope(
            risk_tier=0,
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
        )
        json_str = envelope.to_json()
        data = json.loads(json_str)
        reconstructed = RunEnvelope.from_dict(data)

        self.assertEqual(envelope.run_id, reconstructed.run_id)
        self.assertEqual(envelope.commit_sha, reconstructed.commit_sha)
        self.assertEqual(envelope.risk_tier, reconstructed.risk_tier)


if __name__ == "__main__":
    unittest.main()
