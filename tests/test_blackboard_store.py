"""
Unit tests for Open Cloud Agents: Local Append-Only Blackboard Storage (TASK-3.4).
"""

import tempfile
import unittest
from pathlib import Path

from ocagents.blackboard.envelope import create_run_envelope
from ocagents.blackboard.store import BlackboardStore


class TestBlackboardStore(unittest.TestCase):
    """Test suite covering the SQLite WAL Blackboard findings and state store."""

    def setUp(self):
        self.store = BlackboardStore(":memory:")
        self.envelope = create_run_envelope(
            risk_tier=2,
            commit_sha="1111111234567890abcdef1234567890abcdef12",
            repo="open-cloud-agents/ocagents",
            pr_number=99,
        )
        self.run_id = self.store.save_run(self.envelope)

    def tearDown(self):
        self.store.close()

    def test_save_and_get_run(self):
        """RunEnvelope must be successfully stored and retrievable."""
        retrieved = self.store.get_run(self.run_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.run_id, self.run_id)
        self.assertEqual(retrieved.commit_sha, self.envelope.commit_sha)
        self.assertEqual(retrieved.risk_tier, 2)
        self.assertEqual(retrieved.pr_number, 99)

    def test_list_runs(self):
        """list_runs returns list of recent envelopes."""
        runs = self.store.list_runs()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["run_id"], self.run_id)

    def test_publish_and_query_findings(self):
        """Findings can be published and queried by filters."""
        f1 = {
            "rule_id": "rules/01-destructive-actions.md",
            "category": "Destructive Actions",
            "resource": "aws_s3_bucket.data",
            "evidence": "diff:terraform/s3.tf#L10-L12",
            "severity": "critical",
            "confidence": None,
            "origin": "deterministic_linter",
            "corroboration_status": "tool_verified",
            "agent": "checkov",
            "fact": "Bucket force_destroy is true",
            "recommendation": "Remove force_destroy",
        }
        f2 = {
            "rule_id": "rules/04-cloud-well-architected-invariants.md",
            "category": "Network Security",
            "resource": "azurerm_key_vault.vault",
            "evidence": "diff:terraform/kv.tf#L20-L24",
            "severity": "medium",
            "confidence": 0.88,
            "origin": "model_assertion",
            "corroboration_status": "unverified_model_claim",
            "agent": "devsecops-reviewer",
            "fact": "Public network access enabled",
            "recommendation": "Disable public access",
        }

        fid1 = self.store.publish_finding(f1, self.run_id)
        fid2 = self.store.publish_finding(f2, self.run_id)

        self.assertTrue(fid1.startswith("FND-"))
        self.assertTrue(fid2.startswith("FND-"))

        # Query all
        all_findings = self.store.get_findings(run_id=self.run_id)
        self.assertEqual(len(all_findings), 2)

        # Query by severity
        criticals = self.store.get_findings(run_id=self.run_id, severity="critical")
        self.assertEqual(len(criticals), 1)
        self.assertEqual(criticals[0]["id"], fid1)

        # Query by origin
        model_findings = self.store.get_findings(run_id=self.run_id, origin="model_assertion")
        self.assertEqual(len(model_findings), 1)
        self.assertEqual(model_findings[0]["id"], fid2)

    def test_deduplication_on_publish(self):
        """Publishing duplicate finding merges into single record and updates counts."""
        f_model = {
            "rule_id": "rules/01-destructive-actions.md",
            "category": "Destructive Actions",
            "resource": "aws_s3_bucket.data",
            "evidence": "diff:terraform/s3.tf#L10-L12",
            "severity": "high",
            "confidence": 0.90,
            "origin": "model_assertion",
            "corroboration_status": "unverified_model_claim",
            "agent": "security-compliance-commander",
            "fact": "Bucket force_destroy is true",
            "recommendation": "Remove force_destroy",
        }
        fid_first = self.store.publish_finding(f_model, self.run_id)

        # Corroborating scanner publishes exact same issue
        f_tool = {
            "rule_id": "rules/01-destructive-actions.md",
            "category": "Destructive Actions",
            "resource": "aws_s3_bucket.data",
            "evidence": "diff:terraform/s3.tf#L10-L12",
            "severity": "critical",
            "confidence": None,
            "origin": "deterministic_linter",
            "corroboration_status": "tool_verified",
            "agent": "checkov",
            "fact": "Bucket force_destroy is true",
            "recommendation": "Remove force_destroy",
        }
        fid_second = self.store.publish_finding(f_tool, self.run_id)

        self.assertEqual(fid_first, fid_second)

        # Check in store
        item = self.store.get_finding(fid_first)
        self.assertIsNotNone(item)
        self.assertEqual(item["occurrence_count"], 2)
        self.assertEqual(item["severity"], "critical")
        self.assertEqual(item["corroboration_status"], "tool_verified")
        self.assertEqual(item["origin"], "deterministic_linter")
        self.assertIsNone(item["confidence"])
        self.assertIn("security-compliance-commander", item["corroborating_agents"])
        self.assertIn("checkov", item["corroborating_agents"])

    def test_record_and_get_executions(self):
        """Agent execution events are tracked with token accounting."""
        e1 = self.store.record_execution(
            run_id=self.run_id,
            agent="security-compliance-commander",
            prompt_tokens=4200,
            output_tokens=650,
            duration_ms=1800,
            status="success",
        )
        self.assertGreater(e1, 0)

        execs = self.store.get_executions(self.run_id)
        self.assertEqual(len(execs), 1)
        self.assertEqual(execs[0]["agent"], "security-compliance-commander")
        self.assertEqual(execs[0]["prompt_tokens"], 4200)

    def test_file_backed_store_persistence(self):
        """File-backed SQLite WAL database persists across reconnects."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_file = Path(tmpdir) / "test_blackboard.db"
            store1 = BlackboardStore(db_file)
            run1 = create_run_envelope(risk_tier=1, commit_sha="2222221234567890abcdef1234567890abcdef12")
            store1.save_run(run1)
            store1.publish_finding({
                "rule_id": "rules/04-cloud-well-architected-invariants.md",
                "category": "Storage",
                "resource": "res",
                "evidence": "diff:f#L1-L2",
                "severity": "low",
                "confidence": 0.5,
                "origin": "model_assertion",
                "corroboration_status": "unverified_model_claim",
                "agent": "devsecops-reviewer",
                "fact": "test",
                "recommendation": "test",
            }, run1.run_id)
            store1.close()

            # Re-open
            store2 = BlackboardStore(db_file)
            retrieved_run = store2.get_run(run1.run_id)
            self.assertIsNotNone(retrieved_run)
            findings = store2.get_findings(run_id=run1.run_id)
            self.assertEqual(len(findings), 1)
            store2.close()


if __name__ == "__main__":
    unittest.main()
