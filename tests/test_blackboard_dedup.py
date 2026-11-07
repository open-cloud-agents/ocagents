"""
Unit tests for Open Cloud Agents: Deterministic Finding ID & Deduplication Engine (TASK-3.3).
"""

import re
import unittest

from ocagents.blackboard.dedup import (
    FindingDeduplicator,
    deduplicate_findings,
    derive_finding_id,
    merge_duplicate_findings,
)


class TestBlackboardDeduplication(unittest.TestCase):
    """Test suite covering deterministic ID derivation and deduplication."""

    def test_derive_finding_id_format(self):
        """Derived finding ID must match ^FND-[A-Z0-9]{12}$."""
        pattern = re.compile(r"^FND-[A-Z0-9]{12}$")
        fid = derive_finding_id(
            rule_id="rules/01-destructive-actions.md",
            resource="aws_s3_bucket.data",
            evidence="diff:terraform/storage.tf#L12-L15",
        )
        self.assertTrue(pattern.match(fid), f"ID '{fid}' did not match pattern")

        # Same inputs produce identical ID (idempotency)
        fid2 = derive_finding_id(
            rule_id="rules/01-destructive-actions.md",
            resource="aws_s3_bucket.data",
            evidence="diff:terraform/storage.tf#L12-L15",
        )
        self.assertEqual(fid, fid2)

        # Different evidence produces different ID
        fid3 = derive_finding_id(
            rule_id="rules/01-destructive-actions.md",
            resource="aws_s3_bucket.data",
            evidence="diff:terraform/storage.tf#L20-L25",
        )
        self.assertNotEqual(fid, fid3)

    def test_deduplicate_identical_findings(self):
        """Ingesting duplicate finding increments occurrence_count without phantom records."""
        f1 = {
            "$schema": "https://open-cloud-agents.github.io/schemas/v1/finding.json",
            "rule_id": "rules/04-cloud-well-architected-invariants.md",
            "resource": "azurerm_key_vault.prod",
            "evidence": "diff:terraform/kv.tf#L10-L12",
            "agent": "devsecops-reviewer",
            "origin": "model_assertion",
            "category": "Network Security",
            "fact": "Public network access enabled",
            "recommendation": "Disable public access",
            "severity": "medium",
            "confidence": 0.85,
            "corroboration_status": "unverified_model_claim",
        }
        f2 = dict(f1)

        dedup = FindingDeduplicator()
        id1 = dedup.ingest(f1)
        id2 = dedup.ingest(f2)

        self.assertEqual(id1, id2)
        self.assertEqual(dedup.count(), 1)

        item = dedup.get_by_id(id1)
        self.assertIsNotNone(item)
        self.assertEqual(item["occurrence_count"], 2)

    def test_corroboration_promotion_model_to_tool(self):
        """When a deterministic linter corroborates a model assertion, promote to tool_verified."""
        model_finding = {
            "rule_id": "rules/01-destructive-actions.md",
            "resource": "google_storage_bucket.audit",
            "evidence": "diff:gcp/bucket.tf#L5-L7",
            "agent": "security-compliance-commander",
            "origin": "model_assertion",
            "category": "Destructive Actions",
            "fact": "force_destroy set to true",
            "recommendation": "Remove force_destroy",
            "severity": "high",
            "confidence": 0.90,
            "corroboration_status": "unverified_model_claim",
        }
        tool_finding = {
            "rule_id": "rules/01-destructive-actions.md",
            "resource": "google_storage_bucket.audit",
            "evidence": "diff:gcp/bucket.tf#L5-L7",
            "agent": "checkov",
            "origin": "deterministic_linter",
            "category": "Destructive Actions",
            "fact": "force_destroy set to true",
            "recommendation": "Remove force_destroy",
            "severity": "high",
            "confidence": None,
            "corroboration_status": "tool_verified",
        }

        merged = merge_duplicate_findings(model_finding, tool_finding)
        self.assertEqual(merged["corroboration_status"], "tool_verified")
        self.assertEqual(merged["origin"], "deterministic_linter")
        self.assertIsNone(merged["confidence"])
        self.assertEqual(merged["occurrence_count"], 2)
        self.assertIn("security-compliance-commander", merged["corroborating_agents"])
        self.assertIn("checkov", merged["corroborating_agents"])

    def test_multiple_model_agents_corroboration(self):
        """Distinct specialist agents reporting the same issue are tracked in corroborating_agents."""
        f1 = {
            "rule_id": "rules/04-cloud-well-architected-invariants.md",
            "resource": "aws_security_group.ingress",
            "evidence": "diff:terraform/sg.tf#L14-L16",
            "agent": "devsecops-reviewer",
            "origin": "model_assertion",
            "category": "Network Security",
            "fact": "0.0.0.0/0 allowed",
            "recommendation": "Restrict CIDR",
            "severity": "medium",
            "confidence": 0.80,
            "corroboration_status": "unverified_model_claim",
        }
        f2 = dict(f1)
        f2["agent"] = "security-compliance-commander"
        f2["severity"] = "high"
        f2["confidence"] = 0.95

        merged = merge_duplicate_findings(f1, f2)
        self.assertEqual(merged["severity"], "high")  # escalated
        self.assertEqual(merged["confidence"], 0.95)  # highest confidence
        self.assertEqual(merged["corroborating_agents"], ["devsecops-reviewer", "security-compliance-commander"])

    def test_stateless_deduplicate_findings_preserves_order(self):
        """deduplicate_findings helper preserves original appearance order."""
        f1 = {
            "rule_id": "rules/01-destructive-actions.md",
            "resource": "res1",
            "evidence": "diff:a.tf#L1-L2",
            "agent": "agent1",
        }
        f2 = {
            "rule_id": "rules/02-secrets-and-identity.md",
            "resource": "res2",
            "evidence": "diff:b.tf#L5-L6",
            "agent": "agent2",
        }
        f3 = dict(f1)  # duplicate of f1

        results = deduplicate_findings([f1, f2, f3])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["resource"], "res1")
        self.assertEqual(results[0]["occurrence_count"], 2)
        self.assertEqual(results[1]["resource"], "res2")
        self.assertEqual(results[1]["occurrence_count"], 1)


if __name__ == "__main__":
    unittest.main()

