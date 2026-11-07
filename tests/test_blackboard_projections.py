"""
Unit tests for Open Cloud Agents: TOON / Compact Tabular Prompt Projection Serializer (TASK-3.5).
"""

import json
import unittest

from ocagents.blackboard.projections import (
    estimate_token_count,
    filter_findings_for_agent,
    measure_projection_efficiency,
    project_findings_minified_json,
    project_findings_toon,
)


class TestBlackboardProjections(unittest.TestCase):
    """Test suite covering TOON prompt projections and token reduction."""

    def setUp(self):
        self.sample_findings = [
            {
                "id": f"FND-TEST{i:04d}AAAA",
                "rule_id": "rules/04-cloud-well-architected-invariants.md",
                "category": "Network Security",
                "resource": f"aws_security_group.ingress_{i}",
                "evidence": f"diff:terraform/network.tf#L{i * 10}-L{i * 10 + 5}",
                "severity": "high" if i % 2 == 0 else "medium",
                "confidence": 0.89,
                "corroboration_status": "unverified_model_claim",
                "agent": "devsecops-reviewer",
                "fact": f"Unbounded CIDR 0.0.0.0/0 enabled on port {80 + i}",
                "recommendation": "Restrict security group ingress to VPC CIDR range",
            }
            for i in range(10)
        ]

    def test_project_findings_toon_empty(self):
        """Empty list renders valid zero-count table."""
        out = project_findings_toon([])
        self.assertIn("[FINDINGS_TABLE: count=0]", out)
        self.assertIn("(No findings recorded)", out)

    def test_project_findings_toon_formatting(self):
        """TOON table contains header row and formatted rows with escaped characters."""
        f_with_pipes = {
            "id": "FND-PIPE12345678",
            "rule_id": "rules/01-destructive-actions.md",
            "resource": "res",
            "evidence": "diff:f#L1-L2",
            "severity": "critical",
            "confidence": None,
            "corroboration_status": "tool_verified",
            "fact": "Fact with | pipe and \n newline",
            "recommendation": "Recommendation line",
        }
        out = project_findings_toon([f_with_pipes])
        self.assertIn("[FINDINGS_TABLE: count=1]", out)
        self.assertIn("FND-PIPE12345678", out)
        self.assertIn("Fact with \\| pipe and   newline", out)
        self.assertIn("[/FINDINGS_TABLE]", out)

    def test_token_reduction_benchmark_exceeds_30_percent(self):
        """TOON projection must achieve at least 30% token reduction vs formatted JSON."""
        efficiency = measure_projection_efficiency(self.sample_findings)
        red_raw = efficiency["token_reduction_vs_raw_percent"]
        self.assertGreaterEqual(
            red_raw,
            30.0,
            f"Expected at least 30% reduction vs raw JSON, got {red_raw}%",
        )
        self.assertLess(efficiency["toon_tokens"], efficiency["raw_json_tokens"])

    def test_max_tokens_budget_truncation(self):
        """Strict max_tokens must truncate cleanly at whole-row boundary."""
        # Restrict budget to small token allowance
        out = project_findings_toon(self.sample_findings, max_tokens=150)
        tokens = estimate_token_count(out)
        self.assertLessEqual(tokens, 155)  # small buffer for final closing tag
        self.assertIn("[Truncated at token limit", out)
        self.assertIn("[/FINDINGS_TABLE]", out)

    def test_filter_findings_for_agent(self):
        """Agent domain filtering preserves relevant rules and all critical/high items."""
        f_cost = {
            "rule_id": "rules/04-cloud-well-architected-invariants.md",
            "severity": "low",
        }
        f_secrets = {
            "rule_id": "rules/02-secrets-and-identity.md",
            "severity": "low",
        }
        f_critical = {
            "rule_id": "rules/other.md",
            "severity": "critical",
        }
        findings = [f_cost, f_secrets, f_critical]

        # Security commander receives secrets and critical
        sec_filtered = filter_findings_for_agent(findings, "security-compliance-commander")
        self.assertIn(f_secrets, sec_filtered)
        self.assertIn(f_critical, sec_filtered)

        # DevSecOps reviewer receives all findings
        reviewer_filtered = filter_findings_for_agent(findings, "devsecops-reviewer")
        self.assertEqual(len(reviewer_filtered), 3)

    def test_project_findings_minified_json(self):
        """Minified JSON produces valid JSON without extra whitespace."""
        out = project_findings_minified_json(self.sample_findings[:2])
        parsed = json.loads(out)
        self.assertEqual(len(parsed), 2)
        self.assertNotIn("\n", out)


if __name__ == "__main__":
    unittest.main()

