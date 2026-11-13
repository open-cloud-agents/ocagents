"""
Unit tests for Open Cloud Agents: Dedicated CI Status Check: open-cloud-agents/triage-gate (TASK-4.4).
"""

import json
import tempfile
import unittest
from pathlib import Path

from ocagents.triage.gate import (
    TRIAGE_GATE_CONTEXT,
    TRIAGE_GATE_LABEL,
    TriageGateResult,
    TriageGateStatus,
    evaluate_triage_gate,
    load_findings_source,
    parse_codeowners,
    sync_triage_gate_github,
)


class TestTriageGate(unittest.TestCase):
    """Test suite covering the open-cloud-agents/triage-gate status check engine."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_empty_findings_evaluates_to_success(self):
        """When zero findings exist, triage gate must evaluate to SUCCESS."""
        res = evaluate_triage_gate([])
        self.assertEqual(res.status, TriageGateStatus.SUCCESS)
        self.assertFalse(res.is_blocking)
        self.assertEqual(res.total_findings, 0)
        self.assertEqual(res.unresolved_p0_p1_count, 0)
        self.assertIn("zero unresolved P0/P1 findings", res.description)
        self.assertIn(TRIAGE_GATE_LABEL, res.labels_to_remove)
        self.assertEqual(res.labels_to_add, [])

    def test_unverified_model_critical_assertion_holds_gate_pending(self):
        """Unverified critical model claim (P0) must set status to PENDING and request review."""
        finding = {
            "id": "FND-000000000001",
            "agent": "security-compliance-commander",
            "origin": "model_assertion",
            "rule_id": "rules/02-secrets-and-identity.md",
            "category": "IAM & Secrets",
            "resource": "aws_iam_role.admin",
            "fact": "IAM role allows unbounded administrator access",
            "evidence": "diff:iam.tf#L10-L15",
            "recommendation": "Constrain permissions to least-privilege policy",
            "severity": "critical",
            "confidence": 0.95,
            "corroboration_status": "unverified_model_claim",
        }
        res = evaluate_triage_gate([finding])
        self.assertEqual(res.status, TriageGateStatus.PENDING)
        self.assertTrue(res.is_blocking)
        self.assertEqual(res.p0_count, 1)
        self.assertEqual(res.p1_count, 0)
        self.assertEqual(res.unresolved_p0_p1_count, 1)
        self.assertIn(TRIAGE_GATE_LABEL, res.labels_to_add)
        self.assertEqual(res.labels_to_remove, [])
        self.assertIn("1 critical", res.description)

    def test_unverified_model_high_assertion_holds_gate_pending(self):
        """Unverified high model claim (P1) must set status to PENDING."""
        finding = {
            "id": "FND-000000000002",
            "agent": "principal-cloud-architect",
            "origin": "model_assertion",
            "rule_id": "rules/04-cloud-well-architected-invariants.md",
            "category": "High Availability",
            "resource": "aws_db_instance.primary",
            "fact": "RDS database provisioned single-AZ in production tier",
            "evidence": "diff:db.tf#L20-L22",
            "recommendation": "Set multi_az = true",
            "severity": "high",
            "confidence": 0.91,
            "corroboration_status": "unverified_model_claim",
        }
        res = evaluate_triage_gate([finding])
        self.assertEqual(res.status, TriageGateStatus.PENDING)
        self.assertTrue(res.is_blocking)
        self.assertEqual(res.p0_count, 0)
        self.assertEqual(res.p1_count, 1)
        self.assertEqual(res.unresolved_p0_p1_count, 1)
        self.assertIn(TRIAGE_GATE_LABEL, res.labels_to_add)

    def test_unverified_model_medium_and_low_are_non_blocking(self):
        """P2 model claims (medium/low severity) do not block the gate."""
        findings = [
            {
                "id": "FND-000000000003",
                "agent": "finops-cloud-cost-optimizer",
                "origin": "model_assertion",
                "rule_id": "rules/04-cloud-well-architected-invariants.md",
                "category": "Cost Optimization",
                "resource": "aws_instance.worker",
                "fact": "Instance type m5.large may be rightsized to t4g.large",
                "evidence": "diff:ec2.tf#L5",
                "recommendation": "Rightsize instance to Graviton2",
                "severity": "medium",
                "confidence": 0.88,
                "corroboration_status": "unverified_model_claim",
            },
            {
                "id": "FND-000000000004",
                "agent": "sre-reliability-engineer",
                "origin": "model_assertion",
                "rule_id": "rules/04-cloud-well-architected-invariants.md",
                "category": "Observability",
                "resource": "datadog_monitor.latency",
                "fact": "Evaluation window is 5m; recommend 15m to avoid flapping",
                "evidence": "diff:datadog.tf#L12",
                "recommendation": "Adjust window to 15m",
                "severity": "low",
                "confidence": 0.86,
                "corroboration_status": "unverified_model_claim",
            },
        ]
        res = evaluate_triage_gate(findings)
        self.assertEqual(res.status, TriageGateStatus.SUCCESS)
        self.assertFalse(res.is_blocking)
        self.assertEqual(res.p0_count, 0)
        self.assertEqual(res.p1_count, 0)
        self.assertEqual(res.p2_count, 2)
        self.assertEqual(res.unresolved_p0_p1_count, 0)
        self.assertIn(TRIAGE_GATE_LABEL, res.labels_to_remove)

    def test_human_verified_critical_finding_unblocks_gate(self):
        """A critical model finding that has been human_verified no longer blocks the triage gate."""
        finding = {
            "id": "FND-000000000005",
            "agent": "security-compliance-commander",
            "origin": "model_assertion",
            "rule_id": "rules/01-destructive-actions.md",
            "category": "Data Protection",
            "resource": "aws_s3_bucket.data",
            "fact": "Bucket destroy enabled",
            "evidence": "diff:s3.tf#L4",
            "recommendation": "Remove force_destroy",
            "severity": "critical",
            "confidence": 0.99,
            "corroboration_status": "human_verified",
        }
        res = evaluate_triage_gate([finding])
        self.assertEqual(res.status, TriageGateStatus.SUCCESS)
        self.assertFalse(res.is_blocking)
        self.assertEqual(res.human_verified_count, 1)
        self.assertEqual(res.p0_count, 0)
        self.assertEqual(res.unresolved_p0_p1_count, 0)

    def test_rejected_false_positive_unblocks_gate(self):
        """A finding marked as rejected_false_positive does not hold the gate in PENDING."""
        finding = {
            "id": "FND-000000000006",
            "agent": "principal-cloud-architect",
            "origin": "model_assertion",
            "rule_id": "rules/04-cloud-well-architected-invariants.md",
            "category": "Networking",
            "resource": "aws_security_group.web",
            "fact": "0.0.0.0/0 ingress allowed on port 443",
            "evidence": "diff:sg.tf#L8",
            "recommendation": "Verify public access is intended",
            "severity": "high",
            "confidence": 0.90,
            "corroboration_status": "rejected_false_positive",
        }
        res = evaluate_triage_gate([finding])
        self.assertEqual(res.status, TriageGateStatus.SUCCESS)
        self.assertFalse(res.is_blocking)
        self.assertEqual(res.dismissed_count, 1)
        self.assertEqual(res.p1_count, 0)
        self.assertEqual(res.unresolved_p0_p1_count, 0)

    def test_deterministic_tool_verified_findings_do_not_block_triage_gate(self):
        """Deterministic linter findings are evaluated by pre-flight, not model triage gate."""
        finding = {
            "id": "FND-000000000007",
            "agent": "checkov",
            "origin": "deterministic_linter",
            "rule_id": "rules/04-cloud-well-architected-invariants.md",
            "category": "Infrastructure as Code",
            "resource": "aws_s3_bucket.log",
            "fact": "S3 bucket logging is not enabled",
            "evidence": "repo:terraform/s3.tf#L1-L10",
            "recommendation": "Enable S3 access logging",
            "severity": "high",
            "confidence": None,
            "corroboration_status": "tool_verified",
        }
        res = evaluate_triage_gate([finding])
        self.assertEqual(res.status, TriageGateStatus.SUCCESS)
        self.assertFalse(res.is_blocking)
        self.assertEqual(res.tool_verified_count, 1)
        self.assertEqual(res.p1_count, 0)

    def test_parse_codeowners(self):
        """Tests parsing CODEOWNERS extracting user logins and team slugs."""
        codeowners_content = """# CODEOWNERS test file
* @ibrahimng @open-cloud-agents/security-leads
*.tf @infra-team
docs/* @docs-writer user@example.com
"""
        codeowners_file = self.root / "CODEOWNERS"
        codeowners_file.write_text(codeowners_content, encoding="utf-8")

        reviewers, team_reviewers = parse_codeowners(codeowners_path=codeowners_file)
        self.assertIn("ibrahimng", reviewers)
        self.assertIn("infra-team", reviewers)
        self.assertIn("docs-writer", reviewers)
        self.assertIn("security-leads", team_reviewers)

    def test_markdown_summary_rendering(self):
        """Verifies markdown summary renders accurate table metrics and CODEOWNERS instructions."""
        finding = {
            "id": "FND-8B1C3E4A9F20",
            "agent": "security-compliance-commander",
            "origin": "model_assertion",
            "rule_id": "rules/04-cloud-well-architected-invariants.md",
            "category": "Network Isolation",
            "resource": "azurerm_key_vault.prod",
            "fact": "Key Vault public network access enabled without VNet restrictions",
            "evidence": "diff:keyvault.tf#L24",
            "recommendation": "Disable public access",
            "severity": "high",
            "confidence": 0.94,
            "corroboration_status": "unverified_model_claim",
        }
        res = evaluate_triage_gate([finding])
        res.codeowners = ["@ibrahimng"]
        md = res.to_markdown_summary()

        self.assertIn(TRIAGE_GATE_CONTEXT, md)
        self.assertIn("PENDING", md)
        self.assertIn("FND-8B1C3E4A9F20", md)
        self.assertIn("azurerm_key_vault.prod", md)
        self.assertIn("@ibrahimng", md)
        self.assertIn("/ocagents triage FND-XXX accept", md)

    def test_load_findings_source_formats(self):
        """Tests loading findings from single object, list, and directory."""
        finding = {
            "id": "FND-000000000008",
            "agent": "security-compliance-commander",
            "origin": "model_assertion",
            "rule_id": "rules/02-secrets-and-identity.md",
            "category": "IAM",
            "resource": "role.test",
            "fact": "Test fact",
            "evidence": "diff:test.tf#L1",
            "recommendation": "Fix",
            "severity": "high",
            "confidence": 0.9,
            "corroboration_status": "unverified_model_claim",
        }

        # 1. Single dict file
        f1 = self.root / "single.json"
        f1.write_text(json.dumps(finding), encoding="utf-8")
        loaded1 = load_findings_source(findings_file=f1)
        self.assertEqual(len(loaded1), 1)
        self.assertEqual(loaded1[0]["id"], "FND-000000000008")

        # 2. Array file
        f2 = self.root / "array.json"
        f2.write_text(json.dumps([finding, finding]), encoding="utf-8")
        loaded2 = load_findings_source(findings_file=f2)
        self.assertEqual(len(loaded2), 2)

        # 3. Directory of files
        dir_path = self.root / "findings_dir"
        dir_path.mkdir()
        (dir_path / "a.json").write_text(json.dumps(finding), encoding="utf-8")
        (dir_path / "b.json").write_text(json.dumps(finding), encoding="utf-8")
        loaded3 = load_findings_source(findings_file=dir_path)
        self.assertEqual(len(loaded3), 2)

    def test_sync_triage_gate_github_dry_run(self):
        """Verifies dry-run returns structured planned actions without making network calls."""
        res = evaluate_triage_gate([])
        log = sync_triage_gate_github(
            repo="open-cloud-agents/ocagents",
            commit_sha="abcdef1234567890abcdef1234567890abcdef12",
            gate_result=res,
            pr_number=42,
            dry_run=True,
        )
        self.assertTrue(log["dry_run"])
        self.assertEqual(log["repo"], "open-cloud-agents/ocagents")
        self.assertEqual(log["status_payload"]["state"], "success")
        self.assertEqual(log["status_payload"]["context"], TRIAGE_GATE_CONTEXT)
        self.assertIn("needs-security-review", log["labels_removed"])
        self.assertEqual(log["errors"], [])

    def test_cli_triage_gate_empty_success(self):
        """Tests executing CLI cmd_triage with gate action when clean."""
        import io
        from unittest.mock import patch
        from ocagents.cli import cmd_triage

        class Args:
            action = "gate"
            gate = True
            findings = None
            db = None
            run_id = None
            sha = None
            repo = None
            pr = None
            pr_author = None
            dry_run = False
            github_token = None
            json = True
            repo_root = str(self.root)
            codeowners = None

        f = io.StringIO()
        with patch("sys.stdout", f):
            code = cmd_triage(Args(), self.root)

        self.assertEqual(code, 0)
        output = json.loads(f.getvalue())
        self.assertEqual(output["status"], "success")
        self.assertFalse(output["is_blocking"])

    def test_cli_triage_gate_pending_with_findings_and_sync(self):
        """Tests executing CLI cmd_triage with P0 finding and dry-run GitHub sync."""
        import io
        from unittest.mock import patch
        from ocagents.cli import cmd_triage

        finding = {
            "id": "FND-000000000009",
            "agent": "security-compliance-commander",
            "origin": "model_assertion",
            "rule_id": "rules/02-secrets-and-identity.md",
            "category": "IAM",
            "resource": "role.admin",
            "fact": "Overly broad administrator privileges",
            "evidence": "diff:iam.tf#L1",
            "recommendation": "Constrain IAM policy",
            "severity": "critical",
            "confidence": 0.98,
            "corroboration_status": "unverified_model_claim",
        }
        f_path = self.root / "critical_finding.json"
        f_path.write_text(json.dumps([finding]), encoding="utf-8")

        class Args:
            action = "gate"
            gate = True
            findings = str(f_path)
            db = None
            run_id = None
            sha = "0123456789abcdef0123456789abcdef01234567"
            repo = "open-cloud-agents/ocagents"
            pr = 99
            pr_author = "testuser"
            dry_run = True
            github_token = None
            json = True
            repo_root = str(self.root)
            codeowners = None

        f = io.StringIO()
        with patch("sys.stdout", f):
            code = cmd_triage(Args(), self.root)

        self.assertEqual(code, 0)
        output = json.loads(f.getvalue())
        self.assertEqual(output["status"], "pending")
        self.assertTrue(output["is_blocking"])
        self.assertEqual(output["p0_count"], 1)
        self.assertIn("github_sync", output)
        self.assertEqual(output["github_sync"]["status_payload"]["state"], "pending")


if __name__ == "__main__":
    unittest.main()
