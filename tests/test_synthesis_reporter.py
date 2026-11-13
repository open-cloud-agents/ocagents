"""
Unit tests for Stage 5 User-Facing Markdown Synthesis Reporter (Milestone v2.0 - TASK-4.3).
"""

from __future__ import annotations

import unittest

from ocagents.blackboard.envelope import RunEnvelope
from ocagents.orchestration.blackboard_runner import (
    BlackboardRunSummary,
    SpecialistExecutionResult,
)
from ocagents.reporting.synthesis import (
    calculate_verdict,
    count_findings_by_severity,
    format_evidence_link,
    format_rule_link,
    generate_markdown_report,
    sanitize_github_url,
)


class TestSynthesisReporter(unittest.TestCase):
    """Test suite for Markdown review summary synthesis."""

    def test_sanitize_github_url(self):
        """Verifies various git remote URL formats normalize to HTTPS web URLs."""
        self.assertEqual(
            sanitize_github_url("git@github.com:open-cloud-agents/ocagents.git"),
            "https://github.com/open-cloud-agents/ocagents",
        )
        self.assertEqual(
            sanitize_github_url("https://github.com/open-cloud-agents/ocagents.git"),
            "https://github.com/open-cloud-agents/ocagents",
        )
        self.assertEqual(
            sanitize_github_url("open-cloud-agents/ocagents"),
            "https://github.com/open-cloud-agents/ocagents",
        )
        self.assertIsNone(sanitize_github_url(None))

    def test_format_evidence_link_with_github(self):
        """Verifies evidence URIs convert to clickable GitHub blob line permalinks."""
        link = format_evidence_link(
            evidence="repo:terraform/s3.tf#L12-L14",
            repo_url="https://github.com/open-cloud-agents/ocagents",
            commit_sha="a1b2c3d4e5f67890",
        )
        self.assertEqual(
            link,
            "[`terraform/s3.tf#L12-L14`](https://github.com/open-cloud-agents/ocagents/blob/a1b2c3d4e5f67890/terraform/s3.tf#L12-L14)",
        )

    def test_format_evidence_link_no_repo_url(self):
        """Verifies safe code span fallback when repo URL is unavailable."""
        link = format_evidence_link("diff:app/server.py#L42")
        self.assertEqual(link, "`app/server.py#L42`")

    def test_format_evidence_link_strips_local_workstation_paths(self):
        """Verifies local workstation paths (/Users/...) are strictly scrubbed."""
        link = format_evidence_link("repo:/Users/devuser/project/terraform/s3.tf#L10")
        self.assertNotIn("/Users/", link)
        self.assertNotIn("devuser", link)
        self.assertIn("terraform/s3.tf#L10", link)

    def test_format_rule_link(self):
        """Verifies rule IDs convert to GitHub blob URLs when repo context is provided."""
        link = format_rule_link(
            rule_id="rules/01-destructive-actions.md",
            repo_url="https://github.com/open-cloud-agents/ocagents",
            commit_sha="deadbeef1234",
        )
        self.assertEqual(
            link,
            "[`rules/01-destructive-actions.md`](https://github.com/open-cloud-agents/ocagents/blob/deadbeef1234/rules/01-destructive-actions.md)",
        )

    def test_clean_changeset_report(self):
        """Zero findings produces clean pass verdict and informative notice."""
        report = generate_markdown_report(findings=[])

        self.assertIn("## 🛡️ Open Cloud Agents: Pre-Merge Verification Summary", report)
        self.assertIn("### ✅ CLEAN: All Pre-Merge Quality Gates Passed", report)
        self.assertIn("✨ Clean Changeset", report)
        self.assertIn("| **Total Findings** | **0** |", report)

    def test_critical_and_high_severity_blocks_verdict(self):
        """Critical or High findings trigger ACTION REQUIRED verdict."""
        findings = [
            {
                "id": "FND-C1D2E3F4A5B6",
                "rule_id": "rules/01-destructive-actions.md",
                "category": "security",
                "resource": "aws_s3_bucket.prod",
                "fact": "Bucket force_destroy is enabled on production storage",
                "evidence": "diff:terraform/s3.tf#L12",
                "recommendation": "Remove force_destroy = true",
                "severity": "critical",
                "confidence": 0.95,
                "origin": "model_assertion",
                "corroboration_status": "unverified_model_claim",
                "agent": "security-compliance-commander",
            }
        ]

        verdict_badge, verdict_title, _ = calculate_verdict(findings)
        self.assertEqual(verdict_badge, "🚨 ACTION REQUIRED")
        self.assertIn("P0/P1", verdict_title)

        report = generate_markdown_report(findings=findings)
        self.assertIn("### 🚨 ACTION REQUIRED", report)
        self.assertIn("#### `FND-C1D2E3F4A5B6`: Bucket force_destroy is enabled", report)
        self.assertIn("- **Confidence Score**: 95%", report)
        self.assertIn("- **Reporting Specialist**: `security-compliance-commander`", report)

    def test_advisory_medium_verdict(self):
        """Only medium/low findings result in non-blocking advisory review."""
        findings = [
            {
                "id": "FND-B2C3D4E5F6A1",
                "rule_id": "rules/04-cloud-well-architected-invariants.md",
                "category": "finops",
                "resource": "aws_instance.worker",
                "fact": "Instance type m5.4xlarge appears over-provisioned",
                "evidence": "diff:terraform/ec2.tf#L8",
                "recommendation": "Downsize to m5.xlarge",
                "severity": "medium",
                "confidence": 0.88,
                "origin": "model_assertion",
                "corroboration_status": "unverified_model_claim",
                "agent": "finops-cloud-cost-optimizer",
            }
        ]

        verdict_badge, verdict_title, _ = calculate_verdict(findings)
        self.assertEqual(verdict_badge, "⚠️ ADVISORY REVIEW")

        report = generate_markdown_report(findings=findings)
        self.assertIn("### ⚠️ ADVISORY REVIEW", report)
        self.assertIn("| 🟡 **Medium** | 1 |", report)

    def test_dismissed_false_positive_does_not_block(self):
        """Findings marked rejected_false_positive do not block gate verdict."""
        findings = [
            {
                "id": "FND-A1A2A3A4A5A6",
                "rule_id": "rules/01-destructive-actions.md",
                "category": "security",
                "resource": "test_bucket",
                "fact": "Test bucket destroy",
                "evidence": "diff:test/bucket.tf#L3",
                "recommendation": "None",
                "severity": "critical",
                "confidence": 0.9,
                "origin": "model_assertion",
                "corroboration_status": "rejected_false_positive",
                "agent": "security-compliance-commander",
            }
        ]

        verdict_badge, _, _ = calculate_verdict(findings)
        self.assertEqual(verdict_badge, "✅ CLEAN")

    def test_remediation_diff_preview_rendered_with_safety_callout(self):
        """Verifies proposed remediation diff preview embeds syntax highlighting and safety tip."""
        findings = [
            {
                "id": "FND-E5F6A1B2C3D4",
                "rule_id": "rules/04-cloud-well-architected-invariants.md",
                "category": "security",
                "resource": "azurerm_key_vault.prod",
                "fact": "Public network access enabled",
                "evidence": "diff:terraform/vault.tf#L20",
                "recommendation": "Disable public access",
                "severity": "high",
                "confidence": 0.92,
                "origin": "model_assertion",
                "corroboration_status": "unverified_model_claim",
                "agent": "security-compliance-commander",
                "remediation": {
                    "proposed_draft_available": True,
                    "diff_preview": "- public_network_access_enabled = true\n+ public_network_access_enabled = false",
                },
            }
        ]

        report = generate_markdown_report(findings=findings)
        self.assertIn("Proposed Remediation Preview (Advisory Proposal Only)", report)
        self.assertIn("```diff", report)
        self.assertIn("- public_network_access_enabled = true", report)
        self.assertIn("+ public_network_access_enabled = false", report)
        self.assertIn("Remediation diffs are draft proposals and are **never** automatically merged.", report)

    def test_corroborating_specialists_multiple_reports(self):
        """Verifies cross-agent corroboration displays all reporting agents and occurrence count."""
        findings = [
            {
                "id": "FND-77D86583C467",
                "rule_id": "rules/01-destructive-actions.md",
                "category": "security",
                "resource": "aws_s3_bucket.prod_data",
                "fact": "Force destroy active",
                "evidence": "diff:terraform/s3.tf#L12",
                "recommendation": "Remove force_destroy",
                "severity": "critical",
                "confidence": None,
                "origin": "deterministic_linter",
                "corroboration_status": "tool_verified",
                "agent": "checkov",
                "occurrence_count": 3,
                "corroborating_agents": ["checkov", "security-compliance-commander", "principal-cloud-architect"],
            }
        ]

        report = generate_markdown_report(findings=findings)
        self.assertIn("3 independent reports", report)
        self.assertIn("`checkov`", report)
        self.assertIn("`security-compliance-commander`", report)
        self.assertIn("`principal-cloud-architect`", report)

    def test_telemetry_table_populated(self):
        """Verifies summary telemetry details table renders token and specialist metrics."""
        summary = BlackboardRunSummary(
            run_id="run-test-telemetry-123",
            risk_tier=2,
            tier_name="Tier 2 High Blast Radius",
            agents_activated=["principal-cloud-architect", "security-compliance-commander"],
            total_tokens_consumed=1850,
            execution_time_seconds=1.42,
            agent_results={
                "principal-cloud-architect": SpecialistExecutionResult(
                    agent_id="principal-cloud-architect",
                    status="success",
                    total_tokens=950,
                    duration_ms=820,
                    findings=[{"id": "FND-1"}],
                ),
                "security-compliance-commander": SpecialistExecutionResult(
                    agent_id="security-compliance-commander",
                    status="success",
                    total_tokens=900,
                    duration_ms=600,
                    findings=[{"id": "FND-2"}],
                ),
            },
        )

        envelope = RunEnvelope(
            run_id="run-test-telemetry-123",
            commit_sha="1234567890abcdef",
            risk_tier=2,
        )

        report = generate_markdown_report(
            findings=[],
            run_envelope=envelope,
            run_summary=summary,
        )

        self.assertIn("`run-test-telemetry-123`", report)
        self.assertIn("`12345678`", report)
        self.assertIn("1,850", report)
        self.assertIn("1.42s", report)
        self.assertIn("`principal-cloud-architect`", report)
        self.assertIn("`security-compliance-commander`", report)


if __name__ == "__main__":
    unittest.main()
