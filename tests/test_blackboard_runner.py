"""
Unit tests for Specialist Agent Blackboard Execution Loop (Milestone v2.0 - TASK-4.2).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from ocagents.blackboard.envelope import RunEnvelope
from ocagents.blackboard.store import BlackboardStore
from ocagents.orchestration.blackboard_runner import (
    TIER_2_SPECIALISTS,
    BlackboardRunner,
    SpecialistMetadata,
    load_specialist_metadata,
)
from ocagents.providers.base import (
    ModelProvider,
    ProviderConfig,
    ProviderError,
    ProviderResponse,
    TokenBudgetExceededError,
)
from ocagents.triage.classifier import RiskTier, TriageResult

SAMPLE_TF_DIFF = """diff --git a/terraform/s3.tf b/terraform/s3.tf
index 1111111..2222222 100644
--- a/terraform/s3.tf
+++ b/terraform/s3.tf
@@ -10,3 +10,4 @@ resource "aws_s3_bucket" "prod_data" {
   bucket = "prod-customer-archive"
+  force_destroy = true
 }
"""

SAMPLE_DOCS_DIFF = """diff --git a/docs/architecture.md b/docs/architecture.md
index 1111111..2222222 100644
--- a/docs/architecture.md
+++ b/docs/architecture.md
@@ -1,2 +1,3 @@
 # Cloud Architecture
+Updated disaster recovery plan.
"""


class MockProvider(ModelProvider):
    """Configurable mock model provider for orchestration testing."""

    def __init__(self, findings_payload: dict | list | None = None, tokens_per_call: int = 150) -> None:
        super().__init__(ProviderConfig(provider="mock", model="mock-model"))
        self.findings_payload = findings_payload or {"findings": []}
        self.tokens_per_call = tokens_per_call
        self.call_history: list[dict] = []
        self.should_raise: Exception | None = None

    def generate(self, prompt: str, system_prompt: str | None = None, **kwargs) -> ProviderResponse:
        self.call_history.append({"prompt": prompt, "system_prompt": system_prompt})
        if self.should_raise:
            raise self.should_raise

        content_str = json.dumps(self.findings_payload)
        return ProviderResponse(
            content=content_str,
            parsed_json=self.findings_payload,
            prompt_tokens=self.tokens_per_call // 2,
            completion_tokens=self.tokens_per_call // 2,
            total_tokens=self.tokens_per_call,
            model="mock-model",
            provider="mock",
        )


class TestBlackboardRunner(unittest.TestCase):
    """Test suite for BlackboardRunner orchestration loop."""

    def setUp(self):
        # In-memory SQLite blackboard store
        self.blackboard = BlackboardStore(db_path=":memory:")

    def tearDown(self):
        self.blackboard.close()

    def test_load_specialist_metadata(self):
        """Verifies agent specifications are parsed from disk with declared token budgets."""
        meta = load_specialist_metadata("principal-cloud-architect")
        self.assertIsInstance(meta, SpecialistMetadata)
        self.assertEqual(meta.agent_id, "principal-cloud-architect")
        self.assertIn("Principal Cloud Architect", meta.name)
        self.assertGreater(meta.max_context_tokens, 0)
        self.assertGreater(meta.max_output_tokens, 0)
        self.assertGreater(meta.max_session_total_tokens, 0)
        self.assertTrue(len(meta.system_prompt) > 50)

    def test_load_specialist_metadata_fallback(self):
        """Verifies missing agent files return a safe default metadata structure."""
        meta = load_specialist_metadata("nonexistent-agent", agents_dir=Path("/tmp/empty-dir"))
        self.assertEqual(meta.agent_id, "nonexistent-agent")
        self.assertEqual(meta.name, "Nonexistent Agent")
        self.assertEqual(meta.max_context_tokens, 5000)

    def test_tier_0_llm_bypass(self):
        """Tier 0 doc changesets bypass LLM invocation entirely (0 tokens, 0 agents)."""
        provider = MockProvider()
        runner = BlackboardRunner(blackboard=self.blackboard, provider=provider)

        summary = runner.run(diff=SAMPLE_DOCS_DIFF)

        self.assertEqual(summary.risk_tier, RiskTier.TIER_0)
        self.assertEqual(len(summary.agents_activated), 0)
        self.assertEqual(summary.total_tokens_consumed, 0)
        self.assertEqual(summary.total_findings_published, 0)
        self.assertEqual(len(provider.call_history), 0)

    def test_tier_1_reviewer_only(self):
        """Tier 1 changesets activate only devsecops-reviewer."""
        provider = MockProvider(
            findings_payload={
                "findings": [
                    {
                        "rule_id": "rules/03-surgical-scope-discipline.md",
                        "category": "governance",
                        "resource": "app/main.py",
                        "fact": "Unrelated dependency bump detected",
                        "evidence": "diff:app/main.py#L5",
                        "recommendation": "Revert dependency change",
                        "severity": "low",
                        "confidence": 0.85,
                    }
                ]
            }
        )
        runner = BlackboardRunner(blackboard=self.blackboard, provider=provider)

        app_diff = """diff --git a/app/main.py b/app/main.py
index 1111111..2222222 100644
--- a/app/main.py
+++ b/app/main.py
@@ -1,3 +1,4 @@
 def handle():
+    print("debug")
     return True
"""
        summary = runner.run(diff=app_diff)

        self.assertEqual(summary.risk_tier, RiskTier.TIER_1)
        self.assertEqual(summary.agents_activated, ["devsecops-reviewer"])
        self.assertEqual(summary.total_findings_published, 1)
        self.assertGreater(summary.total_tokens_consumed, 0)

        # Verify finding exists in database
        db_findings = self.blackboard.get_findings(run_id=summary.run_id)
        self.assertEqual(len(db_findings), 1)
        self.assertEqual(db_findings[0]["agent"], "devsecops-reviewer")

    def test_tier_2_parallel_specialist_execution(self):
        """Tier 2 infrastructure changesets trigger parallel specialist loop and TOON context."""
        sample_findings = {
            "findings": [
                {
                    "rule_id": "rules/01-destructive-actions.md",
                    "category": "security",
                    "resource": "aws_s3_bucket.prod_data",
                    "fact": "force_destroy is enabled on production storage",
                    "evidence": "diff:terraform/s3.tf#L12",
                    "recommendation": "Remove force_destroy = true",
                    "severity": "critical",
                    "confidence": 0.95,
                }
            ]
        }

        provider = MockProvider(findings_payload=sample_findings, tokens_per_call=200)
        runner = BlackboardRunner(
            blackboard=self.blackboard,
            provider=provider,
            parallel=True,
            max_workers=3,
        )

        # Pre-populate upstream linter finding on blackboard to test TOON projection
        linter_finding = {
            "$schema": "https://open-cloud-agents.github.io/schemas/v1/finding.json",
            "id": "FND-A1B2C3D4E5F6",
            "agent": "checkov",
            "origin": "deterministic_linter",
            "rule_id": "rules/01-destructive-actions.md",
            "category": "security",
            "resource": "aws_s3_bucket.prod_data",
            "fact": "S3 Bucket force destroy active",
            "evidence": "diff:terraform/s3.tf#L12",
            "recommendation": "Disable force_destroy",
            "severity": "critical",
            "confidence": None,
            "corroboration_status": "tool_verified",
        }

        # Create envelope and seed finding
        envelope = RunEnvelope(
            run_id="run-test-tier2-orchestration",
            commit_sha="a" * 40,
            risk_tier=2,
        )
        self.blackboard.save_run(envelope)
        seeded_id = self.blackboard.publish_finding(linter_finding, run_id="run-test-tier2-orchestration")

        summary = runner.run(
            diff=SAMPLE_TF_DIFF,
            run_envelope=envelope,
        )

        self.assertEqual(summary.risk_tier, 2)
        self.assertEqual(set(summary.agents_activated), set(TIER_2_SPECIALISTS))
        self.assertEqual(len(summary.agent_results), len(TIER_2_SPECIALISTS))

        # Check that TOON projection was included in prompts sent to specialists
        for call in provider.call_history:
            self.assertIn("=== CURRENT BLACKBOARD FINDINGS (UPSTREAM CONTEXT) ===", call["prompt"])
            self.assertIn("[FINDINGS_TABLE:", call["prompt"])
            self.assertIn(seeded_id, call["prompt"])

        # Check executions were audited in database
        executions = self.blackboard.get_executions(run_id="run-test-tier2-orchestration")
        self.assertEqual(len(executions), len(TIER_2_SPECIALISTS))
        for exc in executions:
            self.assertEqual(exc["status"], "success")

    def test_token_budget_exceeded_handled_gracefully(self):
        """Runner catches TokenBudgetExceededError for an individual agent and logs error."""
        provider = MockProvider()
        provider.should_raise = TokenBudgetExceededError("Session exceeded 9000 tokens")

        runner = BlackboardRunner(
            blackboard=self.blackboard,
            provider=provider,
            parallel=False,
        )

        triage = TriageResult(
            risk_tier=2,
            tier_name="Tier 2",
            activated_agents=["security-compliance-commander"],
            file_classifications={},
            file_reasons={},
            reasons=[],
            files_by_tier={},
            diff_summary={},
        )

        summary = runner.run(diff=SAMPLE_TF_DIFF, triage_result=triage)

        self.assertEqual(len(summary.agent_results), 1)
        res = summary.agent_results["security-compliance-commander"]
        self.assertEqual(res.status, "budget_exceeded")
        self.assertIn("exceeded 9000 tokens", res.error_message)

    def test_provider_error_resilience(self):
        """When an individual agent fails, runner captures error without crashing pipeline."""
        provider = MockProvider()
        provider.should_raise = ProviderError("503 Service Unavailable")

        runner = BlackboardRunner(
            blackboard=self.blackboard,
            provider=provider,
            parallel=False,
        )

        triage = TriageResult(
            risk_tier=2,
            tier_name="Tier 2",
            activated_agents=["finops-cloud-cost-optimizer"],
            file_classifications={},
            file_reasons={},
            reasons=[],
            files_by_tier={},
            diff_summary={},
        )

        summary = runner.run(diff=SAMPLE_TF_DIFF, triage_result=triage)

        res = summary.agent_results["finops-cloud-cost-optimizer"]
        self.assertEqual(res.status, "failed")
        self.assertIn("503 Service Unavailable", res.error_message)
        self.assertIn("finops-cloud-cost-optimizer: 503 Service Unavailable", summary.errors)


if __name__ == "__main__":
    unittest.main()
