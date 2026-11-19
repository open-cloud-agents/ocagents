"""
Comprehensive Unit Tests for Adaptive Risk Classifier & Dynamic Agent Invocation Matrix (Issue #102).

Tests coverage requirements:
  - Tier 0: Markdown/docs-only diffs output Tier 0 with empty agent list (0 tokens).
  - Tier 1: Scripting/packaging diffs output Tier 1 activating DevSecOps Engineer.
  - Tier 2: Workflows/core runtime diffs output Tier 2 activating Security Commander + Reviewer.
  - Tier 3: Terraform/IaC diffs output Tier 3 activating PCA, SCC, FinOps, SRE, and Reviewer.
  - High-risk diff screening: IAM wildcards, database drops, 0.0.0.0/0, secrets, force_destroy.
  - Dynamic Invocation Matrix: resolve_invocation_plan, get_invocation_matrix, skipped agents rationale.
"""

import json
import unittest
from unittest.mock import patch

from ocagents.triage.classifier import (
    RiskTier,
    TriageResult,
    classify_changeset,
    classify_diff,
    classify_file,
    scan_diff_for_high_risk_triggers,
)
from ocagents.triage.matrix import (
    ALL_MASTER_AGENTS,
    InvocationPlan,
    get_invocation_matrix,
    resolve_invocation_plan,
)


class TestAdaptiveRiskClassifier(unittest.TestCase):
    """Verifies adaptive risk tier classification and dynamic agent invocation."""

    def test_tier_0_docs_only_empty_agent_list(self):
        """Markdown-only diffs must output Tier 0 with an empty agent list and 0 token spend."""
        diff_text = """diff --git a/docs/architecture.md b/docs/architecture.md
index 1111111..2222222 100644
--- a/docs/architecture.md
+++ b/docs/architecture.md
@@ -10,3 +10,4 @@
  # Architecture Overview
+ Updated documentation section on risk triage.
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_0)
        self.assertEqual(result.tier_name, "Tier 0: Docs & Non-Code Assets (LLM Bypass)")
        self.assertEqual(result.activated_agents, [])
        self.assertEqual(len(result.skipped_agents), 7)
        self.assertEqual(result.diff_summary["tier_0"], 1)
        self.assertEqual(result.diff_summary["tier_1"], 0)
        self.assertEqual(result.diff_summary["tier_2"], 0)
        self.assertEqual(result.diff_summary["tier_3"], 0)
        self.assertEqual(result.invocation_plan["token_ceiling_estimate"], 0)
        self.assertEqual(result.invocation_plan["gating_behavior"], "fast_track_hygiene_only")

    def test_tier_1_scripting_activates_devsecops_engineer(self):
        """Shell script and packaging changes must output Tier 1 activating DevSecOps Engineer."""
        diff_text = """diff --git a/scripts/setup.sh b/scripts/setup.sh
index 1111111..2222222 100755
--- a/scripts/setup.sh
+++ b/scripts/setup.sh
@@ -1,3 +1,4 @@
  #!/usr/bin/env bash
+ echo "Setting up environment..."
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_1)
        self.assertEqual(result.activated_agents, ["devsecops-engineer"])
        self.assertIn("principal-cloud-architect", result.skipped_agents)
        self.assertIn("devsecops-reviewer", result.skipped_agents)
        self.assertIn("security-compliance-commander", result.skipped_agents)
        self.assertEqual(result.diff_summary["tier_1"], 1)
        self.assertEqual(result.invocation_plan["gating_behavior"], "deterministic_lint_and_engineer")
        self.assertGreater(result.invocation_plan["token_ceiling_estimate"], 0)

    def test_tier_2_workflows_and_runtime_activates_security_and_reviewer(self):
        """CI/CD workflows and core runtime files must trigger Tier 2 activating Security Commander and Reviewer."""
        diff_text = """diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
index 1111111..2222222 100644
--- a/.github/workflows/ci.yml
+++ b/.github/workflows/ci.yml
@@ -20,2 +20,3 @@
        run: pytest tests/
+       env: CI_ENV=true
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_2)
        self.assertEqual(
            result.activated_agents,
            ["security-compliance-commander", "devsecops-reviewer"],
        )
        self.assertIn("principal-cloud-architect", result.skipped_agents)
        self.assertIn("finops-cloud-cost-optimizer", result.skipped_agents)
        self.assertIn("sre-reliability-engineer", result.skipped_agents)
        self.assertEqual(result.invocation_plan["gating_behavior"], "security_and_reviewer_audit")

    def test_tier_3_terraform_activates_full_master_suite(self):
        """Terraform/IaC changes must output Tier 3 activating PCA, SCC, FinOps, SRE, and Reviewer."""
        diff_text = """diff --git a/terraform/vpc.tf b/terraform/vpc.tf
index 1111111..2222222 100644
--- a/terraform/vpc.tf
+++ b/terraform/vpc.tf
@@ -1,4 +1,5 @@
  resource "aws_vpc" "main" {
    cidr_block = "10.0.0.0/16"
+   enable_dns_hostnames = true
  }
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)
        self.assertIn("principal-cloud-architect", result.activated_agents)
        self.assertIn("security-compliance-commander", result.activated_agents)
        self.assertIn("finops-cloud-cost-optimizer", result.activated_agents)
        self.assertIn("sre-reliability-engineer", result.activated_agents)
        self.assertIn("devsecops-reviewer", result.activated_agents)
        self.assertEqual(result.invocation_plan["gating_behavior"], "full_master_suite_blackboard")
        self.assertEqual(result.invocation_plan["token_ceiling_estimate"], 25000)

    def test_high_risk_iam_wildcard_escalates_to_tier_3(self):
        """IAM wildcard *:* in a python/json file must escalate to Tier 3."""
        diff_text = """diff --git a/auth/policy.json b/auth/policy.json
--- a/auth/policy.json
+++ b/auth/policy.json
@@ -2,2 +2,3 @@
+  "Action": "*",
+  "Resource": "*"
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)
        self.assertTrue(len(result.high_risk_triggers) > 0)
        self.assertTrue(any("wildcard" in tr.lower() for tr in result.high_risk_triggers))

    def test_high_risk_database_drop_escalates_to_tier_3(self):
        """DROP TABLE or TRUNCATE in any script must escalate to Tier 3."""
        diff_text = """diff --git a/scripts/migrate.sh b/scripts/migrate.sh
--- a/scripts/migrate.sh
+++ b/scripts/migrate.sh
@@ -1,2 +1,3 @@
+DROP TABLE user_sessions;
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)
        self.assertTrue(any("DROP/TRUNCATE" in tr for tr in result.high_risk_triggers))

    def test_high_risk_unbounded_cidr_escalates_to_tier_3(self):
        """0.0.0.0/0 route in a configuration file must escalate to Tier 3."""
        diff_text = """diff --git a/config/security.json b/config/security.json
--- a/config/security.json
+++ b/config/security.json
@@ -1,2 +1,3 @@
+  "allowed_cidr": "0.0.0.0/0"
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)
        self.assertTrue(any("0.0.0.0/0" in tr for tr in result.high_risk_triggers))

    def test_high_risk_secret_key_escalates_to_tier_3(self):
        """Plaintext private key in diff must escalate to Tier 3."""
        hdr = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
        ftr = "-----" + "END RSA PRIVATE KEY" + "-----"
        diff_text = f"""diff --git a/keys/cert.pem b/keys/cert.pem
--- a/keys/cert.pem
+++ b/keys/cert.pem
@@ -0,0 +1,3 @@
+{hdr}
+MIIEowIBAAKCAQEA0
+{ftr}
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)
        self.assertTrue(any("private key" in tr.lower() for tr in result.high_risk_triggers))

    def test_high_risk_force_destroy_escalates_to_tier_3(self):
        """force_destroy = true in diff must escalate to Tier 3."""
        diff_text = """diff --git a/main.tf b/main.tf
--- a/main.tf
+++ b/main.tf
@@ -5,2 +5,3 @@
+  force_destroy = true
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)
        self.assertTrue(any("force-destroy" in tr for tr in result.high_risk_triggers))


class TestDynamicInvocationMatrix(unittest.TestCase):
    """Verifies the dynamic invocation matrix specifications and plan generation."""

    def test_invocation_matrix_structure(self):
        """Matrix must define plans for all 4 tiers (0, 1, 2, 3)."""
        matrix = get_invocation_matrix()
        self.assertEqual(set(matrix.keys()), {0, 1, 2, 3})
        for tier_idx, plan in matrix.items():
            self.assertEqual(plan.risk_tier, tier_idx)
            self.assertIsInstance(plan.tier_name, str)
            self.assertIsInstance(plan.activated_agents, list)
            self.assertIsInstance(plan.skipped_agents, list)
            self.assertIsInstance(plan.rationale, str)
            self.assertIsInstance(plan.gating_behavior, str)
            self.assertIsInstance(plan.token_ceiling_estimate, int)

    def test_tier_agent_partition_consistency(self):
        """Every master agent must be either activated or skipped with no duplicates or omissions."""
        for tier in [RiskTier.TIER_0, RiskTier.TIER_1, RiskTier.TIER_2, RiskTier.TIER_3]:
            plan = resolve_invocation_plan(tier)
            total = set(plan.activated_agents) | set(plan.skipped_agents)
            self.assertEqual(total, set(ALL_MASTER_AGENTS))
            self.assertEqual(len(plan.activated_agents) + len(plan.skipped_agents), len(ALL_MASTER_AGENTS))

    def test_agent_reasons_contain_rationale_for_all_agents(self):
        """Plan must provide explicit justification for every activated and skipped agent."""
        plan = resolve_invocation_plan(RiskTier.TIER_1)
        for agent in ALL_MASTER_AGENTS:
            self.assertIn(agent, plan.agent_reasons)
            reason = plan.agent_reasons[agent]
            if agent in plan.activated_agents:
                self.assertTrue(reason.startswith("ACTIVATED:"))
            else:
                self.assertTrue(reason.startswith("SKIPPED:"))

    def test_to_dict_and_json_serialization(self):
        """InvocationPlan must serialize cleanly to JSON."""
        plan = resolve_invocation_plan(RiskTier.TIER_2, high_risk_triggers=["Sample Trigger"])
        data = plan.to_dict()
        serialized = json.dumps(data)
        self.assertIsInstance(serialized, str)
        self.assertEqual(data["risk_tier"], 2)
        self.assertEqual(data["high_risk_triggers"], ["Sample Trigger"])


if __name__ == "__main__":
    unittest.main()
