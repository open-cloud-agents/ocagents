"""
Unit tests for Open Cloud Agents: Adaptive Change-Set Risk Classifier (Issue #102).
"""

import json
import unittest

from ocagents.triage.classifier import (
    RiskTier,
    classify_changeset,
    classify_diff,
    classify_file,
    classify_git_ref,
)


class TestRiskTierClassifier(unittest.TestCase):
    """Test suite covering the 4-tier blast radius classifier."""

    def test_empty_changeset(self):
        """Empty changeset defaults to Tier 0 with no agents."""
        result = classify_changeset([])
        self.assertEqual(result.risk_tier, RiskTier.TIER_0)
        self.assertEqual(result.activated_agents, [])
        self.assertEqual(len(result.skipped_agents), 7)
        self.assertEqual(result.diff_summary["total_files"], 0)
        self.assertIn("No modified files", result.reasons[0])

    def test_tier_0_docs_and_non_code_assets(self):
        """Documentation and images must be classified as Tier 0."""
        files = [
            "README.md",
            "docs/how-to-use-agents.md",
            "docs/architecture.png",
            "LICENSE",
            ".gitignore",
            "CHANGELOG.md",
            "media/logo.svg",
            "mkdocs.yml",
        ]
        result = classify_changeset(files)
        self.assertEqual(result.risk_tier, RiskTier.TIER_0)
        self.assertEqual(result.activated_agents, [])
        self.assertEqual(len(result.skipped_agents), 7)
        self.assertEqual(result.diff_summary["tier_0"], len(files))
        self.assertEqual(result.diff_summary["tier_1"], 0)
        self.assertEqual(result.diff_summary["tier_2"], 0)
        self.assertEqual(result.diff_summary["tier_3"], 0)
        self.assertIn("bypassing specialist LLM review", result.reasons[0])

    def test_tier_1_scripting_and_packaging_utilities(self):
        """Shell scripts and packaging configs must be classified as Tier 1 (DevSecOps Engineer)."""
        files = [
            "scripts/lint.sh",
            "Formula/ocagents.rb",
            "pyproject.toml",
            "README.md",
        ]
        result = classify_changeset(files)
        self.assertEqual(result.risk_tier, RiskTier.TIER_1)
        self.assertEqual(result.activated_agents, ["devsecops-engineer"])
        self.assertIn("principal-cloud-architect", result.skipped_agents)
        self.assertIn("devsecops-reviewer", result.skipped_agents)
        self.assertEqual(result.diff_summary["tier_0"], 1)  # README.md
        self.assertEqual(result.diff_summary["tier_1"], 3)  # lint.sh, Formula/ocagents.rb, pyproject.toml
        self.assertEqual(result.diff_summary["tier_2"], 0)
        self.assertEqual(result.diff_summary["tier_3"], 0)
        self.assertIn("routing to DevSecOps Engineer", result.reasons[0])

    def test_tier_2_cicd_workflows_and_core_runtime(self):
        """CI/CD workflows and core application runtime files must trigger Tier 2 (Security + Reviewer)."""
        files = [
            ".github/workflows/deploy.yml",
            "src/ocagents/cli.py",
            "README.md",
        ]
        result = classify_changeset(files)
        self.assertEqual(result.risk_tier, RiskTier.TIER_2)
        self.assertIn("security-compliance-commander", result.activated_agents)
        self.assertIn("devsecops-reviewer", result.activated_agents)
        self.assertNotIn("principal-cloud-architect", result.activated_agents)
        self.assertEqual(result.file_classifications[".github/workflows/deploy.yml"], RiskTier.TIER_2)
        self.assertEqual(result.file_classifications["src/ocagents/cli.py"], RiskTier.TIER_2)

    def test_tier_3_terraform_iac(self):
        """Changes to Terraform files must trigger Tier 3 full Master Suite blackboard."""
        files = [
            "terraform/main.tf",
            "terraform/variables.tfvars",
            "src/app.py",
        ]
        result = classify_changeset(files)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)
        self.assertIn("principal-cloud-architect", result.activated_agents)
        self.assertIn("security-compliance-commander", result.activated_agents)
        self.assertIn("finops-cloud-cost-optimizer", result.activated_agents)
        self.assertIn("sre-reliability-engineer", result.activated_agents)
        self.assertIn("devsecops-reviewer", result.activated_agents)
        self.assertEqual(result.diff_summary["tier_3"], 2)

    def test_tier_3_containers_and_helm(self):
        """Dockerfiles, Compose manifests, and Helm charts must trigger Tier 3."""
        for path in [
            "Dockerfile",
            "Dockerfile.prod",
            "docker-compose.yml",
            "charts/service/Chart.yaml",
            "charts/service/values.yaml",
            "k8s/deployment.yaml",
        ]:
            tier, _ = classify_file(path)
            self.assertEqual(tier, RiskTier.TIER_3, f"Expected Tier 3 for {path}")

    def test_tier_3_security_governance_and_rules(self):
        """Modifications to repository rules or exceptions must trigger Tier 3."""
        tier, _ = classify_file("rules/01-destructive-actions.md")
        self.assertEqual(tier, RiskTier.TIER_3)

        tier, _ = classify_file(".ocagents/exceptions.json")
        self.assertEqual(tier, RiskTier.TIER_3)

        tier, _ = classify_file("policy/auth.rego")
        self.assertEqual(tier, RiskTier.TIER_3)

    def test_tier_3_database_migrations(self):
        """Database migrations must trigger Tier 3."""
        tier, _ = classify_file("migrations/001_initial_schema.sql")
        self.assertEqual(tier, RiskTier.TIER_3)

        tier, _ = classify_file("db/migrations/20261119_add_index.sql")
        self.assertEqual(tier, RiskTier.TIER_3)

    def test_tier_3_diff_content_destructive_pattern(self):
        """Diff containing force_destroy = true or unbounded CIDR must be promoted to Tier 3."""
        diff_text = """diff --git a/storage.tf b/storage.tf
--- a/storage.tf
+++ b/storage.tf
@@ -10,2 +10,3 @@
 resource "aws_s3_bucket" "data" {
+  force_destroy = true
 }
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)
        self.assertIn("storage.tf", result.file_classifications)
        self.assertEqual(result.file_classifications["storage.tf"], RiskTier.TIER_3)
        self.assertTrue(any("force-destroy" in tr for tr in result.high_risk_triggers))

    def test_tier_3_diff_content_kubernetes_api(self):
        """Diff containing apiVersion: apps/v1 must be recognized as Tier 3."""
        diff_text = """diff --git a/manifests/web.yaml b/manifests/web.yaml
--- a/manifests/web.yaml
+++ b/manifests/web.yaml
@@ -0,0 +1,5 @@
+apiVersion: apps/v1
+kind: Deployment
+metadata:
+  name: web-api
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)

    def test_tier_3_diff_content_iam_wildcards(self):
        """Diff expanding IAM permissions with *:* or AdministratorAccess must trigger Tier 3."""
        diff_text = """diff --git a/iam_policy.json b/iam_policy.json
--- a/iam_policy.json
+++ b/iam_policy.json
@@ -5,2 +5,3 @@
+  "Action": "*",
+  "Resource": "*"
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)
        self.assertTrue(any("wildcard" in tr.lower() for tr in result.high_risk_triggers))

    def test_tier_3_diff_content_database_drop(self):
        """Diff containing DROP TABLE or TRUNCATE must trigger Tier 3."""
        diff_text = """diff --git a/scripts/setup.sh b/scripts/setup.sh
--- a/scripts/setup.sh
+++ b/scripts/setup.sh
@@ -1,2 +1,3 @@
+DROP TABLE customer_records;
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_3)
        self.assertTrue(any("DROP/TRUNCATE" in tr for tr in result.high_risk_triggers))

    def test_unknown_extension_safe_fallback(self):
        """Unrecognized extensions fall back safely to Tier 1."""
        tier, reasons = classify_file("config/custom.unknownext")
        self.assertEqual(tier, RiskTier.TIER_1)
        self.assertIn("default safe route", reasons[0])

    def test_to_dict_serialization(self):
        """TriageResult must be fully JSON serializable."""
        result = classify_changeset(["terraform/vpc.tf", "src/main.py", "docs/index.md"])
        data = result.to_dict()
        serialized = json.dumps(data)
        self.assertIsInstance(serialized, str)
        self.assertEqual(data["risk_tier"], RiskTier.TIER_3)
        self.assertEqual(data["diff_summary"]["total_files"], 3)
        self.assertIn("invocation_plan", data)
        self.assertIn("skipped_agents", data)

    def test_classify_git_ref_failure_fails_closed(self):
        """Nonexistent git ref must raise RuntimeError (fail closed)."""
        with self.assertRaises(RuntimeError):
            classify_git_ref("nonexistent_base_ref_12345", head_ref="HEAD")


if __name__ == "__main__":
    unittest.main()
