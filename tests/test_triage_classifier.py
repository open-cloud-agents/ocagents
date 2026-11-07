"""
Unit tests for Open Cloud Agents: Blast Radius Risk Tier Classifier (TASK-3.1).
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
    """Test suite covering the 3-tier blast radius classifier."""

    def test_empty_changeset(self):
        """Empty changeset defaults to Tier 0 with no agents."""
        result = classify_changeset([])
        self.assertEqual(result.risk_tier, RiskTier.TIER_0)
        self.assertEqual(result.activated_agents, [])
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
        ]
        result = classify_changeset(files)
        self.assertEqual(result.risk_tier, RiskTier.TIER_0)
        self.assertEqual(result.activated_agents, [])
        self.assertEqual(result.diff_summary["tier_0"], len(files))
        self.assertEqual(result.diff_summary["tier_1"], 0)
        self.assertEqual(result.diff_summary["tier_2"], 0)
        self.assertIn("bypassing specialist LLM review", result.reasons[0])

    def test_tier_1_application_code_only(self):
        """Application source code without IaC must be classified as Tier 1."""
        files = [
            "src/ocagents/cli.py",
            "src/ocagents/utils.py",
            "pyproject.toml",
            "README.md",
        ]
        result = classify_changeset(files)
        self.assertEqual(result.risk_tier, RiskTier.TIER_1)
        self.assertEqual(result.activated_agents, ["devsecops-reviewer"])
        self.assertEqual(result.diff_summary["tier_0"], 1)  # README.md
        self.assertEqual(result.diff_summary["tier_1"], 3)  # cli.py, utils.py, pyproject.toml
        self.assertEqual(result.diff_summary["tier_2"], 0)
        self.assertIn("routing to DevSecOps Reviewer", result.reasons[0])

    def test_tier_2_terraform_iac(self):
        """Changes to Terraform files must trigger Tier 2 Master Suite blackboard."""
        files = [
            "terraform/main.tf",
            "terraform/variables.tfvars",
            "src/app.py",
        ]
        result = classify_changeset(files)
        self.assertEqual(result.risk_tier, RiskTier.TIER_2)
        self.assertIn("principal-cloud-architect", result.activated_agents)
        self.assertIn("security-compliance-commander", result.activated_agents)
        self.assertIn("finops-cloud-cost-optimizer", result.activated_agents)
        self.assertIn("sre-reliability-engineer", result.activated_agents)
        self.assertIn("devsecops-reviewer", result.activated_agents)
        self.assertEqual(result.diff_summary["tier_2"], 2)

    def test_tier_2_cicd_workflows(self):
        """Modifications to GitHub Actions workflows must trigger Tier 2."""
        files = [
            ".github/workflows/deploy.yml",
            "README.md",
        ]
        result = classify_changeset(files)
        self.assertEqual(result.risk_tier, RiskTier.TIER_2)
        self.assertEqual(result.file_classifications[".github/workflows/deploy.yml"], RiskTier.TIER_2)

    def test_tier_2_containers_and_helm(self):
        """Dockerfiles, Compose manifests, and Helm charts must trigger Tier 2."""
        for path in [
            "Dockerfile",
            "Dockerfile.prod",
            "docker-compose.yml",
            "charts/service/Chart.yaml",
            "charts/service/values.yaml",
            "k8s/deployment.yaml",
        ]:
            tier, _ = classify_file(path)
            self.assertEqual(tier, RiskTier.TIER_2, f"Expected Tier 2 for {path}")

    def test_tier_2_security_governance_and_rules(self):
        """Modifications to repository rules or exceptions must trigger Tier 2."""
        tier, _ = classify_file("rules/01-destructive-actions.md")
        self.assertEqual(tier, RiskTier.TIER_2)

        tier, _ = classify_file(".ocagents/exceptions.json")
        self.assertEqual(tier, RiskTier.TIER_2)

        tier, _ = classify_file("policy/auth.rego")
        self.assertEqual(tier, RiskTier.TIER_2)

    def test_tier_2_diff_content_destructive_pattern(self):
        """Diff containing force_destroy = true or unbounded CIDR must be promoted to Tier 2."""
        diff_text = """diff --git a/storage.tf b/storage.tf
--- a/storage.tf
+++ b/storage.tf
@@ -10,2 +10,3 @@
 resource "aws_s3_bucket" "data" {
+  force_destroy = true
 }
"""
        result = classify_diff(diff_text)
        self.assertEqual(result.risk_tier, RiskTier.TIER_2)
        self.assertIn("storage.tf", result.file_classifications)
        self.assertEqual(result.file_classifications["storage.tf"], RiskTier.TIER_2)

    def test_tier_2_diff_content_kubernetes_api(self):
        """Diff containing apiVersion: apps/v1 must be recognized as Tier 2."""
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
        self.assertEqual(result.risk_tier, RiskTier.TIER_2)

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
        self.assertEqual(data["risk_tier"], RiskTier.TIER_2)
        self.assertEqual(data["diff_summary"]["total_files"], 3)

    def test_classify_git_ref_failure_fails_closed(self):
        """Nonexistent git ref must raise RuntimeError (fail closed)."""
        with self.assertRaises(RuntimeError):
            classify_git_ref("nonexistent_base_ref_12345", head_ref="HEAD")


if __name__ == "__main__":
    unittest.main()

