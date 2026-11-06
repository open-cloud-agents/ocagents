"""Unit tests for OPA (Rego) policy evaluator and institutional guardrails.

Validates that Terraform plan JSON and Kubernetes YAML/JSON manifests are evaluated
against institutional Rule 01 (destruction guard) and Rule 04 (well-architected invariants),
emitting canonical findings complying with schemas/v1/finding.json and filtered by diffs.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

from ocagents.findings.schema_validator import SchemaValidator
from ocagents.scanner.opa import (
    OpaEvaluator,
    evaluate_manifest,
    evaluate_terraform_plan,
    parse_manifest_documents,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TF_DESTRUCTIVE_FIXTURE = FIXTURES_DIR / "terraform" / "tfplan_destructive.json"
TF_CLEAN_FIXTURE = FIXTURES_DIR / "terraform" / "tfplan_clean.json"
K8S_INSECURE_FIXTURE = FIXTURES_DIR / "k8s" / "deployment_insecure.yaml"
K8S_VALID_FIXTURE = FIXTURES_DIR / "k8s" / "deployment_valid.yaml"

SAMPLE_DIFF = """diff --git a/infra/main.tf b/infra/main.tf
index 1111111..2222222 100644
--- a/infra/main.tf
+++ b/infra/main.tf
@@ -10,6 +10,8 @@
 resource "aws_s3_bucket" "artifacts_archive" {
+  force_destroy = true
+  bucket        = "corp-artifacts-prod"
 }
"""


class TestOpaEvaluator(unittest.TestCase):
    """Test suite for OPA policy evaluator on Terraform plans and Kubernetes manifests."""

    def setUp(self) -> None:
        self.validator = SchemaValidator()
        self.evaluator = OpaEvaluator(repo_root=FIXTURES_DIR.parent.parent)

    def test_evaluate_terraform_destructive_plan(self) -> None:
        """Terraform plan with deletions, forced replacement, force_destroy, and missing invariants is flagged."""
        findings = self.evaluator.evaluate_terraform_plan(
            TF_DESTRUCTIVE_FIXTURE,
            target_file="infra/main.tf",
        )

        self.assertGreaterEqual(len(findings), 4)

        # Validate every finding conforms to schemas/v1/finding.json
        for f in findings:
            ok, errors = self.validator.validate(f)
            self.assertTrue(
                ok,
                f"Finding failed canonical schema validation: {errors} - {f.get('id')} - {f.get('fact')}",
            )
            self.assertEqual(f["origin"], "deterministic_linter")
            self.assertEqual(f["corroboration_status"], "tool_verified")
            self.assertIsNone(f["confidence"])

        # Check Rule 01: Resource Deletion (aws_security_group_rule)
        deletion_findings = [
            f for f in findings
            if f["rule_id"] == "rules/01-destructive-actions.md"
            and "deletion" in f["fact"].lower()
        ]
        self.assertEqual(len(deletion_findings), 1)
        self.assertEqual(deletion_findings[0]["resource"], "aws_security_group_rule.legacy_ingress")
        self.assertEqual(deletion_findings[0]["severity"], "critical")

        # Check Rule 01: Stateful Forced Replacement (aws_db_instance)
        replacement_findings = [
            f for f in findings
            if f["rule_id"] == "rules/01-destructive-actions.md"
            and "forced replacement" in f["fact"].lower()
        ]
        self.assertEqual(len(replacement_findings), 1)
        self.assertEqual(replacement_findings[0]["resource"], "aws_db_instance.primary_database")
        self.assertEqual(replacement_findings[0]["severity"], "critical")

        # Check Rule 01: force_destroy flag (aws_s3_bucket)
        force_destroy_findings = [
            f for f in findings
            if f["rule_id"] == "rules/01-destructive-actions.md"
            and "force_destroy" in f["fact"].lower()
        ]
        self.assertEqual(len(force_destroy_findings), 1)
        self.assertEqual(force_destroy_findings[0]["resource"], "aws_s3_bucket.artifacts_archive")

        # Check Rule 04: S3 missing encryption
        s3_encryption_findings = [
            f for f in findings
            if f["rule_id"] == "rules/04-cloud-well-architected-invariants.md"
            and "encryption" in f["fact"].lower()
        ]
        self.assertEqual(len(s3_encryption_findings), 1)
        self.assertEqual(s3_encryption_findings[0]["resource"], "aws_s3_bucket.artifacts_archive")

        # Check Rule 04: Database missing Multi-AZ
        multi_az_findings = [
            f for f in findings
            if f["rule_id"] == "rules/04-cloud-well-architected-invariants.md"
            and "multi-az" in f["fact"].lower()
        ]
        self.assertEqual(len(multi_az_findings), 1)
        self.assertEqual(multi_az_findings[0]["resource"], "aws_db_instance.primary_database")

    def test_evaluate_terraform_clean_plan(self) -> None:
        """Clean Terraform plan produces zero policy findings."""
        findings = self.evaluator.evaluate_terraform_plan(
            TF_CLEAN_FIXTURE,
            target_file="infra/main.tf",
        )
        self.assertEqual(len(findings), 0)

    def test_evaluate_kubernetes_insecure_manifest(self) -> None:
        """Kubernetes manifest with privileged container, missing limits, and no readiness is flagged."""
        findings = self.evaluator.evaluate_kubernetes_manifest(
            K8S_INSECURE_FIXTURE,
            target_file="k8s/deployment_insecure.yaml",
        )

        self.assertEqual(len(findings), 3)

        # Validate every finding conforms to schemas/v1/finding.json
        for f in findings:
            ok, errors = self.validator.validate(f)
            self.assertTrue(
                ok,
                f"Finding failed canonical schema validation: {errors} - {f.get('id')} - {f.get('fact')}",
            )
            self.assertEqual(f["rule_id"], "rules/04-cloud-well-architected-invariants.md")

        # 1. Privileged container (critical)
        priv_findings = [f for f in findings if "privileged" in f["fact"].lower()]
        self.assertEqual(len(priv_findings), 1)
        self.assertEqual(priv_findings[0]["severity"], "critical")
        self.assertEqual(priv_findings[0]["resource"], "deployment/payment-processor")

        # 2. Missing memory limit (high)
        mem_findings = [f for f in findings if "memory limit" in f["fact"].lower()]
        self.assertEqual(len(mem_findings), 1)
        self.assertEqual(mem_findings[0]["severity"], "high")

        # 3. Missing readiness probe (medium)
        probe_findings = [f for f in findings if "readinessprobe" in f["fact"].lower()]
        self.assertEqual(len(probe_findings), 1)
        self.assertEqual(probe_findings[0]["severity"], "medium")

    def test_evaluate_kubernetes_valid_manifest(self) -> None:
        """Clean Kubernetes manifest with non-privileged container and readiness probe has 0 findings."""
        findings = self.evaluator.evaluate_kubernetes_manifest(
            K8S_VALID_FIXTURE,
            target_file="k8s/deployment_valid.yaml",
        )
        self.assertEqual(len(findings), 0)

    def test_terraform_diff_filtering(self) -> None:
        """Findings on modified diff lines are retained while out-of-diff findings are filtered."""
        findings = self.evaluator.evaluate_terraform_plan(
            TF_DESTRUCTIVE_FIXTURE,
            target_file="infra/main.tf",
            diff_text=SAMPLE_DIFF,
        )
        self.assertGreater(len(findings), 0, "Diff filter must retain findings intersecting modified diff hunks")
        retained_resources = {f["resource"] for f in findings}
        self.assertIn("aws_s3_bucket.artifacts_archive", retained_resources)
        self.assertNotIn("aws_security_group_rule.legacy_ingress", retained_resources)

        # Confirm evidence accurately points to line 11 (the exact force_destroy line in SAMPLE_DIFF)
        force_destroy_f = next(f for f in findings if "force_destroy" in f["fact"].lower())
        self.assertIn("#L11", force_destroy_f["evidence"])
        self.assertTrue(force_destroy_f["metadata"].get("line_resolved"))

    def test_terraform_file_source_span_resolution(self) -> None:
        """Evaluating against actual HCL file locates exact attribute lines and block spans."""
        hcl_fixture = FIXTURES_DIR / "terraform" / "main.tf"
        findings = self.evaluator.evaluate_terraform_plan(
            TF_DESTRUCTIVE_FIXTURE,
            target_file=str(hcl_fixture),
        )
        force_destroy_f = next(f for f in findings if "force_destroy" in f["fact"].lower())
        # In main.tf, force_destroy = true is on line 17
        self.assertIn("#L17", force_destroy_f["evidence"])
        self.assertTrue(force_destroy_f["metadata"]["line_resolved"])
        self.assertEqual(force_destroy_f["metadata"]["location_precision"], "exact")

    @patch("subprocess.run")
    def test_opa_cli_execution_mocked(self, mock_run: MagicMock) -> None:
        """When OPA CLI is present, OpaEvaluator executes 'opa eval' and normalizes findings."""
        fake_opa_output = {
            "result": [
                {
                    "expressions": [
                        {
                            "value": {
                                "destructive_actions": {
                                    "violations": [
                                        {
                                            "rule_id": "rules/01-destructive-actions.md",
                                            "severity": "critical",
                                            "resource": "aws_db_instance.primary_database",
                                            "title": "Stateful resource triggers forced replacement",
                                            "recommendation": "Migrate database in-place.",
                                        }
                                    ]
                                },
                                "well_architected": {
                                    "violations": [
                                        {
                                            "rule_id": "rules/04-cloud-well-architected-invariants.md",
                                            "severity": "high",
                                            "resource": "aws_s3_bucket.artifacts_archive",
                                            "title": "Missing server_side_encryption",
                                            "recommendation": "Configure KMS encryption.",
                                        }
                                    ]
                                },
                            }
                        }
                    ]
                }
            ]
        }
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(fake_opa_output),
            stderr="",
        )

        cli_evaluator = OpaEvaluator(
            repo_root=FIXTURES_DIR.parent.parent,
            use_cli_if_available=True,
        )
        cli_evaluator._opa_cli = "/usr/local/bin/opa"

        findings = cli_evaluator.evaluate_terraform_plan(
            TF_DESTRUCTIVE_FIXTURE,
            target_file="infra/main.tf",
        )

        self.assertEqual(len(findings), 2)
        mock_run.assert_called_once()
        called_args = mock_run.call_args[0][0]
        self.assertEqual(called_args[0], "/usr/local/bin/opa")
        self.assertEqual(called_args[1], "eval")
        self.assertIn("data.open_cloud_agents", called_args)

        for f in findings:
            ok, errors = self.validator.validate(f)
            self.assertTrue(ok, f"Finding failed schema validation: {errors}")
            self.assertEqual(f["metadata"]["evaluator"], "opa_cli")
            self.assertEqual(f["metadata"]["policy_engine"], "opa_rego")

    def test_builtin_evaluator_metadata(self) -> None:
        """When use_cli_if_available=False, findings are strictly stamped with builtin_rego_engine."""
        builtin_evaluator = OpaEvaluator(
            repo_root=FIXTURES_DIR.parent.parent,
            use_cli_if_available=False,
        )
        findings = builtin_evaluator.evaluate_terraform_plan(
            TF_DESTRUCTIVE_FIXTURE,
            target_file="infra/main.tf",
        )
        self.assertGreaterEqual(len(findings), 4)
        for f in findings:
            self.assertEqual(f["metadata"]["evaluator"], "builtin_rego_engine")

    def test_evaluate_file_auto_detection(self) -> None:
        """evaluate_file automatically detects Terraform plan vs Kubernetes YAML."""
        tf_findings = self.evaluator.evaluate_file(TF_DESTRUCTIVE_FIXTURE)
        self.assertGreaterEqual(len(tf_findings), 4)

        k8s_findings = self.evaluator.evaluate_file(K8S_INSECURE_FIXTURE)
        self.assertEqual(len(k8s_findings), 3)

    def test_parse_manifest_documents_json_and_yaml(self) -> None:
        """parse_manifest_documents correctly handles both JSON and YAML documents."""
        # JSON manifest
        json_doc = '{"kind": "Deployment", "metadata": {"name": "api-service"}}'
        docs = parse_manifest_documents(json_doc)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["kind"], "Deployment")
        self.assertEqual(docs[0]["metadata"]["name"], "api-service")

        # Multi-document YAML
        yaml_content = """---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: doc-one
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: doc-two
"""
        docs_yaml = parse_manifest_documents(yaml_content)
        self.assertEqual(len(docs_yaml), 2)
        self.assertEqual(docs_yaml[0]["kind"], "Deployment")
        self.assertEqual(docs_yaml[1]["kind"], "StatefulSet")

    def test_functional_helpers(self) -> None:
        """Module-level functional helpers evaluate_terraform_plan and evaluate_manifest work as expected."""
        tf_findings = evaluate_terraform_plan(TF_DESTRUCTIVE_FIXTURE)
        self.assertGreaterEqual(len(tf_findings), 4)

        k8s_findings = evaluate_manifest(K8S_INSECURE_FIXTURE)
        self.assertEqual(len(k8s_findings), 3)

    def test_missing_file_raises_not_found(self) -> None:
        """Evaluating a non-existent file raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            self.evaluator.evaluate_file(FIXTURES_DIR / "non_existent_file.json")


if __name__ == "__main__":
    unittest.main()
