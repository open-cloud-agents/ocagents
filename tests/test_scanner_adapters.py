"""Unit tests for Checkov and Trivy ingest bridges and PR diff filtering.

Validates that Checkov native JSON and Trivy native JSON / SARIF are parsed into
canonical findings complying with schemas/v1/finding.json and filtered against active diffs.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from ocagents.findings.schema_validator import SchemaValidator
from ocagents.scanner.checkov import CheckovAdapter, parse_checkov_output
from ocagents.scanner.diff_filter import (
    filter_findings_by_diff,
    is_finding_in_diff,
    parse_diff_modified_lines,
)
from ocagents.scanner.trivy import TrivyAdapter, parse_trivy_output

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


SAMPLE_DIFF = """diff --git a/infra/s3.tf b/infra/s3.tf
index 1111111..2222222 100644
--- a/infra/s3.tf
+++ b/infra/s3.tf
@@ -14,6 +14,8 @@
   bucket = "my-storage-bucket"
+  acl    = "private"
+  tags   = { Environment = "prod" }
 }
diff --git a/infra/iam.tf b/infra/iam.tf
index 3333333..4444444 100644
--- a/infra/iam.tf
+++ b/infra/iam.tf
@@ -46,3 +46,4 @@
   Statement = [{
+    Action   = "*"
     Resource = "*"
   }]
"""


class TestDiffFilter(unittest.TestCase):
    """Test suite for unified diff line parsing and finding filtration."""

    def test_parse_diff_modified_lines(self):
        """Diff parser correctly captures added lines on new side of hunks."""
        modified = parse_diff_modified_lines(SAMPLE_DIFF)
        self.assertIn("infra/s3.tf", modified)
        self.assertIn("infra/iam.tf", modified)

        # In infra/s3.tf, lines 15 and 16 were added
        self.assertEqual(modified["infra/s3.tf"], {15, 16})
        # In infra/iam.tf, line 47 was added
        self.assertEqual(modified["infra/iam.tf"], {47})

    def test_is_finding_in_diff(self):
        """Evaluates whether finding evidence line ranges intersect diff additions."""
        modified = parse_diff_modified_lines(SAMPLE_DIFF)

        # Finding on infra/s3.tf L12-L25 intersects lines 15, 16 -> True
        f_matching = {"evidence": "repo:infra/s3.tf#L12-L25"}
        self.assertTrue(is_finding_in_diff(f_matching, modified))

        # Finding on infra/s3.tf L50-L60 does not intersect -> False
        f_not_matching = {"evidence": "repo:infra/s3.tf#L50-L60"}
        self.assertFalse(is_finding_in_diff(f_not_matching, modified))

        # Finding on a file not in the diff -> False
        f_other_file = {"evidence": "repo:infra/vpc.tf#L1-L10"}
        self.assertFalse(is_finding_in_diff(f_other_file, modified))

    def test_filter_findings_by_diff_with_scheme_conversion(self):
        """filter_findings_by_diff retains intersecting findings and optionally updates scheme to diff:."""
        findings = [
            {"id": "FND-01", "evidence": "repo:infra/s3.tf#L12-L25"},
            {"id": "FND-02", "evidence": "repo:infra/s3.tf#L50-L60"},
            {"id": "FND-03", "evidence": "repo:infra/iam.tf#L45-L52"},
        ]

        # 1. Without scheme conversion
        retained = filter_findings_by_diff(findings, SAMPLE_DIFF, convert_to_diff_scheme=False)
        self.assertEqual(len(retained), 2)
        retained_ids = [f["id"] for f in retained]
        self.assertIn("FND-01", retained_ids)
        self.assertIn("FND-03", retained_ids)
        self.assertNotIn("FND-02", retained_ids)
        self.assertTrue(retained[0]["evidence"].startswith("repo:"))

        # 2. With scheme conversion (repo: -> diff:)
        retained_converted = filter_findings_by_diff(findings, SAMPLE_DIFF, convert_to_diff_scheme=True)
        self.assertEqual(len(retained_converted), 2)
        self.assertEqual(retained_converted[0]["evidence"], "diff:infra/s3.tf#L12-L25")
        self.assertEqual(retained_converted[1]["evidence"], "diff:infra/iam.tf#L45-L52")


class TestCheckovAdapter(unittest.TestCase):
    """Test suite for Checkov native JSON output parsing and diff filtering."""

    def setUp(self):
        self.schema_validator = SchemaValidator()
        self.adapter = CheckovAdapter()
        self.checkov_json_path = FIXTURES_DIR / "checkov" / "checkov_native.json"

    def test_parse_native_checkov_json(self):
        """Checkov native JSON parses into canonical findings satisfying schemas/v1/finding.json."""
        findings = self.adapter.parse_file(self.checkov_json_path)
        self.assertEqual(len(findings), 2)

        # 1. S3 Public Access Block check (CKV_AWS_20)
        f1 = findings[0]
        self.assertEqual(f1["agent"], "checkov")
        self.assertEqual(f1["origin"], "deterministic_linter")
        self.assertEqual(f1["rule_id"], "rules/04-cloud-well-architected-invariants.md")
        self.assertEqual(f1["resource"], "aws_s3_bucket.data_bucket")
        self.assertEqual(f1["evidence"], "repo:infra/s3.tf#L12-L25")
        self.assertEqual(f1["severity"], "high")
        self.assertIsNone(f1["confidence"])
        self.assertEqual(f1["corroboration_status"], "tool_verified")
        self.assertTrue(f1["id"].startswith("FND-"))

        ok1, err1 = self.schema_validator.validate(f1)
        self.assertTrue(ok1, f"Finding 1 schema invalid: {err1}")

        # 2. S3 Force Destroy check (CKV_AWS_1)
        f2 = findings[1]
        self.assertEqual(f2["rule_id"], "rules/01-destructive-actions.md")
        self.assertEqual(f2["resource"], "aws_s3_bucket.legacy_bucket")
        self.assertEqual(f2["evidence"], "repo:infra/s3.tf#L50-L60")
        self.assertEqual(f2["severity"], "critical")

        ok2, err2 = self.schema_validator.validate(f2)
        self.assertTrue(ok2, f"Finding 2 schema invalid: {err2}")

    def test_checkov_diff_filtering(self):
        """Checkov findings outside modified PR diff lines are filtered out."""
        # Baseline: 2 findings in checkov_native.json
        # When filtered with SAMPLE_DIFF (which modifies lines 15-16 in infra/s3.tf):
        # CKV_AWS_20 (L12-L25) intersects -> retained
        # CKV_AWS_1 (L50-L60) does not intersect -> filtered out
        filtered = self.adapter.parse_file(self.checkov_json_path, diff_text=SAMPLE_DIFF)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["metadata"]["check_id"], "CKV_AWS_20")

    def test_parse_checkov_output_functional_wrapper(self):
        """parse_checkov_output convenience function returns valid findings."""
        findings = parse_checkov_output(self.checkov_json_path)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["agent"], "checkov")


class TestTrivyAdapter(unittest.TestCase):
    """Test suite for Trivy native JSON and SARIF parsing and diff filtering."""

    def setUp(self):
        self.schema_validator = SchemaValidator()
        self.adapter = TrivyAdapter()
        self.trivy_json_path = FIXTURES_DIR / "trivy" / "trivy_native.json"
        self.trivy_sarif_path = FIXTURES_DIR / "sarif" / "trivy_sample.sarif"

    def test_parse_native_trivy_json(self):
        """Trivy native JSON parses misconfigurations and vulnerabilities into canonical findings."""
        findings = self.adapter.parse_file(self.trivy_json_path)
        self.assertEqual(len(findings), 2)

        # 1. IAM Misconfiguration (AVD-AWS-0057)
        iam_finding = findings[0]
        self.assertEqual(iam_finding["agent"], "trivy")
        self.assertEqual(iam_finding["origin"], "deterministic_linter")
        self.assertEqual(iam_finding["rule_id"], "rules/02-secrets-and-identity.md")
        self.assertEqual(iam_finding["resource"], "aws_iam_policy.admin_role")
        self.assertEqual(iam_finding["evidence"], "repo:infra/iam.tf#L45-L52")
        self.assertEqual(iam_finding["severity"], "critical")
        self.assertIsNone(iam_finding["confidence"])
        self.assertEqual(iam_finding["corroboration_status"], "tool_verified")

        ok1, err1 = self.schema_validator.validate(iam_finding)
        self.assertTrue(ok1, f"IAM finding schema invalid: {err1}")

        # 2. Package Vulnerability (CVE-2023-1234)
        vuln_finding = findings[1]
        self.assertEqual(vuln_finding["rule_id"], "rules/04-cloud-well-architected-invariants.md")
        self.assertEqual(vuln_finding["resource"], "package.json:express@4.17.1")
        self.assertEqual(vuln_finding["severity"], "high")
        self.assertIn("Upgrade express to version 4.18.2", vuln_finding["recommendation"])

        ok2, err2 = self.schema_validator.validate(vuln_finding)
        self.assertTrue(ok2, f"Vuln finding schema invalid: {err2}")

    def test_trivy_sarif_auto_routing(self):
        """TrivyAdapter automatically detects and routes SARIF inputs."""
        findings = self.adapter.parse_file(self.trivy_sarif_path)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["agent"], "trivy")

    def test_trivy_diff_filtering(self):
        """Trivy findings outside modified PR diff lines are filtered out."""
        # When filtered with SAMPLE_DIFF:
        # infra/iam.tf L45-L52 intersects line 47 -> retained
        # package.json is not modified in diff -> filtered out
        filtered = self.adapter.parse_file(self.trivy_json_path, diff_text=SAMPLE_DIFF)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["metadata"]["trivy_id"], "AVD-AWS-0057")

    def test_parse_trivy_output_functional_wrapper(self):
        """parse_trivy_output convenience function returns valid findings."""
        findings = parse_trivy_output(self.trivy_json_path)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["agent"], "trivy")


if __name__ == "__main__":
    unittest.main()
