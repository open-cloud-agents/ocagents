"""Unit tests for Universal SARIF v2.1.0 Normalizer.

Validates that standard SARIF outputs from Checkov, Trivy, CodeQL, and Semgrep
are converted into canonical findings conforming to schemas/v1/finding.json and ADR-002.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from ocagents.findings.normalizer import (
    CANONICAL_SCHEMA_URI,
    EXPLICIT_RULE_MAP,
    RULE_DESTRUCTIVE,
    RULE_HYGIENE,
    RULE_SCOPE,
    RULE_SECRETS,
    RULE_WELL_ARCHITECTED,
    SarifNormalizer,
    clean_artifact_uri,
    compute_finding_id,
    map_category,
    map_rule_id,
    map_severity,
    normalize_sarif,
)
from ocagents.findings.schema_validator import SchemaValidator

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "sarif"


class TestSarifNormalizer(unittest.TestCase):
    """Test suite for SARIF ingestion and normalization into canonical findings."""

    def setUp(self):
        self.schema_validator = SchemaValidator()
        self.normalizer = SarifNormalizer()

    def test_checkov_sarif_normalization(self):
        """Verify Checkov SARIF maps IaC rules, logical resources, and severities."""
        checkov_path = FIXTURES_DIR / "checkov_sample.sarif"
        findings = self.normalizer.normalize_file(checkov_path)

        self.assertEqual(len(findings), 2)

        # 1. Inspect S3 Public Access Block finding (CKV_AWS_20)
        f1 = findings[0]
        self.assertEqual(f1["$schema"], CANONICAL_SCHEMA_URI)
        self.assertEqual(f1["agent"], "checkov")
        self.assertEqual(f1["origin"], "deterministic_linter")
        self.assertEqual(f1["rule_id"], RULE_WELL_ARCHITECTED)
        self.assertEqual(f1["resource"], "module.storage.aws_s3_bucket.data_bucket")
        self.assertEqual(f1["evidence"], "repo:infra/s3.tf#L12-L25")
        self.assertEqual(f1["severity"], "high")
        self.assertIsNone(f1["confidence"])
        self.assertEqual(f1["corroboration_status"], "tool_verified")
        self.assertTrue(f1["id"].startswith("FND-"))
        self.assertEqual(len(f1["id"]), 16)

        # Schema validation
        ok1, err1 = self.schema_validator.validate(f1)
        self.assertTrue(ok1, f"Finding 1 schema invalid: {err1}")

        # 2. Inspect force_destroy finding (CKV_AWS_1)
        f2 = findings[1]
        self.assertEqual(f2["rule_id"], RULE_DESTRUCTIVE)
        self.assertEqual(f2["resource"], "aws_s3_bucket.ephemeral_bucket")
        self.assertEqual(f2["evidence"], "repo:infra/s3.tf#L28-L35")
        self.assertEqual(f2["severity"], "critical")
        self.assertIsNone(f2["confidence"])
        self.assertEqual(f2["corroboration_status"], "tool_verified")

        ok2, err2 = self.schema_validator.validate(f2)
        self.assertTrue(ok2, f"Finding 2 schema invalid: {err2}")

    def test_trivy_sarif_normalization(self):
        """Verify Trivy SARIF maps IAM and container findings correctly."""
        trivy_path = FIXTURES_DIR / "trivy_sample.sarif"
        findings = self.normalizer.normalize_file(trivy_path)

        self.assertEqual(len(findings), 2)

        # 1. IAM wildcard policy (AVD-AWS-0057)
        iam_finding = findings[0]
        self.assertEqual(iam_finding["agent"], "trivy")
        self.assertEqual(iam_finding["rule_id"], RULE_SECRETS)
        self.assertEqual(iam_finding["severity"], "critical")
        self.assertEqual(iam_finding["evidence"], "repo:infra/iam.tf#L45-L52")
        self.assertIsNone(iam_finding["confidence"])
        self.assertEqual(iam_finding["corroboration_status"], "tool_verified")

        ok1, err1 = self.schema_validator.validate(iam_finding)
        self.assertTrue(ok1, f"IAM finding schema invalid: {err1}")

        # 2. Container root user (DS002)
        container_finding = findings[1]
        self.assertEqual(container_finding["rule_id"], RULE_WELL_ARCHITECTED)
        self.assertEqual(container_finding["severity"], "medium")
        self.assertEqual(container_finding["evidence"], "repo:Dockerfile#L1")

        ok2, err2 = self.schema_validator.validate(container_finding)
        self.assertTrue(ok2, f"Container finding schema invalid: {err2}")

    def test_codeql_sarif_normalization(self):
        """Verify CodeQL SARIF maps CVSS security-severity scores and SAST rules."""
        codeql_path = FIXTURES_DIR / "codeql_sample.sarif"
        findings = self.normalizer.normalize_file(codeql_path)

        self.assertEqual(len(findings), 2)

        # 1. Cleartext credentials (py/cleartext-storage-sensitive-data, score: 8.8 -> high)
        cred_finding = findings[0]
        self.assertEqual(cred_finding["agent"], "codeql")
        self.assertEqual(cred_finding["rule_id"], RULE_SECRETS)
        self.assertEqual(cred_finding["severity"], "high")
        self.assertEqual(cred_finding["evidence"], "repo:app/config.py#L18-L20")

        ok1, err1 = self.schema_validator.validate(cred_finding)
        self.assertTrue(ok1, f"Cred finding schema invalid: {err1}")

        # 2. Path injection (py/path-injection, score: 5.5 -> medium)
        path_finding = findings[1]
        self.assertEqual(path_finding["rule_id"], RULE_HYGIENE)
        self.assertEqual(path_finding["severity"], "medium")
        self.assertEqual(path_finding["evidence"], "repo:app/utils.py#L88-L92")

        ok2, err2 = self.schema_validator.validate(path_finding)
        self.assertTrue(ok2, f"Path finding schema invalid: {err2}")

    def test_compute_finding_id_determinism_and_uniqueness(self):
        """Finding IDs must be deterministic and collision-resistant."""
        rule_id = "rules/04-cloud-well-architected-invariants.md"
        res = "aws_s3_bucket.main"
        ev = "repo:infra/s3.tf#L10-L20"

        id1 = compute_finding_id(rule_id, res, ev)
        id2 = compute_finding_id(rule_id, res, ev)

        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("FND-"))
        self.assertEqual(len(id1), 16)

        # Any variance changes the hash ID
        id_diff_res = compute_finding_id(rule_id, "aws_s3_bucket.other", ev)
        self.assertNotEqual(id1, id_diff_res)

        id_diff_ev = compute_finding_id(rule_id, res, "repo:infra/s3.tf#L30-L40")
        self.assertNotEqual(id1, id_diff_ev)

    def test_severity_mapping_ladder(self):
        """Verify severity mapping handles scores, explicit property levels, and SARIF levels."""
        # 1. Numeric CVSS scores
        self.assertEqual(map_severity("error", {"security-severity": "9.5"}), "critical")
        self.assertEqual(map_severity("error", {"security-severity": "7.5"}), "high")
        self.assertEqual(map_severity("warning", {"security-severity": "5.0"}), "medium")
        self.assertEqual(map_severity("note", {"security-severity": "2.5"}), "low")

        # 2. Explicit properties severity
        self.assertEqual(map_severity("error", {"severity": "CRITICAL"}), "critical")
        self.assertEqual(map_severity("error", {"severity": "HIGH"}), "high")
        self.assertEqual(map_severity("warning", {"severity": "MEDIUM"}), "medium")
        self.assertEqual(map_severity("note", {"severity": "LOW"}), "low")

        # 3. Standard SARIF levels
        self.assertEqual(map_severity("error"), "high")
        self.assertEqual(map_severity("warning"), "medium")
        self.assertEqual(map_severity("note"), "low")
        self.assertEqual(map_severity("none"), "info")
        self.assertEqual(map_severity(""), "medium")

    def test_clean_artifact_uri(self):
        """Artifact URIs must normalize to clean repository-relative POSIX paths."""
        self.assertEqual(clean_artifact_uri("infra/main.tf"), "infra/main.tf")
        self.assertEqual(clean_artifact_uri("file:///workspace/infra/main.tf"), "workspace/infra/main.tf")
        self.assertEqual(clean_artifact_uri("%SRCROOT%/infra/main.tf"), "infra/main.tf")
        self.assertEqual(clean_artifact_uri("/infra/main.tf"), "infra/main.tf")
        self.assertEqual(clean_artifact_uri("./infra/main.tf"), "infra/main.tf")
        self.assertEqual(clean_artifact_uri("infra//nested/../main.tf"), "infra/nested/main.tf")
        self.assertEqual(clean_artifact_uri(""), "unknown")

    def test_custom_rule_mapping(self):
        """Callers can provide explicit rule mapping dictionaries or callable mappers."""
        custom_map = {
            "MY_CUSTOM_LINTER_01": "rules/01-destructive-actions.md",
        }
        sarif_payload = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "custom-linter"}},
                    "results": [
                        {
                            "ruleId": "MY_CUSTOM_LINTER_01",
                            "message": {"text": "Custom check flagged dangerous operation."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "deploy.sh"},
                                        "region": {"startLine": 5},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        normalizer = SarifNormalizer(rule_map=custom_map)
        findings = normalizer.normalize(sarif_payload)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "rules/01-destructive-actions.md")
        self.assertEqual(findings[0]["evidence"], "repo:deploy.sh#L5")

    def test_deduplication_of_identical_sarif_results(self):
        """Identical SARIF results must deduplicate to single idempotent finding."""
        sarif_payload = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test-scanner"}},
                    "results": [
                        {
                            "ruleId": "CKV_AWS_20",
                            "message": {"text": "Missing S3 block."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "infra/s3.tf"},
                                        "region": {"startLine": 10, "endLine": 15},
                                    }
                                }
                            ],
                            "properties": {"resource": "aws_s3_bucket.main"},
                        },
                        {
                            "ruleId": "CKV_AWS_20",
                            "message": {"text": "Missing S3 block."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "infra/s3.tf"},
                                        "region": {"startLine": 10, "endLine": 15},
                                    }
                                }
                            ],
                            "properties": {"resource": "aws_s3_bucket.main"},
                        },
                    ],
                }
            ],
        }

        findings = self.normalizer.normalize(sarif_payload)
        self.assertEqual(len(findings), 1)

    def test_functional_convenience_helper(self):
        """normalize_sarif convenience wrapper returns valid findings."""
        checkov_path = FIXTURES_DIR / "checkov_sample.sarif"
        findings = normalize_sarif(checkov_path)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["agent"], "checkov")

    def test_malformed_sarif_handling(self):
        """Normalizer handles empty runs, empty results, and malformed inputs gracefully."""
        # 1. Empty runs
        self.assertEqual(self.normalizer.normalize({"version": "2.1.0", "runs": []}), [])

        # 2. Empty results
        self.assertEqual(
            self.normalizer.normalize(
                {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}]}
            ),
            [],
        )

        # 3. Missing file
        with self.assertRaises(FileNotFoundError):
            self.normalizer.normalize_file("nonexistent.sarif")

        # 4. Invalid JSON string
        with self.assertRaises(ValueError):
            self.normalizer.normalize("{bad json")


if __name__ == "__main__":
    unittest.main()
