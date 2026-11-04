"""Unit tests for Open Cloud Agents Findings Schema & Provenance Engine (v1.4)."""

import json
from pathlib import Path
import sys
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from ocagents.findings import FindingValidator, SchemaValidator, ProvenanceVerifier
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "findings"


class TestFindingsSchemaValidator(unittest.TestCase):
    """Tests JSON Schema compliance."""

    def setUp(self):
        self.validator = SchemaValidator()

    def test_schema_file_exists_and_is_valid_json(self):
        schema_file = REPO_ROOT / "schemas" / "v1" / "finding.json"
        self.assertTrue(schema_file.is_file(), "schemas/v1/finding.json must exist")
        data = json.loads(schema_file.read_text(encoding="utf-8"))
        self.assertIn("required", data)
        self.assertIn("properties", data)
        self.assertEqual(data["title"], "OpenCloudAgentsFinding")

    def test_valid_diff_finding_schema(self):
        fixture = json.loads((FIXTURES_DIR / "valid_diff_finding.json").read_text(encoding="utf-8"))
        ok, errors = self.validator.validate(fixture)
        self.assertTrue(ok, f"Expected valid diff finding, got errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_valid_repo_finding_schema(self):
        fixture = json.loads((FIXTURES_DIR / "valid_repo_finding.json").read_text(encoding="utf-8"))
        ok, errors = self.validator.validate(fixture)
        self.assertTrue(ok, f"Expected valid repo finding, got errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_invalid_missing_fields(self):
        fixture = json.loads((FIXTURES_DIR / "invalid_missing_fields.json").read_text(encoding="utf-8"))
        ok, errors = self.validator.validate(fixture)
        self.assertFalse(ok)
        self.assertTrue(any("evidence" in err for err in errors))
        self.assertTrue(any("severity" in err for err in errors))
        self.assertTrue(any("confidence" in err for err in errors))

    def test_invalid_confidence_type(self):
        fixture = json.loads((FIXTURES_DIR / "invalid_confidence_type.json").read_text(encoding="utf-8"))
        ok, errors = self.validator.validate(fixture)
        self.assertFalse(ok)
        self.assertTrue(any("confidence" in err for err in errors))

    def test_invalid_origin_enum(self):
        fixture = json.loads((FIXTURES_DIR / "invalid_origin_enum.json").read_text(encoding="utf-8"))
        ok, errors = self.validator.validate(fixture)
        self.assertFalse(ok)
        self.assertTrue(any("origin" in err for err in errors))

    def test_invalid_locator_scheme(self):
        fixture = json.loads((FIXTURES_DIR / "invalid_locator_scheme.json").read_text(encoding="utf-8"))
        ok, errors = self.validator.validate(fixture)
        self.assertFalse(ok)
        self.assertTrue(any("evidence" in err for err in errors))


class TestFindingsProvenanceVerifier(unittest.TestCase):
    """Tests catalog integrity and evidence anchor corroboration."""

    def setUp(self):
        self.verifier = ProvenanceVerifier(repo_root=REPO_ROOT)
        self.diff_text = (FIXTURES_DIR / "sample.diff").read_text(encoding="utf-8")

    def test_valid_rule_catalog_entry(self):
        ok, err = self.verifier.verify_rule("rules/04-cloud-well-architected-invariants.md")
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_invalid_rule_catalog_entry(self):
        ok, err = self.verifier.verify_rule("rules/99-non-existent-rule.md")
        self.assertFalse(ok)
        self.assertIn("not found in rules catalog", err)

    def test_valid_diff_anchor_with_diff_hunk(self):
        ok, err = self.verifier.verify_evidence("diff:terraform/keyvault.tf#L24-L26", diff_text=self.diff_text)
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_diff_anchor_file_not_in_diff(self):
        ok, err = self.verifier.verify_evidence("diff:other/file.tf#L10-L15", diff_text=self.diff_text)
        self.assertFalse(ok)
        self.assertIn("not found in active pull request diff", err)

    def test_diff_anchor_lines_outside_hunk(self):
        # sample.diff modifies lines 20-29
        ok, err = self.verifier.verify_evidence("diff:terraform/keyvault.tf#L80-L90", diff_text=self.diff_text)
        self.assertFalse(ok)
        self.assertIn("does not intersect modified diff lines", err)

    def test_valid_repo_baseline_anchor(self):
        ok, err = self.verifier.verify_evidence("repo:rules/README.md#L1-L10")
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_repo_anchor_file_not_found(self):
        ok, err = self.verifier.verify_evidence("repo:non_existent/file.md#L1-L5")
        self.assertFalse(ok)
        self.assertIn("not found in workspace tree", err)

    def test_repo_anchor_lines_out_of_bounds(self):
        ok, err = self.verifier.verify_evidence("repo:rules/README.md#L9999-L10000")
        self.assertFalse(ok)
        self.assertIn("exceeds file line count", err)

    def test_cloud_locator_syntax(self):
        ok, err = self.verifier.verify_evidence("cloud:azure:/subscriptions/123/resourceGroups/rg/vaults/kv")
        self.assertTrue(ok)
        self.assertIsNone(err)

        ok_bad, err_bad = self.verifier.verify_evidence("cloud:unknown_provider:res-123")
        self.assertFalse(ok_bad)
        self.assertIn("Unsupported cloud provider", err_bad)


class TestUnifiedFindingValidator(unittest.TestCase):
    """Tests end-to-end FindingValidator orchestration."""

    def setUp(self):
        self.validator = FindingValidator(repo_root=REPO_ROOT)
        self.diff_text = (FIXTURES_DIR / "sample.diff").read_text(encoding="utf-8")

    def test_validate_valid_diff_file(self):
        res = self.validator.validate_file(FIXTURES_DIR / "valid_diff_finding.json", diff_text=self.diff_text)
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.all_errors), 0)
        self.assertEqual(res.finding_id, "FND-8B1C3E4A9F20")

    def test_validate_valid_repo_file(self):
        res = self.validator.validate_file(FIXTURES_DIR / "valid_repo_finding.json")
        self.assertTrue(res.is_valid)
        self.assertEqual(len(res.all_errors), 0)
        self.assertEqual(res.finding_id, "FND-1A2B3C4D5E6F")

    def test_validate_invalid_rule_id_file(self):
        res = self.validator.validate_file(FIXTURES_DIR / "invalid_rule_id.json")
        self.assertFalse(res.is_valid)
        self.assertEqual(len(res.schema_errors), 0)
        self.assertEqual(len(res.provenance_errors), 1)
        self.assertIn("not found in rules catalog", res.provenance_errors[0])


if __name__ == "__main__":
    unittest.main()
