"""Unit tests for Open Cloud Agents Findings Schema & Provenance Engine (v1.4)."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from ocagents.findings import (
    FindingValidator,
    SchemaValidator,
    ProvenanceVerifier,
    resolve_default_repo_root,
)

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

    def test_boolean_confidence_rejected(self):
        fixture = json.loads((FIXTURES_DIR / "valid_diff_finding.json").read_text(encoding="utf-8"))
        fixture["confidence"] = True  # bool should not be accepted as float/null
        ok, errors = self.validator.validate(fixture)
        self.assertFalse(ok)
        self.assertTrue(any("not boolean" in err for err in errors))

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


class TestProvenanceVerifier(unittest.TestCase):
    """Tests provenance verifier and evidence corroboration."""

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
        # sample.diff modifies line 25
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
        self.assertTrue(res.is_valid, f"Validation failed with errors: {res.all_errors}")
        self.assertEqual(len(res.all_errors), 0)
        self.assertEqual(res.finding_id, "FND-8B1C3E4A9F20")

    def test_validate_valid_repo_file(self):
        res = self.validator.validate_file(FIXTURES_DIR / "valid_repo_finding.json")
        self.assertTrue(res.is_valid, f"Validation failed with errors: {res.all_errors}")
        self.assertEqual(len(res.all_errors), 0)
        self.assertEqual(res.finding_id, "FND-1A2B3C4D5E6F")

    def test_validate_invalid_rule_id_file(self):
        res = self.validator.validate_file(FIXTURES_DIR / "invalid_rule_id.json")
        self.assertFalse(res.is_valid)
        self.assertEqual(len(res.schema_errors), 0)
        self.assertEqual(len(res.provenance_errors), 1)
        self.assertIn("not found in rules catalog", res.provenance_errors[0])


class TestFindingsProvenanceRegressionCases(unittest.TestCase):
    """Focused regression tests for path traversal, diff-context validation, and repo root defaults."""

    def test_repo_evidence_rejects_path_traversal(self):
        """repo: evidence must stay within the repository root."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "rules").mkdir()
            (repo / "rules" / "README.md").write_text("# ok\n", encoding="utf-8")
            verifier = ProvenanceVerifier(repo_root=repo)

            # should fail: escapes repo root via ../
            ok, err = verifier.verify_evidence("repo:../escape.txt#L1-L2")
            self.assertFalse(ok)
            self.assertIn("outside repository root", str(err).lower())

    def test_diff_anchor_rejects_context_only_hunk_lines(self):
        """diff: evidence must map to modified lines, not generic hunk context."""
        diff_text = """diff --git a/file.tf b/file.tf
index 1111111..2222222 100644
--- a/file.tf
+++ b/file.tf
@@ -10,4 +10,4 @@
   keep_this = "a"
- old_value = "bad"
+ new_value = "good"
   trailing_context = "c"
"""

        verifier = ProvenanceVerifier(repo_root=Path.cwd())
        # the test deliberately targets the unchanged context line in the hunk
        ok, err = verifier.verify_evidence("diff:file.tf#L12-L12", diff_text=diff_text)
        self.assertFalse(ok)
        self.assertIn("modified diff lines", str(err).lower())

    def test_cli_uses_cwd_repo_root_when_repo_root_is_unset(self):
        """If the working directory looks like the repo root, prefer it over the installed asset root."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            (repo / "rules").mkdir()
            (repo / "rules" / "README.md").write_text("# ok\n", encoding="utf-8")
            (repo / "schemas").mkdir()
            (repo / "schemas" / "v1").mkdir()
            (repo / "schemas" / "v1" / "finding.json").write_text(
                json.dumps({
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "title": "OpenCloudAgentsFinding",
                    "type": "object",
                    "required": [
                        "id",
                        "agent",
                        "origin",
                        "rule_id",
                        "category",
                        "resource",
                        "fact",
                        "evidence",
                        "recommendation",
                        "severity",
                        "confidence",
                        "corroboration_status",
                    ],
                    "properties": {
                        "id": {"type": "string"},
                        "agent": {"type": "string"},
                        "origin": {"type": "string"},
                        "rule_id": {"type": "string"},
                        "category": {"type": "string"},
                        "resource": {"type": "string"},
                        "fact": {"type": "string"},
                        "evidence": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "severity": {"type": "string"},
                        "confidence": {"type": ["number", "null"]},
                        "corroboration_status": {"type": "string"},
                    },
                    "additionalProperties": False,
                }),
                encoding="utf-8",
            )

            # a valid repo-root candidate
            old_cwd = Path.cwd()
            try:
                os.chdir(repo)
                args = SimpleNamespace(path=".", diff=None, repo_root=None)

                resolved_repo_root = resolve_default_repo_root(
                    explicit_root=getattr(args, "repo_root", None),
                    target_path=getattr(args, "path", None),
                    asset_root=Path("/opt/installed/share/ocagents"),
                )

                validator = FindingValidator(repo_root=resolved_repo_root)
                ok, err = validator.provenance_verifier.verify_rule("rules/README.md")
                self.assertTrue(ok)
                self.assertIsNone(err)
            finally:
                os.chdir(old_cwd)


class TestSchemaConsistency(unittest.TestCase):
    """Verifies that schemas/v1/finding.json and SchemaValidator constraints stay in sync."""

    def test_schema_matches_validator_constants(self):
        schema_path = REPO_ROOT / "schemas" / "v1" / "finding.json"
        raw_schema = json.loads(schema_path.read_text(encoding="utf-8"))

        validator = SchemaValidator(schema_path=schema_path)
        self.assertEqual(validator.required_fields, raw_schema["required"])
        self.assertEqual(validator.allowed_origins, set(raw_schema["properties"]["origin"]["enum"]))
        self.assertEqual(validator.allowed_severities, set(raw_schema["properties"]["severity"]["enum"]))
        self.assertEqual(
            validator.allowed_corroborations,
            set(raw_schema["properties"]["corroboration_status"]["enum"]),
        )


if __name__ == "__main__":
    unittest.main()
