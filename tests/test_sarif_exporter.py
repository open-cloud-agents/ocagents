"""
Unit tests for Open Cloud Agents: SARIF 2.1.0 Exporter (#103).
"""

import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from ocagents import __version__
from ocagents.blackboard import (
    BlackboardStore,
    build_sarif_log,
    create_run_envelope,
    findings_to_sarif_json,
)
from ocagents.blackboard.sarif_exporter import (
    FINGERPRINT_KEY,
    SARIF_SCHEMA_URI,
    SRCROOT,
)
from ocagents.findings.normalizer import SarifNormalizer

FIXTURES = Path(__file__).parent / "fixtures" / "findings"
SCHEMA_URL = "https://open-cloud-agents.github.io/schemas/v1/finding.json"


def _finding(**overrides):
    finding = {
        "$schema": SCHEMA_URL,
        "id": "FND-AAAAAAAAAAAA",
        "agent": "devsecops-reviewer",
        "origin": "deterministic_linter",
        "rule_id": "rules/01-destructive-actions.md",
        "category": "IaC Safety",
        "resource": "aws_db_instance.main",
        "fact": "db_name change forces replacement",
        "evidence": "diff:terraform/rds.tf#L16-L18",
        "recommendation": "Revert the db_name change",
        "severity": "critical",
        "confidence": None,
        "corroboration_status": "tool_verified",
    }
    finding.update(overrides)
    return finding


def _load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class TestSarifLogStructure(unittest.TestCase):
    """Top-level SARIF 2.1.0 structure required by GitHub Code Scanning."""

    def test_empty_findings_produce_a_valid_empty_run(self):
        log = build_sarif_log([])
        self.assertEqual(log["version"], "2.1.0")
        self.assertEqual(log["$schema"], SARIF_SCHEMA_URI)
        self.assertEqual(len(log["runs"]), 1)
        run = log["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["tool"]["driver"]["rules"], [])

    def test_tool_driver_metadata(self):
        driver = build_sarif_log([_finding()])["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "Open Cloud Agents")
        self.assertEqual(driver["version"], __version__)
        self.assertTrue(driver["informationUri"].startswith("https://"))

    def test_run_id_is_stored_as_a_property_not_an_analysis_category(self):
        run = build_sarif_log([_finding()], run_id="run-123")["runs"][0]
        self.assertEqual(run["properties"]["ocagentsRunId"], "run-123")
        self.assertNotIn("automationDetails", run)

    def test_json_output_is_deterministic(self):
        findings = [_load_fixture("valid_diff_finding.json"), _load_fixture("valid_repo_finding.json")]
        self.assertEqual(findings_to_sarif_json(findings), findings_to_sarif_json(findings))
        self.assertEqual(json.loads(findings_to_sarif_json(findings)), build_sarif_log(findings))


class TestResultMapping(unittest.TestCase):
    """Finding fields to SARIF results."""

    def test_diff_evidence_maps_to_physical_location_with_line_range(self):
        result = build_sarif_log([_finding()])["runs"][0]["results"][0]
        physical = result["locations"][0]["physicalLocation"]
        self.assertEqual(physical["artifactLocation"], {"uri": "terraform/rds.tf", "uriBaseId": SRCROOT})
        self.assertEqual(physical["region"], {"startLine": 16, "endLine": 18})

    def test_single_line_repo_evidence_has_no_end_line(self):
        result = build_sarif_log([_finding(evidence="repo:main.tf#L7")])["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"], {"startLine": 7})

    def test_cloud_evidence_maps_to_logical_location(self):
        evidence = "cloud:aws:arn:aws:s3:::prod-logs"
        result = build_sarif_log([_finding(evidence=evidence)])["runs"][0]["results"][0]
        location = result["locations"][0]
        self.assertNotIn("physicalLocation", location)
        self.assertEqual(location["logicalLocations"][0]["fullyQualifiedName"], "aws:arn:aws:s3:::prod-logs")

    def test_path_traversal_segments_are_removed(self):
        result = build_sarif_log([_finding(evidence="repo:../../etc/passwd#L1")])["runs"][0]["results"][0]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "etc/passwd")

    def test_unparseable_evidence_has_no_location(self):
        result = build_sarif_log([_finding(evidence="somewhere")])["runs"][0]["results"][0]
        self.assertNotIn("locations", result)
        self.assertEqual(result["properties"]["evidence"], "somewhere")

    def test_severity_to_level(self):
        expected = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
        for severity, level in expected.items():
            with self.subTest(severity=severity):
                result = build_sarif_log([_finding(severity=severity)])["runs"][0]["results"][0]
                self.assertEqual(result["level"], level)

    def test_unknown_severity_defaults_to_note(self):
        result = build_sarif_log([_finding(severity="bogus")])["runs"][0]["results"][0]
        self.assertEqual(result["level"], "note")

    def test_message_combines_fact_and_recommendation(self):
        result = build_sarif_log([_finding()])["runs"][0]["results"][0]
        self.assertEqual(
            result["message"]["text"], "db_name change forces replacement\n\nRecommendation: Revert the db_name change"
        )

    def test_finding_id_becomes_stable_fingerprint(self):
        result = build_sarif_log([_finding()])["runs"][0]["results"][0]
        self.assertEqual(result["partialFingerprints"], {FINGERPRINT_KEY: "FND-AAAAAAAAAAAA"})

    def test_rejected_false_positive_is_suppressed(self):
        result = build_sarif_log([_finding(corroboration_status="rejected_false_positive")])["runs"][0]["results"][0]
        self.assertEqual(result["suppressions"][0]["kind"], "external")
        kept = build_sarif_log([_finding()])["runs"][0]["results"][0]
        self.assertNotIn("suppressions", kept)

    def test_properties_keep_provenance(self):
        finding = _load_fixture("valid_diff_finding.json")
        props = build_sarif_log([finding])["runs"][0]["results"][0]["properties"]
        self.assertEqual(props["findingId"], finding["id"])
        self.assertEqual(props["agent"], finding["agent"])
        self.assertEqual(props["confidence"], 0.94)
        self.assertEqual(props["corroborationStatus"], "unverified_model_claim")
        self.assertIn("public_network_access_enabled = false", props["remediationPreview"])

    def test_malformed_entries_do_not_crash(self):
        log = build_sarif_log(["not-a-dict", None, {}, {"severity": "high"}])
        results = log["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["ruleId"], "rules/unknown.md")
        self.assertEqual(results[0]["message"]["text"], "No description provided")


class TestRuleDescriptors(unittest.TestCase):
    """Rules are deduplicated and report the highest severity they cover."""

    def test_rules_are_deduplicated_and_indexed(self):
        findings = [
            _finding(id="FND-000000000001", rule_id="rules/01-destructive-actions.md"),
            _finding(id="FND-000000000002", rule_id="rules/02-secrets-and-identity.md"),
            _finding(id="FND-000000000003", rule_id="rules/01-destructive-actions.md"),
        ]
        run = build_sarif_log(findings)["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        self.assertEqual([r["id"] for r in rules], ["rules/01-destructive-actions.md", "rules/02-secrets-and-identity.md"])
        for result in run["results"]:
            self.assertEqual(rules[result["ruleIndex"]]["id"], result["ruleId"])

    def test_rule_reports_highest_severity(self):
        findings = [_finding(severity="low"), _finding(id="FND-000000000009", severity="high")]
        rule = build_sarif_log(findings)["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["security-severity"], "8.0")
        self.assertEqual(rule["defaultConfiguration"]["level"], "error")

    def test_rule_metadata(self):
        rule = build_sarif_log([_finding()])["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["name"], "DestructiveActions")
        self.assertEqual(
            rule["helpUri"], "https://github.com/open-cloud-agents/ocagents/blob/main/rules/01-destructive-actions.md"
        )
        self.assertEqual(rule["properties"]["tags"], ["IaC Safety"])


class TestRoundTrip(unittest.TestCase):
    """The project's own SARIF normalizer must read back what the exporter writes."""

    def test_export_then_normalize(self):
        originals = [_load_fixture("valid_diff_finding.json"), _load_fixture("valid_repo_finding.json")]
        sarif = build_sarif_log(originals)
        normalized = SarifNormalizer(repo_root=Path.cwd(), evidence_scheme="repo").normalize(sarif)
        self.assertEqual(len(normalized), 2)
        by_rule = {f["rule_id"]: f for f in normalized}
        for original in originals:
            with self.subTest(rule=original["rule_id"]):
                back = by_rule[original["rule_id"]]
                self.assertEqual(back["severity"], original["severity"])
                path_and_lines = original["evidence"].split(":", 1)[1]
                self.assertEqual(back["evidence"], f"repo:{path_and_lines}")


class TestCliStoreExport(unittest.TestCase):
    """`ocagents store export --format sarif` writes a SARIF file from the blackboard."""

    def test_store_export_sarif(self):
        from ocagents.cli import cmd_store

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "blackboard.db"
            with BlackboardStore(db) as store:
                run_id = store.save_run(create_run_envelope(risk_tier=2, commit_sha="a" * 40))
                store.publish_finding(_load_fixture("valid_diff_finding.json"), run_id)
            out = Path(tmp) / "ocagents.sarif"
            args = argparse.Namespace(store_action="export", run_id=run_id, format="sarif", out=str(out), db=str(db), json=False)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cmd_store(args, Path.cwd()), 0)
            log = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(log["version"], "2.1.0")
            self.assertEqual(log["runs"][0]["properties"]["ocagentsRunId"], run_id)
            self.assertEqual(len(log["runs"][0]["results"]), 1)


@unittest.skipUnless(os.environ.get("OCAGENTS_SARIF_SCHEMA"), "set OCAGENTS_SARIF_SCHEMA to the official SARIF 2.1.0 JSON schema file")
class TestOfficialSchema(unittest.TestCase):
    """Optional: validates against the official OASIS SARIF 2.1.0 schema (not vendored)."""

    def test_validates_against_official_schema(self):
        import jsonschema

        schema = json.loads(Path(os.environ["OCAGENTS_SARIF_SCHEMA"]).read_text(encoding="utf-8"))
        findings = [
            _load_fixture("valid_diff_finding.json"),
            _load_fixture("valid_repo_finding.json"),
            _finding(evidence="cloud:aws:arn:aws:s3:::prod-logs", corroboration_status="rejected_false_positive"),
            {},
        ]
        jsonschema.validate(build_sarif_log(findings, run_id="run-1"), schema)


if __name__ == "__main__":
    unittest.main()
