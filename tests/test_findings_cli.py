"""
Unit tests for the `ocagents findings` command group (#103):
list, inspect, triage, export, stats, plus the store/triage persistence fixes.
"""

import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ocagents import cli
from ocagents.blackboard import BlackboardStore, create_run_envelope
from ocagents.findings.commands import (
    clean_text,
    filter_findings,
    findings_to_csv,
    render_finding_detail,
    render_findings_table,
    sort_findings,
    summarize_findings,
)
from ocagents.triage.gate import (
    TriageGateStatus,
    evaluate_triage_gate,
    load_findings_source,
)
from ocagents.triage.resolution import ResolutionAction, resolve_finding_in_store

SCHEMA_URL = "https://open-cloud-agents.github.io/schemas/v1/finding.json"


def _finding(**overrides):
    finding = {
        "$schema": SCHEMA_URL,
        "agent": "devsecops-reviewer",
        "origin": "model_assertion",
        "rule_id": "rules/02-secrets-and-identity.md",
        "category": "IAM & Secrets",
        "resource": "aws_iam_role.admin",
        "fact": "IAM role allows unbounded administrator access",
        "evidence": "diff:iam.tf#L10-L15",
        "recommendation": "Constrain permissions to a least-privilege policy",
        "severity": "critical",
        "confidence": 0.95,
        "corroboration_status": "unverified_model_claim",
    }
    finding.update(overrides)
    return finding


def run_cli(*argv):
    """Runs `ocagents <argv>` in-process and returns (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with mock.patch.object(sys, "argv", ["ocagents", *argv]), \
            mock.patch.object(cli.atexit, "register"), \
            mock.patch.object(cli, "init_background_update_check"), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cli.main()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    return code, out.getvalue(), err.getvalue()


class BlackboardFixture(unittest.TestCase):
    """Temp repo with CODEOWNERS and a Blackboard holding two runs."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".github").mkdir()
        (self.root / ".github" / "CODEOWNERS").write_text("* @alice\n", encoding="utf-8")
        self.db = self.root / "blackboard.db"

        with BlackboardStore(self.db) as store:
            old = create_run_envelope(
                risk_tier=1, commit_sha="1" * 40, repo_root=self.root,
                timestamp_utc="2026-01-01T00:00:00Z",
            )
            self.old_run = store.save_run(old)
            store.publish_finding(
                _finding(severity="medium", resource="old.tf", evidence="diff:old.tf#L1-L2"),
                self.old_run,
            )

            new = create_run_envelope(
                risk_tier=2, commit_sha="2" * 40, repo_root=self.root,
                timestamp_utc="2026-02-01T00:00:00Z",
            )
            self.run = store.save_run(new)
            self.critical_id = store.publish_finding(_finding(), self.run)
            self.low_id = store.publish_finding(
                _finding(
                    severity="low",
                    agent="sre-reliability-engineer",
                    category="Reliability",
                    rule_id="rules/05-reliability.md",
                    resource="deploy.yaml",
                    evidence="diff:deploy.yaml#L3-L9",
                    origin="deterministic_linter",
                    corroboration_status="tool_verified",
                    confidence=None,
                ),
                self.run,
            )

    def tearDown(self):
        self._tmp.cleanup()

    def stored(self, finding_id):
        with BlackboardStore(self.db) as store:
            return store.get_finding(finding_id)

    def findings_cli(self, *argv):
        return run_cli("findings", *argv, "--db", str(self.db))


class TestFilterSortSummarize(unittest.TestCase):

    def setUp(self):
        self.findings = [
            _finding(id="FND-B", severity="low", agent="sre", category="Reliability"),
            _finding(id="FND-A", severity="critical", agent="devsecops-reviewer"),
            _finding(id="FND-C", severity="high", corroboration_status="human_verified"),
        ]

    def test_filters_are_case_insensitive_and_accept_comma_lists(self):
        ids = [f["id"] for f in filter_findings(self.findings, severity=["CRITICAL,High"])]
        self.assertEqual(sorted(ids), ["FND-A", "FND-C"])

    def test_different_filters_are_combined_with_and(self):
        result = filter_findings(self.findings, severity="critical,high", status="human_verified")
        self.assertEqual([f["id"] for f in result], ["FND-C"])

    def test_no_filters_returns_everything(self):
        self.assertEqual(len(filter_findings(self.findings)), 3)

    def test_sort_puts_highest_severity_first(self):
        self.assertEqual([f["id"] for f in sort_findings(self.findings)], ["FND-A", "FND-C", "FND-B"])

    def test_summary_counts_every_severity_including_zero(self):
        stats = summarize_findings(self.findings)
        self.assertEqual(stats["total"], 3)
        self.assertEqual(
            stats["by_severity"],
            {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0},
        )
        self.assertEqual(stats["by_status"]["unverified_model_claim"], 2)
        self.assertEqual(stats["by_agent"]["sre"], 1)


class TestOutputSafety(unittest.TestCase):
    """Finding text can come from a model, so it is treated as untrusted."""

    def test_terminal_escape_sequences_are_stripped(self):
        finding = _finding(id="FND-X", fact="ok\x1b]0;pwned\x07\x1b[31mred", resource="a\x9bb")
        detail = render_finding_detail(finding)
        table = render_findings_table([finding])
        for text in (detail, table):
            self.assertNotIn("\x1b", text)
            self.assertNotIn("\x07", text)
            self.assertNotIn("\x9b", text)
        self.assertEqual(clean_text("a\tb\nc\x00"), "a\tb\nc")

    def test_csv_neutralizes_spreadsheet_formulas(self):
        finding = _finding(id="FND-X", recommendation='=HYPERLINK("http://evil")', fact="@SUM(A1)")
        rows = list(csv.DictReader(io.StringIO(findings_to_csv([finding]))))
        self.assertEqual(rows[0]["recommendation"], "'=HYPERLINK(\"http://evil\")")
        self.assertEqual(rows[0]["fact"], "'@SUM(A1)")
        self.assertEqual(rows[0]["severity"], "critical")

    def test_table_colors_only_when_asked(self):
        finding = _finding(id="FND-X")
        self.assertNotIn("\033[", render_findings_table([finding]))
        self.assertIn("\033[", render_findings_table([finding], use_color=True))


class TestStoreTriagePersistence(BlackboardFixture):
    """Regression tests: triage decisions used to be silently lost for the Blackboard store."""

    def test_resolve_finding_updates_column_and_document(self):
        with BlackboardStore(self.db) as store:
            updated = store.resolve_finding(
                self.critical_id, "rejected_false_positive", {"action": "dismiss", "reason": "lab only"}
            )
            self.assertEqual(updated["corroboration_status"], "rejected_false_positive")
            self.assertEqual(updated["metadata"]["resolution"]["previous_status"], "unverified_model_claim")
            self.assertEqual(len(store.get_findings(run_id=self.run)), 2)
            filtered = store._conn.execute(
                "SELECT corroboration_status FROM findings WHERE id = ?", (self.critical_id,)
            ).fetchone()[0]
            self.assertEqual(filtered, "rejected_false_positive")

    def test_resolve_finding_rejects_unknown_status_and_id(self):
        with BlackboardStore(self.db) as store:
            with self.assertRaises(ValueError):
                store.resolve_finding(self.critical_id, "tool_verified", {})
            self.assertIsNone(store.resolve_finding("FND-000000000000", "human_verified", {}))

    def test_resolve_finding_in_store_persists(self):
        ok = resolve_finding_in_store(self.db, self.critical_id, ResolutionAction.ACCEPT, "alice", "checked")
        self.assertTrue(ok)
        finding = self.stored(self.critical_id)
        self.assertEqual(finding["corroboration_status"], "human_verified")
        self.assertEqual(finding["metadata"]["resolution"]["resolved_by"], "alice")

    def test_resolve_finding_in_store_reports_missing(self):
        self.assertFalse(resolve_finding_in_store(self.db, "FND-000000000000", ResolutionAction.ACCEPT, "alice"))
        missing_db = self.root / "missing.db"
        self.assertFalse(resolve_finding_in_store(missing_db, self.critical_id, ResolutionAction.ACCEPT, "alice"))
        self.assertFalse(missing_db.exists())

    def test_triage_gate_reads_findings_from_store(self):
        findings = load_findings_source(db_path=self.db, run_id=self.run)
        self.assertEqual(len(findings), 2)
        self.assertEqual(evaluate_triage_gate(findings).status, TriageGateStatus.PENDING)


class TestFindingsList(BlackboardFixture):

    def test_defaults_to_latest_run_sorted_by_severity(self):
        code, out, _ = self.findings_cli("list", "--json")
        self.assertEqual(code, 0)
        ids = [f["id"] for f in json.loads(out)]
        self.assertEqual(ids, [self.critical_id, self.low_id])

    def test_run_id_and_all_runs(self):
        _, out, _ = self.findings_cli("list", "--json", "--run-id", self.old_run)
        self.assertEqual([f["resource"] for f in json.loads(out)], ["old.tf"])
        _, out, _ = self.findings_cli("list", "--json", "--all-runs")
        self.assertEqual(len(json.loads(out)), 3)

    def test_filters_and_limit(self):
        _, out, _ = self.findings_cli("list", "--json", "--severity", "low")
        self.assertEqual([f["id"] for f in json.loads(out)], [self.low_id])
        _, out, _ = self.findings_cli("list", "--json", "--agent", "SRE-reliability-engineer", "--status", "tool_verified")
        self.assertEqual([f["id"] for f in json.loads(out)], [self.low_id])
        _, out, _ = self.findings_cli("list", "--json", "--limit", "1")
        self.assertEqual(len(json.loads(out)), 1)

    def test_text_table(self):
        code, out, _ = self.findings_cli("list")
        self.assertEqual(code, 0)
        self.assertIn(f"2 finding(s) (run {self.run})", out)
        self.assertIn(self.critical_id, out)
        self.assertIn("SEVERITY", out)

    def test_missing_database_is_an_error_and_is_not_created(self):
        missing = self.root / "nope" / "blackboard.db"
        code, _, err = run_cli("findings", "list", "--db", str(missing))
        self.assertEqual(code, 1)
        self.assertIn("No Blackboard database", err)
        self.assertFalse(missing.exists())

    def test_reads_from_json_file(self):
        path = self.root / "findings.json"
        path.write_text(json.dumps([_finding(id="FND-111111111111", severity="high")]), encoding="utf-8")
        code, out, _ = run_cli("findings", "list", "--json", "--file", str(path))
        self.assertEqual(code, 0)
        self.assertEqual([f["id"] for f in json.loads(out)], ["FND-111111111111"])


class TestFindingsInspect(BlackboardFixture):

    def test_inspect_shows_detail_and_accepts_lowercase_id(self):
        code, out, _ = self.findings_cli("inspect", self.critical_id.lower())
        self.assertEqual(code, 0)
        self.assertIn(f"ID:          {self.critical_id}", out)
        self.assertIn("Provenance:", out)
        self.assertIn("Constrain permissions", out)

    def test_inspect_json(self):
        _, out, _ = self.findings_cli("inspect", self.critical_id, "--json")
        self.assertEqual(json.loads(out)["id"], self.critical_id)

    def test_inspect_unknown_or_missing_id(self):
        code, _, err = self.findings_cli("inspect", "FND-000000000000")
        self.assertEqual(code, 1)
        self.assertIn("not found", err)
        code, _, err = self.findings_cli("inspect")
        self.assertEqual(code, 1)
        self.assertIn("Usage", err)


class TestFindingsTriage(BlackboardFixture):

    def triage(self, *argv):
        return self.findings_cli("triage", *argv, "--repo-root", str(self.root))

    def test_dismiss_by_codeowner_is_persisted(self):
        code, out, _ = self.triage(self.critical_id, "--action", "dismiss", "--reason", "lab only", "--actor", "@alice")
        self.assertEqual(code, 0, out)
        finding = self.stored(self.critical_id)
        self.assertEqual(finding["corroboration_status"], "rejected_false_positive")
        resolution = finding["metadata"]["resolution"]
        self.assertEqual(resolution["resolved_by"], "alice")
        self.assertEqual(resolution["reason"], "lab only")

        _, out, _ = self.findings_cli("inspect", self.critical_id)
        self.assertIn("Reason:      lab only", out)

    def test_accept_without_reason(self):
        code, _, _ = self.triage(self.critical_id, "--action", "accept", "--actor", "alice")
        self.assertEqual(code, 0)
        self.assertEqual(self.stored(self.critical_id)["corroboration_status"], "human_verified")

    def test_non_codeowner_is_denied(self):
        code, _, err = self.triage(self.critical_id, "--action", "accept", "--actor", "mallory")
        self.assertEqual(code, 1)
        self.assertIn("Authorization denied", err)
        self.assertEqual(self.stored(self.critical_id)["corroboration_status"], "unverified_model_claim")

    def test_dismiss_requires_reason(self):
        code, _, err = self.triage(self.critical_id, "--action", "dismiss", "--actor", "alice")
        self.assertEqual(code, 1)
        self.assertIn("--reason", err)
        self.assertEqual(self.stored(self.critical_id)["corroboration_status"], "unverified_model_claim")

    def test_requires_action_and_valid_id(self):
        code, _, err = self.triage(self.critical_id, "--actor", "alice")
        self.assertEqual(code, 1)
        self.assertIn("--action", err)
        code, _, err = self.triage("FND-bad", "--action", "accept", "--actor", "alice")
        self.assertEqual(code, 1)
        self.assertIn("Invalid finding ID", err)

    def test_unknown_finding(self):
        code, _, err = self.triage("FND-000000000000", "--action", "accept", "--actor", "alice")
        self.assertEqual(code, 1)
        self.assertIn("not found", err)


class TestFindingsExportAndStats(BlackboardFixture):

    def test_export_csv_to_file(self):
        out_file = self.root / "out" / "findings.csv"
        code, out, _ = self.findings_cli("export", "--format", "csv", "--out", str(out_file))
        self.assertEqual(code, 0)
        self.assertIn("Exported 2 finding(s)", out)
        rows = list(csv.DictReader(out_file.open(encoding="utf-8", newline="")))
        self.assertEqual([r["id"] for r in rows], [self.critical_id, self.low_id])

    def test_export_sarif_respects_filters(self):
        code, out, _ = self.findings_cli("export", "--format", "sarif", "--severity", "critical")
        self.assertEqual(code, 0)
        log = json.loads(out)
        self.assertEqual(log["version"], "2.1.0")
        self.assertEqual(len(log["runs"][0]["results"]), 1)
        self.assertEqual(log["runs"][0]["properties"]["ocagentsRunId"], self.run)

    def test_export_json_markdown_and_toon(self):
        _, out, _ = self.findings_cli("export")
        self.assertEqual(len(json.loads(out)), 2)
        code, out, _ = self.findings_cli("export", "--format", "markdown")
        self.assertEqual(code, 0)
        self.assertIn("#", out)
        code, out, _ = self.findings_cli("export", "--format", "toon")
        self.assertEqual(code, 0)
        self.assertIn(self.critical_id, out)

    def test_export_rejects_unknown_format(self):
        code, _, err = self.findings_cli("export", "--format", "xml")
        self.assertEqual(code, 1)
        self.assertIn("Unsupported export format", err)

    def test_stats_json(self):
        code, out, _ = self.findings_cli("stats", "--json")
        self.assertEqual(code, 0)
        stats = json.loads(out)
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["run_id"], self.run)
        self.assertEqual(stats["by_severity"]["critical"], 1)
        self.assertEqual(stats["by_origin"], {"deterministic_linter": 1, "model_assertion": 1})

    def test_stats_text(self):
        code, out, _ = self.findings_cli("stats", "--all-runs")
        self.assertEqual(code, 0)
        self.assertIn("Total findings: 3", out)
        self.assertIn("Severity:", out)


class TestValidateStillWorks(unittest.TestCase):
    """`ocagents findings <path>` keeps validating finding documents."""

    def test_path_argument_routes_to_validator(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run_cli("findings", tmp)
        self.assertEqual(code, 0)
        self.assertIn("No JSON finding files found", out)

    def test_help_topic(self):
        code, out, _ = run_cli("help", "findings")
        self.assertEqual(code, 0)
        self.assertIn("ocagents findings", out)
        self.assertIn("triage <FND-ID>", out)


if __name__ == "__main__":
    unittest.main()
