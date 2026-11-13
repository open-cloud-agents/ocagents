"""
Unit tests for Open Cloud Agents: Human Triage Resolution Directives (TASK-4.5).
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ocagents.triage.gate import (
    TRIAGE_GATE_CONTEXT,
    TRIAGE_GATE_LABEL,
    TriageGateStatus,
    evaluate_triage_gate,
)
from ocagents.triage.resolution import (
    ResolutionAction,
    TriageDirective,
    apply_directive,
    apply_maintainer_approval,
    execute_triage_directives,
    is_authorized_maintainer,
    parse_triage_directives,
    resolve_finding_in_store,
)


class TestTriageResolution(unittest.TestCase):
    """Test suite covering slash directives, maintainer approval, and triage gate release."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

        # Create temporary CODEOWNERS file
        codeowners_content = """# Repository Code Ownership
* @ibrahimng @open-cloud-agents/sec-ops
"""
        self.codeowners_file = self.root / ".github" / "CODEOWNERS"
        self.codeowners_file.parent.mkdir(parents=True)
        self.codeowners_file.write_text(codeowners_content, encoding="utf-8")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_parse_single_accept_directive(self):
        """Parses a standard accept slash directive."""
        text = "/ocagents triage FND-8B1C3E4A9F20 accept"
        directives = parse_triage_directives(text, author="ibrahimng")
        self.assertEqual(len(directives), 1)
        d = directives[0]
        self.assertEqual(d.finding_id, "FND-8B1C3E4A9F20")
        self.assertEqual(d.action, ResolutionAction.ACCEPT)
        self.assertIsNone(d.reason)
        self.assertEqual(d.author, "ibrahimng")

    def test_parse_dismiss_directive_with_quoted_reason(self):
        """Parses a dismiss slash directive with a quoted reason string."""
        text = '/ocagents triage FND-8B1C3E4A9F20 dismiss --reason "Dev environment exception"'
        directives = parse_triage_directives(text, author="@ibrahimng")
        self.assertEqual(len(directives), 1)
        d = directives[0]
        self.assertEqual(d.finding_id, "FND-8B1C3E4A9F20")
        self.assertEqual(d.action, ResolutionAction.DISMISS)
        self.assertEqual(d.reason, "Dev environment exception")
        self.assertEqual(d.author, "ibrahimng")

    def test_parse_reverse_syntax_order(self):
        """Parses /ocagents triage accept FND-XXX reverse order syntax."""
        text = "/ocagents triage accept FND-112233445566 --reason 'Security sign-off verified'"
        directives = parse_triage_directives(text)
        self.assertEqual(len(directives), 1)
        d = directives[0]
        self.assertEqual(d.finding_id, "FND-112233445566")
        self.assertEqual(d.action, ResolutionAction.ACCEPT)
        self.assertEqual(d.reason, "Security sign-off verified")

    def test_parse_multiple_directives_in_multiline_comment(self):
        """Extracts all valid directives from a conversational pull request comment."""
        comment = """Hello @team,

I have reviewed the findings identified by the specialist agents.
/ocagents triage FND-AAAAAAAAAAAA accept --reason "Audited by Security Team"
Some discussion text here...
/ocagents triage FND-BBBBBBBBBBBB dismiss --reason "Known false positive"
Ignoring random line: /ocagents triage invalid-id accept
"""
        directives = parse_triage_directives(comment, author="ibrahimng")
        self.assertEqual(len(directives), 2)
        self.assertEqual(directives[0].finding_id, "FND-AAAAAAAAAAAA")
        self.assertEqual(directives[0].action, ResolutionAction.ACCEPT)
        self.assertEqual(directives[1].finding_id, "FND-BBBBBBBBBBBB")
        self.assertEqual(directives[1].action, ResolutionAction.DISMISS)

    def test_is_authorized_maintainer(self):
        """Verifies author matches CODEOWNERS list."""
        self.assertTrue(is_authorized_maintainer("ibrahimng", codeowners_path=self.codeowners_file))
        self.assertTrue(is_authorized_maintainer("@ibrahimng", codeowners_path=self.codeowners_file))
        self.assertTrue(is_authorized_maintainer("sec-ops", codeowners_path=self.codeowners_file))
        self.assertFalse(is_authorized_maintainer("unauthorized_user", codeowners_path=self.codeowners_file))
        self.assertFalse(is_authorized_maintainer("", codeowners_path=self.codeowners_file))

    def test_apply_directive_accept(self):
        """Applying accept transitions finding to human_verified and records resolution metadata."""
        finding = {
            "id": "FND-8B1C3E4A9F20",
            "agent": "security-compliance-commander",
            "origin": "model_assertion",
            "severity": "high",
            "corroboration_status": "unverified_model_claim",
            "metadata": {},
        }
        directive = TriageDirective(
            finding_id="FND-8B1C3E4A9F20",
            action=ResolutionAction.ACCEPT,
            reason="Verified compliant with CIS Benchmark 2.4",
            author="ibrahimng",
        )
        updated, ok, msg = apply_directive(directive, [finding], actor="ibrahimng")

        self.assertTrue(ok)
        self.assertIsNotNone(updated)
        self.assertEqual(updated["corroboration_status"], "human_verified")
        self.assertIn("resolution", updated["metadata"])
        self.assertEqual(updated["metadata"]["resolution"]["action"], "accept")
        self.assertEqual(updated["metadata"]["resolution"]["resolved_by"], "ibrahimng")
        self.assertEqual(updated["metadata"]["resolution"]["reason"], "Verified compliant with CIS Benchmark 2.4")

    def test_apply_directive_dismiss(self):
        """Applying dismiss transitions finding to rejected_false_positive."""
        finding = {
            "id": "FND-8B1C3E4A9F20",
            "agent": "principal-cloud-architect",
            "origin": "model_assertion",
            "severity": "critical",
            "corroboration_status": "unverified_model_claim",
        }
        directive = TriageDirective(
            finding_id="FND-8B1C3E4A9F20",
            action=ResolutionAction.DISMISS,
            reason="Intentional public endpoint for OAuth callback",
            author="ibrahimng",
        )
        updated, ok, msg = apply_directive(directive, [finding], actor="ibrahimng")

        self.assertTrue(ok)
        self.assertEqual(updated["corroboration_status"], "rejected_false_positive")
        self.assertEqual(updated["metadata"]["resolution"]["action"], "dismiss")

    def test_apply_directive_nonexistent_finding(self):
        """Applying directive to missing finding returns False and clear error."""
        directive = TriageDirective(
            finding_id="FND-999999999999",
            action=ResolutionAction.ACCEPT,
        )
        updated, ok, msg = apply_directive(directive, [], actor="ibrahimng")
        self.assertFalse(ok)
        self.assertIsNone(updated)
        self.assertIn("not found", msg)

    def test_resolve_finding_in_store(self):
        """Verifies direct resolution persistence in SQLite Blackboard database."""
        db_path = self.root / "blackboard.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE findings (
                id TEXT PRIMARY KEY,
                run_id TEXT,
                agent TEXT,
                origin TEXT,
                rule_id TEXT,
                severity TEXT,
                corroboration_status TEXT,
                metadata TEXT
            );
        """)
        conn.execute("""
            INSERT INTO findings VALUES (
                'FND-1234567890AB',
                'run-test-01',
                'devsecops-reviewer',
                'model_assertion',
                'rules/01-destructive-actions.md',
                'high',
                'unverified_model_claim',
                '{}'
            );
        """)
        conn.commit()
        conn.close()

        ok = resolve_finding_in_store(
            db_path=db_path,
            finding_id="FND-1234567890AB",
            action=ResolutionAction.ACCEPT,
            actor="ibrahimng",
            reason="Sign-off granted",
        )
        self.assertTrue(ok)

        # Verify record in DB
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT corroboration_status, metadata FROM findings WHERE id = 'FND-1234567890AB'")
        row = cursor.fetchone()
        conn.close()

        self.assertEqual(row[0], "human_verified")
        meta = json.loads(row[1])
        self.assertEqual(meta["resolution"]["action"], "accept")
        self.assertEqual(meta["resolution"]["resolved_by"], "ibrahimng")

    def test_apply_maintainer_approval(self):
        """PR approval transitions all pending model claims to human_verified."""
        findings = [
            {
                "id": "FND-000000000001",
                "severity": "critical",
                "corroboration_status": "unverified_model_claim",
            },
            {
                "id": "FND-000000000002",
                "severity": "high",
                "corroboration_status": "unverified_model_claim",
            },
            {
                "id": "FND-000000000003",
                "severity": "medium",
                "corroboration_status": "tool_verified",
            },
        ]
        count, ids = apply_maintainer_approval(findings, reviewer="ibrahimng")
        self.assertEqual(count, 2)
        self.assertIn("FND-000000000001", ids)
        self.assertIn("FND-000000000002", ids)
        self.assertEqual(findings[0]["corroboration_status"], "human_verified")
        self.assertEqual(findings[1]["corroboration_status"], "human_verified")
        self.assertEqual(findings[2]["corroboration_status"], "tool_verified")

    def test_execute_triage_directives_unblocks_gate(self):
        """Executing an accept directive on a P0 finding transitions gate to SUCCESS."""
        finding = {
            "id": "FND-8B1C3E4A9F20",
            "agent": "security-compliance-commander",
            "origin": "model_assertion",
            "severity": "critical",
            "corroboration_status": "unverified_model_claim",
        }
        findings = [finding]

        # Prior to directive, gate is PENDING
        before_gate = evaluate_triage_gate(findings, codeowners_path=self.codeowners_file)
        self.assertEqual(before_gate.status, TriageGateStatus.PENDING)
        self.assertTrue(before_gate.is_blocking)

        comment = '/ocagents triage FND-8B1C3E4A9F20 accept --reason "Risk verified and signed off"'
        result = execute_triage_directives(
            comment_body=comment,
            actor="ibrahimng",
            findings=findings,
            codeowners_path=self.codeowners_file,
            repo_root=self.root,
        )

        self.assertTrue(result.success)
        self.assertTrue(result.authorized)
        self.assertEqual(len(result.resolved_findings), 1)
        self.assertIsNotNone(result.gate_result)
        self.assertEqual(result.gate_result.status, TriageGateStatus.SUCCESS)
        self.assertFalse(result.gate_result.is_blocking)
        self.assertIn("Triage Gate State:** `✅ SUCCESS`", result.response_message)
        self.assertIn("FND-8B1C3E4A9F20", result.response_message)

    def test_execute_triage_directives_unauthorized_user_rejected(self):
        """Unauthorized comment authors cannot resolve findings."""
        finding = {
            "id": "FND-8B1C3E4A9F20",
            "agent": "security-compliance-commander",
            "origin": "model_assertion",
            "severity": "critical",
            "corroboration_status": "unverified_model_claim",
        }
        comment = "/ocagents triage FND-8B1C3E4A9F20 accept"
        result = execute_triage_directives(
            comment_body=comment,
            actor="external_attacker",
            findings=[finding],
            codeowners_path=self.codeowners_file,
            repo_root=self.root,
        )

        self.assertFalse(result.success)
        self.assertFalse(result.authorized)
        self.assertIn("Authorization Denied", result.response_message)
        # Verify finding remains unverified
        self.assertEqual(finding["corroboration_status"], "unverified_model_claim")

    def test_cli_triage_accept_and_dismiss(self):
        """Tests CLI command execution for triage accept and dismiss subcommands."""
        import io
        from unittest.mock import patch
        from ocagents.cli import cmd_triage

        finding = {
            "id": "FND-999988887777",
            "agent": "security-compliance-commander",
            "origin": "model_assertion",
            "severity": "high",
            "corroboration_status": "unverified_model_claim",
        }
        f_file = self.root / "findings.json"
        f_file.write_text(json.dumps([finding]), encoding="utf-8")

        # 1. Test accept
        class ArgsAccept:
            action = "accept"
            target_id = "FND-999988887777"
            id = None
            resolution = None
            reason = "Security audited"
            comment = None
            actor = "ibrahimng"
            findings = str(f_file)
            db = None
            run_id = None
            sha = None
            repo = None
            pr = None
            pr_author = None
            codeowners = str(self.codeowners_file)
            dry_run = False
            github_token = None
            json = True
            save = True
            repo_root = str(self.root)

        f = io.StringIO()
        with patch("sys.stdout", f):
            code = cmd_triage(ArgsAccept(), self.root)

        self.assertEqual(code, 0)
        out = json.loads(f.getvalue())
        self.assertTrue(out["success"])
        self.assertEqual(out["corroboration_status"], "human_verified")
        self.assertEqual(out["gate_status"], "success")

        # Verify written back to JSON
        updated_data = json.loads(f_file.read_text(encoding="utf-8"))
        self.assertEqual(updated_data[0]["corroboration_status"], "human_verified")


if __name__ == "__main__":
    unittest.main()
