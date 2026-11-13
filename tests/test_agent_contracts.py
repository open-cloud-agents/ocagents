"""Unit tests for Open Cloud Agents Frontmatter Contracts and Token Budgeting (v1.4 TASK-1.6)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "agents"))

from ocagents.cli import parse_agent_frontmatter
from ocagents.frontmatter import parse_frontmatter as shared_parse_frontmatter, parse_scalar
from agent_pipeline import parse_frontmatter, validate_agent_specs, REQUIRED_AGENTS


class TestAgentContractsSuite(unittest.TestCase):
    """Verifies that all 7 master suite agents satisfy ADR-002 contracts."""

    def test_all_seven_agents_present_and_valid(self):
        errors = validate_agent_specs(str(REPO_ROOT))
        self.assertEqual(errors, [], f"Agent spec validation failed with errors: {errors}")

    def test_each_agent_declares_token_budget_and_handoff_contract(self):
        agents_dir = REPO_ROOT / "agents" / "7-agent-master-suite"
        for agent_name in REQUIRED_AGENTS:
            agent_path = agents_dir / agent_name
            self.assertTrue(agent_path.is_file(), f"Missing agent file: {agent_name}")

            meta, body = parse_agent_frontmatter(agent_path)

            # Token Budget Check
            self.assertIn("token_budget", meta, f"{agent_name}: Missing 'token_budget'")
            tb = meta["token_budget"]
            self.assertIsInstance(tb, dict)
            for req_key in ("max_context_tokens", "max_output_tokens", "max_session_total_tokens"):
                self.assertIn(req_key, tb, f"{agent_name}: Missing '{req_key}'")
                self.assertIsInstance(tb[req_key], int, f"{agent_name}: '{req_key}' must be int")
                self.assertNotIsInstance(tb[req_key], bool, f"{agent_name}: '{req_key}' cannot be bool")
                self.assertGreater(tb[req_key], 0, f"{agent_name}: '{req_key}' must be > 0")

            self.assertLessEqual(
                tb["max_context_tokens"],
                tb["max_session_total_tokens"],
                f"{agent_name}: max_context_tokens should not exceed max_session_total_tokens",
            )

            # Handoff Contract Check
            self.assertIn("handoff_contract", meta, f"{agent_name}: Missing 'handoff_contract'")
            hc = meta["handoff_contract"]
            self.assertIsInstance(hc, dict)
            self.assertEqual(hc.get("output_schema"), "schemas/v1/finding.json")
            out_schema_path = REPO_ROOT / hc["output_schema"]
            self.assertTrue(out_schema_path.is_file(), f"Schema file not found: {out_schema_path}")


class TestAgentFrontmatterParserAndValidatorRegressions(unittest.TestCase):
    """Tests the parsing mechanics and edge-case validation rules."""

    def _create_stub_repo(self, td: str) -> tuple[Path, Path]:
        repo = Path(td)
        suite = repo / "agents" / "7-agent-master-suite"
        suite.mkdir(parents=True)
        schemas = repo / "schemas" / "v1"
        schemas.mkdir(parents=True)
        (schemas / "finding.json").write_text("{}", encoding="utf-8")
        return repo, suite

    def _write_valid_stubs(self, suite: Path, exclude: str | None = None):
        for a in REQUIRED_AGENTS:
            if a == exclude:
                continue
            (suite / a).write_text(
                """---
name: Stub
description: Test
tools: [read]
token_budget:
  max_context_tokens: 4000
  max_output_tokens: 500
  max_session_total_tokens: 8000
handoff_contract:
  output_schema: schemas/v1/finding.json
---
## Mandate
Testing.
""",
                encoding="utf-8",
            )

    def test_parse_frontmatter_nested_structures(self):
        content = """---
name: Test Agent
tools: [read, search]
token_budget:
  max_context_tokens: 4000
  max_output_tokens: 800
  max_session_total_tokens: 6000
handoff_contract:
  input_schema: null
  output_schema: schemas/v1/finding.json
  max_payload_tokens: 300
---
## Mandate
Execute defensive reviews.
"""
        meta, body = parse_frontmatter(content)
        self.assertEqual(meta["name"], "Test Agent")
        self.assertEqual(meta["tools"], ["read", "search"])
        self.assertEqual(
            meta["token_budget"],
            {
                "max_context_tokens": 4000,
                "max_output_tokens": 800,
                "max_session_total_tokens": 6000,
            },
        )
        self.assertEqual(
            meta["handoff_contract"],
            {
                "input_schema": None,
                "output_schema": "schemas/v1/finding.json",
                "max_payload_tokens": 300,
            },
        )
        self.assertIn("## Mandate", body)

    def test_frontmatter_parser_parity(self):
        content = """---
name: Parity Spec
active: true
debug_mode: false
count: 42
threshold: 3.14
empty_field: null
tags: [alpha, beta, "gamma delta"]
token_budget:
  max_context_tokens: 5000
  max_output_tokens: 1000
  max_session_total_tokens: 9000
handoff_contract:
  input_schema: null
  output_schema: schemas/v1/finding.json
---
## Objectives
Testing parity.
"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".md", encoding="utf-8") as tf:
            tf.write(content)
            temp_path = Path(tf.name)

        try:
            meta_direct, body_direct = parse_frontmatter(content)
            meta_cli, body_cli = parse_agent_frontmatter(temp_path)
            meta_shared, body_shared = shared_parse_frontmatter(content)

            self.assertEqual(meta_direct, meta_cli)
            self.assertEqual(meta_direct, meta_shared)
            self.assertEqual(body_direct, body_cli)
            self.assertEqual(body_direct, body_shared)
            self.assertIs(meta_direct["active"], True)
            self.assertIs(meta_direct["debug_mode"], False)
            self.assertIsNone(meta_direct["empty_field"])
            self.assertEqual(meta_direct["count"], 42)
            self.assertEqual(meta_direct["threshold"], 3.14)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_validator_rejects_missing_token_budget_section(self):
        with tempfile.TemporaryDirectory() as td:
            repo, suite = self._create_stub_repo(td)
            self._write_valid_stubs(suite, exclude="principal-cloud-architect.md")

            (suite / "principal-cloud-architect.md").write_text(
                """---
name: Architect
description: Test
tools: [read]
handoff_contract:
  output_schema: schemas/v1/finding.json
---
## Core Mandate
Testing.
""",
                encoding="utf-8",
            )

            errors = validate_agent_specs(str(repo))
            self.assertTrue(
                any("Missing required 'token_budget'" in err for err in errors),
                f"Expected error for missing token_budget section, got: {errors}",
            )

    def test_validator_rejects_missing_handoff_contract_section(self):
        with tempfile.TemporaryDirectory() as td:
            repo, suite = self._create_stub_repo(td)
            self._write_valid_stubs(suite, exclude="principal-cloud-architect.md")

            (suite / "principal-cloud-architect.md").write_text(
                """---
name: Architect
description: Test
tools: [read]
token_budget:
  max_context_tokens: 4000
  max_output_tokens: 500
  max_session_total_tokens: 8000
---
## Core Mandate
Testing.
""",
                encoding="utf-8",
            )

            errors = validate_agent_specs(str(repo))
            self.assertTrue(
                any("Missing required 'handoff_contract'" in err for err in errors),
                f"Expected error for missing handoff_contract section, got: {errors}",
            )

    def test_validator_rejects_boolean_token_values(self):
        with tempfile.TemporaryDirectory() as td:
            repo, suite = self._create_stub_repo(td)
            self._write_valid_stubs(suite, exclude="principal-cloud-architect.md")

            (suite / "principal-cloud-architect.md").write_text(
                """---
name: Architect
description: Test
tools: [read]
token_budget:
  max_context_tokens: true
  max_output_tokens: 500
  max_session_total_tokens: 8000
handoff_contract:
  output_schema: schemas/v1/finding.json
---
## Core Mandate
Testing.
""",
                encoding="utf-8",
            )

            errors = validate_agent_specs(str(repo))
            self.assertTrue(
                any("rejecting boolean/non-int" in err for err in errors),
                f"Expected error rejecting boolean as token count, got: {errors}",
            )

    def test_validator_rejects_schema_path_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            repo, suite = self._create_stub_repo(td)
            self._write_valid_stubs(suite, exclude="principal-cloud-architect.md")

            (suite / "principal-cloud-architect.md").write_text(
                """---
name: Architect
description: Test
tools: [read]
token_budget:
  max_context_tokens: 4000
  max_output_tokens: 500
  max_session_total_tokens: 8000
handoff_contract:
  output_schema: schemas/v1/../../outside.json
---
## Core Mandate
Testing.
""",
                encoding="utf-8",
            )

            errors = validate_agent_specs(str(repo))
            self.assertTrue(
                any("Path traversal ('..') is strictly prohibited" in err for err in errors),
                f"Expected path traversal rejection error, got: {errors}",
            )

    def test_validator_flags_invalid_token_budget_ordering(self):
        with tempfile.TemporaryDirectory() as td:
            repo, suite = self._create_stub_repo(td)
            self._write_valid_stubs(suite, exclude="principal-cloud-architect.md")

            (suite / "principal-cloud-architect.md").write_text(
                """---
name: Architect
description: Test
tools: [read]
token_budget:
  max_context_tokens: 15000
  max_output_tokens: 500
  max_session_total_tokens: 5000
handoff_contract:
  output_schema: schemas/v1/finding.json
---
## Core Mandate
Testing.
""",
                encoding="utf-8",
            )

            errors = validate_agent_specs(str(repo))
            self.assertTrue(
                any("exceeds max_session_total_tokens" in err for err in errors),
                f"Expected error for context tokens exceeding session tokens, got: {errors}",
            )

    def test_validator_flags_missing_schema_file(self):
        with tempfile.TemporaryDirectory() as td:
            repo, suite = self._create_stub_repo(td)
            self._write_valid_stubs(suite, exclude="principal-cloud-architect.md")

            (suite / "principal-cloud-architect.md").write_text(
                """---
name: Stub
description: Test
tools: [read]
token_budget:
  max_context_tokens: 4000
  max_output_tokens: 500
  max_session_total_tokens: 8000
handoff_contract:
  output_schema: schemas/v1/nonexistent.json
---
## Mandate
Testing.
""",
                encoding="utf-8",
            )

            errors = validate_agent_specs(str(repo))
            self.assertTrue(
                any("Schema file not found" in err for err in errors),
                f"Expected error for missing schema file, got: {errors}",
            )


if __name__ == "__main__":
    unittest.main()
