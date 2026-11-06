"""Unit tests for Open Cloud Agents Frontmatter Contracts and Token Budgeting (v1.4 TASK-1.6)."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts" / "agents"))

from ocagents.cli import parse_agent_frontmatter
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

    def test_validator_flags_invalid_token_budget(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            suite = repo / "agents" / "7-agent-master-suite"
            suite.mkdir(parents=True)
            schemas = repo / "schemas" / "v1"
            schemas.mkdir(parents=True)
            (schemas / "finding.json").write_text("{}", encoding="utf-8")

            # Create an invalid agent spec where max_context_tokens > max_session_total_tokens
            invalid_agent = suite / "principal-cloud-architect.md"
            invalid_agent.write_text(
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

            # And stub the other 6 agents
            for a in REQUIRED_AGENTS:
                if a == "principal-cloud-architect.md":
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

            errors = validate_agent_specs(str(repo))
            self.assertTrue(
                any("exceeds max_session_total_tokens" in err for err in errors),
                f"Expected error for context tokens exceeding session tokens, got: {errors}",
            )

    def test_validator_flags_missing_schema_file(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            suite = repo / "agents" / "7-agent-master-suite"
            suite.mkdir(parents=True)

            for a in REQUIRED_AGENTS:
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
  output_schema: schemas/v1/nonexistent.json
---
## Mandate
Testing.
""",
                    encoding="utf-8",
                )

            errors = validate_agent_specs(str(repo))
            self.assertTrue(
                any("not found" in err for err in errors),
                f"Expected error for missing schema file, got: {errors}",
            )


if __name__ == "__main__":
    unittest.main()
