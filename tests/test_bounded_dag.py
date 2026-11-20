"""
Unit tests for Bounded Execution DAG and Anti-Proliferation Interaction Circuit Breaker.
(Milestone v2.2 - Issue #100 - TASK-6.3)
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from ocagents.blackboard.store import BlackboardStore
from ocagents.cli import main
from ocagents.orchestration.blackboard_runner import (
    BlackboardRunner,
)
from ocagents.orchestration.circuit_breaker import (
    CircuitBreakerError,
    CircuitBreakerPolicy,
    CircuitBreakerStatus,
    InteractionCircuitBreaker,
    InteractionCycleError,
    MaxHopsExceededError,
    PeerToPeerProhibitedError,
    TokenCeilingExceededError,
)
from ocagents.orchestration.dag import (
    DAGCycleError,
    DAGPhase,
    DAGPhaseOrderError,
    DAGStage,
    DAGStageNotFoundError,
    DAGValidationError,
    ExecutionDAG,
    get_canonical_dag,
)
from ocagents.providers.base import ModelProvider, ProviderResponse


class TestInteractionCircuitBreaker(unittest.TestCase):
    """Tests for InteractionCircuitBreaker governance, ceilings, and ping-pong detection."""

    def test_default_policy(self) -> None:
        policy = CircuitBreakerPolicy()
        self.assertEqual(policy.max_corroboration_hops, 2)
        self.assertEqual(policy.max_total_workflow_tokens, 50000)
        self.assertEqual(policy.max_per_agent_tokens, 12000)
        self.assertTrue(policy.fail_closed)
        self.assertTrue(policy.prohibit_peer_to_peer)

    def test_record_token_spend_within_limits(self) -> None:
        cb = InteractionCircuitBreaker()
        cb.record_token_spend("principal-cloud-architect", 1500, 500)
        self.assertEqual(cb.total_tokens, 2000)
        self.assertEqual(cb.agent_tokens["principal-cloud-architect"], 2000)
        self.assertFalse(cb.is_tripped())
        self.assertEqual(cb.status, CircuitBreakerStatus.ACTIVE)

    def test_record_token_spend_exceeds_agent_ceiling_fail_closed(self) -> None:
        policy = CircuitBreakerPolicy(max_per_agent_tokens=3000, fail_closed=True)
        cb = InteractionCircuitBreaker(policy=policy)
        cb.record_token_spend("sre-reliability-engineer", 1500, 500)  # 2000 (ok)

        with self.assertRaises(TokenCeilingExceededError) as ctx:
            cb.record_token_spend("sre-reliability-engineer", 1000, 500)  # 3500 (> 3000)

        self.assertIn("exceeded session token ceiling", str(ctx.exception))
        self.assertTrue(cb.is_tripped())
        self.assertEqual(cb.status, CircuitBreakerStatus.TRIPPED)
        self.assertIsNotNone(cb.tripped_at_utc)

    def test_record_token_spend_exceeds_agent_ceiling_fail_open(self) -> None:
        policy = CircuitBreakerPolicy(max_per_agent_tokens=3000, fail_closed=False)
        cb = InteractionCircuitBreaker(policy=policy)
        cb.record_token_spend("finops-cloud-cost-optimizer", 2500, 1000)  # 3500 (> 3000)
        self.assertTrue(cb.is_tripped())
        self.assertEqual(cb.status, CircuitBreakerStatus.TRIPPED)

    def test_record_token_spend_exceeds_workflow_ceiling(self) -> None:
        policy = CircuitBreakerPolicy(max_total_workflow_tokens=5000, max_per_agent_tokens=10000, fail_closed=True)
        cb = InteractionCircuitBreaker(policy=policy)
        cb.record_token_spend("agent-1", 1500, 1000)  # 2500
        cb.record_token_spend("agent-2", 1500, 1000)  # 5000 total

        with self.assertRaises(TokenCeilingExceededError) as ctx:
            cb.record_token_spend("agent-3", 100, 100)  # 5200 total

        self.assertIn("Workflow exceeded cumulative token ceiling", str(ctx.exception))
        self.assertTrue(cb.is_tripped())

    def test_finding_corroboration_within_hops(self) -> None:
        policy = CircuitBreakerPolicy(max_corroboration_hops=2)
        cb = InteractionCircuitBreaker(policy=policy)
        cb.record_finding_corroboration("FND-001", acting_agent="security-compliance-commander")
        cb.record_finding_corroboration("FND-001", acting_agent="devsecops-reviewer", prior_agent="security-compliance-commander")
        self.assertEqual(cb.finding_hops["FND-001"], 2)
        self.assertFalse(cb.is_tripped())

    def test_finding_corroboration_exceeds_hops(self) -> None:
        policy = CircuitBreakerPolicy(max_corroboration_hops=2, fail_closed=True)
        cb = InteractionCircuitBreaker(policy=policy)
        cb.record_finding_corroboration("FND-001", acting_agent="security-compliance-commander")
        cb.record_finding_corroboration("FND-001", acting_agent="devsecops-reviewer", prior_agent="security-compliance-commander")

        with self.assertRaises(MaxHopsExceededError) as ctx:
            cb.record_finding_corroboration("FND-001", acting_agent="sre-reliability-engineer", prior_agent="devsecops-reviewer")

        self.assertIn("exceeded maximum review/corroboration rounds", str(ctx.exception))
        self.assertTrue(cb.is_tripped())

    def test_ping_pong_interaction_cycle_detection(self) -> None:
        policy = CircuitBreakerPolicy(max_corroboration_hops=2, fail_closed=True)
        cb = InteractionCircuitBreaker(policy=policy)

        # Agent A -> Agent B (1)
        cb.record_finding_corroboration("FND-002", acting_agent="agent-b", prior_agent="agent-a")
        # Agent B -> Agent A (2)
        cb.record_finding_corroboration("FND-002", acting_agent="agent-a", prior_agent="agent-b")

        # Agent A -> Agent B (3) - cycle limit exceeded
        with self.assertRaises(InteractionCycleError) as ctx:
            cb.record_finding_corroboration("FND-002", acting_agent="agent-b", prior_agent="agent-a")

        self.assertIn("Recursive interaction cycle detected between", str(ctx.exception))
        self.assertTrue(cb.is_tripped())

    def test_audit_output_detects_peer_to_peer_prose(self) -> None:
        bad_outputs = [
            "Hey @security-compliance-commander, please check this KMS configuration.",
            "I am delegating this finding to devsecops-reviewer for verification.",
            "Please review this, @finops-cloud-cost-optimizer.",
            "Send this to sre-reliability-engineer for SLO validation.",
        ]

        for bad in bad_outputs:
            with self.subTest(output=bad):
                breaker = InteractionCircuitBreaker()
                with self.assertRaises(PeerToPeerProhibitedError):
                    breaker.audit_agent_output_for_peer_delegation(bad, agent_id="principal-cloud-architect")
                self.assertTrue(breaker.is_tripped())

    def test_audit_output_allows_valid_findings_prose(self) -> None:
        cb = InteractionCircuitBreaker()
        valid_prose = (
            "The KMS key rotation policy is missing automatic 90-day rotation. "
            "Resource 'aws_kms_key.primary' must enable 'enable_key_rotation = true'."
        )
        cb.audit_agent_output_for_peer_delegation(valid_prose, agent_id="security-compliance-commander")
        self.assertFalse(cb.is_tripped())

    def test_circuit_breaker_telemetry_summary(self) -> None:
        cb = InteractionCircuitBreaker()
        cb.record_token_spend("agent-1", 100, 50)
        summary = cb.get_summary()
        self.assertEqual(summary["status"], "ACTIVE")
        self.assertFalse(summary["is_tripped"])
        self.assertEqual(summary["total_tokens"], 150)
        self.assertEqual(summary["agent_tokens"]["agent-1"], 150)
        self.assertIn("policy", summary)


class TestExecutionDAG(unittest.TestCase):
    """Tests for declarative execution DAG validation, topological sorting, and cycle detection."""

    def test_canonical_dag_valid(self) -> None:
        dag = get_canonical_dag()
        errors = dag.validate()
        self.assertEqual(errors, [])
        self.assertEqual(len(dag.stages), 4)

    def test_canonical_dag_topological_sort(self) -> None:
        dag = get_canonical_dag()
        ordered = dag.topological_sort()
        order_ids = [s.stage_id for s in ordered]
        expected_order = [
            "preflight-gate",
            "architecture-security-assessment",
            "verification-cost-optimization",
            "release-human-triage",
        ]
        self.assertEqual(order_ids, expected_order)

    def test_dag_cycle_detection(self) -> None:
        stage_a = DAGStage(
            stage_id="stage-a",
            name="Stage A",
            phase=DAGPhase.ASSESSMENT,
            agents=["agent-a"],
            depends_on=["stage-b"],
        )
        stage_b = DAGStage(
            stage_id="stage-b",
            name="Stage B",
            phase=DAGPhase.ASSESSMENT,
            agents=["agent-b"],
            depends_on=["stage-a"],
        )
        dag = ExecutionDAG(
            dag_id="cyclic-dag",
            name="Cyclic DAG",
            version="1.0.0",
            circuit_breaker=CircuitBreakerPolicy(),
            stages={"stage-a": stage_a, "stage-b": stage_b},
        )
        with self.assertRaises(DAGCycleError) as ctx:
            dag.topological_sort()
        self.assertIn("Circular dependency detected", str(ctx.exception))

    def test_dag_multi_node_cycle_detection(self) -> None:
        stage_1 = DAGStage(stage_id="s1", name="S1", phase=DAGPhase.ASSESSMENT, agents=["a1"], depends_on=["s3"])
        stage_2 = DAGStage(stage_id="s2", name="S2", phase=DAGPhase.ASSESSMENT, agents=["a2"], depends_on=["s1"])
        stage_3 = DAGStage(stage_id="s3", name="S3", phase=DAGPhase.ASSESSMENT, agents=["a3"], depends_on=["s2"])
        dag = ExecutionDAG(
            dag_id="tri-cycle-dag",
            name="Tri Cycle DAG",
            version="1.0.0",
            circuit_breaker=CircuitBreakerPolicy(),
            stages={"s1": stage_1, "s2": stage_2, "s3": stage_3},
        )
        with self.assertRaises(DAGCycleError):
            dag.topological_sort()

    def test_dag_phase_order_violation(self) -> None:
        # Preflight depends on Assessment (backward phase dependency)
        preflight = DAGStage(
            stage_id="preflight-1",
            name="Preflight Stage",
            phase=DAGPhase.PREFLIGHT,
            agents=["checkov"],
            depends_on=["assessment-1"],
        )
        assessment = DAGStage(
            stage_id="assessment-1",
            name="Assessment Stage",
            phase=DAGPhase.ASSESSMENT,
            agents=["principal-cloud-architect"],
            depends_on=[],
        )
        dag = ExecutionDAG(
            dag_id="inverted-phase-dag",
            name="Inverted Phase DAG",
            version="1.0.0",
            circuit_breaker=CircuitBreakerPolicy(),
            stages={"preflight-1": preflight, "assessment-1": assessment},
        )
        with self.assertRaises(DAGPhaseOrderError) as ctx:
            dag.topological_sort()
        self.assertIn("Phase order violation", str(ctx.exception))

    def test_dag_missing_dependency(self) -> None:
        stage = DAGStage(
            stage_id="orphan-stage",
            name="Orphan",
            phase=DAGPhase.ASSESSMENT,
            agents=["agent-x"],
            depends_on=["non-existent-stage"],
        )
        dag = ExecutionDAG(
            dag_id="missing-dep-dag",
            name="Missing Dep DAG",
            version="1.0.0",
            circuit_breaker=CircuitBreakerPolicy(),
            stages={"orphan-stage": stage},
        )
        with self.assertRaises(DAGStageNotFoundError):
            dag.topological_sort()

    def test_dag_to_dict_and_from_dict_roundtrip(self) -> None:
        dag = get_canonical_dag()
        serialized = dag.to_dict()
        self.assertIn("$schema", serialized)
        self.assertEqual(serialized["dag_id"], "canonical-enterprise-review-dag")
        self.assertEqual(len(serialized["stages"]), 4)

        reconstructed = ExecutionDAG.from_dict(serialized)
        self.assertEqual(reconstructed.dag_id, dag.dag_id)
        self.assertEqual(len(reconstructed.stages), len(dag.stages))
        self.assertEqual(reconstructed.circuit_breaker.max_corroboration_hops, 2)

    def test_dag_from_file(self) -> None:
        dag = get_canonical_dag()
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
            json.dump(dag.to_dict(), tf)
            tf.flush()
            temp_path = tf.name

        try:
            loaded_dag = ExecutionDAG.from_file(temp_path)
            self.assertEqual(loaded_dag.dag_id, dag.dag_id)
            self.assertEqual(len(loaded_dag.stages), 4)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_stage_invalid_phase(self) -> None:
        with self.assertRaises(DAGValidationError):
            DAGStage.from_dict(
                {
                    "stage_id": "bad-stage",
                    "name": "Bad Stage",
                    "phase": "invalid_phase",
                    "agents": ["agent-a"],
                }
            )


class TestDAGBlackboardIntegration(unittest.TestCase):
    """Tests integrating InteractionCircuitBreaker with BlackboardRunner."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_blackboard.db"
        self.store = BlackboardStore(self.db_path)

    def tearDown(self) -> None:
        self.store.close()
        self.temp_dir.cleanup()

    def test_runner_trips_on_circuit_breaker(self) -> None:
        policy = CircuitBreakerPolicy(max_total_workflow_tokens=100, fail_closed=False)
        cb = InteractionCircuitBreaker(policy=policy)

        # Pre-trip circuit breaker
        cb.record_token_spend("prior-agent", 80, 50)  # 130 > 100 -> TRIPPED
        self.assertTrue(cb.is_tripped())
        cb.policy.fail_closed = True

        mock_provider = MagicMock(spec=ModelProvider)
        runner = BlackboardRunner(
            blackboard=self.store,
            provider=mock_provider,
            circuit_breaker=cb,
            parallel=False,
        )

        with self.assertRaises(Exception) as ctx:
            runner.run(diff="diff --git a/main.tf b/main.tf\n+resource aws_s3_bucket b {}\n")
        self.assertIn("Circuit breaker", str(ctx.exception))

    def test_runner_detects_prohibited_peer_to_peer(self) -> None:
        cb = InteractionCircuitBreaker(CircuitBreakerPolicy(prohibit_peer_to_peer=True, fail_closed=True))

        mock_provider = MagicMock(spec=ModelProvider)
        finding_data = {
            "findings": [
                {
                    "$schema": "https://open-cloud-agents.github.io/schemas/v1/finding.json",
                    "id": "FND-000000000001",
                    "agent": "principal-cloud-architect",
                    "origin": "model_assertion",
                    "rule_id": "rules/01-destructive-actions.md",
                    "category": "architecture",
                    "resource": "aws_s3_bucket.data",
                    "fact": "Hey @security-compliance-commander please review.",
                    "evidence": "diff:main.tf#L10",
                    "recommendation": "Fix bucket encryption.",
                    "severity": "medium",
                    "confidence": 0.9,
                    "corroboration_status": "unverified_model_claim",
                }
            ]
        }
        # Mock provider returning peer-to-peer prose
        mock_provider.generate.return_value = ProviderResponse(
            content=json.dumps(finding_data),
            parsed_json=finding_data,
            prompt_tokens=100,
            completion_tokens=50,
            model="mock-model",
        )

        runner = BlackboardRunner(
            blackboard=self.store,
            provider=mock_provider,
            circuit_breaker=cb,
            parallel=False,
        )

        with self.assertRaises(CircuitBreakerError):
            runner.run(
                diff="diff --git a/main.tf b/main.tf\n+resource aws_s3_bucket b {}\n",
                target_agents=["principal-cloud-architect"],
            )


class TestDAGCLICommands(unittest.TestCase):
    """Tests ocagents dag validate and plan CLI commands."""

    def test_cli_dag_validate(self) -> None:
        with io.StringIO() as buf:
            import contextlib
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as ctx:
                    main(["dag", "validate"])
                self.assertEqual(ctx.exception.code, 0)
            output = buf.getvalue()
            self.assertIn("EXECUTION DAG VALIDATION", output)
            self.assertIn("PASSED", output)

    def test_cli_dag_validate_json(self) -> None:
        with io.StringIO() as buf:
            import contextlib
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as ctx:
                    main(["dag", "validate", "--json"])
                self.assertEqual(ctx.exception.code, 0)
            data = json.loads(buf.getvalue())
            self.assertTrue(data["valid"])
            self.assertEqual(data["dag_id"], "canonical-enterprise-review-dag")

    def test_cli_dag_plan(self) -> None:
        with io.StringIO() as buf:
            import contextlib
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as ctx:
                    main(["dag", "plan"])
                self.assertEqual(ctx.exception.code, 0)
            output = buf.getvalue()
            self.assertIn("BOUNDED EXECUTION PLAN", output)
            self.assertIn("preflight-gate", output)
            self.assertIn("release-human-triage", output)

    def test_cli_dag_plan_json(self) -> None:
        with io.StringIO() as buf:
            import contextlib
            with contextlib.redirect_stdout(buf):
                with self.assertRaises(SystemExit) as ctx:
                    main(["dag", "plan", "--json"])
                self.assertEqual(ctx.exception.code, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(len(data["execution_order"]), 4)
            self.assertEqual(data["circuit_breaker"]["max_corroboration_hops"], 2)


if __name__ == "__main__":
    unittest.main()
