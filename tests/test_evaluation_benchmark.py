"""
Open Cloud Agents: Unit Tests for Evaluation Benchmark & Token Calibration Suite (TASK-4.6).
"""

import json
from pathlib import Path
import tempfile
import unittest

from ocagents.benchmark import (
    BENCHMARK_VERSION,
    CalibrationBin,
    CalibrationReport,
    ExecutionMetrics,
    GroundTruthFinding,
    MODEL_PRICING,
    ThresholdMetric,
    calculate_cost_usd,
    calibrate_confidence,
    estimate_tokens,
    load_benchmark_callsets,
    run_comparative_benchmark,
)
from ocagents.benchmark.baseline import (
    SEQUENTIAL_BASELINE_AGENTS,
    simulate_blackboard_execution,
    simulate_linear_baseline,
)
from ocagents.cli import cmd_benchmark


class TestEvaluationBenchmark(unittest.TestCase):
    """Test suite covering token estimation, baseline simulation, calibration, and CLI."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_estimate_tokens(self):
        """Validates standard 4-chars/token heuristic and boundary conditions."""
        self.assertEqual(estimate_tokens(""), 0)
        self.assertEqual(estimate_tokens("a"), 1)
        self.assertEqual(estimate_tokens("abcd"), 1)
        self.assertEqual(estimate_tokens("abcdefgh"), 2)
        # 400 characters -> ~100 tokens
        self.assertEqual(estimate_tokens("a" * 400), 100)

    def test_calculate_cost_usd(self):
        """Validates cost calculations across foundation models."""
        # claude-3-5-sonnet: $3 / 1M prompt, $15 / 1M completion
        cost_sonnet = calculate_cost_usd(1_000_000, 1_000_000, model="claude-3-5-sonnet")
        self.assertEqual(cost_sonnet, 18.0)

        # gpt-4o: $2.50 / 1M prompt, $10.00 / 1M completion
        cost_gpt = calculate_cost_usd(1_000_000, 1_000_000, model="gpt-4o")
        self.assertEqual(cost_gpt, 12.5)

        # gemini-1-5-flash: $0.075 / 1M prompt, $0.30 / 1M completion
        cost_flash = calculate_cost_usd(1_000_000, 1_000_000, model="gemini-1-5-flash")
        self.assertEqual(cost_flash, 0.375)

    def test_load_benchmark_callsets(self):
        """Verifies synthetic evaluation callsets structure and versioning."""
        scenarios = load_benchmark_callsets()
        self.assertGreaterEqual(len(scenarios), 5)
        self.assertEqual(BENCHMARK_VERSION, "2026.11-v1")

        # Verify risk tiers coverage: 0, 1, 2
        tiers = {s.risk_tier for s in scenarios}
        self.assertIn(0, tiers)
        self.assertIn(1, tiers)
        self.assertIn(2, tiers)

        # Verify ground truth findings integrity
        for s in scenarios:
            for f in s.ground_truth_findings:
                self.assertTrue(0.0 <= f.model_confidence <= 1.0)
                self.assertTrue(f.finding_id.startswith("FND-"))
                self.assertIn(f.severity, ["critical", "high", "medium", "low"])

    def test_simulate_linear_baseline(self):
        """Verifies linear conversational chaining baseline with compounding tokens."""
        scenarios = load_benchmark_callsets()
        sec_scenario = next(s for s in scenarios if s.scenario_id == "SCN-04-SECURITY-CRITICAL")
        metrics = simulate_linear_baseline(sec_scenario)

        # All 7 agents must run in sequential baseline
        self.assertEqual(len(metrics.activated_agents), 7)
        self.assertEqual(metrics.activated_agents, SEQUENTIAL_BASELINE_AGENTS)

        # Context compounding must be present
        self.assertGreater(metrics.prompt_tokens, 20_000)
        self.assertGreater(metrics.completion_tokens, 3_000)
        self.assertGreater(metrics.cost_usd, 0.0)
        self.assertGreater(metrics.latency_ms, 7000.0)

    def test_simulate_blackboard_tier_0(self):
        """Verifies Stage 2 triage completely bypasses LLM for Tier 0 documentation."""
        scenarios = load_benchmark_callsets()
        tier0_scenario = next(s for s in scenarios if s.risk_tier == 0)
        metrics = simulate_blackboard_execution(tier0_scenario)

        # 100% token elimination
        self.assertEqual(metrics.prompt_tokens, 0)
        self.assertEqual(metrics.completion_tokens, 0)
        self.assertEqual(metrics.total_tokens, 0)
        self.assertEqual(metrics.cost_usd, 0.0)
        self.assertEqual(len(metrics.activated_agents), 0)

    def test_simulate_blackboard_tier_1(self):
        """Verifies Tier 1 application logic activates only scoped reviewer agent."""
        scenarios = load_benchmark_callsets()
        tier1_scenario = next(s for s in scenarios if s.risk_tier == 1)
        metrics = simulate_blackboard_execution(tier1_scenario)

        self.assertEqual(metrics.activated_agents, ["devsecops-reviewer"])
        self.assertLess(metrics.total_tokens, 5000)
        self.assertGreater(metrics.total_tokens, 0)

    def test_simulate_blackboard_tier_2(self):
        """Verifies Tier 2 executes only relevant specialist agents concurrently."""
        scenarios = load_benchmark_callsets()
        dr_scenario = next(s for s in scenarios if s.scenario_id == "SCN-03-MULTIREGION-DR")
        metrics = simulate_blackboard_execution(dr_scenario)

        self.assertEqual(len(metrics.activated_agents), 5)
        self.assertIn("principal-cloud-architect", metrics.activated_agents)
        self.assertIn("security-compliance-commander", metrics.activated_agents)
        # Latency should reflect parallel execution (not 7 sequential turns)
        self.assertLess(metrics.latency_ms, 2000.0)

    def test_token_reduction_hypothesis_verified(self):
        """Rigorously verifies ADR-002 hypothesis: 65% to 80% overall token reduction."""
        report = run_comparative_benchmark()
        self.assertTrue(report.hypothesis_verified)
        self.assertGreaterEqual(report.overall_token_savings_pct, 65.0)
        self.assertLessEqual(report.overall_token_savings_pct, 85.0)
        self.assertGreater(report.overall_cost_savings_pct, 65.0)

    def test_confidence_calibration_metrics(self):
        """Verifies Expected Calibration Error (ECE) and Brier Score calculations."""
        # Construct synthetic calibrated finding set
        findings = [
            GroundTruthFinding("FND-1", "rules/01", "Cat", "res", "fact", "high", True, 0.95),
            GroundTruthFinding("FND-2", "rules/01", "Cat", "res", "fact", "high", True, 0.90),
            GroundTruthFinding("FND-3", "rules/01", "Cat", "res", "fact", "high", True, 0.88),
            GroundTruthFinding("FND-4", "rules/01", "Cat", "res", "fact", "low", False, 0.65),
            GroundTruthFinding("FND-5", "rules/01", "Cat", "res", "fact", "low", False, 0.60),
        ]
        cal = calibrate_confidence(findings, num_bins=10)
        self.assertEqual(cal.total_findings, 5)
        self.assertGreater(cal.brier_score, 0.0)
        self.assertLess(cal.brier_score, 0.3)
        self.assertGreaterEqual(cal.expected_calibration_error, 0.0)
        self.assertIn(cal.verdict, ["WELL_CALIBRATED", "MODERATELY_CALIBRATED", "POORLY_CALIBRATED"])

    def test_threshold_sensitivity_optimal_point(self):
        """Verifies threshold sensitivity curve identifies tau=0.85 as optimal operating point."""
        scenarios = load_benchmark_callsets()
        all_findings = []
        for s in scenarios:
            all_findings.extend(s.ground_truth_findings)

        cal = calibrate_confidence(all_findings)
        self.assertEqual(cal.recommended_threshold, 0.85)

        # Check threshold metric at 0.85
        t85 = next(t for t in cal.threshold_metrics if abs(t.threshold - 0.85) < 1e-4)
        self.assertEqual(t85.precision, 1.0)
        self.assertEqual(t85.recall, 1.0)
        self.assertEqual(t85.f1_score, 1.0)
        self.assertEqual(t85.false_positives, 0)

    def test_benchmark_report_serialization(self):
        """Validates report JSON and Markdown rendering."""
        report = run_comparative_benchmark()
        md = report.to_markdown()
        self.assertIn("# Open Cloud Agents: Evaluation Benchmark & Token Calibration Report", md)
        self.assertIn("ADR-002 Hypothesis Validation", md)
        self.assertIn("SCN-01-DOCS", md)
        self.assertIn("tau >= 0.85", md)

        report_json = report.to_json()
        data = json.loads(report_json)
        self.assertEqual(data["benchmark_version"], BENCHMARK_VERSION)
        self.assertTrue(data["hypothesis_verified"])
        self.assertEqual(len(data["results"]), 5)

    def test_cli_benchmark_command(self):
        """Tests ocagents benchmark command execution and file export."""
        class MockArgs:
            model = "claude-3-5-sonnet"
            format = "markdown"
            json = False
            export_md = str(self.root / "bench.md")
            export_json = str(self.root / "bench.json")

        exit_code = cmd_benchmark(MockArgs(), self.root)
        self.assertEqual(exit_code, 0)
        self.assertTrue(Path(MockArgs.export_md).is_file())
        self.assertTrue(Path(MockArgs.export_json).is_file())

        # Verify exported JSON is valid
        content = json.loads(Path(MockArgs.export_json).read_text(encoding="utf-8"))
        self.assertEqual(content["benchmark_version"], BENCHMARK_VERSION)


if __name__ == "__main__":
    unittest.main()
