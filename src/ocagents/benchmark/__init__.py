"""
Open Cloud Agents: Evaluation Benchmark & Token Calibration Suite (Milestone v2.0 - TASK-4.6).

Provides empirical benchmarking tools comparing the Open Cloud Agents Blackboard Architecture
against Linear Conversational Chaining baselines, and computes model confidence calibration metrics.
"""

from ocagents.benchmark.calibration import (
    CalibrationBin,
    CalibrationReport,
    ThresholdMetric,
    calibrate_confidence,
)
from ocagents.benchmark.callsets import (
    BENCHMARK_VERSION,
    BenchmarkScenario,
    GroundTruthFinding,
    load_benchmark_callsets,
)
from ocagents.benchmark.metrics import (
    MODEL_PRICING,
    ExecutionMetrics,
    calculate_cost_usd,
    estimate_tokens,
)
from ocagents.benchmark.runner import (
    BenchmarkReport,
    BenchmarkResult,
    run_comparative_benchmark,
)

__all__ = [
    "BENCHMARK_VERSION",
    "BenchmarkReport",
    "BenchmarkResult",
    "BenchmarkScenario",
    "CalibrationBin",
    "CalibrationReport",
    "ExecutionMetrics",
    "GroundTruthFinding",
    "MODEL_PRICING",
    "ThresholdMetric",
    "calculate_cost_usd",
    "calibrate_confidence",
    "estimate_tokens",
    "load_benchmark_callsets",
    "run_comparative_benchmark",
]
