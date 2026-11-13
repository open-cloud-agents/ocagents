"""
Open Cloud Agents: Model Confidence Calibration & Metric Engine (TASK-4.6).

Computes Expected Calibration Error (ECE), Brier Score, and Threshold Sensitivity
across versioned synthetic callsets to empirically validate ADR-002 confidence thresholds.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from typing import Any

from ocagents.benchmark.callsets import BENCHMARK_VERSION, GroundTruthFinding


@dataclass
class CalibrationBin:
    """A confidence interval bin used to compute Expected Calibration Error (ECE)."""

    bin_index: int
    lower_bound: float
    upper_bound: float
    sample_count: int
    average_confidence: float
    accuracy: float
    calibration_error: float

    def to_dict(self) -> dict[str, Any]:
        """Converts calibration bin to dictionary."""
        return asdict(self)


@dataclass
class ThresholdMetric:
    """Operating characteristics evaluated at a specific confidence cutoff threshold."""

    threshold: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    escalation_rate: float

    def to_dict(self) -> dict[str, Any]:
        """Converts threshold metric to dictionary."""
        return asdict(self)


@dataclass
class CalibrationReport:
    """Comprehensive confidence calibration evaluation report."""

    benchmark_version: str
    total_findings: int
    expected_calibration_error: float
    max_calibration_error: float
    brier_score: float
    bins: list[CalibrationBin]
    threshold_metrics: list[ThresholdMetric]
    recommended_threshold: float
    verdict: str

    def to_dict(self) -> dict[str, Any]:
        """Converts calibration report to dictionary."""
        d = asdict(self)
        d["bins"] = [b.to_dict() for b in self.bins]
        d["threshold_metrics"] = [t.to_dict() for t in self.threshold_metrics]
        return d


def calibrate_confidence(
    findings: list[GroundTruthFinding],
    num_bins: int = 10,
    candidate_thresholds: list[float] | None = None,
) -> CalibrationReport:
    """
    Computes calibration metrics (ECE, MCE, Brier score) and threshold sensitivity curves
    for a list of ground truth findings.

    Args:
        findings: List of GroundTruthFinding objects.
        num_bins: Number of confidence bins (default: 10, width 0.1).
        candidate_thresholds: Threshold values to test (default: [0.70, 0.75, 0.80, 0.85, 0.90, 0.95]).

    Returns:
        CalibrationReport with calibration metrics and sensitivity analysis.
    """
    if candidate_thresholds is None:
        candidate_thresholds = [0.70, 0.75, 0.80, 0.85, 0.90, 0.95]

    total_findings = len(findings)
    if total_findings == 0:
        return CalibrationReport(
            benchmark_version=BENCHMARK_VERSION,
            total_findings=0,
            expected_calibration_error=0.0,
            max_calibration_error=0.0,
            brier_score=0.0,
            bins=[],
            threshold_metrics=[],
            recommended_threshold=0.85,
            verdict="INSUFFICIENT_DATA",
        )

    # 1. Compute Brier Score: Mean squared error of probabilities
    # Brier = (1 / N) * sum((confidence_i - y_i)^2)
    squared_errors = [
        (f.model_confidence - (1.0 if f.is_true_positive else 0.0)) ** 2
        for f in findings
    ]
    brier_score = round(sum(squared_errors) / total_findings, 6)

    # 2. Compute Expected Calibration Error (ECE) and Max Calibration Error (MCE)
    bin_width = 1.0 / num_bins
    bins: list[CalibrationBin] = []
    weighted_error_sum = 0.0
    max_error = 0.0

    for i in range(num_bins):
        lower = round(i * bin_width, 4)
        upper = round((i + 1) * bin_width, 4)

        # Include upper bound 1.0 in the last bin
        if i == num_bins - 1:
            bin_items = [f for f in findings if lower <= f.model_confidence <= upper]
        else:
            bin_items = [f for f in findings if lower <= f.model_confidence < upper]

        count = len(bin_items)
        if count > 0:
            avg_conf = sum(f.model_confidence for f in bin_items) / count
            acc = sum(1.0 for f in bin_items if f.is_true_positive) / count
            cal_err = abs(acc - avg_conf)
            weighted_error_sum += (count / total_findings) * cal_err
            if cal_err > max_error:
                max_error = cal_err
        else:
            avg_conf = 0.0
            acc = 0.0
            cal_err = 0.0

        bins.append(
            CalibrationBin(
                bin_index=i,
                lower_bound=lower,
                upper_bound=upper,
                sample_count=count,
                average_confidence=round(avg_conf, 4),
                accuracy=round(acc, 4),
                calibration_error=round(cal_err, 4),
            )
        )

    ece = round(weighted_error_sum, 6)
    mce = round(max_error, 6)

    # 3. Threshold Sensitivity Analysis
    threshold_metrics: list[ThresholdMetric] = []
    best_threshold = 0.85
    best_f1 = -1.0

    for tau in candidate_thresholds:
        tp = sum(1 for f in findings if f.model_confidence >= tau and f.is_true_positive)
        fp = sum(1 for f in findings if f.model_confidence >= tau and not f.is_true_positive)
        fn = sum(1 for f in findings if f.model_confidence < tau and f.is_true_positive)
        tn = sum(1 for f in findings if f.model_confidence < tau and not f.is_true_positive)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2.0 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        escalation_rate = (tp + fp) / total_findings

        metric = ThresholdMetric(
            threshold=round(tau, 2),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1_score=round(f1, 4),
            escalation_rate=round(escalation_rate, 4),
        )
        threshold_metrics.append(metric)

        # Track optimal F1 threshold
        if f1 > best_f1 or (math.isclose(f1, best_f1) and abs(tau - 0.85) < abs(best_threshold - 0.85)):
            best_f1 = f1
            best_threshold = tau

    # Verdict classification
    if ece <= 0.10:
        verdict = "WELL_CALIBRATED"
    elif ece <= 0.20:
        verdict = "MODERATELY_CALIBRATED"
    else:
        verdict = "POORLY_CALIBRATED"

    return CalibrationReport(
        benchmark_version=BENCHMARK_VERSION,
        total_findings=total_findings,
        expected_calibration_error=ece,
        max_calibration_error=mce,
        brier_score=brier_score,
        bins=bins,
        threshold_metrics=threshold_metrics,
        recommended_threshold=best_threshold,
        verdict=verdict,
    )
