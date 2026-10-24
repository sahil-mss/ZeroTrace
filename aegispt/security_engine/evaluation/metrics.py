"""Statistical metrics calculator for security testing evaluation.

TASK 3: Implements robust confusion matrix math, precision, recall, F1 score,
false positive rate, and safe zero-denominator handling.
"""

from typing import Sequence
from aegispt.security_engine.evaluation.models import (
    BenchmarkMetrics,
    ScenarioResult,
)


class MetricsCalculator:
    """Calculates statistical detection metrics with safe zero-division boundaries."""

    @classmethod
    def calculate(
        cls,
        scenario_results: Sequence[ScenarioResult],
        total_runtime_seconds: float = 0.0,
        completed_scans: int | None = None,
    ) -> BenchmarkMetrics:
        """Compute complete BenchmarkMetrics from itemized scenario outcomes."""
        total = len(scenario_results)
        if total == 0:
            return BenchmarkMetrics(
                total_scenarios=0,
                true_positives=0,
                false_positives=0,
                true_negatives=0,
                false_negatives=0,
                precision=0.0,
                recall=0.0,
                f1_score=0.0,
                false_positive_rate=0.0,
                scan_completion_rate=1.0,
                average_runtime_seconds=0.0,
            )

        tp = sum(1 for r in scenario_results if r.classification == "TP")
        fp = sum(1 for r in scenario_results if r.classification == "FP")
        tn = sum(1 for r in scenario_results if r.classification == "TN")
        fn = sum(1 for r in scenario_results if r.classification == "FN")

        # Precision: TP / (TP + FP)
        precision_denom = tp + fp
        precision = (tp / precision_denom) if precision_denom > 0 else 0.0

        # Recall (Sensitivity): TP / (TP + FN)
        recall_denom = tp + fn
        recall = (tp / recall_denom) if recall_denom > 0 else 0.0

        # F1 Score: 2 * (P * R) / (P + R)
        f1_denom = precision + recall
        f1_score = (2.0 * precision * recall / f1_denom) if f1_denom > 0 else 0.0

        # False-Positive Rate: FP / (FP + TN)
        fpr_denom = fp + tn
        fpr = (fp / fpr_denom) if fpr_denom > 0 else 0.0

        # Scan completion rate
        scans_done = completed_scans if completed_scans is not None else total
        completion_rate = (scans_done / total) if total > 0 else 1.0

        # Runtime
        if total_runtime_seconds <= 0.0:
            total_runtime_seconds = sum(r.runtime_seconds for r in scenario_results)
        avg_runtime = (total_runtime_seconds / total) if total > 0 else 0.0

        return BenchmarkMetrics(
            total_scenarios=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1_score, 4),
            false_positive_rate=round(fpr, 4),
            scan_completion_rate=round(completion_rate, 4),
            average_runtime_seconds=round(avg_runtime, 4),
        )
