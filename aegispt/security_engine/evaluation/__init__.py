"""Evaluation harness and benchmark subsystem.

Executes reproducible evaluation runs against isolated lab targets (e.g. Docker
containers) and calculates precision, recall, and detection metrics.
"""

from aegispt.security_engine.evaluation.harness import BenchmarkHarness
from aegispt.security_engine.evaluation.lab_manager import (
    LabConfig,
    LabManager,
    LabStatus,
)
from aegispt.security_engine.evaluation.metrics import MetricsCalculator
from aegispt.security_engine.evaluation.models import (
    BenchmarkMetrics,
    BenchmarkScenario,
    EvaluationReport,
    ScenarioResult,
)
from aegispt.security_engine.evaluation.scenarios import (
    JUICE_SHOP_BENCHMARK_SCENARIOS,
)

__all__ = [
    "LabConfig",
    "LabManager",
    "LabStatus",
    "BenchmarkScenario",
    "ScenarioResult",
    "BenchmarkMetrics",
    "EvaluationReport",
    "MetricsCalculator",
    "BenchmarkHarness",
    "JUICE_SHOP_BENCHMARK_SCENARIOS",
]
