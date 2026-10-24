"""Evaluation harness and benchmark subsystem.

Executes reproducible evaluation runs against isolated lab targets (e.g. Docker
containers) and calculates precision, recall, and detection metrics.
"""

from aegispt.security_engine.evaluation.lab_manager import (
    LabConfig,
    LabManager,
    LabStatus,
)

__all__ = ["LabConfig", "LabManager", "LabStatus"]
