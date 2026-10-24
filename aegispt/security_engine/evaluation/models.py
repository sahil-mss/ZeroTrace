"""Data models for benchmark scenarios, evaluation metrics, and reports.

TASK 1, 4 & 5: Defines schemas for ground truth test scenarios, statistical
confusion matrices, and reproducible evaluation reports.
"""

from datetime import datetime, timezone
from typing import Any
import uuid

from pydantic import BaseModel, Field

from aegispt.security_engine.schemas.enums import VerificationStatus


class BenchmarkScenario(BaseModel):
    """Specification of an authorized test scenario with known ground truth."""

    scenario_id: str = Field(
        ...,
        min_length=1,
        description="Unique scenario identifier (e.g. 'SCN-JUICE-XSS-01').",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Clear operational explanation of the scenario.",
    )
    lab_application: str = Field(
        default="OWASP Juice Shop",
        description="Name of the evaluated deliberately vulnerable application.",
    )
    target_endpoint: str = Field(
        ...,
        description="Relative or absolute target endpoint URL (e.g. '/#/search').",
    )
    vulnerability_category: str = Field(
        ...,
        description="Weakness category or CWE identifier (e.g. 'CWE-79', 'CWE-89').",
    )
    ground_truth: bool = Field(
        ...,
        description="True if vulnerability is genuinely present; False if defended/absent.",
    )
    expected_scanner_behavior: str = Field(
        ...,
        description="Expected scanner detection action (e.g. 'DETECT_ALERT', 'NO_ALERT').",
    )
    expected_verification_status: VerificationStatus = Field(
        default=VerificationStatus.CONFIRMED,
        description="Expected verification verdict from verification engine.",
    )
    evidence_requirements: list[str] = Field(
        default_factory=list,
        description="Required evidence citations needed to substantiate finding.",
    )


class ScenarioResult(BaseModel):
    """Evaluation outcome for an individual scenario."""

    scenario_id: str = Field(..., description="Referenced scenario identifier.")
    ground_truth: bool = Field(..., description="Documented ground truth.")
    detected: bool = Field(..., description="True if scanner generated a finding.")
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNVERIFIED,
        description="Status assigned by verification engine.",
    )
    matches_expected_verification: bool = Field(
        default=False,
        description="True if verification status matches scenario expectation.",
    )
    runtime_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Elapsed execution runtime for this scenario.",
    )
    classification: str = Field(
        ...,
        description="Confusion matrix classification: 'TP', 'FP', 'TN', or 'FN'.",
    )


class BenchmarkMetrics(BaseModel):
    """Statistical detection and verification performance metrics."""

    total_scenarios: int = Field(..., ge=0, description="Total number of evaluated scenarios.")
    true_positives: int = Field(default=0, ge=0, description="Vulnerable scenarios correctly detected (TP).")
    false_positives: int = Field(default=0, ge=0, description="Defended scenarios incorrectly flagged (FP).")
    true_negatives: int = Field(default=0, ge=0, description="Defended scenarios correctly ignored (TN).")
    false_negatives: int = Field(default=0, ge=0, description="Vulnerable scenarios missed by scanner (FN).")
    precision: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Precision: TP / (TP + FP). Bounded to 0.0 when denominator is zero.",
    )
    recall: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Recall (Sensitivity): TP / (TP + FN). Bounded to 0.0 when denominator is zero.",
    )
    f1_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Harmonic mean of precision and recall. Bounded to 0.0 when denominator is zero.",
    )
    false_positive_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Fall-out: FP / (FP + TN). Bounded to 0.0 when denominator is zero.",
    )
    scan_completion_rate: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Ratio of successfully completed scans to total attempted scans.",
    )
    average_runtime_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Mean runtime per scenario in seconds.",
    )


class EvaluationReport(BaseModel):
    """Comprehensive, reproducible benchmark evaluation report."""

    report_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique identifier for this evaluation report.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of evaluation execution.",
    )
    scanner_id: str = Field(..., description="Scanner evaluated (e.g. 'owasp_zap', 'nmap').")
    scanner_version: str = Field(default="Unknown", description="Version of the evaluated tool.")
    scan_profile: str = Field(..., description="Scan profile ID executed.")
    lab_application: str = Field(default="OWASP Juice Shop", description="Target application.")
    lab_version: str = Field(default="17.1.1", description="Documented target application version.")
    dataset_version: str = Field(default="1.0.0", description="Version of the benchmark scenarios catalogue.")
    total_scenarios: int = Field(..., ge=0, description="Count of evaluated scenarios.")
    detection_results: dict[str, Any] = Field(
        default_factory=dict,
        description="Summary of detection breakdown.",
    )
    verification_results: dict[str, Any] = Field(
        default_factory=dict,
        description="Summary of verification status counts.",
    )
    metrics: BenchmarkMetrics = Field(..., description="Computed statistical performance metrics.")
    scenario_results: list[ScenarioResult] = Field(
        default_factory=list,
        description="Itemized scenario outcomes.",
    )
    total_runtime_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Total elapsed execution time in seconds.",
    )
    known_limitations: list[str] = Field(
        default_factory=list,
        description="Documented benchmark boundaries and environmental constraints.",
    )
