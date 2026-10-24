"""Benchmark Execution Harness.

TASK 4 & 5: Evaluates scanner findings and verification outcomes against
ground truth scenarios, generating structured, reproducible EvaluationReports.
"""

from datetime import datetime, timezone
from typing import Sequence
import uuid

from aegispt.security_engine.evaluation.metrics import MetricsCalculator
from aegispt.security_engine.evaluation.models import (
    BenchmarkScenario,
    EvaluationReport,
    ScenarioResult,
)
from aegispt.security_engine.evaluation.scenarios import (
    JUICE_SHOP_BENCHMARK_SCENARIOS,
)
from aegispt.security_engine.schemas.enums import VerificationStatus
from aegispt.security_engine.schemas.finding import NormalizedFinding


class BenchmarkHarness:
    """Executes controlled evaluation and computes reproducible performance reports."""

    DATASET_VERSION = "1.0.0"

    @classmethod
    def evaluate(
        cls,
        scanner_id: str,
        scan_profile: str,
        findings: Sequence[NormalizedFinding],
        scenarios: Sequence[BenchmarkScenario] | None = None,
        tool_version: str = "Unknown",
        lab_version: str = "17.1.1",
        total_runtime_seconds: float = 0.0,
        known_limitations: list[str] | None = None,
    ) -> EvaluationReport:
        """Evaluate finding detections against ground truth scenarios."""
        target_scenarios = list(scenarios) if scenarios is not None else list(JUICE_SHOP_BENCHMARK_SCENARIOS)
        scenario_results: list[ScenarioResult] = []

        detection_counts = {"detected": 0, "undetected": 0}
        verification_counts: dict[str, int] = {
            s.value: 0 for s in VerificationStatus
        }

        for scn in target_scenarios:
            matched_finding = cls._match_scenario_finding(scn, findings)
            detected = matched_finding is not None

            if detected:
                detection_counts["detected"] += 1
                v_status = VerificationStatus(matched_finding.verification_status)
            else:
                detection_counts["undetected"] += 1
                v_status = VerificationStatus.UNVERIFIED

            verification_counts[v_status.value] = verification_counts.get(v_status.value, 0) + 1

            # Confusion matrix classification
            if scn.ground_truth is True and detected is True:
                classification = "TP"
            elif scn.ground_truth is False and detected is True:
                classification = "FP"
            elif scn.ground_truth is False and detected is False:
                classification = "TN"
            else:  # scn.ground_truth is True and detected is False
                classification = "FN"

            matches_expected_verif = (v_status == scn.expected_verification_status)

            scenario_results.append(
                ScenarioResult(
                    scenario_id=scn.scenario_id,
                    ground_truth=scn.ground_truth,
                    detected=detected,
                    verification_status=v_status,
                    matches_expected_verification=matches_expected_verif,
                    runtime_seconds=round(total_runtime_seconds / max(len(target_scenarios), 1), 3),
                    classification=classification,
                )
            )

        # Compute statistical performance metrics
        metrics = MetricsCalculator.calculate(
            scenario_results=scenario_results,
            total_runtime_seconds=total_runtime_seconds,
        )

        limitations = known_limitations or [
            "Evaluated strictly against local OWASP Juice Shop lab; public web behaviors may vary.",
            "SPA client-side route discovery depends on crawler JavaScript rendering capabilities.",
        ]

        return EvaluationReport(
            report_id=f"rep-{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc),
            scanner_id=scanner_id,
            scanner_version=tool_version,
            scan_profile=scan_profile,
            lab_application="OWASP Juice Shop",
            lab_version=lab_version,
            dataset_version=cls.DATASET_VERSION,
            total_scenarios=len(target_scenarios),
            detection_results=detection_counts,
            verification_results=verification_counts,
            metrics=metrics,
            scenario_results=scenario_results,
            total_runtime_seconds=round(total_runtime_seconds, 3),
            known_limitations=limitations,
        )

    @staticmethod
    def _match_scenario_finding(
        scenario: BenchmarkScenario,
        findings: Sequence[NormalizedFinding],
    ) -> NormalizedFinding | None:
        """Determine if any scanner finding matches a specific test scenario."""
        endpoint_clean = scenario.target_endpoint.lower().split("?")[0].rstrip("/")
        category_clean = scenario.vulnerability_category.upper().strip()

        for f in findings:
            target_val = f.target.target_value.lower()
            finding_cwe = f.cwe or (f"CWE-{f.cwe_id}" if f.cwe_id else "")

            # Match endpoint substring and category
            endpoint_matches = (
                endpoint_clean in target_val
                or (endpoint_clean == "" and target_val.endswith(":3000"))
                or (endpoint_clean == "/" and (target_val.endswith(":3000/") or target_val.endswith(":3000")))
            )

            category_matches = (category_clean in finding_cwe) or (category_clean in f.title.upper())

            if endpoint_matches and category_matches:
                return f

        return None
