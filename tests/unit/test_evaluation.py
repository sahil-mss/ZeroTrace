"""Unit tests for MetricsCalculator and BenchmarkHarness."""


from aegispt.security_engine.evaluation import (
    BenchmarkHarness,
    JUICE_SHOP_BENCHMARK_SCENARIOS,
    MetricsCalculator,
    ScenarioResult,
)
from aegispt.security_engine.schemas import (
    AssetType,
    EvidenceReference,
    NormalizedFinding,
    ScanTarget,
    Severity,
    VerificationStatus,
)


class TestMetricsCalculatorEdgeCases:
    """Verifies statistical metric math and safe zero-division handling."""

    def test_empty_evaluation_results(self) -> None:
        """Zero scenarios must yield clean 0.0 metrics without division errors."""
        metrics = MetricsCalculator.calculate([])
        assert metrics.total_scenarios == 0
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0
        assert metrics.f1_score == 0.0
        assert metrics.false_positive_rate == 0.0
        assert metrics.scan_completion_rate == 1.0

    def test_all_true_positives(self) -> None:
        """When every sample is TP, precision, recall, and F1 must be 1.0."""
        results = [
            ScenarioResult(
                scenario_id=f"SCN-{i}",
                ground_truth=True,
                detected=True,
                classification="TP",
            )
            for i in range(5)
        ]
        metrics = MetricsCalculator.calculate(results)
        assert metrics.true_positives == 5
        assert metrics.false_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.f1_score == 1.0
        assert metrics.false_positive_rate == 0.0

    def test_all_false_positives(self) -> None:
        """When every sample is FP, precision and recall must be 0.0."""
        results = [
            ScenarioResult(
                scenario_id=f"SCN-{i}",
                ground_truth=False,
                detected=True,
                classification="FP",
            )
            for i in range(4)
        ]
        metrics = MetricsCalculator.calculate(results)
        assert metrics.true_positives == 0
        assert metrics.false_positives == 4
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0
        assert metrics.f1_score == 0.0

    def test_no_positive_samples_in_ground_truth(self) -> None:
        """When dataset has only negative samples, zero positives are handled cleanly."""
        results = [
            ScenarioResult(
                scenario_id="SCN-TN",
                ground_truth=False,
                detected=False,
                classification="TN",
            ),
            ScenarioResult(
                scenario_id="SCN-FP",
                ground_truth=False,
                detected=True,
                classification="FP",
            ),
        ]
        metrics = MetricsCalculator.calculate(results)
        assert metrics.true_positives == 0
        assert metrics.false_negatives == 0
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0
        assert metrics.false_positive_rate == 0.5  # FP / (FP + TN) = 1 / 2

    def test_no_negative_samples_in_ground_truth(self) -> None:
        """When dataset has only positive samples, zero negatives are handled cleanly."""
        results = [
            ScenarioResult(
                scenario_id="SCN-TP",
                ground_truth=True,
                detected=True,
                classification="TP",
            ),
            ScenarioResult(
                scenario_id="SCN-FN",
                ground_truth=True,
                detected=False,
                classification="FN",
            ),
        ]
        metrics = MetricsCalculator.calculate(results)
        assert metrics.false_positives == 0
        assert metrics.true_negatives == 0
        assert metrics.precision == 1.0  # TP / (TP + FP) = 1 / 1
        assert metrics.recall == 0.5     # TP / (TP + FN) = 1 / 2
        assert metrics.false_positive_rate == 0.0  # FP / (FP + TN) = 0 / 0 -> 0.0

    def test_balanced_confusion_matrix(self) -> None:
        """Verify standard mixed scenario calculation: 2 TP, 1 FP, 1 TN, 1 FN."""
        results = [
            ScenarioResult(scenario_id="1", ground_truth=True, detected=True, classification="TP"),
            ScenarioResult(scenario_id="2", ground_truth=True, detected=True, classification="TP"),
            ScenarioResult(scenario_id="3", ground_truth=False, detected=True, classification="FP"),
            ScenarioResult(scenario_id="4", ground_truth=False, detected=False, classification="TN"),
            ScenarioResult(scenario_id="5", ground_truth=True, detected=False, classification="FN"),
        ]
        metrics = MetricsCalculator.calculate(results, total_runtime_seconds=10.0)

        assert metrics.total_scenarios == 5
        assert metrics.true_positives == 2
        assert metrics.false_positives == 1
        assert metrics.true_negatives == 1
        assert metrics.false_negatives == 1

        # Precision = 2 / (2 + 1) = 0.6667
        assert metrics.precision == 0.6667
        # Recall = 2 / (2 + 1) = 0.6667
        assert metrics.recall == 0.6667
        # F1 = 0.6667
        assert metrics.f1_score == 0.6667
        # FPR = 1 / (1 + 1) = 0.5
        assert metrics.false_positive_rate == 0.5
        # Avg runtime = 10 / 5 = 2.0s
        assert metrics.average_runtime_seconds == 2.0


class TestBenchmarkHarnessAndScenarios:
    """Verifies end-to-end evaluation harness execution, matching, and reporting."""

    def test_ground_truth_catalogue_structure(self) -> None:
        """Verify preconfigured Juice Shop benchmark scenarios are valid."""
        assert len(JUICE_SHOP_BENCHMARK_SCENARIOS) >= 5
        # Ensure both positive (vulnerable) and negative (defended) scenarios exist
        positives = [s for s in JUICE_SHOP_BENCHMARK_SCENARIOS if s.ground_truth is True]
        negatives = [s for s in JUICE_SHOP_BENCHMARK_SCENARIOS if s.ground_truth is False]
        assert len(positives) >= 3
        assert len(negatives) >= 2

    def test_harness_evaluation_and_report_generation(self) -> None:
        """Execute benchmark harness with mock detected findings and verify report."""
        # Simulated findings detected by scanner
        target = ScanTarget(asset_type=AssetType.WEB_URL, target_value="http://127.0.0.1:3000/#/search?q=test")
        finding_xss = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Reflected XSS",
            description="XSS detected in search",
            severity=Severity.HIGH,
            target=target,
            cwe_id=79,
            verified=True,
            verification_status=VerificationStatus.CONFIRMED.value,
            evidence=[EvidenceReference(evidence_type="xss", content_snippet="<script>")],
        )

        report = BenchmarkHarness.evaluate(
            scanner_id="owasp_zap",
            scan_profile="zap_passive_baseline",
            findings=[finding_xss],
            tool_version="2.14.0",
            total_runtime_seconds=12.5,
        )

        assert report.report_id.startswith("rep-")
        assert report.scanner_id == "owasp_zap"
        assert report.scanner_version == "2.14.0"
        assert report.lab_application == "OWASP Juice Shop"
        assert report.dataset_version == "1.0.0"
        assert report.total_scenarios == len(JUICE_SHOP_BENCHMARK_SCENARIOS)
        assert len(report.scenario_results) == len(JUICE_SHOP_BENCHMARK_SCENARIOS)
        assert report.metrics.total_scenarios == len(JUICE_SHOP_BENCHMARK_SCENARIOS)
        assert report.metrics.true_positives >= 1
        assert len(report.known_limitations) > 0
