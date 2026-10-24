"""Unit tests for the Finding Normalization Engine."""

from datetime import datetime, timezone
import pytest

from aegispt.security_engine.normalization import (
    FindingDeduplicator,
    NormalizationPipeline,
    SeverityMapper,
)
from aegispt.security_engine.schemas import (
    AssetType,
    EvidenceReference,
    NormalizedFinding,
    RawScanEvidence,
    ScanResult,
    ScanStatus,
    ScanTarget,
    Severity,
)


@pytest.fixture
def base_target() -> ScanTarget:
    """Fixture providing a base local web target."""
    return ScanTarget(
        target_id="asset-juice-shop-001",
        asset_type=AssetType.WEB_URL,
        target_value="http://127.0.0.1:3000",
        is_in_scope=True,
    )


class TestSeverityMapper:
    """Verifies explicit severity mapping semantics for different tool categories."""

    def test_zap_severity_mapping(self) -> None:
        """Verify ZAP risk levels map accurately and preserve original strings."""
        cases = [
            ("3", Severity.HIGH),
            ("High", Severity.HIGH),
            ("2", Severity.MEDIUM),
            ("Medium", Severity.MEDIUM),
            ("Medium (High)", Severity.MEDIUM),
            ("1", Severity.LOW),
            ("Low", Severity.LOW),
            ("0", Severity.INFO),
            ("Informational", Severity.INFO),
        ]
        for raw, expected in cases:
            mapped, original = SeverityMapper.map_zap_severity(raw)
            assert mapped == expected
            assert original == raw

    def test_nmap_severity_mapping(self) -> None:
        """Verify Nmap port states are strictly classified as informational telemetry."""
        mapped, original = SeverityMapper.map_nmap_severity("open")
        assert mapped == Severity.INFO
        assert original == "open"

    def test_generic_severity_heuristics(self) -> None:
        """Verify fallback generic mapping."""
        assert SeverityMapper.map_generic_severity("CRITICAL")[0] == Severity.CRITICAL
        assert SeverityMapper.map_generic_severity("high")[0] == Severity.HIGH
        assert SeverityMapper.map_generic_severity("UNKNOWN_FLAG")[0] == Severity.INFO


class TestFindingDeduplicator:
    """Verifies deterministic fingerprinting and deduplication logic."""

    def test_stable_fingerprint_and_id_generation(self, base_target: ScanTarget) -> None:
        """Identical finding attributes must produce identical fingerprints and IDs."""
        f1 = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Cross Site Scripting (Reflected)",
            description="XSS in query parameter",
            severity=Severity.HIGH,
            target=base_target,
            cwe_id=79,
            evidence=[
                EvidenceReference(
                    evidence_type="zap_alert_instance",
                    content_snippet="<script>alert(1)</script>",
                    metadata={"parameter": "q", "plugin_id": "40012"},
                )
            ],
        )

        fp1 = FindingDeduplicator.compute_fingerprint(f1)
        id1 = FindingDeduplicator.generate_stable_id(fp1)

        fp2 = FindingDeduplicator.compute_fingerprint(f1)
        id2 = FindingDeduplicator.generate_stable_id(fp2)

        assert fp1 == fp2
        assert id1 == id2
        assert id1.startswith("finding-")

    def test_duplicate_findings_merged_with_aggregated_evidence(
        self, base_target: ScanTarget
    ) -> None:
        """Duplicate findings for same asset/vulnerability merge evidence and update last_seen."""
        time1 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)
        time2 = datetime(2026, 10, 24, 11, 0, 0, tzinfo=timezone.utc)

        f1 = NormalizedFinding(
            scanner_id="owasp_zap",
            title="SQL Injection",
            description="SQLi detected",
            severity=Severity.HIGH,
            target=base_target,
            cwe_id=89,
            first_observed_at=time1,
            evidence=[
                EvidenceReference(
                    evidence_type="payload",
                    content_snippet="' OR 1=1--",
                    metadata={"parameter": "id", "plugin_id": "40018"},
                )
            ],
        )

        f2 = NormalizedFinding(
            scanner_id="owasp_zap",
            title="SQL Injection",
            description="SQLi detected",
            severity=Severity.HIGH,
            target=base_target,
            cwe_id=89,
            first_observed_at=time2,
            evidence=[
                EvidenceReference(
                    evidence_type="payload",
                    content_snippet="' UNION SELECT 1,2--",
                    metadata={"parameter": "id", "plugin_id": "40018"},
                )
            ],
        )

        merged = FindingDeduplicator.deduplicate([f1, f2])

        assert len(merged) == 1
        result = merged[0]
        # Verify evidence aggregation: both distinct payloads are preserved
        assert len(result.evidence) == 2
        # Verify last_seen updated to later timestamp
        assert result.last_seen == time2

    def test_different_assets_are_never_merged(self) -> None:
        """Same vulnerability on different assets must remain distinct findings."""
        target_a = ScanTarget(asset_type=AssetType.WEB_URL, target_value="http://127.0.0.1:3000/app1")
        target_b = ScanTarget(asset_type=AssetType.WEB_URL, target_value="http://127.0.0.1:3000/app2")

        f_a = NormalizedFinding(
            scanner_id="owasp_zap",
            title="XSS",
            description="Reflected XSS",
            severity=Severity.HIGH,
            target=target_a,
            cwe_id=79,
            evidence=[EvidenceReference(evidence_type="xss", content_snippet="alert(1)")],
        )
        f_b = NormalizedFinding(
            scanner_id="owasp_zap",
            title="XSS",
            description="Reflected XSS",
            severity=Severity.HIGH,
            target=target_b,
            cwe_id=79,
            evidence=[EvidenceReference(evidence_type="xss", content_snippet="alert(1)")],
        )

        deduped = FindingDeduplicator.deduplicate([f_a, f_b])
        assert len(deduped) == 2
        targets = {f.target.target_value for f in deduped}
        assert "http://127.0.0.1:3000/app1" in targets
        assert "http://127.0.0.1:3000/app2" in targets


class TestNormalizationPipeline:
    """Verifies end-to-end normalization pipeline from ScanResult."""

    def test_normalize_valid_scan_result(self, base_target: ScanTarget) -> None:
        """Valid ScanResult is normalized, evidence hashes associated, and stable IDs assigned."""
        raw_evidence = RawScanEvidence(
            scanner_id="owasp_zap",
            file_path="artifacts/scans/test.json",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            byte_size=1024,
            content_type="application/json",
        )

        finding = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Missing Anti-clickjacking Header",
            description="X-Frame-Options not set",
            severity=Severity.MEDIUM,
            original_severity="Medium",
            target=base_target,
            cwe_id=1021,
            evidence=[EvidenceReference(evidence_type="header", content_snippet="Missing X-Frame-Options")],
        )

        scan_result = ScanResult(
            request_id="req-123",
            scanner_id="owasp_zap",
            status=ScanStatus.SUCCESS,
            target=base_target,
            profile_id="zap_passive_baseline",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            duration_seconds=5.0,
            findings=[finding],
            raw_evidence=raw_evidence,
        )

        normalized = NormalizationPipeline.normalize_scan_result(
            scan_result,
            assessment_id="assessment-2026-q4",
            tool_version="2.14.0",
        )

        assert len(normalized) == 1
        n = normalized[0]
        assert n.assessment_id == "assessment-2026-q4"
        assert n.tool_version == "2.14.0"
        assert n.severity == Severity.MEDIUM
        assert n.original_severity == "Medium"
        assert n.finding_id.startswith("finding-")
        assert n.fingerprint is not None
        # Verify evidence associated with raw artifact provenance
        assert n.evidence[0].source_artifact_id == raw_evidence.artifact_id
        assert n.evidence[0].sha256_hash == raw_evidence.sha256_hash

    def test_nmap_scan_result_produces_no_vulnerability_findings(
        self, base_target: ScanTarget
    ) -> None:
        """Nmap service scan results do not fabricate false vulnerability findings."""
        scan_result = ScanResult(
            request_id="nmap-req-1",
            scanner_id="nmap",
            status=ScanStatus.SUCCESS,
            target=base_target,
            profile_id="nmap_fast_discovery",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            duration_seconds=1.5,
            findings=[],  # Factual Nmap scan has empty findings
        )

        normalized = NormalizationPipeline.normalize_scan_result(scan_result)
        assert normalized == []

    def test_invalid_input_type_raises_type_error(self) -> None:
        """Non-ScanResult input raises TypeError."""
        with pytest.raises(TypeError) as exc:
            NormalizationPipeline.normalize_scan_result({"invalid": "dict"})
        assert "Expected ScanResult instance" in str(exc.value)

    def test_schema_field_completeness(self, base_target: ScanTarget) -> None:
        """Verify all requested Task 2 fields are accessible on NormalizedFinding."""
        f = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Test Finding",
            description="Test Description",
            severity=Severity.LOW,
            target=base_target,
            cwe_id=200,
            cve_id="CVE-2026-0001",
            root_cause="Information disclosure via headers",
            remediation="Suppress banner headers",
            confidence="High",
        )

        dump = f.model_dump()
        expected_fields = [
            "finding_id", "assessment_id", "asset_id", "title", "description",
            "severity", "confidence", "verification_status", "evidence_ids",
            "cwe", "cve", "root_cause", "remediation", "tool_name",
            "tool_version", "first_seen", "last_seen",
        ]
        for field in expected_fields:
            assert field in dump, f"Field '{field}' missing from NormalizedFinding schema"
