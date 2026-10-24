"""Unit tests for the Finding Verification Engine and Verification Plugins."""

from datetime import datetime
from unittest.mock import MagicMock
import pytest
import requests

from aegispt.security_engine.schemas import (
    AssetType,
    EvidenceReference,
    NormalizedFinding,
    ScanTarget,
    Severity,
    VerificationStatus,
)
from aegispt.security_engine.verification import (
    BaseVerifier,
    VerificationEngine,
)


@pytest.fixture
def target_juice_shop() -> ScanTarget:
    """Fixture providing an authorized local Juice Shop target."""
    return ScanTarget(
        target_id="asset-juice-shop-001",
        asset_type=AssetType.WEB_URL,
        target_value="http://127.0.0.1:3000",
        is_in_scope=True,
    )


@pytest.fixture
def engine() -> VerificationEngine:
    """Fixture providing a fresh VerificationEngine instance."""
    return VerificationEngine()


class TestVerificationPreflightRules:
    """Verifies pre-flight validation rules (scope, evidence existence, correlation)."""

    def test_missing_evidence_rejected_as_unverified(
        self, engine: VerificationEngine, target_juice_shop: ScanTarget
    ) -> None:
        """Finding with empty evidence must be marked UNVERIFIED."""
        finding = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Unsubstantiated Flaw",
            description="No proof provided",
            severity=Severity.HIGH,
            target=target_juice_shop,
            evidence=[],  # Missing evidence
        )

        updated, record = engine.verify_finding(finding)

        assert updated.verification_status == VerificationStatus.UNVERIFIED.value
        assert updated.verified is False
        assert record.new_status == VerificationStatus.UNVERIFIED
        assert "No verifiable supporting evidence" in record.reason

    def test_out_of_scope_finding_rejected_as_unverified(
        self, engine: VerificationEngine
    ) -> None:
        """Finding targeting an asset not in assessment scope is marked UNVERIFIED."""
        out_of_scope_target = ScanTarget(
            asset_type=AssetType.WEB_URL,
            target_value="http://127.0.0.1:4000/unauthorized",
            is_in_scope=True,
        )
        finding = NormalizedFinding(
            scanner_id="owasp_zap",
            title="XSS",
            description="XSS test",
            severity=Severity.MEDIUM,
            target=out_of_scope_target,
            evidence=[EvidenceReference(evidence_type="xss", content_snippet="<script>")],
        )

        assessment_scope = {"http://127.0.0.1:3000"}
        updated, record = engine.verify_finding(finding, assessment_scope=assessment_scope)

        assert updated.verification_status == VerificationStatus.UNVERIFIED.value
        assert "does not belong to authorized assessment scope" in record.reason

    def test_mismatched_evidence_target_rejected(
        self, engine: VerificationEngine, target_juice_shop: ScanTarget
    ) -> None:
        """Evidence citation referencing an unrelated host is marked UNVERIFIED."""
        finding = NormalizedFinding(
            scanner_id="owasp_zap",
            title="XSS",
            description="XSS test",
            severity=Severity.MEDIUM,
            target=target_juice_shop,  # Target is 127.0.0.1:3000
            evidence=[
                EvidenceReference(
                    evidence_type="xss",
                    content_snippet="<script>alert(1)</script>",
                    metadata={"target_url": "http://192.168.1.100:8080/mismatch"},
                )
            ],
        )

        updated, record = engine.verify_finding(finding)

        assert updated.verification_status == VerificationStatus.UNVERIFIED.value
        assert "references mismatched target" in record.reason


class TestVerificationPlugins:
    """Verifies deterministic verifier plugins: HeaderSecurity, PassiveReflection, LabGroundTruth."""

    def test_confirmed_missing_header_via_live_probe(
        self, engine: VerificationEngine, target_juice_shop: ScanTarget
    ) -> None:
        """Live HTTP probe confirming header absence marks finding CONFIRMED."""
        finding = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Content Security Policy (CSP) Header Not Set",
            description="CSP header is missing.",
            severity=Severity.LOW,
            target=target_juice_shop,
            cwe_id=693,
            evidence=[EvidenceReference(evidence_type="header", content_snippet="Missing header")],
        )

        # Mock live session returning headers without Content-Security-Policy
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Server": "Node.js", "Content-Type": "text/html"}
        mock_session.get.return_value = mock_resp
        engine._session = mock_session

        updated, record = engine.verify_finding(finding)

        assert updated.verification_status == VerificationStatus.CONFIRMED.value
        assert updated.verified is True
        assert record.new_status == VerificationStatus.CONFIRMED
        assert "genuinely missing" in record.reason

    def test_false_positive_header_when_header_is_present(
        self, engine: VerificationEngine, target_juice_shop: ScanTarget
    ) -> None:
        """Live probe finding that header is actually present marks finding FALSE_POSITIVE."""
        finding = NormalizedFinding(
            scanner_id="owasp_zap",
            title="X-Frame-Options Header Missing",
            description="Header missing",
            severity=Severity.MEDIUM,
            target=target_juice_shop,
            cwe_id=1021,
            evidence=[EvidenceReference(evidence_type="header", content_snippet="Missing header")],
        )

        # Mock live session returning X-Frame-Options present
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"X-Frame-Options": "SAMEORIGIN"}
        mock_session.get.return_value = mock_resp
        engine._session = mock_session

        updated, record = engine.verify_finding(finding)

        assert updated.verification_status == VerificationStatus.FALSE_POSITIVE.value
        assert updated.verified is False
        assert record.new_status == VerificationStatus.FALSE_POSITIVE
        assert "is present in response headers" in record.reason

    def test_confirmed_xss_unencoded_reflection(
        self, engine: VerificationEngine, target_juice_shop: ScanTarget
    ) -> None:
        """Unencoded script reflection in evidence snippet marks finding CONFIRMED."""
        finding = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Reflected XSS in search",
            description="XSS in query parameter",
            severity=Severity.HIGH,
            target=ScanTarget(
                asset_type=AssetType.WEB_URL,
                target_value="http://127.0.0.1:3000/#/search?q=test",
            ),
            cwe_id=79,
            evidence=[
                EvidenceReference(
                    evidence_type="xss",
                    content_snippet="<div>Search result for: <script>alert(1)</script></div>",
                    metadata={"attack": "<script>alert(1)</script>", "parameter": "q"},
                )
            ],
        )

        updated, record = engine.verify_finding(finding)

        assert updated.verification_status == VerificationStatus.CONFIRMED.value
        assert updated.verified is True
        assert "unencoded payload reflection" in record.reason

    def test_false_positive_xss_safely_encoded(
        self, engine: VerificationEngine, target_juice_shop: ScanTarget
    ) -> None:
        """HTML-entity encoded reflection in snippet marks finding FALSE_POSITIVE."""
        finding = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Reflected XSS",
            description="XSS claimed by scanner",
            severity=Severity.HIGH,
            target=ScanTarget(
                asset_type=AssetType.WEB_URL,
                target_value="http://127.0.0.1:3000/profile?name=test",
            ),
            cwe_id=79,
            evidence=[
                EvidenceReference(
                    evidence_type="xss",
                    content_snippet="<div>Welcome, &lt;script&gt;alert(1)&lt;/script&gt;</div>",
                    metadata={"attack": "<script>alert(1)</script>", "parameter": "name"},
                )
            ],
        )

        updated, record = engine.verify_finding(finding)

        assert updated.verification_status == VerificationStatus.FALSE_POSITIVE.value
        assert updated.verified is False
        assert "safely HTML-entity encoded" in record.reason

    def test_likely_finding_when_live_probe_fails(
        self, engine: VerificationEngine, target_juice_shop: ScanTarget
    ) -> None:
        """When live probe fails but evidence indicates absence, marks finding LIKELY."""
        finding = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Anti-Clickjacking (X-Frame-Options) Missing",
            description="Header missing",
            severity=Severity.LOW,
            target=target_juice_shop,
            cwe_id=1021,
            evidence=[EvidenceReference(evidence_type="header", content_snippet="Missing header in response")],
        )

        # Mock connection error during live probe
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.ConnectionError("Connection refused")
        engine._session = mock_session

        updated, record = engine.verify_finding(finding)

        assert updated.verification_status == VerificationStatus.LIKELY.value
        assert updated.verified is False
        assert record.new_status == VerificationStatus.LIKELY

    def test_needs_review_when_evidence_is_ambiguous(
        self, engine: VerificationEngine, target_juice_shop: ScanTarget
    ) -> None:
        """Ambiguous evidence that cannot be deterministically verified returns NEEDS_REVIEW."""
        finding = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Uncategorized Information Leak",
            description="Ambiguous telemetry",
            severity=Severity.INFO,
            target=target_juice_shop,
            cwe_id=200,
            evidence=[EvidenceReference(evidence_type="snippet", content_snippet="200 OK")],
        )

        updated, record = engine.verify_finding(finding)

        assert updated.verification_status == VerificationStatus.NEEDS_REVIEW.value
        assert updated.verified is False
        assert record.new_status == VerificationStatus.NEEDS_REVIEW

    def test_verifier_exception_handled_as_needs_review(
        self, engine: VerificationEngine, target_juice_shop: ScanTarget
    ) -> None:
        """Unexpected plugin crash is trapped safely and logged as NEEDS_REVIEW."""
        class CrashingVerifier(BaseVerifier):
            @property
            def verification_id(self) -> str:
                return "verifier_crashing"
            @property
            def supported_finding_types(self) -> list[str]:
                return ["CWE-999"]
            @property
            def preconditions(self) -> list[str]:
                return []
            @property
            def required_permission_level(self):
                from aegispt.security_engine.schemas import PermissionLevel
                return PermissionLevel.SAFE_AUDIT
            @property
            def evidence_requirements(self) -> list[str]:
                return []
            @property
            def potential_impact(self):
                from aegispt.security_engine.schemas import ImpactLevel
                return ImpactLevel.NONE
            def verify(self, finding, session=None):
                raise RuntimeError("Simulated crash in verification plugin!")

        engine.verifiers.insert(0, CrashingVerifier())

        finding = NormalizedFinding(
            scanner_id="test",
            title="Bug",
            description="desc",
            severity=Severity.LOW,
            target=target_juice_shop,
            cwe_id=999,
            evidence=[EvidenceReference(evidence_type="test", content_snippet="proof")],
        )

        updated, record = engine.verify_finding(finding)
        assert updated.verification_status == VerificationStatus.NEEDS_REVIEW.value
        assert "encountered error" in record.reason


class TestVerificationAuditTrail:
    """Verifies complete, immutable audit trail generation."""

    def test_audit_log_captures_all_events(
        self, engine: VerificationEngine, target_juice_shop: ScanTarget
    ) -> None:
        """Every verification attempt must record finding ID, method, timestamp, evidence IDs, and reason."""
        f1 = NormalizedFinding(
            scanner_id="owasp_zap",
            title="CSP Missing",
            description="desc",
            severity=Severity.LOW,
            target=target_juice_shop,
            cwe_id=693,
            evidence=[EvidenceReference(evidence_type="header", content_snippet="missing")],
        )
        f2 = NormalizedFinding(
            scanner_id="owasp_zap",
            title="Empty Evidence",
            description="desc",
            severity=Severity.LOW,
            target=target_juice_shop,
            evidence=[],  # Will fail evidence check
        )

        findings, records = engine.verify_all([f1, f2])

        assert len(records) == 2
        assert len(engine.audit_log) == 2

        rec1 = records[0]
        assert rec1.finding_id == f1.finding_id
        assert rec1.verification_method != ""
        assert isinstance(rec1.timestamp, datetime)
        assert len(rec1.evidence_ids) == 1
        assert rec1.previous_status == "UNVERIFIED"
        assert rec1.new_status in (VerificationStatus.CONFIRMED, VerificationStatus.LIKELY)
        assert len(rec1.reason) > 0

        rec2 = records[1]
        assert rec2.finding_id == f2.finding_id
        assert rec2.verification_method == "rule_evidence_existence_check"
        assert rec2.new_status == VerificationStatus.UNVERIFIED
