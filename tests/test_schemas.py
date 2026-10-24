from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from schemas import (
    AIAnalysis,
    Assessment,
    AssessmentStatus,
    Asset,
    AssetType,
    ConfidenceLevel,
    DiscoveredService,
    Evidence,
    Finding,
    FindingSeverity,
    VerificationStatus,
)


def test_assessment_valid_lifecycle():
    now = datetime.now(UTC)
    assessment = Assessment(
        id="asm_test_001",
        name="OWASP Juice Shop Lab Assessment",
        target="http://localhost:3000",
        status=AssessmentStatus.IN_PROGRESS,
        created_at=now,
    )
    assert assessment.id == "asm_test_001"
    assert assessment.status == AssessmentStatus.IN_PROGRESS
    assert assessment.completed_at is None

    # Mark completed
    assessment.status = AssessmentStatus.COMPLETED
    assessment.completed_at = now + timedelta(minutes=15)
    assert assessment.completed_at > assessment.created_at


def test_assessment_invalid_completion_date():
    now = datetime.now(UTC)
    with pytest.raises(ValidationError) as exc_info:
        Assessment(
            id="asm_bad",
            name="Bad Assessment",
            target="127.0.0.1",
            created_at=now,
            completed_at=now - timedelta(hours=1),
        )
    assert "completed_at cannot be earlier than created_at" in str(exc_info.value)


def test_asset_and_services():
    asset = Asset(
        id="ast_001",
        assessment_id="asm_test_001",
        hostname_or_address="app.local.test",
        asset_type=AssetType.WEB_APP,
        discovered_services=[
            DiscoveredService(port=80, protocol="tcp", service_name="http"),
            DiscoveredService(port=443, protocol="tcp", service_name="https", banner="nginx/1.24"),
        ],
        source="nmap",
    )
    assert len(asset.discovered_services) == 2
    assert asset.discovered_services[1].port == 443
    assert asset.asset_type == AssetType.WEB_APP


def test_evidence_provenance():
    ev = Evidence(
        id="ev_001",
        source="owasp_zap",
        description="SQL injection error observed in login response body",
        reference_or_artifact_location="/artifacts/zap_log_42.json",
        raw_data="HTTP 500: syntax error at or near 'SELECT'",
    )
    assert ev.id == "ev_001"
    assert ev.raw_data is not None


def test_finding_requires_evidence_when_confirmed():
    # Attempting to confirm finding without evidence must fail
    with pytest.raises(ValidationError) as exc_info:
        Finding(
            id="fnd_unbacked",
            assessment_id="asm_test_001",
            title="Unbacked Finding",
            description="Fabricated without proof",
            severity=FindingSeverity.HIGH,
            confidence=ConfidenceLevel.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
            evidence_references=[],  # Empty!
            source_tool="custom_scanner",
        )
    assert (
        "cannot have verification_status=CONFIRMED without at least one supporting evidence reference"
        in str(exc_info.value)
    )

    # With evidence reference, confirmation succeeds
    finding = Finding(
        id="fnd_backed",
        assessment_id="asm_test_001",
        title="Validated SQL Injection",
        description="SQL syntax error returned when single quote injected",
        severity=FindingSeverity.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        verification_status=VerificationStatus.CONFIRMED,
        evidence_references=["ev_001"],
        source_tool="owasp_zap",
        cwe="CWE-89",
    )
    assert finding.verification_status == VerificationStatus.CONFIRMED
    assert "ev_001" in finding.evidence_references


def test_ai_analysis_citation_guard_passes():
    analysis = AIAnalysis(
        concise_summary="Critical SQL Injection in User Login Endpoint",
        reasoning_summary="Based on evidence ev_001, single quote injection triggers database syntax exception.",
        severity_assessment=FindingSeverity.CRITICAL,
        severity_justification="Allows authentication bypass and arbitrary database queries.",
        confidence_assessment=ConfidenceLevel.HIGH,
        confidence_justification="Direct error disclosure confirms database-level reflection.",
        recommended_remediation="Use parameterized queries / prepared statements with ORM.",
        limitations_and_missing_evidence=["Blind SQL injection timing was not evaluated."],
        cited_evidence_ids=["ev_001"],
    )

    # Valid citations
    available_evidence = {"ev_001", "ev_002"}
    analysis.validate_citations(available_evidence)


def test_ai_analysis_hallucination_detected():
    analysis = AIAnalysis(
        concise_summary="Fabricated Remote Code Execution",
        reasoning_summary="The model inferred RCE from imagined evidence.",
        severity_assessment=FindingSeverity.CRITICAL,
        severity_justification="Critical impact.",
        confidence_assessment=ConfidenceLevel.HIGH,
        confidence_justification="High confidence.",
        recommended_remediation="Patch host.",
        limitations_and_missing_evidence=[],
        cited_evidence_ids=["ev_ghost_999"],  # Does not exist in real evidence store!
    )

    available_evidence = {"ev_001"}
    with pytest.raises(ValueError) as exc_info:
        analysis.validate_citations(available_evidence)

    assert "AI hallucination detected" in str(exc_info.value)
    assert "ev_ghost_999" in str(exc_info.value)


def test_json_roundtrip():
    finding = Finding(
        id="fnd_json",
        assessment_id="asm_json",
        title="Insecure Direct Object Reference",
        description="User profile accessible via incremented ID parameter.",
        severity=FindingSeverity.MEDIUM,
        confidence=ConfidenceLevel.MEDIUM,
        verification_status=VerificationStatus.LIKELY,
        evidence_references=["ev_idor_01"],
        source_tool="manual_verification",
    )
    json_str = finding.model_dump_json()
    reconstructed = Finding.model_validate_json(json_str)
    assert reconstructed.id == finding.id
    assert reconstructed.severity == FindingSeverity.MEDIUM
