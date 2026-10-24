import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from backend.app import app
from modules.ai.adapter import DeterministicFallbackAdapter, RemoteLLMAdapter
from modules.ai.config import AIConfig
from schemas.contracts import Evidence, Finding
from schemas.enums import ConfidenceLevel, FindingSeverity, VerificationStatus


@pytest.fixture
def sample_finding_and_evidence():
    now = datetime.now(UTC)
    ev = Evidence(
        id="ev_zap_sqli_01",
        source="owasp_zap",
        description="Union SELECT response reflection in product search query parameter q",
        observed_at=now,
        raw_data='HTTP 200 OK\n[{"id": 1, "admin": true}]',
    )
    finding = Finding(
        id="fnd_test_sqli",
        assessment_id="asm_test_01",
        title="Union SQL Injection in Search Parameter",
        description="Parameter q is directly concatenated into database query string.",
        severity=FindingSeverity.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        verification_status=VerificationStatus.CONFIRMED,
        evidence_references=["ev_zap_sqli_01"],
        source_tool="owasp_zap",
        cwe="CWE-89",
    )
    return finding, [ev]


def test_valid_output_deterministic(sample_finding_and_evidence):
    finding, evidence = sample_finding_and_evidence
    adapter = DeterministicFallbackAdapter()

    analysis = adapter.analyze(finding, evidence)

    # Core Task schema compliance
    assert analysis.summary is not None
    assert len(analysis.evidence_facts) > 0
    assert len(analysis.interpretation) > 0
    assert analysis.severity == FindingSeverity.CRITICAL
    assert analysis.severity_justification != ""
    assert analysis.confidence == ConfidenceLevel.HIGH
    assert analysis.confidence_justification != ""
    assert analysis.verification_status == VerificationStatus.CONFIRMED
    assert len(analysis.remediation) > 0
    assert isinstance(analysis.limitations, list)
    assert analysis.requires_human_review is True
    assert analysis.is_rule_based_fallback is True
    assert analysis.analysis_provider == "deterministic_fallback"
    assert "ev_zap_sqli_01" in analysis.cited_evidence_ids


def test_missing_evidence_behavior():
    finding = Finding(
        id="fnd_unbacked_timing",
        assessment_id="asm_test_01",
        title="Potential Timing Side Channel in Token Verification",
        description="Static check flagged non-constant-time string comparison.",
        severity=FindingSeverity.MEDIUM,
        confidence=ConfidenceLevel.LOW,
        verification_status=VerificationStatus.UNVERIFIED,
        evidence_references=[],  # ZERO EVIDENCE
        source_tool="semgrep",
    )

    adapter = DeterministicFallbackAdapter()
    analysis = adapter.analyze(finding, evidence_records=[])

    # Rule: If input lacks evidence, lower confidence and state verification is needed
    assert analysis.confidence == ConfidenceLevel.LOW
    assert analysis.verification_status == VerificationStatus.UNVERIFIED
    assert len(analysis.cited_evidence_ids) == 0
    assert any("EVIDENCE" in limit.upper() for limit in analysis.limitations)


def test_anti_upgrade_rule(sample_finding_and_evidence):
    # Candidate finding is unverified
    finding = Finding(
        id="fnd_unconfirmed_candidate",
        assessment_id="asm_test_01",
        title="Heuristic Suspicion",
        description="Scanner flagged possible issue.",
        severity=FindingSeverity.HIGH,
        confidence=ConfidenceLevel.LOW,
        verification_status=VerificationStatus.UNVERIFIED,
        evidence_references=[],
        source_tool="scanner_probe",
    )

    config = AIConfig(
        provider="remote",
        api_base="http://localhost:11434/v1",
        allow_external_calls=True,
    )
    adapter = RemoteLLMAdapter(config=config)

    # Mock remote model attempting to illegally mark it as CONFIRMED
    mock_payload = {
        "summary": "Model hallucinating confirmed state",
        "evidence_facts": ["Imagined fact"],
        "interpretation": ["Imagined impact"],
        "severity": "high",
        "severity_justification": "Grounded in input",
        "confidence": "high",
        "confidence_justification": "High confidence",
        "verification_status": "confirmed",  # ILLEGAL UPGRADE ATTEMPT!
        "remediation": ["Patch it"],
        "limitations": [],
        "requires_human_review": True,
        "cited_evidence_ids": [],
    }

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"choices": [{"message": {"content": json.dumps(mock_payload)}}]}
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.Client.post", return_value=mock_resp):
        analysis = adapter.analyze(finding, evidence_records=[])

    # Must NOT be CONFIRMED! Clamped by platform safety rule
    assert analysis.verification_status != VerificationStatus.CONFIRMED
    assert any("attempted to mark finding as confirmed" in lim for lim in analysis.limitations)


def test_provider_timeout_fallback(sample_finding_and_evidence):
    finding, evidence = sample_finding_and_evidence
    config = AIConfig(
        provider="remote",
        api_base="http://localhost:11434/v1",
        timeout_seconds=0.5,
        allow_external_calls=True,
    )
    adapter = RemoteLLMAdapter(config=config)

    with patch("httpx.Client.post", side_effect=httpx.TimeoutException("Connection timed out")):
        analysis = adapter.analyze(finding, evidence)

    # Must not crash! Must fall back gracefully to deterministic analysis
    assert analysis.is_rule_based_fallback is True
    assert any("timed out" in lim.lower() for lim in analysis.limitations)
    assert analysis.summary != ""


def test_malformed_json_fallback(sample_finding_and_evidence):
    finding, evidence = sample_finding_and_evidence
    config = AIConfig(
        provider="remote",
        api_base="http://localhost:11434/v1",
        allow_external_calls=True,
    )
    adapter = RemoteLLMAdapter(config=config)

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "choices": [
            {"message": {"content": "Here is your analysis: { broken json, invalid structure..."}}
        ]
    }
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.Client.post", return_value=mock_resp):
        analysis = adapter.analyze(finding, evidence)

    # Malformed output must not crash application
    assert analysis.is_rule_based_fallback is True
    assert any("malformed" in lim.lower() for lim in analysis.limitations)


def test_external_call_consent_block(sample_finding_and_evidence):
    finding, evidence = sample_finding_and_evidence
    # External URL with consent disabled
    config = AIConfig(
        provider="openai",
        api_base="https://api.openai.com/v1",
        allow_external_calls=False,  # BLOCKED!
    )
    adapter = RemoteLLMAdapter(config=config)

    with patch("httpx.Client.post") as mock_post:
        analysis = adapter.analyze(finding, evidence)
        mock_post.assert_not_called()  # No external network call allowed!

    assert analysis.is_rule_based_fallback is True
    assert any("external transmission blocked" in lim.lower() for lim in analysis.limitations)


def test_backend_api_endpoint(sample_finding_and_evidence):
    finding, evidence = sample_finding_and_evidence
    client = TestClient(app)

    # 1. Health endpoint
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"

    # 2. Analyze endpoint
    payload = {
        "finding": finding.model_dump(mode="json"),
        "evidence": [ev.model_dump(mode="json") for ev in evidence],
    }

    resp = client.post("/api/ai/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"] != ""
    assert data["severity"] == "critical"
    assert data["requires_human_review"] is True
    assert "ev_zap_sqli_01" in data["cited_evidence_ids"]


def test_api_authentication_enforcement(sample_finding_and_evidence, monkeypatch):
    finding, evidence = sample_finding_and_evidence
    monkeypatch.setenv("API_AUTH_TOKEN", "secret_lab_token_123")
    client = TestClient(app)

    payload = {
        "finding": finding.model_dump(mode="json"),
        "evidence": [ev.model_dump(mode="json") for ev in evidence],
    }

    # Unauthenticated request fails
    resp = client.post("/api/ai/analyze", json=payload)
    assert resp.status_code == 401

    # Authenticated with X-API-Key succeeds
    resp = client.post(
        "/api/ai/analyze", json=payload, headers={"X-API-Key": "secret_lab_token_123"}
    )
    assert resp.status_code == 200

    # Authenticated with Bearer token succeeds
    resp = client.post(
        "/api/ai/analyze",
        json=payload,
        headers={"Authorization": "Bearer secret_lab_token_123"},
    )
    assert resp.status_code == 200
