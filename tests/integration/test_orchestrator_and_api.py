"""
Integration test verifying end-to-end assessment lifecycle, scope boundaries,
evidence verification, and job cancellation via the canonical ZeroTrace app (backend.app.main).
"""

import tempfile
import pytest
from fastapi.testclient import TestClient

from aegis_common.enums import (
    AssessmentStatus,
    EvidenceSourceType,
    Severity,
    VerificationStatus,
)
from backend.app.core.config import settings
from backend.app.db.models import Base
from backend.app.db.session import get_db, get_engine, get_session_factory
from backend.app.main import create_application

TEST_AUTH_TOKEN = "test-secret-zerotrace-token-e2e"
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_AUTH_TOKEN}"}


@pytest.fixture
def client_and_session():
    db_file = tempfile.mktemp(suffix=".db")
    db_url = f"sqlite:///{db_file}"
    engine = get_engine(db_url)
    Base.metadata.create_all(bind=engine)
    session_factory = get_session_factory(engine)

    app = create_application()

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    settings.API_AUTH_TOKEN = TEST_AUTH_TOKEN

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_end_to_end_assessment_workflow(client_and_session):
    client = client_and_session

    # 1. Create an Assessment
    payload = {
        "title": "Local OWASP Juice Shop Lab Test",
        "organization_name": "Security Research Lab",
        "authorized_by": "Lead Security Engineer",
        "description": "Authorized penetration testing assessment for local lab application",
        "authorization_acknowledged": True,
        "scope": {
            "target_domains": ["lab.example.test"],
            "target_ips": ["127.0.0.1"],
            "target_cidrs": [],
            "target_urls": ["http://127.0.0.1:3000"],
            "excluded_targets": ["production.example.test"],
            "allowed_ports": [80, 443, 3000, 8080],
            "max_requests_per_minute": 60,
            "max_concurrency": 2,
            "allowed_permission_level": "PASSIVE_ONLY",
        },
    }

    resp = client.post("/assessments", json=payload, headers=AUTH_HEADERS)
    assert resp.status_code == 201
    assessment_data = resp.json()
    assessment_id = assessment_data["assessment_id"]
    assert assessment_id is not None
    assert assessment_data["status"] == "PENDING_APPROVAL"

    # Explicitly approve assessment
    resp_approve = client.post(
        f"/assessments/{assessment_id}/approve",
        json={"approver": "Lead Security Engineer"},
        headers=AUTH_HEADERS,
    )
    assert resp_approve.status_code == 200
    assert resp_approve.json()["status"] == "APPROVED"

    # 2. Try to enqueue an OUT-OF-SCOPE start/job -> Must be rejected!
    out_of_scope_job = {
        "task_type": "OSINT_DNS",
        "target_input": "unauthorized-external-target.com",
    }
    resp_bad = client.post(f"/assessments/{assessment_id}/start", json=out_of_scope_job, headers=AUTH_HEADERS)
    assert resp_bad.status_code == 400
    assert "violates assessment scope" in resp_bad.json()["detail"].lower()

    # Verify audit event logged
    resp_events = client.get(f"/assessments/{assessment_id}/events", headers=AUTH_HEADERS)
    assert resp_events.status_code == 200
    events = resp_events.json()
    assert len(events) >= 1

    # 3. Register in-scope target asset and submit in-scope Evidence
    asset_resp = client.post(
        f"/assessments/{assessment_id}/assets",
        json={"raw_value": "http://127.0.0.1:3000", "asset_type": "url"},
        headers=AUTH_HEADERS,
    )
    assert asset_resp.status_code == 201
    asset_id = asset_resp.json()["asset_id"]

    resp_evi = client.post(
        f"/assessments/{assessment_id}/evidence",
        json={
            "source_name": "ZAP_Baseline",
            "source_type": EvidenceSourceType.SCANNER_ZAP.value,
            "data": {"alert": "Missing Anti-clickjacking Header", "url": "http://127.0.0.1:3000"},
            "asset_id": asset_id,
        },
        headers=AUTH_HEADERS,
    )
    assert resp_evi.status_code == 201
    registered_evidence_id = resp_evi.json()["evidence_id"]

    # 4. Submit a Finding with a fake/non-existent evidence ID -> Must be rejected!
    bad_finding = {
        "assessment_id": assessment_id,
        "asset_id": asset_id,
        "title": "Fake SQL Injection",
        "description": "Hallucinated issue without evidence",
        "severity": Severity.HIGH.value,
        "confidence": 0.9,
        "verification_status": VerificationStatus.UNVERIFIED.value,
        "evidence_ids": ["evi_does_not_exist_999"],
        "remediation": "Fix input validation",
        "source_tool": "ai_analyst",
    }
    resp_bad_find = client.post(f"/assessments/{assessment_id}/findings", json=bad_finding, headers=AUTH_HEADERS)
    assert resp_bad_find.status_code == 400
    assert "evidence provenance violation" in resp_bad_find.json()["detail"].lower()

    # 5. Submit valid Finding with registered evidence ID -> Succeeds!
    valid_finding = {
        "assessment_id": assessment_id,
        "asset_id": asset_id,
        "title": "Missing Anti-clickjacking Header (X-Frame-Options)",
        "description": "The web application does not set X-Frame-Options or CSP frame-ancestors.",
        "cwe": "CWE-1021",
        "severity": Severity.LOW.value,
        "confidence": 0.95,
        "verification_status": VerificationStatus.LIKELY.value,
        "evidence_ids": [registered_evidence_id],
        "remediation": "Configure helmet middleware or add X-Frame-Options: DENY header.",
        "source_tool": "ZAP_Baseline",
    }
    resp_good_find = client.post(f"/assessments/{assessment_id}/findings", json=valid_finding, headers=AUTH_HEADERS)
    assert resp_good_find.status_code == 201

    # 6. Retrieve Report status response
    resp_report = client.get(f"/assessments/{assessment_id}/report", headers=AUTH_HEADERS)
    assert resp_report.status_code == 200
    assert resp_report.json()["status"] == "NOT_READY"

    # 7. Cancel assessment immediately
    resp_cancel = client.post(f"/assessments/{assessment_id}/cancel", json={"reason": "Test finished"}, headers=AUTH_HEADERS)
    assert resp_cancel.status_code == 200
    assert resp_cancel.json()["status"] == AssessmentStatus.CANCELLED.value
