import tempfile

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from schemas.enums import JobStatus
from schemas.models import EvidenceSourceType


@pytest.fixture
def test_client():
    db_file = tempfile.mktemp(suffix=".db")
    app = create_app(f"sqlite:///{db_file}")
    client = TestClient(app)
    return client


def test_end_to_end_assessment_workflow(test_client):
    # 1. Create an Assessment
    payload = {
        "title": "Local OWASP Juice Shop Lab Test",
        "organization_name": "Security Research Lab",
        "authorized_by": "Lead Security Engineer",
        "description": "Authorized penetration testing assessment for local lab application",
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

    resp = test_client.post("/assessments", json=payload)
    assert resp.status_code == 201
    assessment_data = resp.json()
    assessment_id = assessment_data["assessment_id"]
    assert assessment_id is not None
    assert assessment_data["status"] == "APPROVED"

    # 2. Try to enqueue an OUT-OF-SCOPE job (e.g. google.com or excluded target) -> Must be rejected!
    out_of_scope_job = {
        "task_type": "OSINT_DNS",
        "target_input": "unauthorized-external-target.com",
        "permission_level": "PASSIVE_ONLY",
    }
    resp_bad = test_client.post(f"/assessments/{assessment_id}/jobs", json=out_of_scope_job)
    assert resp_bad.status_code == 201
    bad_job_data = resp_bad.json()
    assert bad_job_data["status"] == JobStatus.FAILED.value
    assert "Scope violation" in bad_job_data["error_message"]

    # Verify audit event logged for rejected scope check
    resp_events = test_client.get(f"/assessments/{assessment_id}/events")
    events = resp_events.json()
    rejection_events = [e for e in events if e["event_type"] == "SCOPE_CHECK_REJECTED"]
    assert len(rejection_events) == 1

    # 3. Submit an in-scope Evidence record (as Person 1, Person 2, or Person 3)
    # Calculate correct hash using EvidenceStore to match
    store = test_client.app.state.evidence_store
    evidence_obj = store.create_evidence(
        assessment_id=assessment_id,
        source_type=EvidenceSourceType.SCANNER_ZAP,
        tool_name="ZAP_Baseline",
        data={"alert": "Missing Anti-clickjacking Header", "url": "http://127.0.0.1:3000"},
    )
    resp_evi = test_client.post(
        f"/assessments/{assessment_id}/evidence",
        json=evidence_obj.model_dump(mode="json"),
    )
    assert resp_evi.status_code == 201
    registered_evidence_id = resp_evi.json()["evidence_id"]

    # 4. Submit a Finding with a fake/non-existent evidence ID -> Must be rejected!
    bad_finding = {
        "assessment_id": assessment_id,
        "asset_id": "asset_01",
        "title": "Fake SQL Injection",
        "description": "Hallucinated issue without evidence",
        "severity": "HIGH",
        "confidence": 0.9,
        "verification_status": "UNVERIFIED",
        "evidence_ids": ["evi_does_not_exist_999"],
        "remediation": "Fix input validation",
        "tool_name": "ai_analyst",
    }
    resp_bad_find = test_client.post(f"/assessments/{assessment_id}/findings", json=bad_finding)
    assert resp_bad_find.status_code == 400
    assert "does not exist in assessment evidence store" in resp_bad_find.json()["detail"]

    # 5. Submit valid Finding with the registered evidence ID
    valid_finding = {
        "assessment_id": assessment_id,
        "asset_id": "asset_juice_01",
        "title": "Missing Anti-clickjacking Header (X-Frame-Options)",
        "description": "The web application does not set X-Frame-Options or CSP frame-ancestors.",
        "cwe": "CWE-1021",
        "severity": "LOW",
        "confidence": 0.95,
        "verification_status": "LIKELY",
        "evidence_ids": [registered_evidence_id],
        "root_cause": "Missing security header configuration in Express app.",
        "remediation": "Configure helmet middleware or add X-Frame-Options: DENY header.",
        "tool_name": "ZAP_Baseline",
    }
    resp_good_find = test_client.post(f"/assessments/{assessment_id}/findings", json=valid_finding)
    assert resp_good_find.status_code == 201

    # 6. Retrieve Final Report summary
    resp_report = test_client.get(f"/assessments/{assessment_id}/report")
    assert resp_report.status_code == 200
    report = resp_report.json()
    assert report["summary"]["total_findings"] == 1
    assert report["summary"]["total_evidence_records"] == 1

    # 7. Cancel assessment immediately
    resp_cancel = test_client.post(f"/assessments/{assessment_id}/cancel")
    assert resp_cancel.status_code == 200
    assert resp_cancel.json()["status"] == "CANCELLED"
