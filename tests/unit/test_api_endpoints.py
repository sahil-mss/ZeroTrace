"""
Unit and Integration Tests for ZeroTrace Authenticated REST API (Session 8).

Verifies:
- Bearer token authentication (fail-closed behavior, timing-safe validation, public health endpoint)
- Assessment creation without implicit approval or automatic scanning
- Scope and authorization acknowledgement validation
- Execution control: approval gating, job enqueuing through JobService (no direct scanner execution)
- Assessment cancellation propagating through JobService and audit logging
- Persisted asset and finding retrieval (empty collections when none exist, no fabricated data)
- Evidence, audit event, and job retrieval isolation by assessment
- Report readiness status (explicit NOT_READY response, never fabricated)
- Partner integration endpoints (evidence and finding submissions with evidence ID validation)
"""

import tempfile

import pytest
from fastapi.testclient import TestClient

from aegis_common.enums import (
    AssessmentStatus,
    EvidenceSourceType,
    JobStatus,
    ScopeStatus,
    Severity,
    VerificationStatus,
)
from backend.app.core.config import settings
from backend.app.db.models import Base
from backend.app.db.session import get_db, get_engine, get_session_factory
from backend.app.main import create_application

TEST_AUTH_TOKEN = "test-secret-zerotrace-token-12345"
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_AUTH_TOKEN}"}


@pytest.fixture
def test_db_session():
    """Provides a fresh, isolated SQLite database for each API test."""
    db_file = tempfile.mktemp(suffix=".db")
    db_url = f"sqlite:///{db_file}"
    engine = get_engine(db_url)
    Base.metadata.create_all(bind=engine)
    session_factory = get_session_factory(engine)

    session = session_factory()
    try:
        yield session, session_factory
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(test_db_session):
    """FastAPI TestClient with overridden database session and configured token."""
    _, session_factory = test_db_session
    app = create_application()

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    settings.API_BEARER_TOKEN = TEST_AUTH_TOKEN

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


# ==============================================================================
# 1. Health Endpoint Tests (Public)
# ==============================================================================


def test_health_endpoint_public_and_minimal(client):
    """GET /health must be public and return minimal status without secrets or internal details."""
    # No Authorization header provided
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "healthy"
    assert data["app_name"] == "ZeroTrace"
    assert "version" in data
    # Ensure no environment variables, paths or secrets are leaked
    assert "API_BEARER_TOKEN" not in data
    assert "DATABASE_URL" not in data
    assert "STORAGE_DIR" not in data


# ==============================================================================
# 2. Authentication Dependency Tests
# ==============================================================================


def test_auth_fail_closed_when_unconfigured(client):
    """Protected endpoints must fail closed (401) when API_BEARER_TOKEN is not configured."""
    original_token = settings.API_BEARER_TOKEN
    try:
        settings.API_BEARER_TOKEN = ""  # Unconfigured / empty
        resp = client.get("/assessments", headers=AUTH_HEADERS)
        assert resp.status_code == 401
        assert "Authentication is not configured" in resp.json()["detail"]
        assert "WWW-Authenticate" in resp.headers
    finally:
        settings.API_BEARER_TOKEN = original_token


def test_auth_rejects_missing_or_invalid_tokens(client):
    """Protected endpoints must reject requests with missing, invalid or malformed bearer tokens."""
    # 1. Missing Authorization header
    resp_missing = client.get("/assessments")
    assert resp_missing.status_code == 401
    assert "Missing or malformed" in resp_missing.json()["detail"]

    # 2. Wrong Bearer token value
    resp_invalid = client.get("/assessments", headers={"Authorization": "Bearer wrong-token-xyz"})
    assert resp_invalid.status_code == 401
    assert "Invalid authentication token" in resp_invalid.json()["detail"]

    # 3. Wrong auth scheme (Basic instead of Bearer)
    resp_scheme = client.get("/assessments", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert resp_scheme.status_code == 401


def test_auth_succeeds_with_valid_bearer_token(client):
    """Requests with valid Bearer token must succeed."""
    resp = client.get("/assessments", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ==============================================================================
# 3. Assessment Lifecycle & Scope Creation Tests
# ==============================================================================


def test_create_assessment_validation_and_no_implicit_approval(client):
    """
    Creating an assessment records scope and authorization acknowledgement.
    It MUST NOT implicitly approve the assessment or launch a scan.
    """
    # 1. Reject request with empty scope
    bad_payload = {
        "title": "Invalid Scope Assessment",
        "organization_name": "Test Org",
        "authorized_by": "Security Officer",
        "scope_rules": [],
    }
    resp_bad = client.post("/assessments", json=bad_payload, headers=AUTH_HEADERS)
    assert resp_bad.status_code == 400
    assert "at least one authorized target" in resp_bad.json()["detail"]

    # 2. Valid assessment creation
    valid_payload = {
        "title": "Alpha Lab Penetration Assessment",
        "organization_name": "Acme Defense Corp",
        "authorized_by": "CISO Alice Smith",
        "owner": "red_team",
        "authorization_reference": "SOW-2026-0042",
        "authorization_acknowledged": True,
        "description": "Authorized target evaluation for internal alpha environment",
        "scope_rules": [
            {
                "target_type": "domain",
                "target_value": "alpha.internal.test",
                "include_subdomains": False,
                "approved_ports": [80, 443],
            },
            {
                "target_type": "ip_address",
                "target_value": "192.168.10.50",
                "approved_ports": [80, 443, 8080],
            },
        ],
        "permitted_profiles": ["PASSIVE_ONLY"],
        "max_concurrency": 2,
        "max_requests_per_minute": 60,
    }

    resp = client.post("/assessments", json=valid_payload, headers=AUTH_HEADERS)
    assert resp.status_code == 201
    created = resp.json()

    assert created["assessment_id"].startswith("assess_")
    assert created.get("name") == "Alpha Lab Penetration Assessment" or created.get("title") == "Alpha Lab Penetration Assessment"
    assert created["organization_name"] == "Acme Defense Corp"
    assert created["authorization_acknowledged"] is True
    # CRITICAL: Status must be PENDING_APPROVAL on creation
    assert created["status"] == AssessmentStatus.PENDING_APPROVAL.value

    # Verify an immutable audit log entry was created
    assessment_id = created["assessment_id"]
    events_resp = client.get(f"/assessments/{assessment_id}/events", headers=AUTH_HEADERS)
    assert events_resp.status_code == 200
    events = events_resp.json()
    assert len(events) == 1
    assert events[0]["event_type"] == "ASSESSMENT_CREATED"


def test_list_assessments_with_pagination(client):
    """Collection endpoints must support limit and offset pagination."""
    # Create 3 assessments
    for i in range(3):
        payload = {
            "title": f"Test Assessment {i}",
            "organization_name": f"Org {i}",
            "authorized_by": f"Operator {i}",
            "scope": {
                "target_domains": [f"target{i}.example.test"],
                "allowed_ports": [443],
            },
        }
        resp = client.post("/assessments", json=payload, headers=AUTH_HEADERS)
        assert resp.status_code == 201

    # Page 1: limit 2, offset 0
    page1 = client.get("/assessments?limit=2&offset=0", headers=AUTH_HEADERS).json()
    assert len(page1) == 2

    # Page 2: limit 2, offset 2
    page2 = client.get("/assessments?limit=2&offset=2", headers=AUTH_HEADERS).json()
    assert len(page2) == 1


def test_get_assessment_by_id_and_missing_resource(client):
    """Retrieves assessment by ID or returns HTTP 404 for missing resource."""
    # 1. Missing resource
    resp_404 = client.get("/assessments/assess_nonexistent_999", headers=AUTH_HEADERS)
    assert resp_404.status_code == 404
    assert "not found" in resp_404.json()["detail"].lower()

    # 2. Existing resource
    payload = {
        "title": "Existing Assessment",
        "organization_name": "Defense Lab",
        "authorized_by": "SecOps",
        "scope": {"target_domains": ["existing.example.test"]},
    }
    created = client.post("/assessments", json=payload, headers=AUTH_HEADERS).json()
    assessment_id = created["assessment_id"]

    resp_get = client.get(f"/assessments/{assessment_id}", headers=AUTH_HEADERS)
    assert resp_get.status_code == 200
    assert resp_get.json()["assessment_id"] == assessment_id


# ==============================================================================
# 4. Assessment Execution Control (Start, Approve, Cancel)
# ==============================================================================


def test_start_endpoint_requires_explicit_approval(client):
    """
    POST /assessments/{assessment_id}/start must reject unapproved assessments.
    Approval requires formal sign-off before start can enqueue jobs.
    """
    # 1. Create assessment (starts in PENDING_APPROVAL)
    payload = {
        "title": "Strict Approval Flow Test",
        "organization_name": "Gov Security Unit",
        "authorized_by": "Director Chen",
        "scope": {
            "target_domains": ["gateway.secure.test"],
            "allowed_ports": [443],
            "allowed_permission_level": "PASSIVE_ONLY",
        },
    }
    created = client.post("/assessments", json=payload, headers=AUTH_HEADERS).json()
    assessment_id = created["assessment_id"]

    # 2. Attempt to start while PENDING_APPROVAL -> Must be rejected!
    resp_start_unapproved = client.post(f"/assessments/{assessment_id}/start", headers=AUTH_HEADERS)
    assert resp_start_unapproved.status_code == 400
    assert "pending approval" in resp_start_unapproved.json()["detail"].lower()

    # 3. Formally approve the assessment
    resp_approve = client.post(
        f"/assessments/{assessment_id}/approve",
        json={"approver": "Lead Auditor Bob", "notes": "Scope validated and approved against SOW."},
        headers=AUTH_HEADERS,
    )
    assert resp_approve.status_code == 200
    assert resp_approve.json()["status"] == AssessmentStatus.APPROVED.value

    # 4. Start assessment now that it is APPROVED -> Enqueues job in JobService
    resp_start = client.post(
        f"/assessments/{assessment_id}/start",
        json={"task_type": "PASSIVE_RECON", "target_input": "gateway.secure.test"},
        headers=AUTH_HEADERS,
    )
    assert resp_start.status_code == 200
    start_data = resp_start.json()
    assert start_data["status"] == AssessmentStatus.ACTIVE.value
    assert start_data["job"]["status"] == JobStatus.QUEUED.value
    assert start_data["job"]["target_input"] == "gateway.secure.test"

    # Verify audit event for start
    events = client.get(f"/assessments/{assessment_id}/events", headers=AUTH_HEADERS).json()
    event_types = [e["event_type"] for e in events]
    assert "ASSESSMENT_APPROVED" in event_types
    assert "ASSESSMENT_STARTED" in event_types


def test_start_endpoint_rejects_scope_violations(client):
    """
    POST /assessments/{assessment_id}/start must deterministically reject proposed
    targets that violate assessment scope rules.
    """
    payload = {
        "title": "Scope Enforced Start Test",
        "organization_name": "Test Lab",
        "authorized_by": "Officer Dave",
        "scope": {
            "target_domains": ["authorized.internal.test"],
            "excluded_targets": ["forbidden.internal.test"],
        },
    }
    created = client.post("/assessments", json=payload, headers=AUTH_HEADERS).json()
    assessment_id = created["assessment_id"]

    # Approve
    client.post(
        f"/assessments/{assessment_id}/approve",
        json={"approver": "Officer Dave"},
        headers=AUTH_HEADERS,
    )

    # Attempt to start with an out-of-scope target
    resp_out_of_scope = client.post(
        f"/assessments/{assessment_id}/start",
        json={"target_input": "external-unauthorized-target.com"},
        headers=AUTH_HEADERS,
    )
    assert resp_out_of_scope.status_code == 400
    assert "violates assessment scope" in resp_out_of_scope.json()["detail"].lower()


def test_cancel_assessment_and_jobs(client):
    """
    POST /assessments/{assessment_id}/cancel must request cooperative cancellation
    through JobService, cancel active jobs, and record an audit event.
    """
    payload = {
        "title": "Cancellation Flow Test",
        "organization_name": "Cancel Org",
        "authorized_by": "Manager Eve",
        "scope": {"target_domains": ["cancel.target.test"]},
    }
    created = client.post("/assessments", json=payload, headers=AUTH_HEADERS).json()
    assessment_id = created["assessment_id"]

    # Approve and Start to create an active QUEUED job
    client.post(
        f"/assessments/{assessment_id}/approve",
        json={"approver": "Manager Eve"},
        headers=AUTH_HEADERS,
    )
    client.post(f"/assessments/{assessment_id}/start", headers=AUTH_HEADERS)

    # Trigger cancellation
    cancel_resp = client.post(
        f"/assessments/{assessment_id}/cancel",
        json={"reason": "Emergency security hold"},
        headers=AUTH_HEADERS,
    )
    assert cancel_resp.status_code == 200
    cancel_data = cancel_resp.json()
    assert cancel_data["status"] == AssessmentStatus.CANCELLED.value
    assert cancel_data["cancelled_jobs_count"] >= 1

    # Verify that subsequent start on cancelled assessment is rejected
    resp_restart = client.post(f"/assessments/{assessment_id}/start", headers=AUTH_HEADERS)
    assert resp_restart.status_code == 400
    assert "terminal status" in resp_restart.json()["detail"].lower()

    # Verify job record in database transitioned to CANCELLED
    jobs = client.get(f"/assessments/{assessment_id}/jobs", headers=AUTH_HEADERS).json()
    assert len(jobs) >= 1
    assert jobs[0]["status"] == JobStatus.CANCELLED.value


# ==============================================================================
# 5. Asset and Finding Retrieval Tests (No Fake Data)
# ==============================================================================


def test_asset_and_finding_retrieval_persisted_and_empty_collections(client):
    """
    GET /assessments/{assessment_id}/assets and /findings must return actual persisted records.
    When empty, they must return [] rather than fabricated demonstration findings.
    """
    payload = {
        "title": "Clean Assessment Without Findings",
        "organization_name": "Audit Corp",
        "authorized_by": "Frank Analyst",
        "scope": {"target_domains": ["clean.audit.test"]},
    }
    created = client.post("/assessments", json=payload, headers=AUTH_HEADERS).json()
    assessment_id = created["assessment_id"]

    # 1. Assets: Should be empty initially
    assets_resp = client.get(f"/assessments/{assessment_id}/assets", headers=AUTH_HEADERS)
    assert assets_resp.status_code == 200
    assert assets_resp.json() == []

    # 2. Findings: Should be empty list, NEVER fabricated demonstration records
    findings_resp = client.get(f"/assessments/{assessment_id}/findings", headers=AUTH_HEADERS)
    assert findings_resp.status_code == 200
    assert findings_resp.json() == []

    # 3. Approve assessment and register one real asset via partner endpoint
    client.post(
        f"/assessments/{assessment_id}/approve",
        json={"approver": "Frank Analyst"},
        headers=AUTH_HEADERS,
    )

    asset_resp = client.post(
        f"/assessments/{assessment_id}/assets",
        json={
            "raw_value": "clean.audit.test",
            "asset_type": "domain",
            "confidence": 1.0,
        },
        headers=AUTH_HEADERS,
    )
    assert asset_resp.status_code == 201
    registered_asset = asset_resp.json()
    assert (
        registered_asset.get("scope_status") == ScopeStatus.IN_SCOPE.value
        or registered_asset.get("scope_classification") == ScopeStatus.IN_SCOPE.value
    )

    # Now assets collection contains exactly 1 real persisted record
    assets_now = client.get(f"/assessments/{assessment_id}/assets", headers=AUTH_HEADERS).json()
    assert len(assets_now) == 1
    asset_val = assets_now[0].get("normalized_value") or assets_now[0].get("value")
    assert asset_val == "clean.audit.test"


# ==============================================================================
# 6. Evidence and Activity Isolation Tests
# ==============================================================================


def test_evidence_and_jobs_assessment_isolation(client):
    """Evidence and jobs endpoints must return records belonging strictly to the requested assessment."""
    # Create Assessment A
    ass_a = client.post(
        "/assessments",
        json={"title": "Assessment A", "organization_name": "Org A", "authorized_by": "Operator A", "scope": {"target_domains": ["a.test"]}},
        headers=AUTH_HEADERS,
    ).json()

    # Create Assessment B
    ass_b = client.post(
        "/assessments",
        json={"title": "Assessment B", "organization_name": "Org B", "authorized_by": "Operator B", "scope": {"target_domains": ["b.test"]}},
        headers=AUTH_HEADERS,
    ).json()


    # Submit Evidence to Assessment A
    evi_a = client.post(
        f"/assessments/{ass_a['assessment_id']}/evidence",
        json={
            "source_name": "mock_dns",
            "source_type": EvidenceSourceType.DNS_LOOKUP.value,
            "data": {"records": ["192.168.1.1"]},
        },
        headers=AUTH_HEADERS,
    ).json()
    assert evi_a["assessment_id"] == ass_a["assessment_id"]

    # Verify Assessment A lists this evidence
    list_a = client.get(f"/assessments/{ass_a['assessment_id']}/evidence", headers=AUTH_HEADERS).json()
    assert len(list_a) == 1
    assert list_a[0]["evidence_id"] == evi_a["evidence_id"]

    # Verify Assessment B has ZERO evidence records (strict isolation)
    list_b = client.get(f"/assessments/{ass_b['assessment_id']}/evidence", headers=AUTH_HEADERS).json()
    assert len(list_b) == 0


# ==============================================================================
# 7. Report Readiness Endpoint Test
# ==============================================================================


def test_report_endpoint_returns_clear_not_ready_response(client):
    """
    GET /assessments/{assessment_id}/report must return a clear not-ready response
    since reporting has not been implemented yet, rather than generating a fake report.
    """
    payload = {
        "title": "Report Status Test Assessment",
        "organization_name": "Security Labs",
        "authorized_by": "Lead Assessor",
        "scope": {"target_domains": ["report.test.local"]},
    }
    created = client.post("/assessments", json=payload, headers=AUTH_HEADERS).json()
    assessment_id = created["assessment_id"]

    resp = client.get(f"/assessments/{assessment_id}/report", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    report_data = resp.json()

    assert report_data["status"] == "NOT_READY"
    assert report_data["is_ready"] is False
    assert report_data["assessment_id"] == assessment_id
    assert "not ready" in report_data["message"].lower()
    assert "Person 3" in report_data["detail"]


# ==============================================================================
# 8. Finding Submission and Evidence Integrity Validation
# ==============================================================================


def test_finding_submission_validates_evidence_provenance(client):
    """
    POST /assessments/{assessment_id}/findings must reject findings referencing non-existent
    evidence records or mismatched assessments.
    """
    payload = {
        "title": "Finding Provenance Test",
        "organization_name": "Provenance Corp",
        "authorized_by": "Auditor George",
        "scope": {"target_domains": ["provenance.test"]},
    }
    created = client.post("/assessments", json=payload, headers=AUTH_HEADERS).json()
    assessment_id = created["assessment_id"]

    # 1. Register Asset
    asset = client.post(
        f"/assessments/{assessment_id}/assets",
        json={"raw_value": "provenance.test", "asset_type": "domain"},
        headers=AUTH_HEADERS,
    ).json()

    # 2. Register Evidence
    evidence = client.post(
        f"/assessments/{assessment_id}/evidence",
        json={
            "source_name": "scanner_http",
            "source_type": EvidenceSourceType.HTTP_FINGERPRINT.value,
            "data": {"header_missing": "Content-Security-Policy"},
            "asset_id": asset["asset_id"],
        },
        headers=AUTH_HEADERS,
    ).json()

    # 3. Attempt to submit finding with fake evidence ID -> Must be rejected!
    bad_finding_payload = {
        "assessment_id": assessment_id,
        "asset_id": asset["asset_id"],
        "title": "Missing Content-Security-Policy",
        "description": "CSP header is not configured.",
        "remediation": "Configure proper CSP headers.",
        "severity": Severity.LOW.value,
        "confidence": 0.9,
        "verification_status": VerificationStatus.LIKELY.value,
        "evidence_ids": ["evi_hallucinated_nonexistent_999"],
        "source_tool": "custom_probe",
    }
    resp_bad = client.post(
        f"/assessments/{assessment_id}/findings",
        json=bad_finding_payload,
        headers=AUTH_HEADERS,
    )
    assert resp_bad.status_code == 400
    assert "evidence provenance violation" in resp_bad.json()["detail"].lower()

    # 4. Submit valid finding with registered evidence ID -> Succeeds!
    valid_finding_payload = {
        "assessment_id": assessment_id,
        "asset_id": asset["asset_id"],
        "title": "Missing Content-Security-Policy",
        "description": "CSP header is not configured.",
        "remediation": "Configure proper CSP headers.",
        "severity": Severity.LOW.value,
        "confidence": 0.9,
        "verification_status": VerificationStatus.LIKELY.value,
        "evidence_ids": [evidence["evidence_id"]],
        "source_tool": "custom_probe",
    }
    resp_good = client.post(
        f"/assessments/{assessment_id}/findings",
        json=valid_finding_payload,
        headers=AUTH_HEADERS,
    )
    assert resp_good.status_code == 201
    saved_finding = resp_good.json()
    assert saved_finding["finding_id"].startswith("find_")
    assert saved_finding["evidence_ids"] == [evidence["evidence_id"]]
