"""
ZeroTrace Session 9 - End-to-End Backend Integration and Regression Suite.

Validates:
- Complete end-to-end lifecycle using a clean temporary database and deterministic MockOSINTAdapter.
- Authentication, assessment creation without auto-approval, explicit approval workflow.
- Strict scope boundary enforcement, rejection of lookalikes and unauthorized subdomains.
- Asset & Evidence deduplication, immutability, and API retrieval parity.
- Job lifecycle state machine transitions, cancellation, and immutable audit trailing.
- Report endpoint safe responses (no hallucinated data).
- Negative regression tests for auth, cross-assessment evidence, invalid state transitions,
  and sensitive credential masking.
"""

import tempfile

import pytest
from fastapi.testclient import TestClient

from aegis_common.enums import (
    AssessmentStatus,
    JobStatus,
    TargetType,
    TestPermissionLevel,
)
from aegis_common.models.assessment import Assessment, ScopeRule
from backend.app.core.config import settings
from backend.app.db.base import Base
from backend.app.db.models import (
    AssetModel,
    AuditEventModel,
    EvidenceModel,
    JobModel,
)
from backend.app.db.repositories.assessment_repo import AssessmentRepository
from backend.app.db.session import get_db, get_engine, get_session_factory
from backend.app.main import create_application
from backend.app.services.job_service import InvalidStateTransitionError, JobService
from backend.app.services.osint_service import OSINTCollectionService
from backend.app.services.scope_validator import ScopeReasonCode, validate_target
from modules.osint.mock_adapter import MockOSINTAdapter

TEST_AUTH_TOKEN = "zerotrace-integration-secret-test-token-2026"
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_AUTH_TOKEN}"}


@pytest.fixture
def clean_db():
    """Provides a fresh isolated temporary SQLite database for integration testing."""
    db_file = tempfile.mktemp(suffix=".db")
    db_url = f"sqlite:///{db_file}"
    engine = get_engine(db_url)
    Base.metadata.create_all(bind=engine)
    session_factory = get_session_factory(engine)
    session = session_factory()

    yield session, session_factory, engine

    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_app(clean_db):
    """FastAPI application configured with temporary test database and auth token."""
    _, session_factory, _ = clean_db
    app = create_application()

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    settings.API_BEARER_TOKEN = TEST_AUTH_TOKEN

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


# ==============================================================================
# Part 1: Comprehensive End-to-End Integration Test
# ==============================================================================


@pytest.mark.asyncio
async def test_end_to_end_lifecycle_session9(clean_db, test_app):
    """
    End-to-End integration test covering the 15 required integration steps:
    1. Start application with test configuration.
    2. Authenticate test client.
    3. Create assessment with explicit authorization acknowledgement and narrow scope.
    4. Confirm assessment is NOT automatically approved (PENDING_APPROVAL).
    5. Explicitly approve the assessment.
    6. Verify in-scope mock observation is validated.
    7. Confirm scope validation allows approved target and rejects lookalikes & subdomains.
    8. Collect mock observation via deterministic MockOSINTAdapter.
    9. Confirm Asset and Evidence records are persisted in database.
    10. Verify repeated collection is idempotent (no duplicate assets or evidence).
    11. Create a bounded job and exercise full lifecycle.
    12. Request cancellation of an eligible job and confirm state.
    13. Confirm all operations and state transitions are in the immutable audit trail.
    14. Retrieve records through API and compare with persisted DB records.
    15. Confirm report endpoint returns NOT_READY when report is not generated.
    """
    session, session_factory, _ = clean_db
    client = test_app

    # Step 1 & 2: Application running and client authenticates with token
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["app_name"] == "ZeroTrace"

    # Step 3: Create an assessment with explicit authorization and narrow scope
    create_payload = {
        "title": "ZeroTrace Reserved Lab Assessment",
        "description": "Authorized integration verification for lab.example.test",
        "organization_name": "ZeroTrace Verification Lab",
        "authorized_by": "Lead Security Auditor",
        "authorization_reference": "AUTH-ZT-2026-09",
        "authorization_acknowledged": True,
        "scope_rules": [
            {
                "target_type": "DOMAIN",
                "target_value": "lab.example.test",
                "include_subdomains": False,  # Strict: subdomains NOT permitted by default
                "approved_ports": [80, 443, 8080],
                "permitted_path_prefixes": ["/api", "/health"],
            },
            {
                "target_type": "IP_ADDRESS",
                "target_value": "192.168.1.10",
                "approved_ports": [80, 443],
            },
        ],
        "permitted_profiles": ["PASSIVE_ONLY", "ACTIVE_NON_INTRUSIVE"],
    }

    create_resp = client.post("/assessments", json=create_payload, headers=AUTH_HEADERS)
    assert create_resp.status_code == 201
    assessment_data = create_resp.json()
    assessment_id = assessment_data["assessment_id"]
    assert assessment_id is not None

    # Step 4: Verify assessment is NOT automatically approved upon creation
    assert assessment_data["status"] == "PENDING_APPROVAL"
    assert assessment_data["authorization_acknowledged"] is True

    # Step 5: Explicitly approve the assessment via test workflow
    approve_resp = client.post(
        f"/assessments/{assessment_id}/approve",
        json={"approver": "Lead Security Auditor"},
        headers=AUTH_HEADERS,
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "APPROVED"

    # Step 6 & 7: Test ScopeValidator against approved target, lookalikes, and subdomains
    assessment_repo = AssessmentRepository(session)
    stored_assessment = assessment_repo.get(assessment_id)
    assert stored_assessment is not None

    # In-scope exact target
    valid_domain = validate_target("lab.example.test", stored_assessment)
    assert valid_domain.allowed is True
    assert valid_domain.reason_code == ScopeReasonCode.ALLOWED

    # Lookalike domains MUST be rejected
    lookalike_1 = validate_target("lab.example.test.attacker.com", stored_assessment)
    assert lookalike_1.allowed is False
    assert lookalike_1.reason_code == ScopeReasonCode.TARGET_NOT_IN_SCOPE

    lookalike_2 = validate_target("fake-lab.example.test", stored_assessment)
    assert lookalike_2.allowed is False
    assert lookalike_2.reason_code == ScopeReasonCode.TARGET_NOT_IN_SCOPE

    # Unauthorized subdomain must be rejected because include_subdomains=False
    unauth_sub = validate_target("unauthorized.lab.example.test", stored_assessment)
    assert unauth_sub.allowed is False
    assert unauth_sub.reason_code == ScopeReasonCode.SUBDOMAIN_NOT_PERMITTED

    # Step 8: Collect mock observations using deterministic MockOSINTAdapter
    mock_adapter = MockOSINTAdapter()
    osint_service = OSINTCollectionService(session=session, adapters=[mock_adapter])

    summary_1 = await osint_service.run_collection(
        assessment_id=assessment_id,
        target="lab.example.test",
    )
    assert summary_1.status == "COMPLETED"
    assert summary_1.total_targets_queried == 1
    assert summary_1.new_assets_created > 0
    assert summary_1.evidence_records_created > 0

    # Step 9: Confirm Asset and Evidence records are persisted in database
    assets_in_db = session.query(AssetModel).filter_by(assessment_id=assessment_id).all()
    assert len(assets_in_db) > 0
    evidence_in_db = session.query(EvidenceModel).filter_by(assessment_id=assessment_id).all()
    assert len(evidence_in_db) > 0

    initial_asset_count = len(assets_in_db)
    initial_evidence_count = len(evidence_in_db)

    # Step 10: Verify repeated collection does NOT create unnecessary duplicate records
    summary_2 = await osint_service.run_collection(
        assessment_id=assessment_id,
        target="lab.example.test",
    )
    assert summary_2.status == "COMPLETED"
    assert summary_2.new_assets_created == 0  # Deduplicated!
    assert summary_2.evidence_records_created == 0  # Deduplicated!

    session.expire_all()
    assets_after_repeat = session.query(AssetModel).filter_by(assessment_id=assessment_id).all()
    evidence_after_repeat = (
        session.query(EvidenceModel).filter_by(assessment_id=assessment_id).all()
    )
    assert len(assets_after_repeat) == initial_asset_count
    assert len(evidence_after_repeat) == initial_evidence_count

    # Step 11: Create a bounded job and exercise full lifecycle
    job_service = JobService(session=session)
    job_1 = job_service.create_job(
        assessment_id=assessment_id,
        task_type="PASSIVE_RECON",
        target_input="lab.example.test",
        permission_level=TestPermissionLevel.PASSIVE_ONLY,
    )
    assert job_1.status == JobStatus.CREATED

    # Advance through state machine: CREATED -> POLICY_CHECK -> QUEUED -> RUNNING -> REVIEW -> COMPLETED
    job_1 = job_service.enqueue_job(job_1.job_id)
    assert job_1.status == JobStatus.QUEUED

    job_1 = job_service.start_job(job_1.job_id)
    assert job_1.status == JobStatus.RUNNING

    job_1 = job_service.mark_job_for_review(job_1.job_id, findings_summary={"discovered": 1})
    assert job_1.status == JobStatus.REVIEW

    job_1 = job_service.complete_job(job_1.job_id, result_summary={"status": "completed"})
    assert job_1.status == JobStatus.COMPLETED

    # Step 12: Request cancellation of another eligible job via assessment cancel endpoint
    job_2 = job_service.create_job(
        assessment_id=assessment_id,
        task_type="SECONDARY_PROBE",
        target_input="192.168.1.10",
        permission_level=TestPermissionLevel.PASSIVE_ONLY,
    )
    job_2 = job_service.enqueue_job(job_2.job_id)
    assert job_2.status == JobStatus.QUEUED

    cancel_resp = client.post(
        f"/assessments/{assessment_id}/cancel",
        json={"reason": "Operator requested cancellation test"},
        headers=AUTH_HEADERS,
    )
    assert cancel_resp.status_code == 200
    cancel_json = cancel_resp.json()
    assert cancel_json["status"] == "CANCELLED"
    assert cancel_json["cancelled_jobs_count"] >= 1

    # Verify job in DB transitioned to CANCELLED
    session.expire_all()
    cancelled_job_in_db = session.query(JobModel).filter_by(job_id=job_2.job_id).one()
    assert cancelled_job_in_db.status == JobStatus.CANCELLED.value

    # Step 13: Verify all state transitions and operations are reflected in audit trail
    events_in_db = session.query(AuditEventModel).filter_by(assessment_id=assessment_id).all()
    event_types = [e.event_type for e in events_in_db]
    assert "ASSESSMENT_CREATED" in event_types
    assert "ASSESSMENT_APPROVED" in event_types
    assert "ASSESSMENT_CANCELLED" in event_types
    assert any("JOB" in a for a in event_types)

    # Step 14: Retrieve records through API and compare with persisted DB records
    # Verify assessment GET
    api_get_resp = client.get(f"/assessments/{assessment_id}", headers=AUTH_HEADERS)
    assert api_get_resp.status_code == 200
    assert api_get_resp.json()["assessment_id"] == assessment_id

    # Verify assets GET
    api_assets_resp = client.get(f"/assessments/{assessment_id}/assets", headers=AUTH_HEADERS)
    assert api_assets_resp.status_code == 200
    api_assets = api_assets_resp.json()
    assert len(api_assets) == initial_asset_count

    # Verify evidence GET
    api_evidence_resp = client.get(f"/assessments/{assessment_id}/evidence", headers=AUTH_HEADERS)
    assert api_evidence_resp.status_code == 200
    api_evidence = api_evidence_resp.json()
    assert len(api_evidence) == initial_evidence_count

    # Verify jobs GET
    api_jobs_resp = client.get(f"/assessments/{assessment_id}/jobs", headers=AUTH_HEADERS)
    assert api_jobs_resp.status_code == 200
    api_jobs = api_jobs_resp.json()
    assert len(api_jobs) >= 2

    # Step 15: Confirm report endpoint returns safe NOT_READY response without inventing data
    report_resp = client.get(f"/assessments/{assessment_id}/report", headers=AUTH_HEADERS)
    assert report_resp.status_code == 200
    report_data = report_resp.json()
    assert report_data["status"] == "NOT_READY"
    assert (
        "report" in report_data["message"].lower() or "not ready" in report_data["message"].lower()
    )
    assert report_data["assessment_id"] == assessment_id


# ==============================================================================
# Part 2: Negative and Regression Tests
# ==============================================================================


def test_missing_or_invalid_authentication_token_rejected(test_app):
    """Confirm missing or invalid auth token is rejected with 401."""
    client = test_app

    # Missing token
    resp_missing = client.get("/assessments")
    assert resp_missing.status_code == 401

    # Invalid token
    resp_invalid = client.get(
        "/assessments",
        headers={"Authorization": "Bearer invalid_bad_token_999"},
    )
    assert resp_invalid.status_code == 401


def test_unapproved_assessment_cannot_start(clean_db, test_app):
    """Confirm unapproved assessment in PENDING_APPROVAL cannot start execution."""
    session, _, _ = clean_db
    client = test_app

    create_payload = {
        "title": "Unapproved Assessment",
        "description": "Testing start restriction",
        "organization_name": "LabOrg",
        "authorized_by": "Auditor",
        "authorization_acknowledged": True,
        "scope_rules": [
            {
                "target_type": "DOMAIN",
                "target_value": "unapproved.example.test",
                "include_subdomains": False,
            }
        ],
    }
    create_resp = client.post("/assessments", json=create_payload, headers=AUTH_HEADERS)
    assessment_id = create_resp.json()["assessment_id"]

    # Attempt start directly without approval
    start_resp = client.post(
        f"/assessments/{assessment_id}/start",
        json={"target": "unapproved.example.test"},
        headers=AUTH_HEADERS,
    )
    assert start_resp.status_code == 400
    assert (
        "pending approval" in start_resp.json()["detail"].lower()
        or "approval is required" in start_resp.json()["detail"].lower()
    )


def test_out_of_scope_target_rejected_on_start(clean_db, test_app):
    """Confirm out-of-scope targets are strictly rejected upon assessment start."""
    session, _, _ = clean_db
    client = test_app

    create_payload = {
        "title": "Scope Start Test",
        "description": "Authorized for example.test only",
        "organization_name": "LabOrg",
        "authorized_by": "Auditor",
        "authorization_acknowledged": True,
        "scope_rules": [
            {
                "target_type": "DOMAIN",
                "target_value": "example.test",
                "include_subdomains": False,
            }
        ],
    }
    create_resp = client.post("/assessments", json=create_payload, headers=AUTH_HEADERS)
    assessment_id = create_resp.json()["assessment_id"]

    # Explicit approval
    approve_resp = client.post(
        f"/assessments/{assessment_id}/approve",
        json={"approver": "Auditor"},
        headers=AUTH_HEADERS,
    )
    assert approve_resp.status_code == 200

    # Attempt to start with an out-of-scope target
    start_resp = client.post(
        f"/assessments/{assessment_id}/start",
        json={"target_input": "malicious-out-of-scope.com"},
        headers=AUTH_HEADERS,
    )
    assert start_resp.status_code == 400
    assert "violates assessment scope" in start_resp.json()["detail"].lower()


def test_lookalike_domain_hostname_matching_regression(clean_db):
    """Confirm lookalike domains cannot bypass hostname prefix/suffix matching."""
    session, _, _ = clean_db

    assessment = Assessment(
        assessment_id="assess_lookalike_check",
        name="Lookalike Test",
        organization_name="LabOrg",
        authorized_by="Lead",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[
            ScopeRule(
                target_type=TargetType.DOMAIN,
                target_value="target.example.test",
                include_subdomains=True,
            )
        ],
    )

    # Approved
    res_exact = validate_target("target.example.test", assessment)
    assert res_exact.allowed is True

    res_sub = validate_target("sub.target.example.test", assessment)
    assert res_sub.allowed is True

    # Lookalike suffix attacks
    res_evil_1 = validate_target("target.example.test.evil.com", assessment)
    assert res_evil_1.allowed is False

    res_evil_2 = validate_target("target.example.test.attacker.org", assessment)
    assert res_evil_2.allowed is False

    # Lookalike prefix / dash attacks
    res_evil_3 = validate_target("not-target.example.test", assessment)
    assert res_evil_3.allowed is False

    res_evil_4 = validate_target("faketarget.example.test", assessment)
    assert res_evil_4.allowed is False


def test_cross_assessment_evidence_reference_rejected(clean_db, test_app):
    """Confirm a finding cannot reference evidence from a different assessment."""
    session, _, _ = clean_db
    client = test_app

    # Create Assessment A
    resp_a = client.post(
        "/assessments",
        json={
            "title": "Assessment A",
            "organization_name": "Org A",
            "authorized_by": "Admin",
            "authorization_acknowledged": True,
            "scope_rules": [{"target_type": "DOMAIN", "target_value": "a.example.test"}],
        },
        headers=AUTH_HEADERS,
    )
    id_a = resp_a.json()["assessment_id"]
    client.post(f"/assessments/{id_a}/approve", json={"approver": "Admin"}, headers=AUTH_HEADERS)

    # Create Assessment B
    resp_b = client.post(
        "/assessments",
        json={
            "title": "Assessment B",
            "organization_name": "Org B",
            "authorized_by": "Admin",
            "authorization_acknowledged": True,
            "scope_rules": [{"target_type": "DOMAIN", "target_value": "b.example.test"}],
        },
        headers=AUTH_HEADERS,
    )
    id_b = resp_b.json()["assessment_id"]
    client.post(f"/assessments/{id_b}/approve", json={"approver": "Admin"}, headers=AUTH_HEADERS)

    # Submit evidence in Assessment A
    evi_resp = client.post(
        f"/assessments/{id_a}/evidence",
        json={
            "source_name": "dns_probe",
            "source_type": "DNS_LOOKUP",
            "data": {"ip": "10.0.0.1"},
        },
        headers=AUTH_HEADERS,
    )
    assert evi_resp.status_code == 201
    evidence_id_a = evi_resp.json()["evidence_id"]

    # Submit asset in Assessment B
    asset_resp = client.post(
        f"/assessments/{id_b}/assets",
        json={
            "raw_value": "b.example.test",
            "asset_type": "domain",
        },
        headers=AUTH_HEADERS,
    )
    assert asset_resp.status_code == 201
    asset_id_b = asset_resp.json()["asset_id"]

    # Attempt to submit finding in Assessment B referencing Assessment A's evidence
    finding_payload = {
        "assessment_id": id_b,
        "asset_id": asset_id_b,
        "title": "Cross Reference Finding",
        "description": "Testing cross-assessment isolation",
        "severity": "HIGH",
        "confidence": 0.9,
        "verification_status": "LIKELY",
        "evidence_ids": [evidence_id_a],  # ILLEGAL: belongs to Assessment A!
        "remediation": "Validate evidence scoping before submission.",
        "tool_name": "scanner_zap",
    }

    bad_find_resp = client.post(
        f"/assessments/{id_b}/findings",
        json=finding_payload,
        headers=AUTH_HEADERS,
    )
    assert bad_find_resp.status_code == 400
    detail = bad_find_resp.json()["detail"].lower()
    assert "cross-assessment" in detail or "belongs to assessment" in detail


def test_invalid_job_transition_does_not_alter_database_state(clean_db):
    """Confirm invalid state transitions are rejected and leave DB state unchanged."""
    session, _, _ = clean_db

    # Create approved assessment
    assessment = Assessment(
        assessment_id="assess_invalid_trans",
        name="Transition Test",
        organization_name="LabOrg",
        authorized_by="Lead",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[ScopeRule(target_type=TargetType.DOMAIN, target_value="example.test")],
    )
    AssessmentRepository(session).create(assessment)
    session.commit()

    job_service = JobService(session)
    job = job_service.create_job(
        assessment_id="assess_invalid_trans",
        task_type="PORT_SCAN",
        target_input="example.test",
    )
    assert job.status == JobStatus.CREATED

    # Attempt illegal transition: CREATED -> COMPLETED (bypassing POLICY_CHECK, RUNNING, etc.)
    with pytest.raises(InvalidStateTransitionError):
        job_service.complete_job(job.job_id)

    # Confirm database state was NOT altered
    job_in_db = session.query(JobModel).filter_by(job_id=job.job_id).one()
    assert job_in_db.status == JobStatus.CREATED.value


def test_terminal_cancelled_job_cannot_be_restarted(clean_db):
    """Confirm a cancelled job is terminal and cannot transition back to active."""
    session, _, _ = clean_db

    assessment = Assessment(
        assessment_id="assess_terminal_cancel",
        name="Terminal Cancel Test",
        organization_name="LabOrg",
        authorized_by="Lead",
        lifecycle_status=AssessmentStatus.APPROVED,
        scope_rules=[ScopeRule(target_type=TargetType.DOMAIN, target_value="example.test")],
    )
    AssessmentRepository(session).create(assessment)
    session.commit()

    job_service = JobService(session)
    job = job_service.create_job(
        assessment_id="assess_terminal_cancel",
        task_type="CANCEL_TEST",
        target_input="example.test",
    )
    job = job_service.enqueue_job(job.job_id)
    job = job_service.request_cancellation(job.job_id, reason="Cancelled early")
    assert job.status == JobStatus.CANCELLED

    # Attempt illegal transition from CANCELLED -> QUEUED
    with pytest.raises(InvalidStateTransitionError, match="Illegal job state transition"):
        job_service.enqueue_job(job.job_id)

    # Status remains CANCELLED
    job_in_db = session.query(JobModel).filter_by(job_id=job.job_id).one()
    assert job_in_db.status == JobStatus.CANCELLED.value


def test_malformed_finding_unknown_evidence_rejected(clean_db, test_app):
    """Confirm finding with unknown evidence ID is rejected with 400."""
    session, _, _ = clean_db
    client = test_app

    # Create and approve assessment
    resp = client.post(
        "/assessments",
        json={
            "title": "Evidence Test",
            "organization_name": "Org",
            "authorized_by": "Admin",
            "authorization_acknowledged": True,
            "scope_rules": [{"target_type": "DOMAIN", "target_value": "example.test"}],
        },
        headers=AUTH_HEADERS,
    )
    aid = resp.json()["assessment_id"]
    client.post(f"/assessments/{aid}/approve", json={"approver": "Admin"}, headers=AUTH_HEADERS)

    # Register an asset
    asset_resp = client.post(
        f"/assessments/{aid}/assets",
        json={"raw_value": "example.test", "asset_type": "domain"},
        headers=AUTH_HEADERS,
    )
    assert asset_resp.status_code == 201
    asset_id = asset_resp.json()["asset_id"]

    # Submit finding with non-existent evidence ID
    resp_finding = client.post(
        f"/assessments/{aid}/findings",
        json={
            "assessment_id": aid,
            "asset_id": asset_id,
            "title": "Unbacked Finding",
            "description": "Hallucinated issue",
            "severity": "CRITICAL",
            "confidence": 0.9,
            "verification_status": "LIKELY",
            "evidence_ids": ["evi_completely_fabricated_123"],
            "remediation": "Apply fix immediately.",
            "tool_name": "scanner_nmap",
        },
        headers=AUTH_HEADERS,
    )
    assert resp_finding.status_code == 400
    detail = resp_finding.json()["detail"].lower()
    assert "does not exist" in detail or "provenance violation" in detail


def test_sensitive_credentials_not_leaked_in_responses(test_app):
    """Confirm secret tokens or internal keys are never exposed in ordinary API responses."""
    client = test_app

    # Health endpoint check
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    health_text = health_resp.text
    assert TEST_AUTH_TOKEN not in health_text
    assert "secret" not in health_text.lower()
    assert "token" not in health_text.lower()

    # List assessments check
    list_resp = client.get("/assessments", headers=AUTH_HEADERS)
    assert list_resp.status_code == 200
    list_text = list_resp.text
    assert TEST_AUTH_TOKEN not in list_text
