import tempfile
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from aegis_common.enums import (
    AssessmentStatus,
    JobStatus,
    TargetType,
    TestPermissionLevel,
)
from aegis_common.models import Assessment, ScopeRule
from backend.app.db.base import Base
from backend.app.db.repositories.assessment_repo import AssessmentRepository
from backend.app.db.repositories.audit_repo import AuditRepository
from backend.app.db.session import get_engine, get_session_factory
from backend.app.services.job_service import (
    AssessmentNotApprovedError,
    InvalidStateTransitionError,
    JobService,
)


@pytest.fixture
def db_session():
    """Provides an isolated SQLite database session for unit testing."""
    db_file = tempfile.mktemp(suffix=".db")
    engine = get_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    session_factory = get_session_factory(engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def test_assessment(db_session: Session) -> Assessment:
    """Creates a valid active assessment with defined scope and profiles."""
    assessment = Assessment(
        assessment_id="assess_job_test_01",
        name="Job Lifecycle Test Assessment",
        organization_name="ZeroTrace Security Research",
        authorized_by="Lead Security Architect",
        lifecycle_status=AssessmentStatus.APPROVED,
        permitted_profiles=[
            TestPermissionLevel.PASSIVE_ONLY,
            TestPermissionLevel.ACTIVE_NON_INTRUSIVE,
            TestPermissionLevel.INTRUSIVE_TEST,
        ],
        scope_rules=[
            ScopeRule(
                target_value="api.example.test",
                target_type=TargetType.DOMAIN,
                include_subdomains=False,
                approved_ports=[80, 443],
                permitted_path_prefixes=["/api"],
            ),
            ScopeRule(
                target_value="*.sub.example.test",
                target_type=TargetType.DOMAIN,
                include_subdomains=True,
                approved_ports=[80, 443, 8080],
            ),
        ],
    )
    repo = AssessmentRepository(db_session)
    repo.create(assessment)
    db_session.commit()
    return assessment


# -----------------------------------------------------------------------------
# Unit Tests for JobService and Lifecycle State Machine
# -----------------------------------------------------------------------------


def test_job_creation_and_initial_state(db_session: Session, test_assessment: Assessment):
    service = JobService(session=db_session)

    job = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="OSINT_RECON",
        target_input="api.example.test",
        permission_level=TestPermissionLevel.PASSIVE_ONLY,
        timeout_seconds=300,
        max_retries=2,
    )

    assert job.job_id is not None
    assert job.status == JobStatus.CREATED
    assert job.target_input == "api.example.test"
    assert job.timeout_seconds == 300
    assert job.max_retries == 2
    assert job.retry_count == 0
    assert len(job.audit_history) == 1
    assert job.audit_history[0].to_status == JobStatus.CREATED

    # Verify audit trail
    audit_repo = AuditRepository(db_session)
    events = audit_repo.list_by_assessment(test_assessment.assessment_id)
    assert any(e.event_type == "JOB_CREATED" and e.job_id == job.job_id for e in events)


def test_idempotent_job_creation(db_session: Session, test_assessment: Assessment):
    service = JobService(session=db_session)
    idempotency_key = "req_unique_key_12345"

    job1 = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="PORT_SCAN",
        target_input="api.example.test",
        idempotency_key=idempotency_key,
    )

    # Calling create_job with the same idempotency key must return the existing record
    job2 = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="PORT_SCAN",
        target_input="api.example.test",
        idempotency_key=idempotency_key,
    )

    assert job2.job_id == job1.job_id
    jobs = service.list_jobs(test_assessment.assessment_id)
    assert len(jobs) == 1


def test_job_creation_unapproved_or_expired_assessment(db_session: Session):
    repo = AssessmentRepository(db_session)
    service = JobService(session=db_session)

    # 1. Non-existent assessment
    with pytest.raises(AssessmentNotApprovedError, match="does not exist"):
        service.create_job(
            assessment_id="assess_does_not_exist",
            task_type="TEST",
            target_input="example.test",
        )

    # 2. Draft assessment
    draft = repo.create(
        Assessment(
            assessment_id="assess_draft",
            name="Draft",
            organization_name="Org",
            authorized_by="Lead",
            lifecycle_status=AssessmentStatus.DRAFT,
        )
    )
    db_session.commit()

    with pytest.raises(AssessmentNotApprovedError, match="not approved"):
        service.create_job(
            assessment_id=draft.assessment_id,
            task_type="TEST",
            target_input="example.test",
        )

    # 3. Expired assessment
    expired = repo.create(
        Assessment(
            assessment_id="assess_expired",
            name="Expired",
            organization_name="Org",
            authorized_by="Lead",
            lifecycle_status=AssessmentStatus.APPROVED,
            expires_at=datetime.now(UTC) - timedelta(days=1),
        )
    )
    db_session.commit()

    with pytest.raises(AssessmentNotApprovedError, match="expired"):
        service.create_job(
            assessment_id=expired.assessment_id,
            task_type="TEST",
            target_input="example.test",
        )


def test_allowed_transitions_full_lifecycle(db_session: Session, test_assessment: Assessment):
    """
    Tests complete valid progression:
    CREATED -> POLICY_CHECK -> QUEUED -> RUNNING -> REVIEW -> COMPLETED
    """
    service = JobService(session=db_session)

    # 1. Create (CREATED)
    job = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="VULN_VERIFY",
        target_input="api.example.test",
        permission_level=TestPermissionLevel.ACTIVE_NON_INTRUSIVE,
    )
    assert job.status == JobStatus.CREATED

    # 2. Enqueue (which runs policy check and moves to QUEUED)
    job = service.enqueue_job(job.job_id)
    assert job.status == JobStatus.QUEUED

    # 3. Worker claims job (RUNNING)
    job = service.start_job(job.job_id)
    assert job.status == JobStatus.RUNNING
    assert job.started_at is not None

    # 4. Worker yields findings for review (REVIEW)
    findings_data = {"vulnerabilities_found": 1, "cve": "CVE-2023-1234"}
    job = service.mark_job_for_review(job.job_id, findings_summary=findings_data)
    assert job.status == JobStatus.REVIEW
    assert job.result_summary["vulnerabilities_found"] == 1

    # 5. Review completed and verified (COMPLETED)
    final_summary = {"status": "accepted", "risk": "LOW"}
    job = service.complete_job(job.job_id, result_summary=final_summary)
    assert job.status == JobStatus.COMPLETED
    assert job.completed_at is not None

    # Verify audit history length and entries
    assert (
        len(job.audit_history) == 6
    )  # None->CREATED, CREATED->POLICY_CHECK, POLICY_CHECK->QUEUED, QUEUED->RUNNING, RUNNING->REVIEW, REVIEW->COMPLETED


def test_disallowed_transitions_strictly_rejected(db_session: Session, test_assessment: Assessment):
    service = JobService(session=db_session)

    job = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="SCAN",
        target_input="api.example.test",
    )
    assert job.status == JobStatus.CREATED

    # Cannot jump directly from CREATED to RUNNING
    with pytest.raises(InvalidStateTransitionError, match="Illegal job state transition"):
        service.start_job(job.job_id)

    # Database state must remain CREATED
    fresh = service.get_job(job.job_id)
    assert fresh.status == JobStatus.CREATED

    # Enqueue to QUEUED
    job = service.enqueue_job(job.job_id)
    assert job.status == JobStatus.QUEUED

    # Cannot jump directly from QUEUED to COMPLETED
    with pytest.raises(InvalidStateTransitionError, match="Illegal job state transition"):
        service.complete_job(job.job_id)

    fresh = service.get_job(job.job_id)
    assert fresh.status == JobStatus.QUEUED


def test_policy_denial_transitions_to_failed(db_session: Session, test_assessment: Assessment):
    service = JobService(session=db_session)

    # Create job with out-of-scope target
    job = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="PORT_SCAN",
        target_input="unauthorized-external-corp.com",
    )

    # Policy check must fail closed
    checked_job = service.check_job_policy(job.job_id)
    assert checked_job.status == JobStatus.FAILED
    assert "Scope policy violation" in checked_job.error_summary
    assert checked_job.completed_at is not None

    # Verify audit event
    audit_repo = AuditRepository(db_session)
    events = audit_repo.list_by_assessment(test_assessment.assessment_id)
    assert any(e.event_type == "JOB_POLICY_DENIED" and e.job_id == job.job_id for e in events)


def test_intrusive_profile_requires_approval_workflow(
    db_session: Session, test_assessment: Assessment
):
    service = JobService(session=db_session)

    # Job with INTRUSIVE_TEST profile requires explicit sign-off
    job = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="EXPLOIT_VERIFY",
        target_input="api.example.test",
        permission_level=TestPermissionLevel.INTRUSIVE_TEST,
    )

    # Policy check moves to NEEDS_APPROVAL
    job = service.check_job_policy(job.job_id)
    assert job.status == JobStatus.NEEDS_APPROVAL

    # Cannot enqueue directly without approval
    with pytest.raises(InvalidStateTransitionError, match="requires explicit operator approval"):
        service.enqueue_job(job.job_id)

    # Operator approves the job
    job = service.record_approval(
        job_id=job.job_id,
        approver="lead_penetration_tester",
        notes="Authorized lab environment execution.",
    )
    assert job.status == JobStatus.QUEUED

    # Now can be claimed by worker
    job = service.start_job(job.job_id)
    assert job.status == JobStatus.RUNNING


def test_cancellation_from_queued_and_running(db_session: Session, test_assessment: Assessment):
    service = JobService(session=db_session)

    # 1. Cancel from QUEUED
    job1 = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="TASK_A",
        target_input="api.example.test",
    )
    job1 = service.enqueue_job(job1.job_id)
    assert job1.status == JobStatus.QUEUED

    cancelled1 = service.request_cancellation(job1.job_id, reason="Operator stopped queue")
    assert cancelled1.status == JobStatus.CANCELLED
    assert cancelled1.cancellation_requested is True
    assert cancelled1.completed_at is not None

    # Repeated cancellation call on CANCELLED is idempotent
    repeated = service.request_cancellation(job1.job_id)
    assert repeated.status == JobStatus.CANCELLED

    # 2. Cancel from RUNNING
    job2 = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="TASK_B",
        target_input="api.example.test",
    )
    job2 = service.enqueue_job(job2.job_id)
    job2 = service.start_job(job2.job_id)
    assert job2.status == JobStatus.RUNNING

    cancelled2 = service.request_cancellation(job2.job_id, reason="Worker runaway detected")
    assert cancelled2.status == JobStatus.CANCELLED


def test_terminal_states_cannot_restart_or_cancel(db_session: Session, test_assessment: Assessment):
    service = JobService(session=db_session)

    # Complete a job
    job = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="TASK_C",
        target_input="api.example.test",
    )
    job = service.enqueue_job(job.job_id)
    job = service.start_job(job.job_id)
    job = service.complete_job(job.job_id)
    assert job.status == JobStatus.COMPLETED

    # Cannot cancel a COMPLETED job
    with pytest.raises(InvalidStateTransitionError, match="Cannot cancel job .* in terminal state"):
        service.request_cancellation(job.job_id)

    # Cannot enqueue or restart a COMPLETED job
    with pytest.raises(InvalidStateTransitionError, match="Illegal job state transition"):
        service.enqueue_job(job.job_id)

    with pytest.raises(InvalidStateTransitionError, match="Illegal job state transition"):
        service.start_job(job.job_id)


def test_controlled_retries_and_attempt_budget(db_session: Session, test_assessment: Assessment):
    service = JobService(session=db_session)

    job = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="FAIL_TASK",
        target_input="api.example.test",
        max_retries=2,
    )
    job = service.enqueue_job(job.job_id)
    job = service.start_job(job.job_id)
    job = service.fail_job(job.job_id, error_message="Network glitch")
    assert job.status == JobStatus.FAILED
    assert job.retry_count == 0

    # Retry 1: succeeds -> POLICY_CHECK
    retried1 = service.retry_job(job.job_id)
    assert retried1.status == JobStatus.POLICY_CHECK
    assert retried1.retry_count == 1
    assert retried1.error_summary is None

    # Fail again
    job = service.fail_job(retried1.job_id, error_message="Worker OOM")
    assert job.status == JobStatus.FAILED

    # Retry 2: succeeds -> POLICY_CHECK
    retried2 = service.retry_job(job.job_id)
    assert retried2.status == JobStatus.POLICY_CHECK
    assert retried2.retry_count == 2

    # Fail third time
    job = service.fail_job(retried2.job_id, error_message="Persistent crash")
    assert job.status == JobStatus.FAILED

    # Retry 3: Budget exhausted (max_retries = 2) -> must be rejected
    with pytest.raises(ValueError, match="Retry budget exhausted"):
        service.retry_job(job.job_id)

    # Cannot retry a non-failed job
    active_job = service.create_job(
        assessment_id=test_assessment.assessment_id,
        task_type="ACTIVE",
        target_input="api.example.test",
    )
    with pytest.raises(InvalidStateTransitionError, match="only FAILED jobs can be retried"):
        service.retry_job(active_job.job_id)
