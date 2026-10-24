"""
Deterministic Job Lifecycle Management Service for ZeroTrace / AegisPT.

Provides database-backed state transitions, policy validation, approval workflows,
idempotency guarantees, and cooperative cancellation tracking without starting external processes.
"""

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from aegis_common.enums import (
    AssessmentStatus,
    AuditOutcome,
    JobStatus,
    TestPermissionLevel,
)
from aegis_common.models import AuditEvent, Job, JobAuditEntry, ResourceBudget
from aegis_common.utils import utc_now
from backend.app.db.repositories.assessment_repo import AssessmentRepository
from backend.app.db.repositories.audit_repo import AuditRepository
from backend.app.db.repositories.job_repo import JobRepository
from backend.app.services.scope_validator import ScopeValidator

logger = logging.getLogger("zerotrace.services.job")


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal or unlisted lifecycle state transition is attempted."""

    pass


class AssessmentNotApprovedError(ValueError):
    """Raised when creating or managing a job for an unapproved or expired assessment."""

    pass


class PolicyViolationError(ValueError):
    """Raised when a job's target or profile violates assessment policy."""

    pass


# Deterministic State Machine Transition Matrix
ALLOWED_TRANSITIONS: dict[JobStatus, set[JobStatus]] = {
    JobStatus.CREATED: {
        JobStatus.POLICY_CHECK,
        JobStatus.CANCELLED,
    },
    JobStatus.POLICY_CHECK: {
        JobStatus.QUEUED,
        JobStatus.NEEDS_APPROVAL,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    },
    JobStatus.NEEDS_APPROVAL: {
        JobStatus.QUEUED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    },
    JobStatus.QUEUED: {
        JobStatus.RUNNING,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    },
    JobStatus.RUNNING: {
        JobStatus.REVIEW,
        JobStatus.COMPLETED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    },
    JobStatus.REVIEW: {
        JobStatus.COMPLETED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
    },
    JobStatus.FAILED: {
        JobStatus.POLICY_CHECK,  # Controlled retry
    },
    JobStatus.COMPLETED: set(),  # Terminal
    JobStatus.CANCELLED: set(),  # Terminal
}


class JobService:
    """
    Service layer interface for managing deterministic job lifecycles.
    All transitions are validated against ALLOWED_TRANSITIONS and persisted atomically.
    """

    def __init__(self, session: Session):
        self.session = session
        self.job_repo = JobRepository(session)
        self.assessment_repo = AssessmentRepository(session)
        self.audit_repo = AuditRepository(session)

    def create_job(
        self,
        assessment_id: str,
        task_type: str,
        target_input: str,
        requested_targets: list[str] | None = None,
        permission_level: TestPermissionLevel = TestPermissionLevel.PASSIVE_ONLY,
        timeout_seconds: int = 180,
        max_retries: int = 2,
        resource_budget: ResourceBudget | None = None,
        idempotency_key: str | None = None,
    ) -> Job:
        """
        Creates a new Job in CREATED status after confirming assessment validity.
        Supports idempotency to prevent duplicate job creation upon caller retries.
        """
        # 1. Verify Assessment Approval and Expiration
        assessment = self.assessment_repo.get(assessment_id)
        if not assessment:
            raise AssessmentNotApprovedError(
                f"Cannot create job: Assessment '{assessment_id}' does not exist."
            )

        if assessment.lifecycle_status not in (AssessmentStatus.APPROVED, AssessmentStatus.ACTIVE):
            raise AssessmentNotApprovedError(
                f"Cannot create job: Assessment '{assessment_id}' is in "
                f"status '{assessment.lifecycle_status.value}', which is not approved."
            )

        now = utc_now()
        if assessment.expires_at and now > assessment.expires_at:
            raise AssessmentNotApprovedError(
                f"Cannot create job: Assessment '{assessment_id}' has expired on {assessment.expires_at.isoformat()}."
            )

        # 2. Check Idempotency Key
        if idempotency_key:
            existing = self.job_repo.get_by_idempotency_key(assessment_id, idempotency_key)
            if existing:
                logger.info(
                    f"Idempotent retry for assessment '{assessment_id}' with key '{idempotency_key}': "
                    f"returning existing job '{existing.job_id}'."
                )
                return existing

        # 3. Validate Inputs and Resource Constraints
        clean_target = target_input.strip() if target_input else ""
        targets = requested_targets or ([clean_target] if clean_target else [])
        if not clean_target and not targets:
            raise ValueError("Job target_input or requested_targets must not be empty.")

        if not (5 <= timeout_seconds <= 1800):
            raise ValueError(f"Timeout {timeout_seconds}s must be between 5 and 1800 seconds.")

        if not (0 <= max_retries <= 5):
            raise ValueError(f"Max retries {max_retries} must be between 0 and 5.")

        budget = resource_budget or ResourceBudget(timeout_seconds=timeout_seconds)

        initial_result = {"idempotency_key": idempotency_key} if idempotency_key else None

        job = Job(
            assessment_id=assessment_id,
            task_type=task_type,
            status=JobStatus.CREATED,
            target_input=clean_target or targets[0],
            requested_targets=targets,
            permitted_profile=permission_level,
            resource_budget=budget,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            result_summary=initial_result,
        )

        job.audit_history.append(
            JobAuditEntry(
                from_status=None,
                to_status=JobStatus.CREATED,
                timestamp=now,
                reason="Job initialized",
            )
        )

        created = self.job_repo.create(job)
        self._record_audit(
            assessment_id=assessment_id,
            job_id=created.job_id,
            event_type="JOB_CREATED",
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "task_type": task_type,
                "target": clean_target,
                "permission_level": permission_level.value,
                "idempotency_key": idempotency_key,
            },
        )
        self.session.commit()
        return created

    def check_job_policy(self, job_id: str) -> Job:
        """
        Transitions job from CREATED to POLICY_CHECK, evaluates target scope and permissions.
        Moves to QUEUED, NEEDS_APPROVAL, or FAILED based on policy determination.
        """
        job = self._get_job_or_fail(job_id)

        # Transition CREATED -> POLICY_CHECK
        job = self._transition_state(
            job=job,
            to_status=JobStatus.POLICY_CHECK,
            reason="Evaluating target scope and permission profile",
        )

        assessment = self.assessment_repo.get(job.assessment_id)
        if not assessment or assessment.lifecycle_status not in (AssessmentStatus.APPROVED, AssessmentStatus.ACTIVE):
            err_msg = f"Assessment '{job.assessment_id}' is not in approved state."
            return self.fail_job(job.job_id, error_message=err_msg)

        now = utc_now()
        if assessment.expires_at and now > assessment.expires_at:
            err_msg = f"Assessment '{job.assessment_id}' has expired."
            return self.fail_job(job.job_id, error_message=err_msg)

        # 1. Target Scope Check
        for target in job.requested_targets:
            scope_result = ScopeValidator.validate_target(target, assessment)
            if not scope_result.allowed:
                denial_reason = (
                    f"Scope policy violation for target '{target}': {scope_result.explanation}"
                )
                self._record_audit(
                    assessment_id=job.assessment_id,
                    job_id=job.job_id,
                    event_type="JOB_POLICY_DENIED",
                    outcome=AuditOutcome.DENIED,
                    metadata={"target": target, "reason": scope_result.explanation},
                )
                return self.fail_job(job.job_id, error_message=denial_reason)

        # 2. Permission Profile Check
        if job.permitted_profile not in assessment.permitted_profiles:
            denial_reason = (
                f"Permission profile violation: requested profile '{job.permitted_profile.value}' "
                f"is not in assessment permitted profiles {[p.value for p in assessment.permitted_profiles]}."
            )
            self._record_audit(
                assessment_id=job.assessment_id,
                job_id=job.job_id,
                event_type="JOB_POLICY_DENIED",
                outcome=AuditOutcome.DENIED,
                metadata={"reason": denial_reason},
            )
            return self.fail_job(job.job_id, error_message=denial_reason)

        # 3. Check if manual approval is required (e.g. INTRUSIVE_TEST or explicitly configured)
        if job.permitted_profile == TestPermissionLevel.INTRUSIVE_TEST:
            job = self._transition_state(
                job=job,
                to_status=JobStatus.NEEDS_APPROVAL,
                reason="Intrusive test profile requires explicit operator approval",
            )
            self._record_audit(
                assessment_id=job.assessment_id,
                job_id=job.job_id,
                event_type="JOB_NEEDS_APPROVAL",
                outcome=AuditOutcome.SUCCESS,
                metadata={"reason": "Intrusive test level requires operator sign-off"},
            )
            self.session.commit()
            return job

        # 4. Policy Approved -> Move to QUEUED
        job = self._transition_state(
            job=job,
            to_status=JobStatus.QUEUED,
            reason="Policy check passed; ready for worker assignment",
        )
        self._record_audit(
            assessment_id=job.assessment_id,
            job_id=job.job_id,
            event_type="JOB_POLICY_APPROVED",
            outcome=AuditOutcome.SUCCESS,
            metadata={"targets": job.requested_targets},
        )
        self.session.commit()
        return job

    def enqueue_job(self, job_id: str) -> Job:
        """
        Enqueues a job for worker pickup. If in CREATED state, initiates policy check first.
        Idempotent if job is already QUEUED.
        """
        job = self._get_job_or_fail(job_id)

        if job.status == JobStatus.QUEUED:
            return job

        if job.status == JobStatus.CREATED:
            return self.check_job_policy(job_id)

        if job.status == JobStatus.NEEDS_APPROVAL:
            raise InvalidStateTransitionError(
                f"Cannot enqueue job '{job_id}': Job requires explicit operator approval first."
            )

        job = self._transition_state(
            job=job,
            to_status=JobStatus.QUEUED,
            reason="Job explicitly enqueued",
        )
        self._record_audit(
            assessment_id=job.assessment_id,
            job_id=job.job_id,
            event_type="JOB_QUEUED",
            outcome=AuditOutcome.SUCCESS,
            metadata={},
        )
        self.session.commit()
        return job

    def start_job(self, job_id: str) -> Job:
        """
        Transitions QUEUED job to RUNNING. Sets started_at timestamp.
        Does not start external processes. Checks cancellation flag.
        """
        job = self._get_job_or_fail(job_id)

        if job.cancellation_requested:
            return self.request_cancellation(job_id, reason="Cancelled prior to worker start")

        job = self._transition_state(
            job=job,
            to_status=JobStatus.RUNNING,
            reason="Worker claimed job for execution",
        )
        job.started_at = utc_now()
        job = self.job_repo.update(job)

        self._record_audit(
            assessment_id=job.assessment_id,
            job_id=job.job_id,
            event_type="JOB_STARTED",
            outcome=AuditOutcome.SUCCESS,
            metadata={"started_at": job.started_at.isoformat()},
        )
        self.session.commit()
        return job

    def mark_job_for_review(self, job_id: str, findings_summary: dict[str, Any] | None = None) -> Job:
        """
        Transitions RUNNING job to REVIEW for operator verification of results.
        """
        job = self._get_job_or_fail(job_id)

        if findings_summary and isinstance(findings_summary, dict):
            current_summary = job.result_summary or {}
            current_summary.update(findings_summary)
            job.result_summary = current_summary

        job = self._transition_state(
            job=job,
            to_status=JobStatus.REVIEW,
            reason="Worker execution completed; awaiting operator finding review",
        )

        self._record_audit(
            assessment_id=job.assessment_id,
            job_id=job.job_id,
            event_type="JOB_MARKED_FOR_REVIEW",
            outcome=AuditOutcome.SUCCESS,
            metadata={"findings_summary": findings_summary},
        )
        self.session.commit()
        return job

    def record_approval(self, job_id: str, approver: str = "operator", notes: str = "") -> Job:
        """
        Records operator sign-off for a job in NEEDS_APPROVAL state and advances to QUEUED.
        """
        job = self._get_job_or_fail(job_id)

        if job.status != JobStatus.NEEDS_APPROVAL:
            raise InvalidStateTransitionError(
                f"Cannot record approval: Job '{job_id}' is in status '{job.status.value}', "
                f"expected '{JobStatus.NEEDS_APPROVAL.value}'."
            )

        job = self._transition_state(
            job=job,
            to_status=JobStatus.QUEUED,
            reason=f"Approved by {approver}: {notes}".strip(),
        )

        self._record_audit(
            assessment_id=job.assessment_id,
            job_id=job.job_id,
            event_type="JOB_APPROVED",
            outcome=AuditOutcome.SUCCESS,
            metadata={"approver": approver, "notes": notes},
        )
        self.session.commit()
        return job

    def complete_job(self, job_id: str, result_summary: dict[str, Any] | None = None) -> Job:
        """
        Transitions RUNNING or REVIEW job to terminal COMPLETED state.
        Sets completed_at timestamp. Cannot be restarted.
        """
        job = self._get_job_or_fail(job_id)

        if job.cancellation_requested:
            return self.request_cancellation(job_id, reason="Job completed with pending cancellation request")

        if result_summary and isinstance(result_summary, dict):
            current_summary = job.result_summary or {}
            current_summary.update(result_summary)
            job.result_summary = current_summary

        job = self._transition_state(
            job=job,
            to_status=JobStatus.COMPLETED,
            reason="Execution successfully finished",
        )
        job.completed_at = utc_now()
        job = self.job_repo.update(job)

        self._record_audit(
            assessment_id=job.assessment_id,
            job_id=job.job_id,
            event_type="JOB_COMPLETED",
            outcome=AuditOutcome.SUCCESS,
            metadata={"completed_at": job.completed_at.isoformat()},
        )
        self.session.commit()
        return job

    def fail_job(self, job_id: str, error_message: str) -> Job:
        """
        Transitions active job to terminal FAILED state.
        Sets error_summary and completed_at timestamp.
        """
        job = self._get_job_or_fail(job_id)

        if job.status == JobStatus.FAILED:
            return job

        job.error_summary = error_message
        job.completed_at = utc_now()

        job = self._transition_state(
            job=job,
            to_status=JobStatus.FAILED,
            reason=f"Failure: {error_message}",
        )

        self._record_audit(
            assessment_id=job.assessment_id,
            job_id=job.job_id,
            event_type="JOB_FAILED",
            outcome=AuditOutcome.FAILURE,
            metadata={"error": error_message},
        )
        self.session.commit()
        return job

    def request_cancellation(self, job_id: str, reason: str = "User requested cancellation") -> Job:
        """
        Requests cooperative cancellation. If job is not yet completed/failed,
        marks cancellation_requested and transitions to terminal CANCELLED state.
        """
        job = self._get_job_or_fail(job_id)

        if job.status == JobStatus.CANCELLED:
            return job

        if job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
            raise InvalidStateTransitionError(
                f"Cannot cancel job '{job_id}' in terminal state '{job.status.value}'."
            )

        job.cancellation_requested = True
        job.cancellation_reason = reason
        job.completed_at = utc_now()

        job = self._transition_state(
            job=job,
            to_status=JobStatus.CANCELLED,
            reason=f"Cancellation: {reason}",
        )

        self._record_audit(
            assessment_id=job.assessment_id,
            job_id=job.job_id,
            event_type="JOB_CANCELLED",
            outcome=AuditOutcome.CANCELLED,
            metadata={"reason": reason},
        )
        self.session.commit()
        return job

    def retry_job(self, job_id: str) -> Job:
        """
        Controlled retry operation for a FAILED job within its max_retries budget.
        Increments retry_count and transitions back to POLICY_CHECK.
        """
        job = self._get_job_or_fail(job_id)

        if job.status != JobStatus.FAILED:
            raise InvalidStateTransitionError(
                f"Cannot retry job '{job_id}' in state '{job.status.value}': only FAILED jobs can be retried."
            )

        if job.retry_count >= job.max_retries:
            raise ValueError(
                f"Retry budget exhausted for job '{job_id}': attempt {job.retry_count} of {job.max_retries} max retries."
            )

        job.retry_count += 1
        job.error_summary = None
        job.completed_at = None

        job = self._transition_state(
            job=job,
            to_status=JobStatus.POLICY_CHECK,
            reason=f"Controlled retry attempt {job.retry_count}/{job.max_retries}",
        )

        self._record_audit(
            assessment_id=job.assessment_id,
            job_id=job.job_id,
            event_type="JOB_RETRIED",
            outcome=AuditOutcome.SUCCESS,
            metadata={"retry_count": job.retry_count, "max_retries": job.max_retries},
        )
        self.session.commit()
        return job

    def get_job(self, job_id: str) -> Job | None:
        """Retrieves a job by ID."""
        return self.job_repo.get(job_id)

    def list_jobs(self, assessment_id: str, status_filter: JobStatus | None = None) -> list[Job]:
        """Lists jobs for an assessment, with optional status filtering."""
        all_jobs = self.job_repo.list_by_assessment(assessment_id)
        if status_filter is not None:
            return [j for j in all_jobs if j.status == status_filter]
        return all_jobs

    # -------------------------------------------------------------------------
    # Internal State Machine Helpers
    # -------------------------------------------------------------------------

    def _get_job_or_fail(self, job_id: str) -> Job:
        job = self.job_repo.get(job_id)
        if not job:
            raise ValueError(f"Job with ID '{job_id}' does not exist.")
        return job

    def _transition_state(self, job: Job, to_status: JobStatus, reason: str | None = None) -> Job:
        """
        Enforces the ALLOWED_TRANSITIONS table.
        Rejects all unlisted transitions without mutating the database record.
        """
        allowed = ALLOWED_TRANSITIONS.get(job.status, set())
        if to_status not in allowed:
            self.session.rollback()
            raise InvalidStateTransitionError(
                f"Illegal job state transition: cannot transition from '{job.status.value}' to '{to_status.value}'. "
                f"Allowed target states: {[s.value for s in allowed]}"
            )

        old_status = job.status
        job.status = to_status
        job.audit_history.append(
            JobAuditEntry(
                from_status=old_status,
                to_status=to_status,
                timestamp=utc_now(),
                reason=reason,
            )
        )
        return self.job_repo.update(job)

    def _record_audit(
        self,
        assessment_id: str,
        job_id: str,
        event_type: str,
        outcome: AuditOutcome,
        metadata: dict[str, Any],
    ) -> None:
        """Helper to append an immutable audit log entry."""
        try:
            event = AuditEvent(
                assessment_id=assessment_id,
                job_id=job_id,
                event_type=event_type,
                actor="job_service",
                outcome=outcome,
                sanitized_metadata=metadata,
                timestamp=datetime.now(UTC),
            )
            self.audit_repo.record(event)
            self.session.flush()
        except Exception as e:
            logger.error(f"Failed to record audit event '{event_type}': {e}")
