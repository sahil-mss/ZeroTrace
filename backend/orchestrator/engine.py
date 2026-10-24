import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from backend.policy.scope_validator import ScopeValidator
from backend.storage.database import DatabaseManager
from backend.storage.evidence_store import EvidenceStore
from schemas.enums import AssessmentStatus, JobStatus, TestPermissionLevel
from schemas.models import Assessment, Job, JobAuditEntry, utc_now

logger = logging.getLogger("aegispt.orchestrator")


class OrchestratorEngine:
    """
    Deterministic Job Orchestrator & Workflow State Machine.
    Enforces scope checks, permission checks, timeouts, concurrency limits,
    and immediate cancellation controls.
    """

    def __init__(
        self,
        db: DatabaseManager,
        evidence_store: EvidenceStore,
        max_concurrency: int = 3,
    ):
        self.db = db
        self.evidence_store = evidence_store
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.active_tasks: dict[str, asyncio.Task] = {}
        self.registered_task_handlers: dict[
            str, Callable[[Job, Assessment], Coroutine[Any, Any, dict[str, Any]]]
        ] = {}

    def register_task_handler(
        self,
        task_type: str,
        handler: Callable[[Job, Assessment], Coroutine[Any, Any, dict[str, Any]]],
    ):
        """Registers a runner for a given task type (e.g. 'OSINT_DNS', 'NMAP_SCAN', etc.)."""
        self.registered_task_handlers[task_type] = handler

    def transition_job_status(
        self, job: Job, to_status: JobStatus, reason: str | None = None
    ) -> Job:
        """Atomic state machine transition with audit history recording."""
        entry = JobAuditEntry(
            from_status=job.status,
            to_status=to_status,
            timestamp=utc_now(),
            reason=reason,
        )
        job.audit_history.append(entry)
        job.status = to_status

        if to_status == JobStatus.RUNNING and not job.started_at:
            job.started_at = utc_now()
        elif to_status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
            job.completed_at = utc_now()

        saved = self.db.save_job(job)
        self.db.record_audit_event(
            assessment_id=job.assessment_id,
            event_type=f"JOB_STATUS_{to_status.value}",
            actor="orchestrator",
            details={"job_id": job.job_id, "task_type": job.task_type, "reason": reason},
        )
        return saved

    def enqueue_job(
        self,
        assessment_id: str,
        task_type: str,
        target_input: str,
        permission_level: TestPermissionLevel = TestPermissionLevel.PASSIVE_ONLY,
        timeout_seconds: int = 180,
    ) -> Job:
        """
        Creates and enqueues a new Job after verifying assessment state and scope policy.
        """
        assessment = self.db.get_assessment(assessment_id)
        if not assessment:
            raise ValueError(f"Assessment '{assessment_id}' does not exist.")

        if assessment.status not in (AssessmentStatus.APPROVED, AssessmentStatus.ACTIVE):
            raise ValueError(
                f"Cannot enqueue job for assessment in status '{assessment.status.value}'. Must be APPROVED or ACTIVE."
            )

        job = Job(
            assessment_id=assessment_id,
            task_type=task_type,
            target_input=target_input,
            status=JobStatus.CREATED,
            permission_level=permission_level,
            timeout_seconds=timeout_seconds,
        )
        self.transition_job_status(job, JobStatus.CREATED, "Job instantiated")

        # 1. State: POLICY_CHECK
        self.transition_job_status(
            job, JobStatus.POLICY_CHECK, "Verifying target scope and permissions"
        )

        # Check target against assessment scope
        in_scope, scope_reason, _ = ScopeValidator.is_in_scope(target_input, assessment.scope)
        if not in_scope:
            job.error_message = f"Scope violation: {scope_reason}"
            self.transition_job_status(job, JobStatus.FAILED, f"Scope check failed: {scope_reason}")
            self.db.record_audit_event(
                assessment_id=assessment_id,
                event_type="SCOPE_CHECK_REJECTED",
                details={"target": target_input, "reason": scope_reason},
            )
            return job

        # Check test permission level
        perm_ok, perm_reason = ScopeValidator.check_permission(
            permission_level, assessment.scope.allowed_permission_level
        )
        if not perm_ok:
            job.error_message = f"Permission violation: {perm_reason}"
            self.transition_job_status(job, JobStatus.NEEDS_APPROVAL, perm_reason)
            return job

        # Passed policy checks -> Enqueue
        self.transition_job_status(
            job, JobStatus.QUEUED, "Passed policy checks; queued for execution"
        )
        return job

    async def execute_job(self, job_id: str) -> Job:
        """
        Executes a queued job with concurrency semaphore, timeout enforcement,
        and cancellation handling.
        """
        job = self.db.get_job(job_id)
        if not job:
            raise ValueError(f"Job '{job_id}' not found.")

        if job.status != JobStatus.QUEUED:
            logger.warning(f"Job {job_id} is in status {job.status.value}, skipping execution.")
            return job

        assessment = self.db.get_assessment(job.assessment_id)
        if not assessment or assessment.status == AssessmentStatus.CANCELLED:
            self.transition_job_status(job, JobStatus.CANCELLED, "Assessment was cancelled")
            return job

        handler = self.registered_task_handlers.get(job.task_type)
        if not handler:
            job.error_message = f"No handler registered for task type: '{job.task_type}'"
            self.transition_job_status(job, JobStatus.FAILED, "Unregistered task type")
            return job

        async with self.semaphore:
            current_task = asyncio.current_task()
            if current_task:
                self.active_tasks[job.job_id] = current_task

            self.transition_job_status(job, JobStatus.RUNNING, "Worker started task execution")

            try:
                # Run with timeout
                result = await asyncio.wait_for(
                    handler(job, assessment),
                    timeout=float(job.timeout_seconds),
                )
                job.result_summary = result
                self.transition_job_status(
                    job, JobStatus.REVIEW, "Execution completed; reviewing results"
                )
                self.transition_job_status(job, JobStatus.COMPLETED, "Job finished successfully")
            except asyncio.CancelledError:
                job.error_message = "Job execution was cancelled by user or system"
                self.transition_job_status(job, JobStatus.CANCELLED, "Execution cancelled")
                raise
            except TimeoutError:
                job.error_message = f"Job timed out after {job.timeout_seconds} seconds"
                self.transition_job_status(job, JobStatus.FAILED, "Timeout exceeded")
            except Exception as e:
                logger.exception(f"Unhandled error in job {job.job_id}: {str(e)}")
                job.error_message = f"Task failure: {str(e)}"
                self.transition_job_status(job, JobStatus.FAILED, f"Exception: {str(e)}")
            finally:
                self.active_tasks.pop(job.job_id, None)

        return job

    def cancel_job(self, job_id: str, reason: str = "User requested cancellation") -> Job:
        """Immediately stops a running or queued job."""
        job = self.db.get_job(job_id)
        if not job:
            raise ValueError(f"Job '{job_id}' not found.")

        if job.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
            return job

        # Cancel running task if active
        task = self.active_tasks.get(job_id)
        if task and not task.done():
            task.cancel()

        self.transition_job_status(job, JobStatus.CANCELLED, reason)
        return job

    def cancel_assessment(
        self, assessment_id: str, reason: str = "User cancelled assessment"
    ) -> Assessment:
        """Immediately cancels an entire assessment and all its active/queued jobs."""
        assessment = self.db.get_assessment(assessment_id)
        if not assessment:
            raise ValueError(f"Assessment '{assessment_id}' not found.")

        assessment.status = AssessmentStatus.CANCELLED
        assessment.completed_at = utc_now()
        self.db.save_assessment(assessment)

        # Cancel all jobs under this assessment
        jobs = self.db.list_jobs(assessment_id)
        for j in jobs:
            if j.status in (
                JobStatus.CREATED,
                JobStatus.POLICY_CHECK,
                JobStatus.QUEUED,
                JobStatus.RUNNING,
            ):
                self.cancel_job(j.job_id, reason=f"Assessment cancelled: {reason}")

        self.db.record_audit_event(
            assessment_id=assessment_id,
            event_type="ASSESSMENT_CANCELLED",
            details={"reason": reason},
        )
        return assessment
