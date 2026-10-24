
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis_common.enums import JobStatus
from aegis_common.models import Job, JobAuditEntry
from aegis_common.utils import utc_now
from backend.app.db.models import AssessmentModel, JobModel


class JobRepository:
    """Repository handling execution state, lifecycle tracking, and queries for worker jobs."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, job: Job) -> Job:
        # Verify assessment exists
        assessment = self.session.get(AssessmentModel, job.assessment_id)
        if not assessment:
            raise ValueError(f"Cannot enqueue job: Assessment {job.assessment_id} does not exist.")

        model = JobModel.from_domain(job)
        self.session.add(model)
        self.session.flush()
        return model.to_domain()

    def get(self, job_id: str) -> Job | None:
        model = self.session.get(JobModel, job_id)
        if not model:
            return None
        return model.to_domain()

    def update(self, job: Job) -> Job:
        model = self.session.get(JobModel, job.job_id)
        if not model:
            raise ValueError(f"Job with ID {job.job_id} not found.")

        updated = JobModel.from_domain(job)
        for attr in [
            "status",
            "requested_targets_json",
            "target_input",
            "permission_level",
            "timeout_seconds",
            "max_retries",
            "retry_count",
            "cancellation_requested",
            "cancellation_reason",
            "error_message",
            "result_summary_json",
            "audit_history_json",
            "resource_budget_json",
            "started_at",
            "completed_at",
        ]:
            setattr(model, attr, getattr(updated, attr))

        self.session.flush()
        return model.to_domain()

    def update_status(
        self,
        job_id: str,
        new_status: JobStatus,
        reason: str | None = None,
        error_message: str | None = None,
    ) -> Job:
        """Atomic transition helper that also records the transition into job audit history."""
        job = self.get(job_id)
        if not job:
            raise ValueError(f"Job with ID {job_id} not found.")

        old_status = job.status
        job.status = new_status
        if error_message:
            job.error_summary = error_message

        if new_status == JobStatus.RUNNING and not job.started_at:
            job.started_at = utc_now()
        elif new_status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED):
            job.completed_at = utc_now()

        job.audit_history.append(
            JobAuditEntry(
                from_status=old_status,
                to_status=new_status,
                timestamp=utc_now(),
                reason=reason,
            )
        )
        return self.update(job)

    def list_by_assessment(
        self,
        assessment_id: str,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Job]:
        stmt = (
            select(JobModel)
            .where(JobModel.assessment_id == assessment_id)
            .order_by(JobModel.created_at.desc())
        )
        if offset is not None:
            stmt = stmt.offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        models = self.session.scalars(stmt).all()
        return [m.to_domain() for m in models]


    def get_by_idempotency_key(self, assessment_id: str, idempotency_key: str) -> Job | None:
        """Finds a job within an assessment by caller idempotency key."""
        stmt = select(JobModel).where(
            JobModel.assessment_id == assessment_id,
            JobModel.result_summary_json.like(f'%"idempotency_key": "{idempotency_key}"%'),
        )
        model = self.session.scalars(stmt).first()
        if not model:
            return None
        return model.to_domain()
