
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis_common.models import AuditEvent
from backend.app.db.models import AssessmentModel, AuditEventModel, JobModel


class AuditRepository:
    """
    Repository handling append-only audit trail logging.
    Audit records are permanent, immutable, and cannot be updated or overwritten.
    """

    def __init__(self, session: Session):
        self.session = session

    def record(self, event: AuditEvent) -> AuditEvent:
        # 1. Check if an event with this ID already exists - audit events CANNOT be overwritten
        existing = self.session.get(AuditEventModel, event.event_id)
        if existing:
            raise ValueError(
                f"Audit trail immutability violation: Event '{event.event_id}' already exists and cannot be modified."
            )

        # 2. Verify assessment exists
        assessment = self.session.get(AssessmentModel, event.assessment_id)
        if not assessment:
            raise ValueError(f"Cannot record audit event: Assessment '{event.assessment_id}' does not exist.")

        # 3. If job_id is provided, verify job exists and belongs to the same assessment
        if event.job_id:
            job = self.session.get(JobModel, event.job_id)
            if not job:
                raise ValueError(f"Cannot record audit event: Job '{event.job_id}' does not exist.")
            if job.assessment_id != event.assessment_id:
                raise ValueError(
                    f"Audit integrity violation: Job '{event.job_id}' belongs to assessment '{job.assessment_id}', "
                    f"not event assessment '{event.assessment_id}'."
                )

        model = AuditEventModel.from_domain(event)
        self.session.add(model)
        self.session.flush()
        return model.to_domain()

    def get(self, event_id: str) -> AuditEvent | None:
        model = self.session.get(AuditEventModel, event_id)
        if not model:
            return None
        return model.to_domain()

    def list_by_assessment(self, assessment_id: str) -> list[AuditEvent]:
        stmt = (
            select(AuditEventModel)
            .where(AuditEventModel.assessment_id == assessment_id)
            .order_by(AuditEventModel.timestamp.asc())
        )
        models = self.session.scalars(stmt).all()
        return [m.to_domain() for m in models]
