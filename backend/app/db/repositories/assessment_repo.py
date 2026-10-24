from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis_common.models import Assessment
from backend.app.db.models import AssessmentModel


class AssessmentRepository:
    """Repository handling persistence and retrieval of assessments."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, assessment: Assessment) -> Assessment:
        model = AssessmentModel.from_domain(assessment)
        self.session.add(model)
        self.session.flush()
        return model.to_domain()

    def get(self, assessment_id: str) -> Assessment | None:
        model = self.session.get(AssessmentModel, assessment_id)
        if not model:
            return None
        return model.to_domain()

    def update(self, assessment: Assessment) -> Assessment:
        model = self.session.get(AssessmentModel, assessment.assessment_id)
        if not model:
            raise ValueError(f"Assessment with ID {assessment.assessment_id} not found.")

        updated_model = AssessmentModel.from_domain(assessment)
        for attr in [
            "name",
            "description",
            "organization_name",
            "authorized_by",
            "owner",
            "authorization_reference",
            "authorization_acknowledged",
            "scope_rules_json",
            "scope_json",
            "lifecycle_status",
            "max_concurrency",
            "max_requests_per_minute",
            "permitted_profiles_json",
            "updated_at",
            "expires_at",
            "completed_at",
        ]:
            setattr(model, attr, getattr(updated_model, attr))

        self.session.flush()
        return model.to_domain()

    def list_all(self, limit: int = 100, offset: int = 0) -> list[Assessment]:
        stmt = (
            select(AssessmentModel)
            .order_by(AssessmentModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        models = self.session.scalars(stmt).all()
        return [m.to_domain() for m in models]

    def delete(self, assessment_id: str) -> bool:
        model = self.session.get(AssessmentModel, assessment_id)
        if not model:
            return False
        self.session.delete(model)
        self.session.flush()
        return True
