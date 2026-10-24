
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis_common.models import Evidence
from backend.app.db.models import AssessmentModel, AssetModel, EvidenceModel


class EvidenceRepository:
    """Repository handling persistence and verification of evidence provenance records."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, evidence: Evidence) -> Evidence:
        # 1. Verify assessment exists
        assessment = self.session.get(AssessmentModel, evidence.assessment_id)
        if not assessment:
            raise ValueError(f"Cannot store evidence: Assessment {evidence.assessment_id} does not exist.")

        # 2. If asset_id is provided, verify asset exists and belongs to the SAME assessment
        if evidence.asset_id:
            asset = self.session.get(AssetModel, evidence.asset_id)
            if not asset:
                raise ValueError(f"Cannot store evidence: Asset {evidence.asset_id} does not exist.")
            if asset.assessment_id != evidence.assessment_id:
                raise ValueError(
                    f"Evidence integrity violation: Asset {evidence.asset_id} belongs to assessment "
                    f"{asset.assessment_id}, but evidence was submitted for assessment {evidence.assessment_id}."
                )

        model = EvidenceModel.from_domain(evidence)
        self.session.add(model)
        self.session.flush()
        return model.to_domain()

    def get(self, evidence_id: str) -> Evidence | None:
        model = self.session.get(EvidenceModel, evidence_id)
        if not model:
            return None
        return model.to_domain()

    def get_by_hash(self, assessment_id: str, content_hash: str) -> Evidence | None:
        stmt = select(EvidenceModel).where(
            EvidenceModel.assessment_id == assessment_id,
            EvidenceModel.content_hash == content_hash,
        )
        model = self.session.scalars(stmt).first()
        if not model:
            return None
        return model.to_domain()

    def list_by_assessment(self, assessment_id: str) -> list[Evidence]:
        stmt = (
            select(EvidenceModel)
            .where(EvidenceModel.assessment_id == assessment_id)
            .order_by(EvidenceModel.collected_at.asc())
        )
        models = self.session.scalars(stmt).all()
        return [m.to_domain() for m in models]
