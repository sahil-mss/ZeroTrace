
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis_common.models import Finding
from backend.app.db.models import AssessmentModel, AssetModel, EvidenceModel, FindingModel


class FindingRepository:
    """Repository handling persistence, validation, and retrieval of security findings."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, finding: Finding) -> Finding:
        # 1. Verify assessment exists
        assessment = self.session.get(AssessmentModel, finding.assessment_id)
        if not assessment:
            raise ValueError(f"Cannot record finding: Assessment {finding.assessment_id} does not exist.")

        # 2. Verify asset exists and belongs to the same assessment
        asset = self.session.get(AssetModel, finding.asset_id)
        if not asset:
            raise ValueError(f"Cannot record finding: Asset {finding.asset_id} does not exist.")
        if asset.assessment_id != finding.assessment_id:
            raise ValueError(
                f"Finding integrity violation: Asset {finding.asset_id} belongs to assessment "
                f"{asset.assessment_id}, but finding was reported for assessment {finding.assessment_id}."
            )

        # 3. Verify all evidence references exist and belong to this assessment
        for eid in finding.evidence_ids:
            ev = self.session.get(EvidenceModel, eid)
            if not ev:
                raise ValueError(
                    f"Evidence provenance violation: Referenced evidence '{eid}' does not exist."
                )
            if ev.assessment_id != finding.assessment_id:
                raise ValueError(
                    f"Evidence cross-assessment violation: Referenced evidence '{eid}' belongs to "
                    f"assessment '{ev.assessment_id}', not '{finding.assessment_id}'."
                )

        model = FindingModel.from_domain(finding)
        self.session.add(model)
        self.session.flush()
        return model.to_domain()

    def get(self, finding_id: str) -> Finding | None:
        model = self.session.get(FindingModel, finding_id)
        if not model:
            return None
        return model.to_domain()

    def update(self, finding: Finding) -> Finding:
        model = self.session.get(FindingModel, finding.finding_id)
        if not model:
            raise ValueError(f"Finding with ID {finding.finding_id} not found.")

        updated = FindingModel.from_domain(finding)
        for attr in [
            "title",
            "description",
            "cwe",
            "cve",
            "severity",
            "confidence",
            "verification_status",
            "evidence_ids_json",
            "root_cause",
            "remediation",
            "source_tool",
            "tool_version",
            "last_seen",
        ]:
            setattr(model, attr, getattr(updated, attr))

        self.session.flush()
        return model.to_domain()

    def list_by_assessment(
        self,
        assessment_id: str,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Finding]:
        stmt = (
            select(FindingModel)
            .where(FindingModel.assessment_id == assessment_id)
            .order_by(FindingModel.first_seen.asc())
        )
        if offset is not None:
            stmt = stmt.offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        models = self.session.scalars(stmt).all()
        return [m.to_domain() for m in models]

