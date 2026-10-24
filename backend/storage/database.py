from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from aegis_common.models import (
    Assessment,
    Asset,
    AuditEvent,
    Evidence,
    Finding,
    Job,
)
from backend.app.core.config import settings
from backend.app.db.base import Base
from backend.app.db.models import (
    AssessmentModel,
    AssetModel,
    AuditEventModel,
    EvidenceModel,
    FindingModel,
    JobModel,
)
from backend.app.db.repositories import (
    AssessmentRepository,
    AssetRepository,
    AuditRepository,
    EvidenceRepository,
    FindingRepository,
    JobRepository,
)
from backend.app.db.session import get_engine, get_session_factory

__all__ = [
    "Base",
    "AssessmentModel",
    "AssetModel",
    "EvidenceModel",
    "FindingModel",
    "JobModel",
    "AuditEventModel",
    "DatabaseManager",
]


class DatabaseManager:
    """
    Central interface for database interactions across AegisPT.
    Maintains backward compatibility while leveraging SQLAlchemy 2 models and repositories.
    """

    def __init__(self, db_url: str | None = None):
        url = db_url or settings.DATABASE_URL
        self.engine = get_engine(url)
        # Create all tables if not exist (e.g. for development/test runs)
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = get_session_factory(self.engine)

    def get_session(self) -> Session:
        return self.SessionLocal()

    # --- Assessment CRUD ---
    def save_assessment(self, assessment: Assessment) -> Assessment:
        with self.get_session() as session:
            repo = AssessmentRepository(session)
            existing = repo.get(assessment.assessment_id)
            if existing:
                res = repo.update(assessment)
            else:
                res = repo.create(assessment)
            session.commit()
            return res

    def get_assessment(self, assessment_id: str) -> Assessment | None:
        with self.get_session() as session:
            repo = AssessmentRepository(session)
            return repo.get(assessment_id)

    def list_assessments(self) -> list[Assessment]:
        with self.get_session() as session:
            repo = AssessmentRepository(session)
            return repo.list_all()

    # --- Asset CRUD ---
    def save_asset(self, asset: Asset) -> Asset:
        with self.get_session() as session:
            repo = AssetRepository(session)
            res = repo.upsert(asset)
            session.commit()
            return res

    def get_asset_by_value(self, assessment_id: str, value: str) -> Asset | None:
        with self.get_session() as session:
            repo = AssetRepository(session)
            return repo.get_by_value(assessment_id, value)

    def list_assets(self, assessment_id: str) -> list[Asset]:
        with self.get_session() as session:
            repo = AssetRepository(session)
            return repo.list_by_assessment(assessment_id)

    # --- Evidence CRUD ---
    def save_evidence(self, evidence: Evidence) -> Evidence:
        with self.get_session() as session:
            repo = EvidenceRepository(session)
            existing = repo.get(evidence.evidence_id)
            if existing:
                return existing
            res = repo.create(evidence)
            session.commit()
            return res

    def list_evidence(self, assessment_id: str) -> list[Evidence]:
        with self.get_session() as session:
            repo = EvidenceRepository(session)
            return repo.list_by_assessment(assessment_id)

    # --- Findings CRUD ---
    def save_finding(self, finding: Finding) -> Finding:
        with self.get_session() as session:
            repo = FindingRepository(session)
            existing = repo.get(finding.finding_id)
            if existing:
                res = repo.update(finding)
            else:
                res = repo.create(finding)
            session.commit()
            return res

    def list_findings(self, assessment_id: str) -> list[Finding]:
        with self.get_session() as session:
            repo = FindingRepository(session)
            return repo.list_by_assessment(assessment_id)

    # --- Job CRUD ---
    def save_job(self, job: Job) -> Job:
        with self.get_session() as session:
            repo = JobRepository(session)
            existing = repo.get(job.job_id)
            if existing:
                res = repo.update(job)
            else:
                res = repo.create(job)
            session.commit()
            return res

    def get_job(self, job_id: str) -> Job | None:
        with self.get_session() as session:
            repo = JobRepository(session)
            return repo.get(job_id)

    def list_jobs(self, assessment_id: str) -> list[Job]:
        with self.get_session() as session:
            repo = JobRepository(session)
            return repo.list_by_assessment(assessment_id)

    # --- Audit Trail ---
    def record_audit_event(
        self,
        assessment_id: str,
        event_type: str,
        actor: str = "system",
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            assessment_id=assessment_id,
            event_type=event_type,
            actor=actor,
            sanitized_metadata=details or {},
            timestamp=datetime.now(UTC),
        )
        with self.get_session() as session:
            repo = AuditRepository(session)
            res = repo.record(event)
            session.commit()
            return res

    def list_audit_events(self, assessment_id: str) -> list[AuditEvent]:
        with self.get_session() as session:
            repo = AuditRepository(session)
            return repo.list_by_assessment(assessment_id)
