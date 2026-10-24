import json
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from aegis_common.enums import (
    AssessmentStatus,
    AssetType,
    AuditOutcome,
    DataClassification,
    EvidenceSourceType,
    JobStatus,
    ScopeStatus,
    Severity,
    TestPermissionLevel,
    VerificationStatus,
)
from aegis_common.models import (
    Assessment,
    Asset,
    AuditEvent,
    Evidence,
    Finding,
    Job,
    JobAuditEntry,
    ResourceBudget,
    ScopePolicy,
    ScopeRule,
)
from backend.app.db.base import Base


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AssessmentModel(Base):
    """
    SQLAlchemy ORM model for authorized assessments.
    Maps to canonical `Assessment` domain contract.
    """
    __tablename__ = "assessments"

    assessment_id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True, default="")
    organization_name = Column(String(255), nullable=False)
    authorized_by = Column(String(255), nullable=False)
    owner = Column(String(255), nullable=False, default="security_team")
    authorization_reference = Column(String(255), nullable=False, default="AUTH-PENDING")
    authorization_acknowledged = Column(Boolean, nullable=False, default=False)
    scope_rules_json = Column(Text, nullable=False, default="[]")
    scope_json = Column(Text, nullable=False, default="{}")
    lifecycle_status = Column(String(32), nullable=False, default=AssessmentStatus.PENDING_APPROVAL.value, index=True)
    max_concurrency = Column(Integer, nullable=False, default=3)
    max_requests_per_minute = Column(Integer, nullable=False, default=60)
    permitted_profiles_json = Column(Text, nullable=False, default='["PASSIVE_ONLY"]')
    schema_version = Column(String(16), nullable=False, default="1.0")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    assets = relationship("AssetModel", back_populates="assessment", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="assessment", cascade="all, delete-orphan")
    jobs = relationship("JobModel", back_populates="assessment", cascade="all, delete-orphan")
    evidence = relationship("EvidenceModel", back_populates="assessment", cascade="all, delete-orphan")
    events = relationship("AuditEventModel", back_populates="assessment", cascade="all, delete-orphan")

    @property
    def title(self) -> str:
        return self.name

    @title.setter
    def title(self, value: str) -> None:
        self.name = value

    @property
    def status(self) -> str:
        return self.lifecycle_status

    @status.setter
    def status(self, value: str) -> None:
        self.lifecycle_status = value

    def to_domain(self) -> Assessment:
        scope_rules_data = json.loads(self.scope_rules_json) if self.scope_rules_json else []
        scope_rules = [ScopeRule.model_validate(r) for r in scope_rules_data]
        scope_data = json.loads(self.scope_json) if self.scope_json and self.scope_json != "{}" else None
        scope = ScopePolicy.model_validate(scope_data) if scope_data else None
        profiles_data = json.loads(self.permitted_profiles_json) if self.permitted_profiles_json else ["PASSIVE_ONLY"]
        permitted_profiles = [TestPermissionLevel(p) for p in profiles_data]

        return Assessment(
            assessment_id=self.assessment_id,
            name=self.name,
            description=self.description,
            organization_name=self.organization_name,
            authorized_by=self.authorized_by,
            owner=self.owner,
            authorization_reference=self.authorization_reference,
            authorization_acknowledged=self.authorization_acknowledged,
            scope_rules=scope_rules,
            scope=scope,
            lifecycle_status=AssessmentStatus(self.lifecycle_status),
            max_concurrency=self.max_concurrency,
            max_requests_per_minute=self.max_requests_per_minute,
            permitted_profiles=permitted_profiles,
            schema_version=self.schema_version,
            created_at=self.created_at.replace(tzinfo=UTC) if self.created_at and not self.created_at.tzinfo else self.created_at,
            updated_at=self.updated_at.replace(tzinfo=UTC) if self.updated_at and not self.updated_at.tzinfo else self.updated_at,
            expires_at=self.expires_at.replace(tzinfo=UTC) if self.expires_at and not self.expires_at.tzinfo else self.expires_at,
            completed_at=self.completed_at.replace(tzinfo=UTC) if self.completed_at and not self.completed_at.tzinfo else self.completed_at,
        )

    @classmethod
    def from_domain(cls, a: Assessment) -> "AssessmentModel":
        scope_rules_data = [r.model_dump(mode="json") for r in a.scope_rules]
        scope_data = a.scope.model_dump(mode="json") if a.scope else {}
        profiles_data = [p.value for p in a.permitted_profiles]

        return cls(
            assessment_id=a.assessment_id,
            name=a.name,
            description=a.description or "",
            organization_name=a.organization_name,
            authorized_by=a.authorized_by,
            owner=a.owner,
            authorization_reference=a.authorization_reference,
            authorization_acknowledged=a.authorization_acknowledged,
            scope_rules_json=json.dumps(scope_rules_data),
            scope_json=json.dumps(scope_data),
            lifecycle_status=a.lifecycle_status.value,
            max_concurrency=a.max_concurrency,
            max_requests_per_minute=a.max_requests_per_minute,
            permitted_profiles_json=json.dumps(profiles_data),
            schema_version=a.schema_version,
            created_at=a.created_at,
            updated_at=a.updated_at,
            expires_at=a.expires_at,
            completed_at=a.completed_at,
        )


class AssetModel(Base):
    """
    SQLAlchemy ORM model for target assets.
    Maps to canonical `Asset` domain contract.
    """
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("assessment_id", "normalized_value", name="uq_asset_assessment_value"),
        Index("ix_assets_assessment_normalized", "assessment_id", "normalized_value"),
    )

    asset_id = Column(String(64), primary_key=True)
    assessment_id = Column(String(64), ForeignKey("assessments.assessment_id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type = Column(String(32), nullable=False)
    normalized_value = Column(String(512), nullable=False, index=True)
    scope_classification = Column(String(32), nullable=False, default=ScopeStatus.PENDING_REVIEW.value)
    confidence = Column(Float, nullable=False, default=1.0)
    source_evidence_ids_json = Column(Text, nullable=False, default="[]")
    is_inferred = Column(Boolean, nullable=False, default=False)
    directly_observed = Column(Boolean, nullable=False, default=True)
    relationships_json = Column(Text, nullable=False, default="{}")
    metadata_json = Column(Text, nullable=False, default="{}")
    first_seen = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    schema_version = Column(String(16), nullable=False, default="1.0")

    # Relationships
    assessment = relationship("AssessmentModel", back_populates="assets")
    findings = relationship("FindingModel", back_populates="asset", cascade="all, delete-orphan")
    evidence = relationship("EvidenceModel", back_populates="asset")

    @property
    def value(self) -> str:
        return self.normalized_value

    @value.setter
    def value(self, val: str) -> None:
        self.normalized_value = val

    @property
    def scope_status(self) -> str:
        return self.scope_classification

    @scope_status.setter
    def scope_status(self, val: str) -> None:
        self.scope_classification = val

    @property
    def first_observed(self) -> datetime:
        return self.first_seen

    @property
    def last_observed(self) -> datetime:
        return self.last_seen

    @last_observed.setter
    def last_observed(self, val: datetime) -> None:
        self.last_seen = val

    def to_domain(self) -> Asset:
        return Asset(
            asset_id=self.asset_id,
            assessment_id=self.assessment_id,
            asset_type=AssetType(self.asset_type),
            normalized_value=self.normalized_value,
            scope_classification=ScopeStatus(self.scope_classification),
            confidence=self.confidence,
            source_evidence_ids=json.loads(self.source_evidence_ids_json) if self.source_evidence_ids_json else [],
            is_inferred=self.is_inferred,
            directly_observed=self.directly_observed,
            relationships=json.loads(self.relationships_json) if self.relationships_json else {},
            metadata=json.loads(self.metadata_json) if self.metadata_json else {},
            first_seen=self.first_seen.replace(tzinfo=UTC) if self.first_seen and not self.first_seen.tzinfo else self.first_seen,
            last_seen=self.last_seen.replace(tzinfo=UTC) if self.last_seen and not self.last_seen.tzinfo else self.last_seen,
            schema_version=self.schema_version,
        )

    @classmethod
    def from_domain(cls, asset: Asset) -> "AssetModel":
        return cls(
            asset_id=asset.asset_id,
            assessment_id=asset.assessment_id,
            asset_type=asset.asset_type.value,
            normalized_value=asset.normalized_value,
            scope_classification=asset.scope_classification.value,
            confidence=asset.confidence,
            source_evidence_ids_json=json.dumps(asset.source_evidence_ids),
            is_inferred=asset.is_inferred,
            directly_observed=asset.directly_observed,
            relationships_json=json.dumps(asset.relationships),
            metadata_json=json.dumps(asset.metadata),
            first_seen=asset.first_seen,
            last_seen=asset.last_seen,
            schema_version=asset.schema_version,
        )


class EvidenceModel(Base):
    """
    SQLAlchemy ORM model for immutable evidence provenance records.
    Maps to canonical `Evidence` domain contract.
    """
    __tablename__ = "evidence"

    evidence_id = Column(String(64), primary_key=True, index=True)
    assessment_id = Column(String(64), ForeignKey("assessments.assessment_id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(64), ForeignKey("assets.asset_id", ondelete="SET NULL"), nullable=True, index=True)
    source_name = Column(String(128), nullable=False)
    source_type = Column(String(64), nullable=False)
    collection_method = Column(String(64), nullable=False, default="AUTOMATED_PROBE")
    collected_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    content_hash = Column(String(64), nullable=False, index=True)
    raw_payload_ref = Column(String(512), nullable=True)
    sanitized_excerpt = Column(Text, nullable=True)
    data_json = Column(Text, nullable=False, default="{}")
    data_classification = Column(String(32), nullable=False, default=DataClassification.INTERNAL.value)
    tool_version = Column(String(32), nullable=True, default="1.0")
    metadata_json = Column(Text, nullable=False, default="{}")
    schema_version = Column(String(16), nullable=False, default="1.0")

    # Relationships
    assessment = relationship("AssessmentModel", back_populates="evidence")
    asset = relationship("AssetModel", back_populates="evidence")

    @property
    def tool_name(self) -> str:
        return self.source_name

    @tool_name.setter
    def tool_name(self, val: str) -> None:
        self.source_name = val

    @property
    def hash_sha256(self) -> str:
        return self.content_hash

    @hash_sha256.setter
    def hash_sha256(self, val: str) -> None:
        self.content_hash = val

    def to_domain(self) -> Evidence:
        return Evidence(
            evidence_id=self.evidence_id,
            assessment_id=self.assessment_id,
            asset_id=self.asset_id,
            source_name=self.source_name,
            source_type=EvidenceSourceType(self.source_type),
            collection_method=self.collection_method,
            collected_at=self.collected_at.replace(tzinfo=UTC) if self.collected_at and not self.collected_at.tzinfo else self.collected_at,
            content_hash=self.content_hash,
            raw_payload_ref=self.raw_payload_ref,
            sanitized_excerpt=self.sanitized_excerpt,
            data=json.loads(self.data_json) if self.data_json else {},
            data_classification=DataClassification(self.data_classification),
            tool_version=self.tool_version,
            metadata=json.loads(self.metadata_json) if self.metadata_json else {},
            schema_version=self.schema_version,
        )

    @classmethod
    def from_domain(cls, e: Evidence) -> "EvidenceModel":
        return cls(
            evidence_id=e.evidence_id,
            assessment_id=e.assessment_id,
            asset_id=e.asset_id,
            source_name=e.source_name,
            source_type=e.source_type.value,
            collection_method=e.collection_method,
            collected_at=e.collected_at,
            content_hash=e.content_hash,
            raw_payload_ref=e.raw_payload_ref,
            sanitized_excerpt=e.sanitized_excerpt,
            data_json=json.dumps(e.data),
            data_classification=e.data_classification.value,
            tool_version=e.tool_version,
            metadata_json=json.dumps(e.metadata),
            schema_version=e.schema_version,
        )


class FindingModel(Base):
    """
    SQLAlchemy ORM model for security findings and vulnerabilities.
    Maps to canonical `Finding` domain contract.
    """
    __tablename__ = "findings"

    finding_id = Column(String(64), primary_key=True)
    assessment_id = Column(String(64), ForeignKey("assessments.assessment_id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(64), ForeignKey("assets.asset_id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    cwe = Column(String(64), nullable=True)
    cve = Column(String(64), nullable=True)
    severity = Column(String(32), nullable=False, default=Severity.MEDIUM.value, index=True)
    confidence = Column(Float, nullable=False, default=0.8)
    verification_status = Column(String(32), nullable=False, default=VerificationStatus.UNVERIFIED.value, index=True)
    evidence_ids_json = Column(Text, nullable=False, default="[]")
    root_cause = Column(Text, nullable=True)
    remediation = Column(Text, nullable=False)
    source_tool = Column(String(128), nullable=False)
    tool_version = Column(String(32), nullable=True, default="1.0")
    first_seen = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    last_seen = Column(DateTime(timezone=True), nullable=False, default=_utc_now)
    schema_version = Column(String(16), nullable=False, default="1.0")

    # Relationships
    assessment = relationship("AssessmentModel", back_populates="findings")
    asset = relationship("AssetModel", back_populates="findings")

    @property
    def tool_name(self) -> str:
        return self.source_tool

    @tool_name.setter
    def tool_name(self, val: str) -> None:
        self.source_tool = val

    def to_domain(self) -> Finding:
        return Finding(
            finding_id=self.finding_id,
            assessment_id=self.assessment_id,
            asset_id=self.asset_id,
            title=self.title,
            description=self.description,
            cwe=self.cwe,
            cve=self.cve,
            severity=Severity(self.severity),
            confidence=self.confidence,
            verification_status=VerificationStatus(self.verification_status),
            evidence_ids=json.loads(self.evidence_ids_json) if self.evidence_ids_json else [],
            root_cause=self.root_cause,
            remediation=self.remediation,
            source_tool=self.source_tool,
            tool_version=self.tool_version,
            first_seen=self.first_seen.replace(tzinfo=UTC) if self.first_seen and not self.first_seen.tzinfo else self.first_seen,
            last_seen=self.last_seen.replace(tzinfo=UTC) if self.last_seen and not self.last_seen.tzinfo else self.last_seen,
            schema_version=self.schema_version,
        )

    @classmethod
    def from_domain(cls, f: Finding) -> "FindingModel":
        return cls(
            finding_id=f.finding_id,
            assessment_id=f.assessment_id,
            asset_id=f.asset_id,
            title=f.title,
            description=f.description,
            cwe=f.cwe,
            cve=f.cve,
            severity=f.severity.value,
            confidence=f.confidence,
            verification_status=f.verification_status.value,
            evidence_ids_json=json.dumps(f.evidence_ids),
            root_cause=f.root_cause,
            remediation=f.remediation,
            source_tool=f.source_tool,
            tool_version=f.tool_version,
            first_seen=f.first_seen,
            last_seen=f.last_seen,
            schema_version=f.schema_version,
        )


class JobModel(Base):
    """
    SQLAlchemy ORM model for bounded worker and tool tasks.
    Maps to canonical `Job` domain contract.
    """
    __tablename__ = "jobs"

    job_id = Column(String(64), primary_key=True)
    assessment_id = Column(String(64), ForeignKey("assessments.assessment_id", ondelete="CASCADE"), nullable=False, index=True)
    task_type = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default=JobStatus.CREATED.value, index=True)
    requested_targets_json = Column(Text, nullable=False, default="[]")
    target_input = Column(String(512), nullable=False)
    permission_level = Column(String(32), nullable=False, default=TestPermissionLevel.PASSIVE_ONLY.value)
    timeout_seconds = Column(Integer, nullable=False, default=180)
    max_retries = Column(Integer, nullable=False, default=2)
    retry_count = Column(Integer, nullable=False, default=0)
    cancellation_requested = Column(Boolean, nullable=False, default=False)
    cancellation_reason = Column(String(255), nullable=True)
    error_message = Column(Text, nullable=True)
    result_summary_json = Column(Text, nullable=True)
    audit_history_json = Column(Text, nullable=False, default="[]")
    resource_budget_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    schema_version = Column(String(16), nullable=False, default="1.0")

    # Relationships
    assessment = relationship("AssessmentModel", back_populates="jobs")

    @property
    def permitted_profile(self) -> str:
        return self.permission_level

    @permitted_profile.setter
    def permitted_profile(self, val: str) -> None:
        self.permission_level = val

    @property
    def error_summary(self) -> str | None:
        return self.error_message

    @error_summary.setter
    def error_summary(self, val: str | None) -> None:
        self.error_message = val

    def to_domain(self) -> Job:
        budget_data = json.loads(self.resource_budget_json) if self.resource_budget_json and self.resource_budget_json != "{}" else None
        budget = ResourceBudget.model_validate(budget_data) if budget_data else ResourceBudget(timeout_seconds=self.timeout_seconds)
        audit_data = json.loads(self.audit_history_json) if self.audit_history_json else []
        audit_history = [JobAuditEntry.model_validate(e) for e in audit_data]
        result_data = json.loads(self.result_summary_json) if self.result_summary_json else None
        targets = json.loads(self.requested_targets_json) if self.requested_targets_json else []

        return Job(
            job_id=self.job_id,
            assessment_id=self.assessment_id,
            task_type=self.task_type,
            status=JobStatus(self.status),
            requested_targets=targets,
            target_input=self.target_input,
            permitted_profile=TestPermissionLevel(self.permission_level),
            resource_budget=budget,
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
            retry_count=self.retry_count,
            cancellation_requested=self.cancellation_requested,
            cancellation_reason=self.cancellation_reason,
            error_summary=self.error_message,
            result_summary=result_data,
            audit_history=audit_history,
            created_at=self.created_at.replace(tzinfo=UTC) if self.created_at and not self.created_at.tzinfo else self.created_at,
            started_at=self.started_at.replace(tzinfo=UTC) if self.started_at and not self.started_at.tzinfo else self.started_at,
            completed_at=self.completed_at.replace(tzinfo=UTC) if self.completed_at and not self.completed_at.tzinfo else self.completed_at,
            schema_version=self.schema_version,
        )

    @classmethod
    def from_domain(cls, j: Job) -> "JobModel":
        budget_data = j.resource_budget.model_dump(mode="json")
        audit_data = [e.model_dump(mode="json") for e in j.audit_history]
        targets_data = j.requested_targets or ([j.target_input] if j.target_input else [])

        return cls(
            job_id=j.job_id,
            assessment_id=j.assessment_id,
            task_type=j.task_type,
            status=j.status.value,
            requested_targets_json=json.dumps(targets_data),
            target_input=j.target_input,
            permission_level=j.permitted_profile.value,
            timeout_seconds=j.timeout_seconds,
            max_retries=j.max_retries,
            retry_count=j.retry_count,
            cancellation_requested=j.cancellation_requested,
            cancellation_reason=j.cancellation_reason,
            error_message=j.error_summary,
            result_summary_json=json.dumps(j.result_summary) if j.result_summary else None,
            audit_history_json=json.dumps(audit_data),
            resource_budget_json=json.dumps(budget_data),
            created_at=j.created_at,
            started_at=j.started_at,
            completed_at=j.completed_at,
            schema_version=j.schema_version,
        )


class AuditEventModel(Base):
    """
    SQLAlchemy ORM model for append-only audit trail records.
    Maps to canonical `AuditEvent` domain contract.
    """
    __tablename__ = "audit_events"

    event_id = Column(String(64), primary_key=True)
    assessment_id = Column(String(64), ForeignKey("assessments.assessment_id", ondelete="CASCADE"), nullable=False, index=True)
    job_id = Column(String(64), ForeignKey("jobs.job_id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=_utc_now, index=True)
    actor = Column(String(128), nullable=False, default="system")
    outcome = Column(String(32), nullable=False, default=AuditOutcome.SUCCESS.value)
    correlation_id = Column(String(64), nullable=False)
    sanitized_metadata_json = Column(Text, nullable=False, default="{}")
    schema_version = Column(String(16), nullable=False, default="1.0")

    # Relationships
    assessment = relationship("AssessmentModel", back_populates="events")

    @property
    def details_json(self) -> str:
        return self.sanitized_metadata_json

    @details_json.setter
    def details_json(self, val: str) -> None:
        self.sanitized_metadata_json = val

    def to_domain(self) -> AuditEvent:
        metadata = json.loads(self.sanitized_metadata_json) if self.sanitized_metadata_json else {}
        return AuditEvent(
            event_id=self.event_id,
            assessment_id=self.assessment_id,
            job_id=self.job_id,
            event_type=self.event_type,
            timestamp=self.timestamp.replace(tzinfo=UTC) if self.timestamp and not self.timestamp.tzinfo else self.timestamp,
            actor=self.actor,
            outcome=AuditOutcome(self.outcome),
            correlation_id=self.correlation_id,
            sanitized_metadata=metadata,
            schema_version=self.schema_version,
        )

    @classmethod
    def from_domain(cls, ev: AuditEvent) -> "AuditEventModel":
        return cls(
            event_id=ev.event_id,
            assessment_id=ev.assessment_id,
            job_id=ev.job_id,
            event_type=ev.event_type,
            timestamp=ev.timestamp,
            actor=ev.actor,
            outcome=ev.outcome.value,
            correlation_id=ev.correlation_id,
            sanitized_metadata_json=json.dumps(ev.sanitized_metadata),
            schema_version=ev.schema_version,
        )
