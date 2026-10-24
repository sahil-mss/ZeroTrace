"""
ZeroTrace REST API: Assessment & Assessment Execution Endpoints.

Provides authenticated, deterministic endpoints for:
- Assessment creation, listing, retrieval, and approval
- Execution control (start, cancel) backed by JobService
- Asset, finding, evidence, audit event, and job retrieval
- Report readiness status inspection
- Partner integration (evidence, finding, asset submission)

Adheres strictly to AGENTS.md rules:
- No scanners or shell commands are executed inside route handlers
- Scope enforcement is deterministic and validated via ScopeValidator
- All mutations are audited in the append-only AuditRepository
"""

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from aegis_common.enums import (
    AssessmentStatus,
    AssetType,
    AuditOutcome,
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
    ResourceBudget,
    ScopePolicy,
    ScopeRule,
)
from aegis_common.utils import utc_now
from backend.app.api.auth import verify_api_token
from backend.app.db.repositories.assessment_repo import AssessmentRepository
from backend.app.db.repositories.asset_repo import AssetRepository
from backend.app.db.repositories.audit_repo import AuditRepository
from backend.app.db.repositories.evidence_repo import EvidenceRepository
from backend.app.db.repositories.finding_repo import FindingRepository
from backend.app.db.repositories.job_repo import JobRepository
from backend.app.db.session import get_db
from backend.app.services.asset_service import AssetObservation, AssetService
from backend.app.services.evidence_service import EvidenceObservation, EvidenceService
from backend.app.services.job_service import JobService
from backend.app.services.scope_validator import ScopeValidator

logger = logging.getLogger("zerotrace.api.assessments")

router = APIRouter(tags=["Assessments"])


# ==============================================================================
# Request & Response Schemas
# ==============================================================================


class CreateAssessmentRequest(BaseModel):
    """Request model for creating a new authorized assessment."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    name: str = Field(..., min_length=3, max_length=120, alias="title")
    organization_name: str = Field(..., min_length=2, max_length=120)
    authorized_by: str = Field(..., min_length=1, max_length=120)
    description: str | None = Field(default="")
    owner: str = Field(default="security_team", min_length=1, max_length=120)
    authorization_reference: str = Field(
        default="AUTH-PENDING",
        description="Formal tracking reference (e.g., ticket ID or authorization number).",
    )
    authorization_acknowledged: bool = Field(
        default=False,
        description="Operator confirmation of authorization.",
    )
    scope_rules: list[ScopeRule] = Field(
        default_factory=list,
        description="Explicit list of authorized scope boundaries.",
    )
    scope: ScopePolicy | None = Field(
        default=None,
        description="Backward-compatible aggregated scope policy.",
    )
    permitted_profiles: list[TestPermissionLevel] = Field(
        default_factory=lambda: [TestPermissionLevel.PASSIVE_ONLY],
        description="Permitted assessment testing profiles.",
    )
    max_concurrency: int = Field(default=3, ge=1, le=10)
    max_requests_per_minute: int = Field(default=60, ge=1, le=1000)
    expires_at: datetime | None = None


class ApproveAssessmentRequest(BaseModel):
    """Request model for formal operator sign-off and approval of an assessment."""

    approver: str = Field(..., min_length=1, max_length=120)
    notes: str = Field(default="", max_length=500)
    authorization_reference: str | None = None


class StartAssessmentRequest(BaseModel):
    """Request model for starting assessment execution."""

    task_type: str = Field(default="PASSIVE_RECON", max_length=50)
    target_input: str | None = Field(default=None, max_length=255)
    permission_level: TestPermissionLevel | None = None
    timeout_seconds: int = Field(default=180, ge=5, le=1800)


class CancelAssessmentRequest(BaseModel):
    """Request model for cancelling an assessment."""

    reason: str = Field(default="Operator requested assessment cancellation", max_length=255)


class ExecutionControlResponse(BaseModel):
    """Response returned when starting or cancelling execution."""

    message: str
    assessment_id: str
    status: str
    job: Job | None = None
    cancelled_jobs_count: int | None = None


class ReportReadinessResponse(BaseModel):
    """Response indicating the readiness state of an assessment report."""

    status: str
    is_ready: bool
    assessment_id: str
    message: str
    detail: str


class SubmitEvidenceRequest(BaseModel):
    """Request model for Person 2 scanner or Person 1 OSINT evidence submission."""

    source_name: str
    source_type: EvidenceSourceType
    data: dict[str, Any]
    asset_id: str | None = None
    collection_method: str = "AUTOMATED_PROBE"
    raw_payload: str | None = None
    tool_version: str | None = "1.0"
    sanitized_excerpt: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_type", mode="before")
    @classmethod
    def normalize_source_type(cls, v: object) -> object:
        if isinstance(v, str):
            val = v.strip().upper()
            mapping = {
                "AUTOMATED_PROBE": EvidenceSourceType.HTTP_FINGERPRINT,
                "PASSIVE_DNS": EvidenceSourceType.DNS_LOOKUP,
                "DNS": EvidenceSourceType.DNS_LOOKUP,
                "CT": EvidenceSourceType.CERT_TRANSPARENCY,
                "ZAP": EvidenceSourceType.SCANNER_ZAP,
                "NMAP": EvidenceSourceType.SCANNER_NMAP,
            }
            if val in mapping:
                return mapping[val]
            return val
        return v


class RegisterAssetRequest(BaseModel):
    """Request model for asset candidate registration."""

    raw_value: str
    asset_type: AssetType | None = None
    source_evidence_id: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    is_inferred: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("asset_type", mode="before")
    @classmethod
    def normalize_asset_type(cls, v: object) -> object:
        if isinstance(v, str):
            val = v.strip().upper()
            mapping = {
                "DOMAIN": AssetType.DOMAIN,
                "SUBDOMAIN": AssetType.SUBDOMAIN,
                "IP_ADDRESS": AssetType.IP_ADDRESS,
                "IP": AssetType.IP_ADDRESS,
                "URL": AssetType.URL,
                "WEB_APPLICATION": AssetType.WEB_APPLICATION,
                "SERVICE": AssetType.SERVICE,
            }
            if val in mapping:
                return mapping[val]
            return val
        return v



# ==============================================================================
# Helper Verification Functions
# ==============================================================================


def _get_assessment_or_404(assessment_id: str, session: Session) -> Assessment:
    """Retrieves assessment by ID or raises HTTP 404."""
    assessment = AssessmentRepository(session).get(assessment_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment '{assessment_id}' not found.",
        )
    return assessment


# ==============================================================================
# Assessment Endpoints
# ==============================================================================


@router.post(
    "/assessments",
    response_model=Assessment,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new assessment",
)
def create_assessment(
    req: CreateAssessmentRequest,
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> Assessment:
    """
    Creates a new assessment record with supplied scope and authorization acknowledgement.

    CRITICAL RULE:
    - Never defaults to APPROVED on creation.
    - Never launches a scan or shell command automatically.
    - Records an immutable audit log entry.
    """
    # 1. Validate that at least one target is provided
    has_rules = bool(req.scope_rules)
    has_policy_targets = bool(
        req.scope
        and (
            req.scope.target_domains
            or req.scope.target_ips
            or req.scope.target_cidrs
            or req.scope.target_urls
        )
    )

    if not has_rules and not has_policy_targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assessment scope must define at least one authorized target in scope_rules or scope.",
        )

    # 2. Instantiate Assessment domain model (enforcing PENDING_APPROVAL)
    assessment = Assessment(
        name=req.name,
        description=req.description,
        organization_name=req.organization_name,
        authorized_by=req.authorized_by,
        owner=req.owner,
        authorization_reference=req.authorization_reference,
        authorization_acknowledged=req.authorization_acknowledged,
        scope_rules=req.scope_rules,
        scope=req.scope,
        lifecycle_status=AssessmentStatus.PENDING_APPROVAL,
        permitted_profiles=req.permitted_profiles,
        max_concurrency=req.max_concurrency,
        max_requests_per_minute=req.max_requests_per_minute,
        expires_at=req.expires_at,
    )

    # 3. Persist record via AssessmentRepository
    assessment_repo = AssessmentRepository(session)
    saved = assessment_repo.create(assessment)

    # 4. Record audit event
    audit_repo = AuditRepository(session)
    audit_repo.record(
        AuditEvent(
            assessment_id=saved.assessment_id,
            event_type="ASSESSMENT_CREATED",
            actor=req.authorized_by,
            outcome=AuditOutcome.SUCCESS,
            sanitized_metadata={
                "title": saved.name,
                "organization": saved.organization_name,
                "status": saved.lifecycle_status.value,
                "authorization_acknowledged": saved.authorization_acknowledged,
            },
            timestamp=utc_now(),
        )
    )
    session.commit()
    return saved


@router.get(
    "/assessments",
    response_model=list[Assessment],
    summary="List assessments with pagination",
)
def list_assessments(
    limit: int = Query(default=50, ge=1, le=200, description="Page size limit"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> list[Assessment]:
    """Retrieves paginated collection of assessments ordered by creation timestamp."""
    return AssessmentRepository(session).list_all(limit=limit, offset=offset)


@router.get(
    "/assessments/{assessment_id}",
    response_model=Assessment,
    summary="Retrieve assessment by ID",
)
def get_assessment(
    assessment_id: str,
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> Assessment:
    """Retrieves an existing assessment by its unique assessment ID."""
    return _get_assessment_or_404(assessment_id, session)


@router.post(
    "/assessments/{assessment_id}/approve",
    response_model=Assessment,
    summary="Explicitly approve an assessment",
)
def approve_assessment(
    assessment_id: str,
    req: ApproveAssessmentRequest,
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> Assessment:
    """
    Formally records operator approval for an assessment.
    Advances lifecycle status from PENDING_APPROVAL to APPROVED.
    """
    assessment = _get_assessment_or_404(assessment_id, session)

    if assessment.lifecycle_status in (AssessmentStatus.CANCELLED, AssessmentStatus.COMPLETED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve assessment in terminal status '{assessment.lifecycle_status.value}'.",
        )

    assessment.lifecycle_status = AssessmentStatus.APPROVED
    assessment.authorization_acknowledged = True
    if req.authorization_reference:
        assessment.authorization_reference = req.authorization_reference
    assessment.updated_at = utc_now()

    updated = AssessmentRepository(session).update(assessment)

    AuditRepository(session).record(
        AuditEvent(
            assessment_id=assessment_id,
            event_type="ASSESSMENT_APPROVED",
            actor=req.approver,
            outcome=AuditOutcome.SUCCESS,
            sanitized_metadata={"notes": req.notes, "reference": req.authorization_reference},
            timestamp=utc_now(),
        )
    )
    session.commit()
    return updated


# ==============================================================================
# Execution Control Endpoints
# ==============================================================================


@router.post(
    "/assessments/{assessment_id}/start",
    response_model=ExecutionControlResponse,
    summary="Start assessment execution and enqueue bounded job",
)
def start_assessment(
    assessment_id: str,
    req: StartAssessmentRequest | None = None,
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> ExecutionControlResponse:
    """
    Validates assessment approval, scope, and permissions, then creates and enqueues
    a bounded worker job through JobService.

    CRITICAL RULES:
    - Rejects unapproved (PENDING_APPROVAL) or expired assessments.
    - Never executes scanners or shell commands directly inside route handlers.
    - Validates target scope deterministically via ScopeValidator.
    """
    assessment = _get_assessment_or_404(assessment_id, session)

    # 1. Verify Approval State
    if assessment.lifecycle_status == AssessmentStatus.PENDING_APPROVAL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot start assessment '{assessment_id}': Assessment is pending approval. "
                "Explicit operator approval is required before execution can start."
            ),
        )

    if assessment.lifecycle_status in (AssessmentStatus.CANCELLED, AssessmentStatus.COMPLETED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot start assessment in terminal status '{assessment.lifecycle_status.value}'.",
        )

    # 2. Check Expiration
    now = utc_now()
    if assessment.expires_at and now > assessment.expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot start assessment '{assessment_id}': Assessment expired on {assessment.expires_at.isoformat()}.",
        )

    # 3. Determine Candidate Targets from Assessment Scope
    candidate_targets: list[str] = []
    if assessment.scope_rules:
        for rule in assessment.scope_rules:
            if not rule.is_excluded:
                candidate_targets.append(rule.target_value)
    elif assessment.scope:
        candidate_targets.extend(assessment.scope.target_domains)
        candidate_targets.extend(assessment.scope.target_ips)
        candidate_targets.extend(assessment.scope.target_cidrs)
        candidate_targets.extend(assessment.scope.target_urls)

    if not candidate_targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot start assessment: No authorized targets defined in assessment scope.",
        )

    # 4. Resolve Target Input
    chosen_target = req.target_input.strip() if (req and req.target_input) else candidate_targets[0]

    # 5. Deterministic Scope Validation
    scope_result = ScopeValidator.validate_target(chosen_target, assessment)
    if not scope_result.allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Proposed target '{chosen_target}' violates assessment scope: {scope_result.explanation}",
        )

    # 6. Resolve Permissions & Budget
    permission_level = (
        req.permission_level
        if (req and req.permission_level)
        else (assessment.permitted_profiles[0] if assessment.permitted_profiles else TestPermissionLevel.PASSIVE_ONLY)
    )

    if permission_level not in assessment.permitted_profiles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Permission profile '{permission_level.value}' is not permitted by assessment. "
                f"Permitted profiles: {[p.value for p in assessment.permitted_profiles]}"
            ),
        )

    timeout_seconds = req.timeout_seconds if req else 180
    task_type = req.task_type if req else "PASSIVE_RECON"

    # 7. Update assessment status to ACTIVE
    if assessment.lifecycle_status == AssessmentStatus.APPROVED:
        assessment.lifecycle_status = AssessmentStatus.ACTIVE
        assessment.updated_at = now
        AssessmentRepository(session).update(assessment)

    # 8. Create and enqueue job through JobService (no direct process execution)
    job_service = JobService(session)
    created_job = job_service.create_job(
        assessment_id=assessment_id,
        task_type=task_type,
        target_input=chosen_target,
        requested_targets=[chosen_target],
        permission_level=permission_level,
        timeout_seconds=timeout_seconds,
        resource_budget=ResourceBudget(
            timeout_seconds=timeout_seconds,
            max_requests_per_minute=assessment.max_requests_per_minute,
            max_concurrency=assessment.max_concurrency,
        ),
    )

    # Advance job state to QUEUED via policy evaluation
    enqueued_job = job_service.enqueue_job(created_job.job_id)

    # 9. Record audit event
    AuditRepository(session).record(
        AuditEvent(
            assessment_id=assessment_id,
            job_id=enqueued_job.job_id,
            event_type="ASSESSMENT_STARTED",
            actor="operator",
            outcome=AuditOutcome.SUCCESS,
            sanitized_metadata={
                "status": AssessmentStatus.ACTIVE.value,
                "job_id": enqueued_job.job_id,
                "target": chosen_target,
            },
            timestamp=now,
        )
    )
    session.commit()

    return ExecutionControlResponse(
        message="Assessment execution initiated and job enqueued successfully.",
        assessment_id=assessment_id,
        status=assessment.lifecycle_status.value,
        job=enqueued_job,
    )


@router.post(
    "/assessments/{assessment_id}/cancel",
    response_model=ExecutionControlResponse,
    summary="Cancel assessment and all active jobs",
)
def cancel_assessment(
    assessment_id: str,
    req: CancelAssessmentRequest | None = None,
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> ExecutionControlResponse:
    """
    Requests cooperative cancellation through JobService and records an audit event.
    Marks assessment status as CANCELLED.
    """
    assessment = _get_assessment_or_404(assessment_id, session)

    cancel_reason = req.reason if req else "Operator requested assessment cancellation"

    # 1. Cancel all active jobs through JobService
    job_service = JobService(session)
    active_jobs = job_service.list_jobs(assessment_id)
    cancelled_count = 0

    for job in active_jobs:
        if job.status in (
            JobStatus.CREATED,
            JobStatus.POLICY_CHECK,
            JobStatus.QUEUED,
            JobStatus.RUNNING,
            JobStatus.REVIEW,
            JobStatus.NEEDS_APPROVAL,
        ):
            try:
                job_service.request_cancellation(job.job_id, reason=cancel_reason)
                cancelled_count += 1
            except Exception as e:
                logger.warning(f"Could not cancel job '{job.job_id}': {e}")

    # 2. Update assessment status to CANCELLED
    now = utc_now()
    assessment.lifecycle_status = AssessmentStatus.CANCELLED
    assessment.completed_at = now
    assessment.updated_at = now
    AssessmentRepository(session).update(assessment)

    # 3. Record audit event
    AuditRepository(session).record(
        AuditEvent(
            assessment_id=assessment_id,
            event_type="ASSESSMENT_CANCELLED",
            actor="operator",
            outcome=AuditOutcome.CANCELLED,
            sanitized_metadata={"reason": cancel_reason, "cancelled_jobs_count": cancelled_count},
            timestamp=now,
        )
    )
    session.commit()

    return ExecutionControlResponse(
        message="Assessment and active jobs successfully cancelled.",
        assessment_id=assessment_id,
        status=AssessmentStatus.CANCELLED.value,
        cancelled_jobs_count=cancelled_count,
    )


# ==============================================================================
# Asset and Finding Retrieval Endpoints
# ==============================================================================


@router.get(
    "/assessments/{assessment_id}/assets",
    response_model=list[Asset],
    summary="Retrieve assets associated with assessment",
)
def list_assets(
    assessment_id: str,
    scope_status: ScopeStatus | None = Query(default=None, description="Filter by scope classification"),
    asset_type: AssetType | None = Query(default=None, description="Filter by asset type"),
    limit: int = Query(default=100, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Offset"),
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> list[Asset]:
    """
    Returns actual persisted assets for the assessment.
    Never returns fabricated records.
    """
    _get_assessment_or_404(assessment_id, session)
    repo = AssetRepository(session)
    assets = repo.list_by_assessment(assessment_id, limit=limit, offset=offset)

    if scope_status is not None:
        assets = [a for a in assets if a.scope_classification == scope_status]
    if asset_type is not None:
        assets = [a for a in assets if a.asset_type == asset_type]

    return assets


@router.get(
    "/assessments/{assessment_id}/findings",
    response_model=list[Finding],
    summary="Retrieve findings associated with assessment",
)
def list_findings(
    assessment_id: str,
    severity: Severity | None = Query(default=None, description="Filter by severity level"),
    verification_status: VerificationStatus | None = Query(
        default=None, description="Filter by verification status"
    ),
    limit: int = Query(default=100, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Offset"),
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> list[Finding]:
    """
    Returns actual persisted findings.
    When there are no findings, returns an empty list, never fabricated findings.
    """
    _get_assessment_or_404(assessment_id, session)
    repo = FindingRepository(session)
    findings = repo.list_by_assessment(assessment_id, limit=limit, offset=offset)

    if severity is not None:
        findings = [f for f in findings if f.severity == severity]
    if verification_status is not None:
        findings = [f for f in findings if f.verification_status == verification_status]

    return findings


# ==============================================================================
# Evidence and Activity Endpoints
# ==============================================================================


@router.get(
    "/assessments/{assessment_id}/evidence",
    response_model=list[Evidence],
    summary="Retrieve evidence associated with assessment",
)
def list_evidence(
    assessment_id: str,
    asset_id: str | None = Query(default=None, description="Filter by target asset ID"),
    limit: int = Query(default=100, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Offset"),
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> list[Evidence]:
    """
    Returns verified evidence records belonging strictly to the requested assessment.
    """
    _get_assessment_or_404(assessment_id, session)
    repo = EvidenceRepository(session)
    if asset_id:
        return repo.list_by_asset(assessment_id, asset_id, limit=limit, offset=offset)
    return repo.list_by_assessment(assessment_id, limit=limit, offset=offset)


@router.get(
    "/assessments/{assessment_id}/events",
    response_model=list[AuditEvent],
    summary="Retrieve audit trail events for assessment",
)
def list_audit_events(
    assessment_id: str,
    limit: int = Query(default=100, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Offset"),
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> list[AuditEvent]:
    """
    Returns immutable audit events strictly belonging to the requested assessment.
    """
    _get_assessment_or_404(assessment_id, session)
    return AuditRepository(session).list_by_assessment(assessment_id, limit=limit, offset=offset)


@router.get(
    "/assessments/{assessment_id}/jobs",
    response_model=list[Job],
    summary="Retrieve worker jobs belonging to assessment",
)
def list_jobs(
    assessment_id: str,
    status_filter: JobStatus | None = Query(default=None, alias="status", description="Filter by job status"),
    limit: int = Query(default=100, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Offset"),
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> list[Job]:
    """
    Returns worker jobs belonging strictly to the requested assessment.
    """
    _get_assessment_or_404(assessment_id, session)
    jobs = JobRepository(session).list_by_assessment(assessment_id, limit=limit, offset=offset)
    if status_filter is not None:
        jobs = [j for j in jobs if j.status == status_filter]
    return jobs


# ==============================================================================
# Report Endpoint
# ==============================================================================


@router.get(
    "/assessments/{assessment_id}/report",
    response_model=ReportReadinessResponse,
    summary="Inspect assessment report readiness",
)
def get_assessment_report(
    assessment_id: str,
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> ReportReadinessResponse:
    """
    Returns report status. If reporting has not been implemented yet, returns
    a clear not-ready response rather than generating a fake report.
    """
    _get_assessment_or_404(assessment_id, session)

    # Reporting engine implementation is owned by Person 3 (AI & Reporting domain).
    # Return explicit not-ready response rather than fabricating a report.
    return ReportReadinessResponse(
        status="NOT_READY",
        is_ready=False,
        assessment_id=assessment_id,
        message="Assessment report is not ready. Reporting service is not yet implemented.",
        detail="Report generation is scheduled for Person 3 integration.",
    )


# ==============================================================================
# Partner Integration Endpoints (Person 2 Scanners & Person 1 OSINT)
# ==============================================================================


@router.post(
    "/assessments/{assessment_id}/evidence",
    response_model=Evidence,
    status_code=status.HTTP_201_CREATED,
    summary="Submit structured evidence record",
)
def submit_evidence(
    assessment_id: str,
    req: SubmitEvidenceRequest,
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> Evidence:
    """
    Ingests and cryptographically hashes an evidence record via EvidenceService.
    Rejects cross-assessment asset references.
    """
    _get_assessment_or_404(assessment_id, session)

    evidence_service = EvidenceService(session)
    obs = EvidenceObservation(
        assessment_id=assessment_id,
        source_name=req.source_name,
        source_type=req.source_type,
        data=req.data,
        asset_id=req.asset_id,
        collection_method=req.collection_method,
        raw_payload=req.raw_payload,
        tool_version=req.tool_version,
        sanitized_excerpt=req.sanitized_excerpt,
        metadata=req.metadata,
    )
    saved_evidence, _ = evidence_service.ingest_observation(obs)
    session.commit()
    return saved_evidence


@router.post(
    "/assessments/{assessment_id}/findings",
    response_model=Finding,
    status_code=status.HTTP_201_CREATED,
    summary="Submit normalized security finding",
)
def submit_finding(
    assessment_id: str,
    finding: Finding,
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> Finding:
    """
    Submits a security finding backed by verified evidence.
    Enforces evidence provenance and asset boundary validation.
    """
    _get_assessment_or_404(assessment_id, session)

    if finding.assessment_id != assessment_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mismatched assessment_id in finding payload.",
        )

    try:
        finding_repo = FindingRepository(session)
        saved = finding_repo.create(finding)
        session.commit()
        return saved
    except ValueError as e:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/assessments/{assessment_id}/assets",
    response_model=Asset,
    status_code=status.HTTP_201_CREATED,
    summary="Register asset candidate with deterministic scope classification",
)
def register_asset(
    assessment_id: str,
    req: RegisterAssetRequest,
    session: Session = Depends(get_db),
    _token: str = Depends(verify_api_token),
) -> Asset:
    """
    Registers an asset candidate. Scope classification is deterministically evaluated
    by AssetService and never trusted directly from caller input.
    """
    _get_assessment_or_404(assessment_id, session)

    asset_service = AssetService(session)
    obs = AssetObservation(
        assessment_id=assessment_id,
        raw_value=req.raw_value,
        asset_type=req.asset_type,
        source_evidence_id=req.source_evidence_id,
        confidence=req.confidence,
        is_inferred=req.is_inferred,
        metadata=req.metadata,
    )
    saved_asset, _ = asset_service.register_asset(obs)
    session.commit()
    return saved_asset
