"""Assessment Job and Lifecycle Schemas.

Defines the contract between Person 1's orchestrator and Person 2's security testing engine.
Enforces structured job requests, lifecycle state transitions, and comprehensive execution responses.
"""

from datetime import datetime, timezone
from typing import Any
import uuid

from pydantic import BaseModel, Field, model_validator

from aegispt.security_engine.schemas.enums import AssetType, JobStatus, PermissionLevel, VerificationStatus
from aegispt.security_engine.schemas.finding import NormalizedFinding
from aegispt.security_engine.schemas.profile import ResourceBudget, ScanProfile
from aegispt.security_engine.schemas.result import (
    RawScanEvidence,
    ScannerExecutionError,
    ScannerMetadata,
    ScanResult,
)
from aegispt.security_engine.schemas.target import ScanTarget


class ScanJobRequest(BaseModel):
    """Structured scan request dispatched by the backend/orchestrator to Person 2's engine.

    TASK 1: Complete contract including assessment ID, asset ID, target,
    scanner ID, approved profile, permission level, resource budget, and job ID.
    """

    job_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        min_length=1,
        description="Unique job execution tracking ID.",
    )
    assessment_id: str = Field(
        ...,
        min_length=1,
        description="Parent assessment or engagement ID.",
    )
    asset_id: str = Field(
        ...,
        min_length=1,
        description="Authoritative asset ID within Person 1's asset inventory.",
    )
    target: ScanTarget = Field(
        ...,
        description="Target asset specification (type, value, ports).",
    )
    scanner_id: str = Field(
        ...,
        min_length=1,
        description="Registered scanner adapter ID (e.g. 'nmap', 'owasp_zap', 'mock_scanner').",
    )
    profile_id: str = Field(
        default="",
        description="Predefined approved scan profile identifier.",
    )
    approved_profile: str | ScanProfile | None = Field(
        default=None,
        description="Approved scan profile instance or identifier (Task 1 contract alias).",
    )
    permission_level: PermissionLevel = Field(
        default=PermissionLevel.SAFE_AUDIT,
        description="Operator-granted permission tier for this specific job.",
    )
    resource_budget: ResourceBudget = Field(
        default_factory=ResourceBudget,
        description="Resource allocation limits (CPU %, memory MB, rate limit).",
    )
    approved_by_operator: bool = Field(
        default=False,
        description="Explicit human sign-off for intrusive profiles or active probes.",
    )
    options: dict[str, Any] = Field(
        default_factory=dict,
        description="Supplementary execution flags or simulation directives.",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_request_inputs(cls, data: Any) -> Any:
        """Coerce flexible inputs (strings, aliases) to conform to the strict contract."""
        if isinstance(data, dict):
            # 1. Normalize target if string was passed
            raw_target = data.get("target")
            if isinstance(raw_target, str):
                target_str = raw_target.strip()
                if target_str.startswith(("http://", "https://")):
                    asset_type = AssetType.WEB_URL
                elif "/" in target_str:
                    asset_type = AssetType.CIDR_RANGE
                elif any(c.isalpha() for c in target_str.replace("localhost", "").replace("juice-shop", "").replace("local-lab", "")):
                    asset_type = AssetType.HOSTNAME
                else:
                    asset_type = AssetType.IP_ADDRESS
                data["target"] = ScanTarget(asset_type=asset_type, target_value=target_str)

            # 2. Normalize profile identifier from approved_profile, profile, or profile_id
            prof = data.get("approved_profile") or data.get("profile") or data.get("profile_id")
            if prof is not None:
                if hasattr(prof, "profile_id"):
                    pid = str(prof.profile_id)
                elif isinstance(prof, str):
                    pid = prof
                else:
                    pid = str(prof)
                data["profile_id"] = pid
                data["approved_profile"] = pid
            elif not data.get("profile_id"):
                raise ValueError("Scan request must specify an approved profile ('approved_profile' or 'profile_id').")

        return data


class JobStateTransition(BaseModel):
    """Immutable audit record of a job lifecycle transition."""

    from_status: JobStatus | None = Field(
        default=None,
        description="Prior job status, or None if initial creation.",
    )
    to_status: JobStatus = Field(
        ...,
        description="New job status.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the transition.",
    )
    reason: str | None = Field(
        default=None,
        description="Reason or event triggering the state transition.",
    )


class ScanJob(BaseModel):
    """Stateful representation of a scan job across its full lifecycle."""

    job_id: str = Field(
        ...,
        min_length=1,
        description="Unique job identifier.",
    )
    assessment_id: str = Field(
        ...,
        min_length=1,
        description="Associated assessment ID.",
    )
    asset_id: str = Field(
        ...,
        min_length=1,
        description="Associated asset ID.",
    )
    target: ScanTarget = Field(
        ...,
        description="Target being scanned.",
    )
    scanner_id: str = Field(
        ...,
        min_length=1,
        description="Scanner adapter ID.",
    )
    profile_id: str = Field(
        ...,
        min_length=1,
        description="Scan profile ID executed.",
    )
    permission_level: PermissionLevel = Field(
        ...,
        description="Assigned permission level.",
    )
    resource_budget: ResourceBudget = Field(
        ...,
        description="Assigned resource constraints.",
    )
    status: JobStatus = Field(
        default=JobStatus.CREATED,
        description="Current lifecycle status.",
    )
    transitions: list[JobStateTransition] = Field(
        default_factory=list,
        description="Chronological audit log of state transitions.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of job creation.",
    )
    started_at: datetime | None = Field(
        default=None,
        description="Timestamp when scanner execution began.",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="Timestamp when job reached a terminal state.",
    )
    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Wall-clock duration of the execution.",
    )
    result: ScanResult | None = Field(
        default=None,
        description="Raw scan execution result from the scanner adapter.",
    )
    findings: list[NormalizedFinding] = Field(
        default_factory=list,
        description="Normalized and verified findings produced by the job.",
    )
    evidence: RawScanEvidence | None = Field(
        default=None,
        description="Pointer to raw evidence artifact preserved on disk.",
    )
    error: ScannerExecutionError | None = Field(
        default=None,
        description="Structured error details if job failed.",
    )
    logs: list[str] = Field(
        default_factory=list,
        description="Audit and diagnostic logs recorded during execution.",
    )


class ScanJobResponse(BaseModel):
    """Task 5 Result Handling: Structured response returned to Person 1's orchestrator."""

    job_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier of the executed job.",
    )
    status: JobStatus = Field(
        ...,
        description="Terminal status of the job (COMPLETED, FAILED, CANCELLED, NEEDS_APPROVAL).",
    )
    scanner_metadata: ScannerMetadata | None = Field(
        default=None,
        description="Metadata of the scanner adapter that performed the assessment.",
    )
    duration_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Execution duration in seconds.",
    )
    findings: list[NormalizedFinding] = Field(
        default_factory=list,
        description="Normalized findings extracted and deduplicated from scanner results.",
    )
    evidence_references: list[str] = Field(
        default_factory=list,
        description="List of artifact IDs or file paths representing raw supporting evidence.",
    )
    verification_summary: dict[str, VerificationStatus] = Field(
        default_factory=dict,
        description="Map of finding_id -> verification status (CONFIRMED, LIKELY, etc.).",
    )
    error: ScannerExecutionError | None = Field(
        default=None,
        description="Error details if the job failed or timed out.",
    )
    logs: list[str] = Field(
        default_factory=list,
        description="Job audit trail.",
    )
