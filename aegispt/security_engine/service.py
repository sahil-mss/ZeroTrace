"""Security Engine Scanner Service and Lifecycle Orchestration.

TASKS 1, 4, 5:
- Task 1: Expose ScannerService accepting structured scan requests from Person 1's orchestrator.
- Task 4: Complete Job Lifecycle state machine (CREATED -> POLICY_CHECK -> QUEUED -> RUNNING -> REVIEW -> COMPLETED / FAILED / CANCELLED / NEEDS_APPROVAL).
- Task 5: Result handling returning structured ScanJobResponse with scanner metadata, normalized findings, evidence references, and verification statuses.
"""

from datetime import datetime, timezone
from typing import Any
import uuid

from aegispt.security_engine.core.exceptions import (
    ApprovalRequiredError,
    JobLifecycleError,
    ProfileValidationError,
    ScannerRegistryError,
    ScopeViolationError,
    TargetValidationError,
)
from aegispt.security_engine.core.scope import BaseScopeValidator, LocalScopeValidator
from aegispt.security_engine.integrations.base import BaseScanner
from aegispt.security_engine.integrations.mock import MockScanner
from aegispt.security_engine.integrations.nmap import NmapScanner
from aegispt.security_engine.integrations.zap import ZAPScanner
from aegispt.security_engine.normalization import NormalizationPipeline
from aegispt.security_engine.schemas.enums import JobStatus, ScanStatus, VerificationStatus
from aegispt.security_engine.schemas.job import (
    JobStateTransition,
    ScanJob,
    ScanJobRequest,
    ScanJobResponse,
)
from aegispt.security_engine.schemas.profile import APPROVED_SCAN_PROFILES, ScanProfile
from aegispt.security_engine.schemas.result import (
    ScannerExecutionError,
    ScanRequest,
    ScanResult,
)
from aegispt.security_engine.verification import VerificationEngine
from aegispt.security_engine.verification.plugins import (
    HeaderSecurityVerifier,
    LabGroundTruthVerifier,
    PassiveReflectionVerifier,
)


class ScannerRegistry:
    """Registry maintaining available scanner adapters."""

    def __init__(self) -> None:
        self._scanners: dict[str, BaseScanner] = {}

    def register(self, scanner: BaseScanner) -> None:
        """Register a scanner adapter instance."""
        meta = scanner.get_metadata()
        self._scanners[meta.scanner_id] = scanner

    def get(self, scanner_id: str) -> BaseScanner:
        """Retrieve a scanner adapter by identifier."""
        if scanner_id not in self._scanners:
            raise ScannerRegistryError(
                f"Scanner '{scanner_id}' is not registered in the security engine. "
                f"Available: {sorted(list(self._scanners.keys()))}."
            )
        return self._scanners[scanner_id]

    def has(self, scanner_id: str) -> bool:
        """Check if a scanner adapter is registered."""
        return scanner_id in self._scanners

    def list_scanners(self) -> list[str]:
        """Return list of all registered scanner IDs."""
        return sorted(list(self._scanners.keys()))


def create_default_scanner_registry() -> ScannerRegistry:
    """Instantiate standard registry pre-populated with default adapters."""
    registry = ScannerRegistry()
    registry.register(MockScanner())
    registry.register(NmapScanner())
    registry.register(ZAPScanner())
    return registry


class ScannerService:
    """Central service coordinating scan execution, scope validation, finding normalization, and verification."""

    def __init__(
        self,
        registry: ScannerRegistry | None = None,
        scope_validator: BaseScopeValidator | None = None,
        normalization_pipeline: NormalizationPipeline | None = None,
        verification_engine: VerificationEngine | None = None,
        approved_profiles: dict[str, ScanProfile] | None = None,
    ) -> None:
        """Initialize ScannerService with dependencies."""
        self.registry = registry or create_default_scanner_registry()
        self.scope_validator = scope_validator or LocalScopeValidator()
        self.normalization_pipeline = normalization_pipeline or NormalizationPipeline()
        self.verification_engine = verification_engine or VerificationEngine()
        self.approved_profiles = approved_profiles or APPROVED_SCAN_PROFILES
        self._jobs: dict[str, ScanJob] = {}

    def _transition(self, job: ScanJob, new_status: JobStatus, reason: str | None = None) -> None:
        """Record and apply a lifecycle state transition."""
        transition = JobStateTransition(
            from_status=job.status,
            to_status=new_status,
            timestamp=datetime.now(timezone.utc),
            reason=reason,
        )
        job.transitions.append(transition)
        job.status = new_status
        job.logs.append(f"[{transition.timestamp.isoformat()}] State transition: {transition.from_status} -> {new_status} (Reason: {reason})")

    def create_job(self, request: ScanJobRequest) -> ScanJob:
        """Create and store a new scan job in CREATED state."""
        job = ScanJob(
            job_id=request.job_id,
            assessment_id=request.assessment_id,
            asset_id=request.asset_id,
            target=request.target,
            scanner_id=request.scanner_id,
            profile_id=request.profile_id,
            permission_level=request.permission_level,
            resource_budget=request.resource_budget,
            status=JobStatus.CREATED,
            transitions=[],
            logs=[f"Job '{request.job_id}' created for assessment '{request.assessment_id}'."],
        )
        self._transition(job, JobStatus.CREATED, "Job instantiated")
        self._jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str) -> ScanJob | None:
        """Retrieve job state by ID."""
        return self._jobs.get(job_id)

    def cancel_job(self, job_id: str, reason: str = "Operator requested cancellation") -> ScanJobResponse:
        """Cancel an in-progress or queued scan job."""
        job = self.get_job(job_id)
        if not job:
            raise JobLifecycleError(f"Job '{job_id}' not found.")

        terminal_states = {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}
        if job.status in terminal_states:
            raise JobLifecycleError(f"Cannot cancel job '{job_id}' in terminal state '{job.status}'.")

        self._transition(job, JobStatus.CANCELLED, reason)
        job.completed_at = datetime.now(timezone.utc)
        if job.started_at:
            job.duration_seconds = (job.completed_at - job.started_at).total_seconds()

        return self._build_response(job)

    def run_job(self, request: ScanJobRequest) -> ScanJobResponse:
        """Execute a scan job through its complete lifecycle.

        Full lifecycle:
        1. CREATED
        2. POLICY_CHECK (scope validation, profile check, human approval gate)
        3. QUEUED
        4. RUNNING (scanner invocation)
        5. REVIEW (finding normalization and verification)
        6. COMPLETED / FAILED / CANCELLED / NEEDS_APPROVAL
        """
        job = self.create_job(request)

        # ---------------------------------------------------------
        # Phase 1: Policy & Scope Check
        # ---------------------------------------------------------
        self._transition(job, JobStatus.POLICY_CHECK, "Initiating scope and authorization check")

        # Check scanner existence
        if not self.registry.has(job.scanner_id):
            job.error = ScannerExecutionError(
                error_code="SCANNER_NOT_FOUND",
                message=f"Scanner '{job.scanner_id}' is not registered.",
            )
            self._transition(job, JobStatus.FAILED, f"Unknown scanner '{job.scanner_id}'")
            return self._build_response(job)

        # Check profile approval
        if job.profile_id not in self.approved_profiles:
            job.error = ScannerExecutionError(
                error_code="INVALID_SCAN_PROFILE",
                message=f"Profile '{job.profile_id}' is not in approved profiles registry.",
            )
            self._transition(job, JobStatus.FAILED, f"Unapproved profile '{job.profile_id}'")
            return self._build_response(job)

        profile = self.approved_profiles[job.profile_id]

        # Scope enforcement
        try:
            self.scope_validator.validate_target(job.target, assessment_id=job.assessment_id)
        except ScopeViolationError as exc:
            job.error = ScannerExecutionError(
                error_code="SCOPE_VIOLATION",
                message=str(exc),
            )
            self._transition(job, JobStatus.FAILED, "Target failed scope validation")
            return self._build_response(job)

        # Human approval gate
        if profile.requires_human_approval and not request.approved_by_operator:
            self._transition(
                job,
                JobStatus.NEEDS_APPROVAL,
                f"Profile '{profile.profile_id}' requires explicit operator sign-off.",
            )
            return self._build_response(job)

        # ---------------------------------------------------------
        # Phase 2: Queuing
        # ---------------------------------------------------------
        self._transition(job, JobStatus.QUEUED, "Enqueued for scanner execution")

        # ---------------------------------------------------------
        # Phase 3: Running Execution
        # ---------------------------------------------------------
        self._transition(job, JobStatus.RUNNING, "Starting scanner subprocess")
        job.started_at = datetime.now(timezone.utc)

        scanner = self.registry.get(job.scanner_id)
        adapter_request = ScanRequest(
            request_id=job.job_id,
            scanner_id=job.scanner_id,
            target=job.target,
            profile=profile,
            timeout_seconds=profile.timeout_seconds,
            options={**request.options, "approved_by_operator": request.approved_by_operator},
        )

        try:
            scan_result: ScanResult = scanner.execute(adapter_request)
        except Exception as exc:
            job.completed_at = datetime.now(timezone.utc)
            job.duration_seconds = (job.completed_at - job.started_at).total_seconds()
            job.error = ScannerExecutionError(
                error_code="UNEXPECTED_SCANNER_EXCEPTION",
                message=str(exc),
            )
            self._transition(job, JobStatus.FAILED, f"Scanner raised exception: {exc}")
            return self._build_response(job)

        job.result = scan_result
        job.completed_at = datetime.now(timezone.utc)
        job.duration_seconds = scan_result.duration_seconds

        # Map scanner result status to job lifecycle status
        if scan_result.status == ScanStatus.CANCELLED:
            self._transition(job, JobStatus.CANCELLED, "Scanner reported cancellation")
            return self._build_response(job)

        if scan_result.status in (ScanStatus.FAILED, ScanStatus.TIMEOUT):
            job.error = scan_result.error or ScannerExecutionError(
                error_code=scan_result.status.value,
                message=f"Scanner execution resulted in {scan_result.status.value}",
            )
            self._transition(job, JobStatus.FAILED, f"Scanner execution ended with {scan_result.status.value}")
            return self._build_response(job)

        # ---------------------------------------------------------
        # Phase 4: Review (Normalization & Verification)
        # ---------------------------------------------------------
        self._transition(job, JobStatus.REVIEW, "Normalizing findings and running verification engine")

        if scan_result.raw_evidence:
            job.evidence = scan_result.raw_evidence

        normalized_findings = self.normalization_pipeline.normalize_scan_result(
            result=scan_result,
            assessment_id=job.assessment_id,
        )
        for nf in normalized_findings:
            if not nf.asset_id:
                nf.asset_id = job.asset_id

        # Run Verification Engine
        verified_findings, _ = self.verification_engine.verify_all(
            findings=normalized_findings,
            assessment_scope={job.target.target_value, job.asset_id},
        )

        job.findings = verified_findings

        # ---------------------------------------------------------
        # Phase 5: Completed
        # ---------------------------------------------------------
        self._transition(job, JobStatus.COMPLETED, "Scan and verification successfully concluded")
        return self._build_response(job)

    def _build_response(self, job: ScanJob) -> ScanJobResponse:
        """Construct the standardized response for Person 1's orchestrator."""
        meta = None
        if self.registry.has(job.scanner_id):
            try:
                meta = self.registry.get(job.scanner_id).get_metadata()
            except Exception:
                meta = None

        evidence_refs: list[str] = []
        if job.evidence:
            evidence_refs.append(job.evidence.artifact_id)
            if job.evidence.file_path:
                evidence_refs.append(job.evidence.file_path)

        for finding in job.findings:
            for eid in finding.evidence_ids:
                if eid not in evidence_refs:
                    evidence_refs.append(eid)

        verification_summary = {
            f.finding_id: f.verification_status for f in job.findings
        }

        return ScanJobResponse(
            job_id=job.job_id,
            status=job.status,
            scanner_metadata=meta,
            duration_seconds=job.duration_seconds,
            findings=job.findings,
            evidence_references=evidence_refs,
            verification_summary=verification_summary,
            error=job.error,
            logs=job.logs,
        )
