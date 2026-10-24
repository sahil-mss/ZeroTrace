"""Common Abstract Scanner Interface.

TASK 1: Defines the contract that all concrete scanner adapters (Nmap,
OWASP ZAP, MockScanner) must implement. Uses a synchronous design to avoid
premature async overhead while maintaining clean thread-pool and queue
compatibility for Person 1's orchestrator.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from aegispt.security_engine.core.exceptions import (
    ProfileValidationError,
    TargetValidationError,
)
from aegispt.security_engine.schemas.enums import ScanStatus
from aegispt.security_engine.schemas.finding import NormalizedFinding
from aegispt.security_engine.schemas.profile import ScanProfile
from aegispt.security_engine.schemas.result import (
    RawScanEvidence,
    ScannerExecutionError as SchemaExecutionError,
    ScannerMetadata,
    ScanRequest,
    ScanResult,
)
from aegispt.security_engine.schemas.target import ScanTarget


class BaseScanner(ABC):
    """Abstract base class for all security engine scanner adapters."""

    @abstractmethod
    def get_metadata(self) -> ScannerMetadata:
        """Return static capability metadata and supported profile list."""
        raise NotImplementedError

    @abstractmethod
    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target format, asset type compatibility, and local scope.

        Returns True if target is valid and permissible for this scanner.
        Raises TargetValidationError if target violates syntax or authorization.
        """
        raise NotImplementedError

    @abstractmethod
    def validate_profile(self, profile: ScanProfile) -> bool:
        """Validate that the requested profile is supported by this scanner.

        Returns True if profile is supported and safe.
        Raises ProfileValidationError if profile is incompatible or unrecognized.
        """
        raise NotImplementedError

    @abstractmethod
    def run_scan(self, request: ScanRequest) -> ScanResult:
        """Execute the scanner with parameters bound to the request.

        Must respect request.timeout_seconds, manage process lifecycle,
        and generate raw evidence.
        """
        raise NotImplementedError

    @abstractmethod
    def parse_results(self, raw_evidence: RawScanEvidence) -> list[NormalizedFinding]:
        """Parse raw scanner output artifact into normalized findings."""
        raise NotImplementedError

    def execute(self, request: ScanRequest) -> ScanResult:
        """Execute scan with standard safety pre-flight checks and error trapping.

        Enforces:
        1. Target validation.
        2. Profile validation.
        3. Human approval requirement verification.
        4. Structured exception trapping.
        """
        start_time = datetime.now(timezone.utc)
        meta = self.get_metadata()

        # Pre-flight check 1: Target validation
        try:
            self.validate_target(request.target)
        except TargetValidationError as exc:
            end_time = datetime.now(timezone.utc)
            return ScanResult(
                request_id=request.request_id,
                scanner_id=meta.scanner_id,
                status=ScanStatus.FAILED,
                target=request.target,
                profile_id=request.profile.profile_id,
                started_at=start_time,
                completed_at=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                error=SchemaExecutionError(
                    error_code="TARGET_VALIDATION_FAILED",
                    message=str(exc),
                ),
                logs=[f"Pre-flight target validation failed: {exc}"],
            )

        # Pre-flight check 2: Profile validation
        try:
            self.validate_profile(request.profile)
        except ProfileValidationError as exc:
            end_time = datetime.now(timezone.utc)
            return ScanResult(
                request_id=request.request_id,
                scanner_id=meta.scanner_id,
                status=ScanStatus.FAILED,
                target=request.target,
                profile_id=request.profile.profile_id,
                started_at=start_time,
                completed_at=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                error=SchemaExecutionError(
                    error_code="PROFILE_VALIDATION_FAILED",
                    message=str(exc),
                ),
                logs=[f"Pre-flight profile validation failed: {exc}"],
            )

        # Pre-flight check 3: Human approval gating
        if request.profile.requires_human_approval:
            approval_granted = request.options.get("human_approval_granted", False)
            if not approval_granted:
                end_time = datetime.now(timezone.utc)
                return ScanResult(
                    request_id=request.request_id,
                    scanner_id=meta.scanner_id,
                    status=ScanStatus.NEEDS_APPROVAL,
                    target=request.target,
                    profile_id=request.profile.profile_id,
                    started_at=start_time,
                    completed_at=end_time,
                    duration_seconds=(end_time - start_time).total_seconds(),
                    error=SchemaExecutionError(
                        error_code="APPROVAL_REQUIRED",
                        message=f"Profile '{request.profile.profile_id}' requires explicit human operator sign-off.",
                    ),
                    logs=["Execution halted: human operator approval required."],
                )

        # Run scanner implementation
        return self.run_scan(request)
