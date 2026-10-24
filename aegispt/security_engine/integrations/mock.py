"""Mock Scanner Implementation.

TASK 4: Implements the BaseScanner interface with deterministic sample results.
Used to validate engine architecture, schema compatibility, error trapping,
and pipeline flows before integrating external tools (Nmap/ZAP).
"""

from datetime import datetime, timezone
import hashlib
import json
import time

from aegispt.security_engine.core.exceptions import (
    ProfileValidationError,
    TargetValidationError,
)
from aegispt.security_engine.integrations.base import BaseScanner
from aegispt.security_engine.schemas.enums import (
    AssetType,
    ScanStatus,
    Severity,
)
from aegispt.security_engine.schemas.finding import (
    EvidenceReference,
    NormalizedFinding,
)
from aegispt.security_engine.schemas.profile import ScanProfile
from aegispt.security_engine.schemas.result import (
    RawScanEvidence,
    ScannerExecutionError,
    ScannerMetadata,
    ScanRequest,
    ScanResult,
)
from aegispt.security_engine.schemas.target import ScanTarget


class MockScanner(BaseScanner):
    """Deterministic mock scanner adapter for unit testing and interface validation."""

    SCANNER_ID = "mock_scanner"
    VERSION = "1.0.0"

    def get_metadata(self) -> ScannerMetadata:
        """Return static capability metadata for the mock scanner."""
        return ScannerMetadata(
            scanner_id=self.SCANNER_ID,
            name="AegisPT Mock Security Scanner",
            version=self.VERSION,
            vendor="AegisPT Engineering",
            description="Synthetic mock scanner producing deterministic test findings and raw outputs.",
            supported_asset_types=[
                AssetType.IP_ADDRESS,
                AssetType.HOSTNAME,
                AssetType.WEB_URL,
                AssetType.CIDR_RANGE,
            ],
            supported_profiles=[
                "mock_baseline",
                "mock_intrusive_approval",
                "mock_timeout_sim",
            ],
        )

    def validate_target(self, target: ScanTarget) -> bool:
        """Verify target syntax, scope authorization, and local/lab bounds."""
        if not target.is_in_scope:
            raise TargetValidationError(
                f"Target '{target.target_value}' is explicitly flagged as out of scope."
            )

        # Enforce safety guardrail: must be local/lab asset
        if not target.is_local_or_private():
            raise TargetValidationError(
                f"Target '{target.target_value}' is not within authorized local/lab boundaries "
                "(strictly localhost or RFC 1918 / Docker lab ranges allowed)."
            )

        # Ensure asset type is supported
        meta = self.get_metadata()
        if target.asset_type not in meta.supported_asset_types:
            raise TargetValidationError(
                f"Asset type '{target.asset_type}' is not supported by {meta.name}."
            )

        return True

    def validate_profile(self, profile: ScanProfile) -> bool:
        """Verify requested profile is registered and supported."""
        meta = self.get_metadata()
        if profile.profile_id not in meta.supported_profiles:
            raise ProfileValidationError(
                f"Profile '{profile.profile_id}' is not supported by {meta.name}. "
                f"Allowed profiles: {meta.supported_profiles}"
            )
        return True

    def run_scan(self, request: ScanRequest) -> ScanResult:
        """Execute mock scan with deterministic sample finding and evidence generation."""
        start_time = datetime.now(timezone.utc)
        meta = self.get_metadata()

        # Simulation 1: Timeout simulation
        if (
            request.options.get("simulate_timeout")
            or request.profile.parameters.get("simulate_timeout")
            or request.profile.profile_id == "mock_timeout_sim"
        ):
            # Short sleep to simulate elapsed time without stalling tests
            time.sleep(0.01)
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            return ScanResult(
                request_id=request.request_id,
                scanner_id=meta.scanner_id,
                status=ScanStatus.TIMEOUT,
                target=request.target,
                profile_id=request.profile.profile_id,
                started_at=start_time,
                completed_at=end_time,
                duration_seconds=duration,
                error=ScannerExecutionError(
                    error_code="TIMEOUT_EXCEEDED",
                    message=f"Scan exceeded bounded timeout of {request.profile.timeout_seconds}s.",
                ),
                logs=[
                    f"Initialized {meta.name} against {request.target.target_value}",
                    "Simulated process execution exceeded hard timeout threshold.",
                ],
            )

        # Simulation 2: Unhandled error simulation
        if request.options.get("simulate_error"):
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
                error=ScannerExecutionError(
                    error_code="SIMULATED_FAILURE",
                    message="Simulated internal scanner execution failure.",
                    exit_code=1,
                    details={"reason": "Explicit test failure trigger requested."},
                ),
                logs=[
                    f"Initialized {meta.name} against {request.target.target_value}",
                    "Simulated unexpected non-zero exit code 1.",
                ],
            )

        # Normal successful execution: produce deterministic raw output
        raw_payload = json.dumps(
            {
                "tool": meta.name,
                "version": meta.version,
                "scan_target": request.target.target_value,
                "scan_profile": request.profile.profile_id,
                "timestamp": start_time.isoformat(),
                "simulated_findings": [
                    {
                        "id": "MOCK-001",
                        "title": "Mock Open Management Service (HTTP-Alt: 8080)",
                        "severity": "LOW",
                        "port": 8080,
                        "protocol": "tcp",
                        "service": "http-proxy",
                        "cwe": 200,
                        "banner": "Server: MockLab/1.0 (Testing Environment)",
                    }
                ],
            },
            indent=2,
        )

        raw_bytes = raw_payload.encode("utf-8")
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        raw_evidence = RawScanEvidence(
            scanner_id=meta.scanner_id,
            file_path=f"artifacts/scans/mock_{request.request_id}.json",
            sha256_hash=sha256,
            byte_size=len(raw_bytes),
            content_type="application/json",
            raw_snippet=raw_payload[:250],
        )

        findings = self.parse_results(raw_evidence, target=request.target)

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        return ScanResult(
            request_id=request.request_id,
            scanner_id=meta.scanner_id,
            status=ScanStatus.SUCCESS,
            target=request.target,
            profile_id=request.profile.profile_id,
            started_at=start_time,
            completed_at=end_time,
            duration_seconds=duration,
            findings=findings,
            raw_evidence=raw_evidence,
            logs=[
                f"Initialized {meta.name} against {request.target.target_value}",
                f"Completed assessment under profile '{request.profile.profile_id}'",
                f"Identified {len(findings)} normalized finding(s)",
            ],
        )

    def parse_results(
        self,
        raw_evidence: RawScanEvidence,
        target: ScanTarget | None = None,
    ) -> list[NormalizedFinding]:
        """Parse raw scanner artifact into normalized findings."""
        if target is None:
            # Fallback target if parsing standalone artifact
            target = ScanTarget(
                asset_type=AssetType.IP_ADDRESS,
                target_value="127.0.0.1",
            )

        sample_finding = NormalizedFinding(
            scanner_id=self.SCANNER_ID,
            title="Mock Open Management Service (HTTP-Alt: 8080)",
            description="Exposed management interface identified on lab port 8080 without authentication.",
            severity=Severity.LOW,
            target=target,
            cwe_id=200,
            remediation="Restrict exposure of development services to localhost or require mutual TLS.",
            evidence=[
                EvidenceReference(
                    evidence_type="port_banner",
                    content_snippet="Server: MockLab/1.0 (Testing Environment) on port 8080/tcp",
                    source_artifact_id=raw_evidence.artifact_id,
                    sha256_hash=raw_evidence.sha256_hash,
                    metadata={"port": 8080, "protocol": "tcp"},
                )
            ],
        )
        return [sample_finding]
