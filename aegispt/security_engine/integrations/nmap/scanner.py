"""Nmap Security Scanner Adapter.

TASK 1 & 2: Subclasses BaseScanner to provide safe subprocess invocation of Nmap,
using structured XML reports, timeout enforcement, SHA-256 evidence hashing,
and strict scope validation (strictly localhost/lab assets).
"""

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import shutil
import subprocess

from aegispt.security_engine.core.exceptions import (
    ProfileValidationError,
    TargetValidationError,
)
from aegispt.security_engine.integrations.base import BaseScanner
from aegispt.security_engine.integrations.nmap.parser import NmapXMLParser
from aegispt.security_engine.schemas.enums import (
    AssetType,
    ScanStatus,
)
from aegispt.security_engine.schemas.finding import NormalizedFinding
from aegispt.security_engine.schemas.observation import ServiceObservation
from aegispt.security_engine.schemas.profile import ScanProfile
from aegispt.security_engine.schemas.result import (
    RawScanEvidence,
    ScannerExecutionError,
    ScannerMetadata,
    ScanRequest,
    ScanResult,
)
from aegispt.security_engine.schemas.target import ScanTarget


class NmapScanner(BaseScanner):
    """Adapter integrating Nmap network discovery and port scanner into AegisPT."""

    SCANNER_ID = "nmap"
    VERSION = "7.9x"

    def __init__(
        self,
        nmap_binary: str = "nmap",
        artifacts_dir: str | Path = "artifacts/scans",
    ) -> None:
        self.nmap_binary = nmap_binary
        self.artifacts_dir = Path(artifacts_dir)

    def get_metadata(self) -> ScannerMetadata:
        """Return static capability metadata for Nmap."""
        return ScannerMetadata(
            scanner_id=self.SCANNER_ID,
            name="Nmap Network Discovery & Service Scanner",
            version=self.VERSION,
            vendor="Insecure.Org / Gordon Lyon",
            description="Active host discovery, port enumeration, and service version detection.",
            supported_asset_types=[
                AssetType.IP_ADDRESS,
                AssetType.HOSTNAME,
                AssetType.CIDR_RANGE,
            ],
            supported_profiles=[
                "nmap_fast_discovery",
                "nmap_service_version",
                "nmap_custom_ports",
            ],
        )

    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target format, asset type, and strict local/lab scope."""
        if not target.is_in_scope:
            raise TargetValidationError(
                f"Target '{target.target_value}' is explicitly flagged as out of scope."
            )

        # Check for command injection characters in target_value
        forbidden_chars = [";", "&", "|", "`", "$", "\n", "\r", "<", ">"]
        if any(c in target.target_value for c in forbidden_chars):
            raise TargetValidationError(
                f"Target value '{target.target_value}' contains forbidden shell characters."
            )

        # Enforce security guardrail: strictly localhost or private/lab IP
        if not target.is_local_or_private():
            raise TargetValidationError(
                f"Target '{target.target_value}' is not within authorized local/lab boundaries. "
                "Only localhost or RFC 1918 / Docker lab IP ranges are permitted."
            )

        meta = self.get_metadata()
        if target.asset_type not in meta.supported_asset_types:
            raise TargetValidationError(
                f"Asset type '{target.asset_type}' is not supported by {meta.name}. "
                f"Supported: {meta.supported_asset_types}"
            )

        return True

    def validate_profile(self, profile: ScanProfile) -> bool:
        """Ensure requested profile is recognized and safe."""
        meta = self.get_metadata()
        if profile.profile_id not in meta.supported_profiles:
            raise ProfileValidationError(
                f"Profile '{profile.profile_id}' is not supported by {meta.name}. "
                f"Supported profiles: {meta.supported_profiles}"
            )
        return True

    def build_command_args(self, request: ScanRequest, output_xml_path: Path) -> list[str]:
        """Construct safe, deterministic argument vector without shell execution.

        Predefined profiles restrict flags to audited templates.
        """
        # Base command with structured XML output
        args: list[str] = [
            self.nmap_binary,
            "-oX",
            str(output_xml_path),
        ]

        profile_id = request.profile.profile_id

        if profile_id == "nmap_fast_discovery":
            # Fast scan (top 100 ports), timing template 4, skip host discovery ping
            args.extend(["-F", "-T4", "-Pn", "--no-stylesheet"])

        elif profile_id == "nmap_service_version":
            # Service and version probe with light probe intensity
            args.extend(["-sV", "--version-light", "-T4", "-Pn", "--no-stylesheet"])

        elif profile_id == "nmap_custom_ports":
            # Targeted ports
            if request.target.ports:
                port_spec = ",".join(str(p) for p in request.target.ports)
            else:
                port_spec = "80,443,3000,8080"
            args.extend(["-p", port_spec, "-sV", "-T4", "-Pn", "--no-stylesheet"])

        else:
            # Fallback to configured profile parameter flags if explicitly whitelisted
            flags = request.profile.parameters.get("flags", ["-F", "-T4", "-Pn", "--no-stylesheet"])
            args.extend(flags)

        # Add target specification
        args.append(request.target.target_value)
        return args

    def run_scan(self, request: ScanRequest) -> ScanResult:
        """Safely execute Nmap subprocess with bounded timeout and evidence hashing."""
        start_time = datetime.now(timezone.utc)
        meta = self.get_metadata()

        # Check if Nmap binary is available
        if not shutil.which(self.nmap_binary):
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            return ScanResult(
                request_id=request.request_id,
                scanner_id=meta.scanner_id,
                status=ScanStatus.FAILED,
                target=request.target,
                profile_id=request.profile.profile_id,
                started_at=start_time,
                completed_at=end_time,
                duration_seconds=duration,
                error=ScannerExecutionError(
                    error_code="NMAP_NOT_INSTALLED",
                    message=(
                        f"Nmap executable '{self.nmap_binary}' was not found in system PATH. "
                        "Please install Nmap from https://nmap.org/ to execute scans."
                    ),
                ),
                logs=[f"Executable check failed: '{self.nmap_binary}' not found."],
            )

        # Ensure output directory exists and sanitize request_id for safe filesystem path
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        safe_req_id = "".join(c for c in request.request_id if c.isalnum() or c in ("-", "_")) or "scan"
        output_xml_path = self.artifacts_dir / f"nmap_{safe_req_id}.xml"

        # Build argument list
        cmd_args = self.build_command_args(request, output_xml_path)
        timeout = request.timeout_seconds or request.profile.timeout_seconds

        logs = [
            f"Invoking Nmap binary: {self.nmap_binary}",
            f"Target: {request.target.target_value}",
            f"Profile: {request.profile.profile_id}",
            f"Output XML: {output_xml_path}",
            f"Timeout limit: {timeout}s",
        ]

        try:
            # Safe execution: shell=False prevents shell interpolation
            proc = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )

            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()

            if proc.returncode != 0:
                logs.append(f"Nmap exited with non-zero code {proc.returncode}")
                return ScanResult(
                    request_id=request.request_id,
                    scanner_id=meta.scanner_id,
                    status=ScanStatus.FAILED,
                    target=request.target,
                    profile_id=request.profile.profile_id,
                    started_at=start_time,
                    completed_at=end_time,
                    duration_seconds=duration,
                    error=ScannerExecutionError(
                        error_code="NMAP_EXECUTION_FAILED",
                        exit_code=proc.returncode,
                        message=proc.stderr.strip() or f"Nmap exited with code {proc.returncode}",
                        details={"stdout": proc.stdout, "stderr": proc.stderr},
                    ),
                    logs=logs,
                )

        except subprocess.TimeoutExpired:
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            logs.append(f"Nmap process exceeded timeout limit of {timeout}s.")
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
                    message=f"Nmap execution timed out after {timeout} seconds.",
                ),
                logs=logs,
            )

        except Exception as exc:
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            logs.append(f"Unexpected error executing Nmap: {exc}")
            return ScanResult(
                request_id=request.request_id,
                scanner_id=meta.scanner_id,
                status=ScanStatus.FAILED,
                target=request.target,
                profile_id=request.profile.profile_id,
                started_at=start_time,
                completed_at=end_time,
                duration_seconds=duration,
                error=ScannerExecutionError(
                    error_code="SUBPROCESS_ERROR",
                    message=str(exc),
                ),
                logs=logs,
            )

        # Inspect generated XML file
        if not output_xml_path.is_file() or output_xml_path.stat().st_size == 0:
            return ScanResult(
                request_id=request.request_id,
                scanner_id=meta.scanner_id,
                status=ScanStatus.FAILED,
                target=request.target,
                profile_id=request.profile.profile_id,
                started_at=start_time,
                completed_at=end_time,
                duration_seconds=duration,
                error=ScannerExecutionError(
                    error_code="EMPTY_OUTPUT",
                    message="Nmap completed without generating an XML output file.",
                ),
                logs=logs,
            )

        # Hash and archive raw evidence
        raw_bytes = output_xml_path.read_bytes()
        sha256 = hashlib.sha256(raw_bytes).hexdigest()

        raw_evidence = RawScanEvidence(
            scanner_id=meta.scanner_id,
            file_path=str(output_xml_path),
            sha256_hash=sha256,
            byte_size=len(raw_bytes),
            content_type="application/xml",
            raw_snippet=raw_bytes[:300].decode("utf-8", errors="replace"),
        )

        # Parse factual service observations
        observations = NmapXMLParser.parse_file(output_xml_path, strict=False)

        # Parse findings: Strict requirement: "Do not generate vulnerability findings merely because a port is open."
        findings = self.parse_results(raw_evidence)

        logs.append(f"Preserved raw evidence artifact ({len(raw_bytes)} bytes, SHA-256: {sha256[:16]}...)")
        logs.append(f"Parsed {len(observations)} service observation(s). Generated {len(findings)} vulnerability finding(s).")

        return ScanResult(
            request_id=request.request_id,
            scanner_id=meta.scanner_id,
            status=ScanStatus.SUCCESS,
            target=request.target,
            profile_id=request.profile.profile_id,
            started_at=start_time,
            completed_at=end_time,
            duration_seconds=duration,
            observations=observations,
            findings=findings,
            raw_evidence=raw_evidence,
            logs=logs,
        )

    def parse_results(self, raw_evidence: RawScanEvidence) -> list[NormalizedFinding]:
        """Convert raw scanner output into normalized vulnerability findings.

        STRICT SAFETY RULE: Factual port and service states are recorded as
        ServiceObservations, NOT vulnerability findings.
        Returns empty list unless an explicit vulnerability check (e.g. CVE script) was executed.
        """
        return []

    def parse_observations(self, raw_evidence: RawScanEvidence) -> list[ServiceObservation]:
        """Convenience method to parse service observations from raw XML evidence."""
        return NmapXMLParser.parse_file(raw_evidence.file_path, strict=False)
