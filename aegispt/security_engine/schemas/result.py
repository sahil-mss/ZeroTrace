"""Scan request, execution result, and scanner metadata models.

TASK 3: Complete model definitions for scanner execution lifecycle,
including status tracking, raw artifact tracking, normalized findings,
and error reporting.
"""

from datetime import datetime, timezone
from typing import Any
import uuid

from pydantic import BaseModel, Field

from aegispt.security_engine.schemas.enums import AssetType, ScanStatus
from aegispt.security_engine.schemas.finding import NormalizedFinding
from aegispt.security_engine.schemas.observation import ServiceObservation
from aegispt.security_engine.schemas.profile import ScanProfile
from aegispt.security_engine.schemas.target import ScanTarget


class ScannerMetadata(BaseModel):
    """Static metadata and capability report for an integrated scanner."""

    scanner_id: str = Field(
        ...,
        min_length=1,
        description="Canonical unique ID (e.g. 'mock_scanner', 'nmap', 'owasp_zap').",
    )
    name: str = Field(
        ...,
        min_length=1,
        description="Formal scanner name.",
    )
    version: str = Field(
        ...,
        min_length=1,
        description="Tool or adapter version string.",
    )
    vendor: str = Field(
        ...,
        min_length=1,
        description="Author or organization behind the tool.",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Overview of scanner purpose and capabilities.",
    )
    supported_asset_types: list[AssetType] = Field(
        ...,
        min_length=1,
        description="List of asset categories this scanner can inspect.",
    )
    supported_profiles: list[str] = Field(
        ...,
        min_length=1,
        description="List of profile IDs supported by this scanner.",
    )


class ScanRequest(BaseModel):
    """Structured request to execute a security scan."""

    request_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique request tracing ID.",
    )
    scanner_id: str = Field(
        ...,
        min_length=1,
        description="Target scanner to execute.",
    )
    target: ScanTarget = Field(
        ...,
        description="Validated target asset.",
    )
    profile: ScanProfile = Field(
        ...,
        description="Approved scan profile to use.",
    )
    timeout_seconds: int | None = Field(
        default=None,
        gt=0,
        description="Optional timeout override, cannot exceed profile timeout.",
    )
    options: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional execution flags (e.g. simulation triggers).",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when request was scheduled.",
    )


class RawScanEvidence(BaseModel):
    """Reference to raw tool output preserved on disk for audit integrity."""

    artifact_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique reference ID for the stored evidence.",
    )
    scanner_id: str = Field(
        ...,
        min_length=1,
        description="Scanner that produced this raw artifact.",
    )
    file_path: str = Field(
        ...,
        min_length=1,
        description="Absolute or relative file path to the raw output on disk.",
    )
    sha256_hash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description="Cryptographic SHA-256 digest of the raw artifact.",
    )
    byte_size: int = Field(
        ...,
        ge=0,
        description="Size of the raw artifact in bytes.",
    )
    content_type: str = Field(
        default="application/json",
        description="MIME type of the raw artifact (e.g., application/xml, application/json).",
    )
    raw_snippet: str | None = Field(
        default=None,
        description="Optional preview snippet for rapid display in logs or UI.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when artifact was persisted.",
    )


class ScannerExecutionError(BaseModel):
    """Structured report when a scanner fails or encounters an unhandled condition."""

    error_code: str = Field(
        ...,
        min_length=1,
        description="Machine-readable error category (e.g. 'TIMEOUT_EXCEEDED', 'PROCESS_CRASH').",
    )
    message: str = Field(
        ...,
        min_length=1,
        description="Human-readable explanation of failure.",
    )
    exit_code: int | None = Field(
        default=None,
        description="Process exit code if tool terminated abnormally.",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Supplementary diagnostics, stderr output, or stack trace.",
    )
    occurred_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the error event.",
    )


class ScanResult(BaseModel):
    """Comprehensive scan execution result returned to Person 1 orchestrator."""

    result_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique identifier for the scan result.",
    )
    request_id: str = Field(
        ...,
        min_length=1,
        description="Original request ID that triggered this scan.",
    )
    scanner_id: str = Field(
        ...,
        min_length=1,
        description="Scanner that executed this assessment.",
    )
    status: ScanStatus = Field(
        ...,
        description="Terminal execution status (SUCCESS, FAILED, TIMEOUT, etc.).",
    )
    target: ScanTarget = Field(
        ...,
        description="Target asset that was assessed.",
    )
    profile_id: str = Field(
        ...,
        min_length=1,
        description="Profile ID executed.",
    )
    started_at: datetime = Field(
        ...,
        description="Timestamp when scanner execution began.",
    )
    completed_at: datetime = Field(
        ...,
        description="Timestamp when scanner execution finished.",
    )
    duration_seconds: float = Field(
        ...,
        ge=0.0,
        description="Elapsed wall-clock execution time in seconds.",
    )
    findings: list[NormalizedFinding] = Field(
        default_factory=list,
        description="List of normalized security findings parsed from scan results.",
    )
    observations: list[ServiceObservation] = Field(
        default_factory=list,
        description="List of factual network service observations (open/closed ports, service telemetry).",
    )
    raw_evidence: RawScanEvidence | None = Field(
        default=None,
        description="Pointer to raw preserved scan evidence artifact.",
    )
    error: ScannerExecutionError | None = Field(
        default=None,
        description="Error details if status is FAILED or TIMEOUT.",
    )
    logs: list[str] = Field(
        default_factory=list,
        description="Execution audit log lines.",
    )
