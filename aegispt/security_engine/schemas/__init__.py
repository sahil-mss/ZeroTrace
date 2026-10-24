"""Data schemas and contracts for the Security Testing Engine.

Provides unified Pydantic models for targets, scan profiles, normalized findings,
and scan execution results consumed by Person 1 and Person 3.
"""

from aegispt.security_engine.schemas.enums import (
    AssetType,
    ImpactLevel,
    JobStatus,
    OutputFormat,
    PermissionLevel,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from aegispt.security_engine.schemas.finding import (
    EvidenceReference,
    NormalizedFinding,
)
from aegispt.security_engine.schemas.job import (
    JobStateTransition,
    ScanJob,
    ScanJobRequest,
    ScanJobResponse,
)
from aegispt.security_engine.schemas.observation import ServiceObservation
from aegispt.security_engine.schemas.profile import (
    APPROVED_SCAN_PROFILES,
    MOCK_BASELINE_PROFILE,
    MOCK_INTRUSIVE_PROFILE,
    MOCK_TIMEOUT_SIMULATION_PROFILE,
    NMAP_CUSTOM_PORTS_PROFILE,
    NMAP_FAST_DISCOVERY_PROFILE,
    NMAP_SERVICE_VERSION_PROFILE,
    ResourceBudget,
    ScanProfile,
    ZAP_ACTIVE_BASELINE_PROFILE,
    ZAP_PASSIVE_BASELINE_PROFILE,
)
from aegispt.security_engine.schemas.result import (
    RawScanEvidence,
    ScannerExecutionError,
    ScannerMetadata,
    ScanRequest,
    ScanResult,
)
from aegispt.security_engine.schemas.target import ScanTarget

__all__ = [
    # Enums
    "ScanStatus",
    "JobStatus",
    "VerificationStatus",
    "Severity",
    "AssetType",
    "PermissionLevel",
    "ImpactLevel",
    "OutputFormat",
    # Job and Lifecycle
    "ScanJobRequest",
    "JobStateTransition",
    "ScanJob",
    "ScanJobResponse",
    # Target
    "ScanTarget",
    # Profile
    "ResourceBudget",
    "ScanProfile",
    "APPROVED_SCAN_PROFILES",
    "MOCK_BASELINE_PROFILE",
    "MOCK_INTRUSIVE_PROFILE",
    "MOCK_TIMEOUT_SIMULATION_PROFILE",
    "NMAP_FAST_DISCOVERY_PROFILE",
    "NMAP_SERVICE_VERSION_PROFILE",
    "NMAP_CUSTOM_PORTS_PROFILE",
    "ZAP_PASSIVE_BASELINE_PROFILE",
    "ZAP_ACTIVE_BASELINE_PROFILE",
    # Finding & Evidence
    "EvidenceReference",
    "NormalizedFinding",
    # Service Observation
    "ServiceObservation",
    # Result & Request
    "ScannerMetadata",
    "ScanRequest",
    "RawScanEvidence",
    "ScannerExecutionError",
    "ScanResult",
]
