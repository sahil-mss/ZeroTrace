"""Scan profile definitions and approved profile registry.

TASK 2: Predefined scan profiles constrain scanner execution parameters,
guarantee bounded resource consumption, and enforce human approval workflows
for intrusive operations.
"""

from typing import Any
from pydantic import BaseModel, Field, field_validator

from aegispt.security_engine.schemas.enums import (
    AssetType,
    ImpactLevel,
    OutputFormat,
    PermissionLevel,
)


class ResourceBudget(BaseModel):
    """Resource constraints allocated to a scanner execution."""

    max_cpu_percent: int = Field(
        default=50,
        ge=1,
        le=100,
        description="Maximum CPU percentage ceiling allowed for the process.",
    )
    max_memory_mb: int = Field(
        default=512,
        ge=64,
        le=8192,
        description="Maximum RAM allocation in megabytes.",
    )
    max_rate_limit: int = Field(
        default=100,
        ge=1,
        le=10000,
        description="Maximum requests or packets per second to prevent lab exhaustion.",
    )


class ScanProfile(BaseModel):
    """Immutable specification for an approved scanner execution profile."""

    profile_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier for the scan profile (e.g. 'mock_baseline').",
    )
    name: str = Field(
        ...,
        min_length=1,
        description="Human-readable title of the profile.",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Detailed explanation of scanner actions performed.",
    )
    supported_asset_types: list[AssetType] = Field(
        ...,
        min_length=1,
        description="Asset categories compatible with this profile.",
    )
    required_permission_level: PermissionLevel = Field(
        default=PermissionLevel.SAFE_AUDIT,
        description="Privilege level required to trigger this profile.",
    )
    resource_budget: ResourceBudget = Field(
        default_factory=ResourceBudget,
        description="Hardware and bandwidth budget.",
    )
    timeout_seconds: int = Field(
        default=300,
        gt=0,
        le=3600,
        description="Hard process timeout in seconds before cancellation.",
    )
    max_concurrency: int = Field(
        default=1,
        ge=1,
        le=16,
        description="Maximum concurrent targets or tasks permitted under this profile.",
    )
    expected_output_format: OutputFormat = Field(
        ...,
        description="Primary serialization format expected from the tool (XML, JSON, etc.).",
    )
    potential_impact: ImpactLevel = Field(
        default=ImpactLevel.NONE,
        description="Estimated operational impact on the target lab system.",
    )
    requires_human_approval: bool = Field(
        default=False,
        description="True if human operator must sign off before execution.",
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Whitelisted, tool-specific parameters (bounded, no arbitrary flags).",
    )

    @field_validator("profile_id")
    @classmethod
    def validate_profile_id_slug(cls, val: str) -> str:
        """Ensure profile_id is lowercase slug format."""
        slug = val.strip().lower()
        if not all(c.isalnum() or c in ("-", "_") for c in slug):
            raise ValueError(
                f"Profile ID '{val}' must contain only alphanumeric characters, underscores, or hyphens."
            )
        return slug


# ============================================================================
# APPROVED PROFILE REGISTRY
# Predefined approved profiles prevent the AI or backend from constructing
# arbitrary, unsafe scanner command strings.
# ============================================================================

MOCK_BASELINE_PROFILE = ScanProfile(
    profile_id="mock_baseline",
    name="Mock Baseline Discovery",
    description="Deterministic mock scanner for smoke testing and interface validation.",
    supported_asset_types=[
        AssetType.IP_ADDRESS,
        AssetType.HOSTNAME,
        AssetType.WEB_URL,
    ],
    required_permission_level=PermissionLevel.READ_ONLY,
    resource_budget=ResourceBudget(max_cpu_percent=10, max_memory_mb=128, max_rate_limit=50),
    timeout_seconds=30,
    max_concurrency=2,
    expected_output_format=OutputFormat.JSON,
    potential_impact=ImpactLevel.NONE,
    requires_human_approval=False,
)

MOCK_INTRUSIVE_PROFILE = ScanProfile(
    profile_id="mock_intrusive_approval",
    name="Mock Intrusive Approval Test",
    description="Mock intrusive profile used to verify human approval gating.",
    supported_asset_types=[AssetType.IP_ADDRESS, AssetType.WEB_URL],
    required_permission_level=PermissionLevel.INTRUSIVE,
    resource_budget=ResourceBudget(max_cpu_percent=25, max_memory_mb=256, max_rate_limit=100),
    timeout_seconds=30,
    max_concurrency=1,
    expected_output_format=OutputFormat.JSON,
    potential_impact=ImpactLevel.HIGH,
    requires_human_approval=True,
)

MOCK_TIMEOUT_SIMULATION_PROFILE = ScanProfile(
    profile_id="mock_timeout_sim",
    name="Mock Timeout Simulation",
    description="Mock profile configured to trigger deterministic timeout handling.",
    supported_asset_types=[AssetType.IP_ADDRESS, AssetType.HOSTNAME, AssetType.WEB_URL],
    required_permission_level=PermissionLevel.READ_ONLY,
    resource_budget=ResourceBudget(max_cpu_percent=10, max_memory_mb=128, max_rate_limit=10),
    timeout_seconds=1,
    max_concurrency=1,
    expected_output_format=OutputFormat.JSON,
    potential_impact=ImpactLevel.NONE,
    requires_human_approval=False,
    parameters={"simulate_timeout": True},
)

NMAP_FAST_DISCOVERY_PROFILE = ScanProfile(
    profile_id="nmap_fast_discovery",
    name="Nmap Fast Service Discovery",
    description="Lightweight port discovery across top ports with version detection.",
    supported_asset_types=[AssetType.IP_ADDRESS, AssetType.HOSTNAME, AssetType.CIDR_RANGE],
    required_permission_level=PermissionLevel.SAFE_AUDIT,
    resource_budget=ResourceBudget(max_cpu_percent=50, max_memory_mb=256, max_rate_limit=200),
    timeout_seconds=120,
    max_concurrency=2,
    expected_output_format=OutputFormat.XML,
    potential_impact=ImpactLevel.LOW,
    requires_human_approval=False,
    parameters={"flags": ["-F", "-T4", "-Pn", "--no-stylesheet"]},
)

NMAP_SERVICE_VERSION_PROFILE = ScanProfile(
    profile_id="nmap_service_version",
    name="Nmap Service Version Probe",
    description="Detailed service identification and software version extraction.",
    supported_asset_types=[AssetType.IP_ADDRESS, AssetType.HOSTNAME],
    required_permission_level=PermissionLevel.SAFE_AUDIT,
    resource_budget=ResourceBudget(max_cpu_percent=50, max_memory_mb=256, max_rate_limit=150),
    timeout_seconds=300,
    max_concurrency=2,
    expected_output_format=OutputFormat.XML,
    potential_impact=ImpactLevel.LOW,
    requires_human_approval=False,
    parameters={"flags": ["-sV", "--version-light", "-T4", "-Pn", "--no-stylesheet"]},
)

NMAP_CUSTOM_PORTS_PROFILE = ScanProfile(
    profile_id="nmap_custom_ports",
    name="Nmap Custom Ports Scan",
    description="Targeted service inspection restricted to target-specified port list.",
    supported_asset_types=[AssetType.IP_ADDRESS, AssetType.HOSTNAME],
    required_permission_level=PermissionLevel.SAFE_AUDIT,
    resource_budget=ResourceBudget(max_cpu_percent=50, max_memory_mb=256, max_rate_limit=150),
    timeout_seconds=180,
    max_concurrency=2,
    expected_output_format=OutputFormat.XML,
    potential_impact=ImpactLevel.LOW,
    requires_human_approval=False,
    parameters={"flags": ["-sV", "-T4", "-Pn", "--no-stylesheet"]},
)

# Registry dictionary mapping profile_id to validated profile instance
APPROVED_SCAN_PROFILES: dict[str, ScanProfile] = {
    MOCK_BASELINE_PROFILE.profile_id: MOCK_BASELINE_PROFILE,
    MOCK_INTRUSIVE_PROFILE.profile_id: MOCK_INTRUSIVE_PROFILE,
    MOCK_TIMEOUT_SIMULATION_PROFILE.profile_id: MOCK_TIMEOUT_SIMULATION_PROFILE,
    NMAP_FAST_DISCOVERY_PROFILE.profile_id: NMAP_FAST_DISCOVERY_PROFILE,
    NMAP_SERVICE_VERSION_PROFILE.profile_id: NMAP_SERVICE_VERSION_PROFILE,
    NMAP_CUSTOM_PORTS_PROFILE.profile_id: NMAP_CUSTOM_PORTS_PROFILE,
}
