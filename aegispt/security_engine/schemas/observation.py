"""Network service and port observation schemas.

TASK 4: Standard representation of network service discovery telemetry.
Service observations record factual operational states (open/closed ports,
banners, versions) and are strictly separated from vulnerability findings.
"""

from datetime import datetime, timezone

from pydantic import BaseModel, Field


class ServiceObservation(BaseModel):
    """Observation of an exposed network port and service.

    Factual discovery telemetry extracted from network scanners (e.g. Nmap).
    Does NOT constitute a vulnerability finding merely because a port is open.
    """

    host_address: str = Field(
        ...,
        min_length=1,
        description="Target IP address where service was observed.",
    )
    hostname: str | None = Field(
        default=None,
        description="Host domain or FQDN if resolved by scanner.",
    )
    port: int = Field(
        ...,
        ge=1,
        le=65535,
        description="Port number (1-65535).",
    )
    protocol: str = Field(
        default="tcp",
        description="Transport protocol (e.g. 'tcp', 'udp').",
    )
    state: str = Field(
        ...,
        description="Port state (e.g. 'open', 'closed', 'filtered', 'unfiltered').",
    )
    service_name: str | None = Field(
        default=None,
        description="Identified service name (e.g. 'http', 'ssh', 'domain').",
    )
    service_version: str | None = Field(
        default=None,
        description="Identified service version string.",
    )
    product: str | None = Field(
        default=None,
        description="Software product name (e.g. 'Node.js Express framework', 'OpenSSH').",
    )
    extra_info: str | None = Field(
        default=None,
        description="Additional banner info or OS hints.",
    )
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when observation was captured.",
    )
