"""Target and asset specification schemas.

NOTE (PROVISIONAL MODEL):
This model is provisional for Person 2's security engine module. Once Person 1
provides the central backend 'Asset' entity, this model will be adapted or aliased
to maintain strict backward compatibility.
"""

from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse
import uuid

from pydantic import BaseModel, Field, field_validator

from aegispt.security_engine.schemas.enums import AssetType


class ScanTarget(BaseModel):
    """Specification of an assessment target.

    Includes target value, asset classification, port restrictions,
    and built-in safety boundaries.
    """

    target_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique identifier for the target instance.",
    )
    asset_type: AssetType = Field(
        ...,
        description="Type of asset (e.g. IP_ADDRESS, HOSTNAME, WEB_URL).",
    )
    target_value: str = Field(
        ...,
        min_length=1,
        description="The literal value: IPv4/IPv6, FQDN hostname, CIDR, or URL.",
    )
    ports: list[int] | None = Field(
        default=None,
        description="Optional list of destination ports bounded to 1-65535.",
    )
    is_in_scope: bool = Field(
        default=True,
        description="Explicit authorization flag confirming target is inside engagement scope.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary supplementary metadata (tags, environment name, lab ID).",
    )

    @field_validator("target_value")
    @classmethod
    def validate_target_value_not_blank(cls, value: str) -> str:
        """Ensure target value is not empty or whitespace."""
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Target value must not be empty or blank whitespace.")
        return cleaned

    @field_validator("ports")
    @classmethod
    def validate_port_bounds(cls, ports: list[int] | None) -> list[int] | None:
        """Ensure all ports fall within valid TCP/UDP boundaries (1 to 65535)."""
        if ports is None:
            return None
        if not ports:
            raise ValueError("Port list cannot be empty when explicitly specified.")
        for port in ports:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} is out of bounds (allowed: 1-65535).")
        return sorted(list(set(ports)))

    def is_local_or_private(self) -> bool:
        """Check whether the target resolves to localhost or private/lab IP range.

        Returns True for localhost, loopback (127.0.0.0/8, ::1), or RFC1918/Docker networks.
        """
        val = self.target_value
        if self.asset_type == AssetType.WEB_URL:
            parsed = urlparse(val)
            val = parsed.hostname or val

        if val.lower() in ("localhost", "127.0.0.1", "::1", "juice-shop", "local-lab"):
            return True

        try:
            addr = ip_address(val)
            return addr.is_loopback or addr.is_private
        except ValueError:
            pass

        try:
            net = ip_network(val, strict=False)
            return net.is_loopback or net.is_private
        except ValueError:
            pass

        return False
