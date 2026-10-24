"""Configuration management for OWASP ZAP adapter.

TASK 1: Manages connection settings, target URLs, timeouts, concurrency,
and output directories.
SECURITY: Secrets (API keys) are loaded from environment variables and never
stored in source code.
"""

from ipaddress import ip_address
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


class ZAPConfig(BaseModel):
    """Configuration specification for the OWASP ZAP integration."""

    zap_host: str = Field(
        default="127.0.0.1",
        description="Host IP where the OWASP ZAP daemon is listening.",
    )
    zap_port: int = Field(
        default=8080,
        ge=1,
        le=65535,
        description="Port for the OWASP ZAP REST API.",
    )
    api_key: str | None = Field(
        default=None,
        description="ZAP API key for authenticated requests. Defaults to env var AEGISPT_ZAP_API_KEY.",
    )
    target_url: str = Field(
        default="http://127.0.0.1:3000",
        description="Target web application base URL (e.g. OWASP Juice Shop).",
    )
    timeout_seconds: float = Field(
        default=180.0,
        gt=0.0,
        le=3600.0,
        description="Maximum execution timeout for ZAP operations.",
    )
    max_concurrency: int = Field(
        default=1,
        ge=1,
        le=4,
        description="Maximum concurrent scans allowed against the lab.",
    )
    permitted_profiles: list[str] = Field(
        default_factory=lambda: ["zap_passive_baseline", "zap_active_baseline"],
        description="Whitelisted scan profiles approved for execution.",
    )
    artifacts_dir: Path = Field(
        default_factory=lambda: Path("artifacts/scans"),
        description="Local directory where raw JSON evidence files are archived.",
    )
    enforce_local_only: bool = Field(
        default=True,
        description="Guardrail: strictly reject non-local or public destinations.",
    )

    def model_post_init(self, __context: Any) -> None:
        """Load API key from environment variable if not explicitly supplied."""
        if self.api_key is None:
            self.api_key = os.environ.get("AEGISPT_ZAP_API_KEY") or os.environ.get("ZAP_API_KEY")

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, val: str) -> str:
        """Validate URL syntax and scheme."""
        cleaned = val.strip()
        parsed = urlparse(cleaned)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Target URL scheme must be 'http' or 'https', got '{parsed.scheme}'.")
        if not parsed.netloc:
            raise ValueError(f"Target URL must include a host, got '{cleaned}'.")
        return cleaned.rstrip("/")

    @property
    def base_api_url(self) -> str:
        """Return the formatted base URL for ZAP API requests."""
        return f"http://{self.zap_host}:{self.zap_port}"

    def validate_local_scope(self) -> None:
        """Ensure both ZAP daemon host and target URL point to local/lab boundaries.

        Raises ValueError if either endpoint resolves to a public internet address.
        """
        if not self.enforce_local_only:
            return

        for label, val in [("ZAP daemon", self.zap_host), ("Target URL", self.target_url)]:
            parsed = urlparse(val if "://" in val else f"http://{val}")
            hostname = parsed.hostname or val

            if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
                continue

            try:
                addr = ip_address(hostname)
                if addr.is_loopback or addr.is_private:
                    continue
                raise ValueError(
                    f"Security Guardrail: {label} '{hostname}' resolves to a public IP. "
                    "ZAP operations are strictly restricted to localhost or private lab subnets."
                )
            except ValueError as exc:
                if "does not appear to be an IPv4 or IPv6 address" in str(exc):
                    raise ValueError(
                        f"Security Guardrail: {label} hostname '{hostname}' is not a local loopback host. "
                        "Only localhost, 127.0.0.1, ::1, or private IP subnets are allowed."
                    ) from exc
                raise
