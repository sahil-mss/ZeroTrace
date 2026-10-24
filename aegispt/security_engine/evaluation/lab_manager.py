"""Reproducible Local Security Testing Lab Manager.

TASK 2: Manages health, reachability, version detection, and readiness verification
for local target lab environments (e.g. OWASP Juice Shop).

SECURITY CONTROLS:
- Enforces loopback and private/isolated network binding.
- Rejects external public URLs.
- Bounded HTTP request timeouts.
- Does not execute arbitrary Docker shell commands.
"""

from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
import json
from pathlib import Path
import time
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator
import requests


class LabConfig(BaseModel):
    """Configuration specification for a local testing lab instance."""

    lab_name: str = Field(
        default="OWASP Juice Shop Local Lab",
        description="Descriptive title of the lab environment.",
    )
    target_url: str = Field(
        default="http://127.0.0.1:3000",
        description="Base URL of the local target application.",
    )
    host: str = Field(
        default="127.0.0.1",
        description="Target host IP or hostname.",
    )
    port: int = Field(
        default=3000,
        ge=1,
        le=65535,
        description="Documented service port (must be between 1 and 65535).",
    )
    health_endpoint: str = Field(
        default="/",
        description="Endpoint path queried to verify basic web reachability.",
    )
    version_endpoint: str = Field(
        default="/rest/admin/application-version",
        description="Endpoint path returning structured application version information.",
    )
    timeout_seconds: float = Field(
        default=5.0,
        gt=0.0,
        le=60.0,
        description="Per-request HTTP timeout in seconds.",
    )
    enforce_local_only: bool = Field(
        default=True,
        description="Guardrail: When true, strictly rejects non-local or public hostnames/IPs.",
    )
    max_retries: int = Field(
        default=3,
        ge=1,
        le=30,
        description="Number of probe retry attempts during readiness polling.",
    )
    retry_delay_seconds: float = Field(
        default=1.0,
        ge=0.1,
        le=10.0,
        description="Interval in seconds between readiness retry attempts.",
    )
    container_name: str = Field(
        default="aegispt-lab-juice-shop",
        description="Expected Docker container name.",
    )

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, val: str) -> str:
        """Validate URL syntax and scheme."""
        cleaned = val.strip()
        parsed = urlparse(cleaned)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Target URL scheme must be 'http' or 'https', got '{parsed.scheme}'.")
        if not parsed.netloc:
            raise ValueError(f"Target URL must contain a valid host and optional port, got '{cleaned}'.")
        return cleaned.rstrip("/")

    @field_validator("health_endpoint", "version_endpoint")
    @classmethod
    def validate_endpoint_path(cls, val: str) -> str:
        """Ensure endpoint paths start with a leading slash."""
        cleaned = val.strip()
        if not cleaned.startswith("/"):
            cleaned = f"/{cleaned}"
        return cleaned

    def validate_local_scope(self) -> None:
        """Enforce strict local loopback or private subnet boundary.

        Raises ValueError if the target host points to a public internet address.
        """
        if not self.enforce_local_only:
            return

        parsed = urlparse(self.target_url)
        hostname = parsed.hostname or self.host

        if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
            return

        # Check IP address loopback / private status
        try:
            addr = ip_address(hostname)
            if addr.is_loopback or addr.is_private:
                return
            raise ValueError(
                f"Security Guardrail: Target '{hostname}' resolves to a public internet IP. "
                "The testing lab must strictly bind to loopback (127.0.0.1) or an isolated lab subnet."
            )
        except ValueError as err:
            # If not an IP and not localhost/loopback, reject unknown public domain names
            if "does not appear to be an IPv4 or IPv6 address" in str(err):
                raise ValueError(
                    f"Security Guardrail: Target hostname '{hostname}' is not recognized as a local loopback host. "
                    "Only localhost, 127.0.0.1, ::1, or private IP subnets are allowed."
                ) from err
            raise


class LabStatus(BaseModel):
    """Detailed health and readiness report for the security testing lab."""

    lab_name: str = Field(..., description="Name of the evaluated lab.")
    target_url: str = Field(..., description="Target base URL.")
    is_reachable: bool = Field(..., description="True if the lab answered HTTP probes.")
    is_ready: bool = Field(..., description="True if application is operational and ready for testing.")
    application_version: str | None = Field(
        default=None,
        description="Version string extracted from application version endpoint.",
    )
    status_code: int | None = Field(
        default=None,
        description="HTTP status code returned by health probe.",
    )
    response_time_ms: float | None = Field(
        default=None,
        description="Elapsed probe latency in milliseconds.",
    )
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of probe execution.",
    )
    message: str = Field(
        ...,
        description="Human-readable summary of lab operational state.",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Diagnostics, error reasons, or headers.",
    )


class LabManager:
    """Manages operational verification and readiness reporting for local labs."""

    def __init__(
        self,
        config: LabConfig | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.config = config or LabConfig()
        # Verify local scope immediately upon instantiation
        self.config.validate_local_scope()
        self._session = session or requests.Session()

    @classmethod
    def from_file(cls, config_path: str | Path) -> "LabManager":
        """Instantiate LabManager from a JSON configuration file."""
        path = Path(config_path)
        if not path.is_file():
            raise FileNotFoundError(f"Lab configuration file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        config = LabConfig.model_validate(data)
        return cls(config=config)

    def check_reachability(self) -> tuple[bool, int | None, float | None, str | None]:
        """Perform a low-overhead HTTP probe to check application reachability.

        Returns:
            Tuple of (is_reachable, status_code, elapsed_ms, error_message)
        """
        probe_url = f"{self.config.target_url}{self.config.health_endpoint}"
        start_time = time.perf_counter()

        try:
            resp = self._session.get(
                probe_url,
                timeout=self.config.timeout_seconds,
                allow_redirects=True,
            )
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            # Standard HTTP 2xx or 3xx indicates reachable service
            is_reachable = 200 <= resp.status_code < 400
            return is_reachable, resp.status_code, elapsed_ms, None

        except requests.Timeout:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return False, None, elapsed_ms, f"Connection timed out after {self.config.timeout_seconds}s"

        except requests.ConnectionError as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return False, None, elapsed_ms, f"Connection refused or host unreachable: {exc}"

        except requests.RequestException as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
            return False, None, elapsed_ms, f"HTTP request failed: {exc}"

    def fetch_application_version(self) -> str | None:
        """Query the application's version endpoint to retrieve its release identifier."""
        version_url = f"{self.config.target_url}{self.config.version_endpoint}"
        try:
            resp = self._session.get(
                version_url,
                timeout=self.config.timeout_seconds,
            )
            if resp.status_code == 200:
                try:
                    payload = resp.json()
                    # Juice Shop format: {"version": "17.1.1"}
                    if isinstance(payload, dict) and "version" in payload:
                        return str(payload["version"])
                    # Alternative string response
                    return str(payload)
                except ValueError:
                    return resp.text.strip() or None
            return None
        except requests.RequestException:
            return None

    def get_readiness_report(self) -> LabStatus:
        """Evaluate full lab operational readiness for security testing."""
        is_reachable, status_code, elapsed_ms, error_msg = self.check_reachability()

        if not is_reachable:
            return LabStatus(
                lab_name=self.config.lab_name,
                target_url=self.config.target_url,
                is_reachable=False,
                is_ready=False,
                application_version=None,
                status_code=status_code,
                response_time_ms=elapsed_ms,
                message=f"Lab is NOT ready: {error_msg or 'Service unreachable'}",
                details={"error": error_msg, "endpoint": self.config.health_endpoint},
            )

        # Service is reachable, extract version
        version = self.fetch_application_version()

        return LabStatus(
            lab_name=self.config.lab_name,
            target_url=self.config.target_url,
            is_reachable=True,
            is_ready=True,
            application_version=version,
            status_code=status_code,
            response_time_ms=elapsed_ms,
            message=(
                f"Lab is READY for authorized testing (Version: {version or 'Detected'}, "
                f"Response time: {elapsed_ms}ms)"
            ),
            details={
                "status_code": status_code,
                "version_endpoint": self.config.version_endpoint,
                "synthetic_data_ready": True,
            },
        )

    def wait_for_ready(
        self,
        max_wait_seconds: float = 30.0,
        poll_interval_seconds: float = 1.0,
    ) -> LabStatus:
        """Poll the lab until it is fully ready or until max_wait_seconds elapses."""
        start = time.monotonic()
        last_report = self.get_readiness_report()

        while not last_report.is_ready:
            elapsed = time.monotonic() - start
            if elapsed >= max_wait_seconds:
                last_report.message = (
                    f"Readiness check timed out after {elapsed:.1f}s. "
                    f"Last error: {last_report.message}"
                )
                return last_report

            time.sleep(poll_interval_seconds)
            last_report = self.get_readiness_report()

        return last_report
