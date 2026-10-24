import ipaddress
from datetime import datetime
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis_common.enums import AssessmentStatus, TargetType, TestPermissionLevel
from aegis_common.utils import ensure_utc, generate_id, utc_now


class ScopeRule(BaseModel):
    """
    Represents an explicitly approved target boundary.
    Defaults to the narrowest reasonable permission; subdomains are never auto-authorized.
    """

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(default_factory=lambda: generate_id("rule"))
    target_type: TargetType = Field(..., description="Classification of target boundary")
    target_value: str = Field(..., min_length=1, description="Host, IP, CIDR, or URL")
    approved_ports: list[int] = Field(
        default_factory=list, description="Explicitly approved TCP/UDP ports (e.g. [80, 443])"
    )
    permitted_path_prefixes: list[str] = Field(
        default_factory=list, description="Explicitly permitted URL paths (e.g. ['/api', '/v1'])"
    )
    include_subdomains: bool = Field(
        default=False,
        description="Must be explicitly True to authorize subdomains. Defaults to False.",
    )
    is_excluded: bool = Field(
        default=False, description="If True, acts as a hard deny exclusion rule."
    )
    description: str | None = Field(default=None, max_length=255)

    @field_validator("target_type", mode="before")
    @classmethod
    def normalize_target_type(cls, v: object) -> object:
        if isinstance(v, str):
            return v.strip().upper()
        return v

    @field_validator("approved_ports")
    @classmethod
    def validate_ports(cls, ports: list[int]) -> list[int]:
        for p in ports:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} is outside valid range 1-65535")
        return sorted(list(set(ports)))

    @field_validator("target_value")
    @classmethod
    def validate_target_value(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("target_value cannot be empty or whitespace.")
        return clean

    @model_validator(mode="after")
    def validate_target_format(self) -> "ScopeRule":
        val = self.target_value
        if self.target_type == TargetType.IP_ADDRESS:
            try:
                ipaddress.ip_address(val)
            except ValueError as err:
                raise ValueError(f"Invalid IP address format: {val}") from err
        elif self.target_type == TargetType.CIDR:
            try:
                ipaddress.ip_network(val, strict=False)
            except ValueError as err:
                raise ValueError(f"Invalid CIDR range format: {val}") from err
        elif self.target_type == TargetType.URL:
            parsed = urlparse(val)
            if not parsed.scheme or parsed.scheme not in ("http", "https"):
                raise ValueError(f"URL target must specify http or https scheme: {val}")
            if not parsed.netloc:
                raise ValueError(f"URL target must include a valid host: {val}")
        elif self.target_type == TargetType.DOMAIN:
            if "://" in val or "/" in val:
                raise ValueError(f"Domain target must not contain URL schemes or paths: {val}")
        return self


class ScopePolicy(BaseModel):
    """Aggregated scope policy compatible with backend policy validators."""

    model_config = ConfigDict(extra="ignore")

    target_domains: list[str] = Field(default_factory=list)
    target_ips: list[str] = Field(default_factory=list)
    target_cidrs: list[str] = Field(default_factory=list)
    target_urls: list[str] = Field(default_factory=list)
    excluded_targets: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443, 3000, 8000, 8080, 8443])
    max_requests_per_minute: int = Field(default=60, ge=1, le=1000)
    max_concurrency: int = Field(default=3, ge=1, le=10)
    allowed_permission_level: TestPermissionLevel = Field(default=TestPermissionLevel.PASSIVE_ONLY)


class Assessment(BaseModel):
    """
    Canonical authority record for an authorized assessment.
    An assessment is created in PENDING_APPROVAL and requires explicit review.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    assessment_id: str = Field(default_factory=lambda: generate_id("assess"))
    name: str = Field(..., min_length=3, max_length=120, alias="title")
    description: str | None = Field(default="")
    organization_name: str = Field(..., min_length=2, max_length=120)
    authorized_by: str = Field(..., min_length=2, max_length=120)
    owner: str = Field(default="security_team", min_length=2, max_length=120)
    authorization_reference: str = Field(
        default="AUTH-PENDING",
        description="Formal tracking reference (e.g. Ticket ID, SOW number, approval token)",
    )
    authorization_acknowledged: bool = Field(
        default=False, description="Explicit confirmation that operator verified authorization"
    )
    scope_rules: list[ScopeRule] = Field(
        default_factory=list, description="Explicit list of authorized scope boundaries"
    )
    scope: ScopePolicy | None = Field(
        default=None, description="Backward-compatible aggregated scope policy"
    )
    lifecycle_status: AssessmentStatus = Field(
        default=AssessmentStatus.PENDING_APPROVAL,
        alias="status",
        description="Assessment status; never defaults to APPROVED on creation",
    )
    max_concurrency: int = Field(default=3, ge=1, le=10)
    max_requests_per_minute: int = Field(default=60, ge=1, le=1000)
    permitted_profiles: list[TestPermissionLevel] = Field(
        default_factory=lambda: [TestPermissionLevel.PASSIVE_ONLY]
    )
    schema_version: str = Field(default="1.0", frozen=True)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    completed_at: datetime | None = None

    @field_validator("lifecycle_status", mode="before")
    @classmethod
    def normalize_status(cls, v: object) -> object:
        if hasattr(v, "value"):
            v = v.value
        if isinstance(v, str):
            val = v.strip().upper()
            mapping = {
                "PENDING": AssessmentStatus.PENDING_APPROVAL,
                "IN_PROGRESS": AssessmentStatus.ACTIVE,
                "COMPLETED": AssessmentStatus.COMPLETED,
                "CANCELLED": AssessmentStatus.CANCELLED,
            }
            if val in mapping:
                return mapping[val]
            if val in AssessmentStatus.__members__:
                return AssessmentStatus[val]
            return v
        return v

    @field_validator("created_at", "updated_at", "expires_at", "completed_at")
    @classmethod
    def validate_timezone(cls, v: datetime | None) -> datetime | None:
        return ensure_utc(v)

    @model_validator(mode="after")
    def sync_backward_compatible_scope(self) -> "Assessment":
        # If legacy scope was provided and scope_rules empty, convert to scope_rules
        if self.scope and not self.scope_rules:
            rules = []
            for d in self.scope.target_domains:
                clean = d.lstrip("*.")
                rules.append(
                    ScopeRule(
                        target_type=TargetType.DOMAIN,
                        target_value=clean,
                        include_subdomains=d.startswith("*."),
                        approved_ports=self.scope.allowed_ports,
                    )
                )
            for ip in self.scope.target_ips:
                rules.append(
                    ScopeRule(
                        target_type=TargetType.IP_ADDRESS,
                        target_value=ip,
                        approved_ports=self.scope.allowed_ports,
                    )
                )
            for cidr in self.scope.target_cidrs:
                rules.append(
                    ScopeRule(
                        target_type=TargetType.CIDR,
                        target_value=cidr,
                        approved_ports=self.scope.allowed_ports,
                    )
                )
            for url in self.scope.target_urls:
                rules.append(
                    ScopeRule(
                        target_type=TargetType.URL,
                        target_value=url,
                        approved_ports=self.scope.allowed_ports,
                    )
                )
            for excl in self.scope.excluded_targets:
                rules.append(
                    ScopeRule(
                        target_type=TargetType.DOMAIN,
                        target_value=excl,
                        is_excluded=True,
                    )
                )
            self.scope_rules = rules

        # If scope_rules provided but scope is None, populate backward-compatible scope
        if not self.scope and self.scope_rules:
            domains = []
            ips = []
            cidrs = []
            urls = []
            exclusions = []
            ports = set()
            for r in self.scope_rules:
                if r.is_excluded:
                    exclusions.append(r.target_value)
                    continue
                if r.target_type == TargetType.DOMAIN:
                    domains.append(
                        f"*.{r.target_value}" if r.include_subdomains else r.target_value
                    )
                elif r.target_type == TargetType.IP_ADDRESS:
                    ips.append(r.target_value)
                elif r.target_type == TargetType.CIDR:
                    cidrs.append(r.target_value)
                elif r.target_type == TargetType.URL:
                    urls.append(r.target_value)
                for p in r.approved_ports:
                    ports.add(p)
            self.scope = ScopePolicy(
                target_domains=domains,
                target_ips=ips,
                target_cidrs=cidrs,
                target_urls=urls,
                excluded_targets=exclusions,
                allowed_ports=sorted(list(ports)) if ports else [80, 443, 3000, 8000, 8080, 8443],
                max_requests_per_minute=self.max_requests_per_minute,
                max_concurrency=self.max_concurrency,
                allowed_permission_level=self.permitted_profiles[0]
                if self.permitted_profiles
                else TestPermissionLevel.PASSIVE_ONLY,
            )
        return self

    @property
    def title(self) -> str:
        return self.name

    @title.setter
    def title(self, val: str) -> None:
        self.name = val

    @property
    def status(self) -> AssessmentStatus:
        return self.lifecycle_status

    @status.setter
    def status(self, val: AssessmentStatus) -> None:
        self.lifecycle_status = val
