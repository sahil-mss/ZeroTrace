import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_common.enums import Severity, VerificationStatus
from aegis_common.utils import ensure_utc, generate_id, utc_now

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
CWE_PATTERN = re.compile(r"^CWE-\d{1,5}$", re.IGNORECASE)


class Finding(BaseModel):
    """
    Canonical Finding contract for security vulnerabilities and misconfigurations.

    NOTE: Person 2 (Security Scanners & Tool Integrations Lead) must review
    this contract before treating it as finalized for active scanner pipelines.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    finding_id: str = Field(default_factory=lambda: generate_id("find"))
    assessment_id: str = Field(..., min_length=3)
    asset_id: str = Field(..., min_length=3)
    title: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=10)
    cwe: str | None = Field(default=None, description="Common Weakness Enumeration, e.g. 'CWE-79'")
    cve: str | None = Field(
        default=None, description="Common Vulnerabilities and Exposures, e.g. 'CVE-2023-1234'"
    )
    severity: Severity = Field(default=Severity.MEDIUM)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNVERIFIED,
        description="Verification state; never defaults to CONFIRMED",
    )
    evidence_ids: list[str] = Field(
        ...,
        min_length=1,
        description="Cryptographic references to supporting Evidence objects. Model-generated evidence IDs are strictly rejected unless verified against storage.",
    )
    root_cause: str | None = Field(default=None, max_length=500)
    remediation: str = Field(
        ..., min_length=5, description="Actionable technical steps to resolve finding"
    )
    source_tool: str = Field(..., min_length=1, alias="tool_name")
    tool_version: str | None = Field(default="1.0")
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    schema_version: str = Field(default="1.0", frozen=True)

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0 inclusive.")
        return round(v, 4)

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Every finding MUST reference at least one verified evidence ID.")
        cleaned = [e.strip() for e in v if e.strip()]
        if not cleaned:
            raise ValueError("evidence_ids cannot contain only whitespace.")
        return list(dict.fromkeys(cleaned))

    @field_validator("cve")
    @classmethod
    def validate_cve_format(cls, v: str | None) -> str | None:
        if v is not None and v.strip():
            clean = v.strip().upper()
            if not CVE_PATTERN.match(clean):
                raise ValueError(
                    f"Malformed CVE identifier '{v}'. Expected format 'CVE-YYYY-NNNNN'."
                )
            return clean
        return None

    @field_validator("cwe")
    @classmethod
    def validate_cwe_format(cls, v: str | None) -> str | None:
        if v is not None and v.strip():
            clean = v.strip().upper()
            if not CWE_PATTERN.match(clean):
                raise ValueError(f"Malformed CWE identifier '{v}'. Expected format 'CWE-NNN'.")
            return clean
        return None

    @field_validator("first_seen", "last_seen")
    @classmethod
    def validate_utc(cls, v: datetime) -> datetime:
        return ensure_utc(v) or utc_now()

    @property
    def tool_name(self) -> str:
        return self.source_tool

    @tool_name.setter
    def tool_name(self, val: str) -> None:
        self.source_tool = val
