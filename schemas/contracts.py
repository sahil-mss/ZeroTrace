from datetime import UTC, datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

from schemas.enums import (
    AssessmentStatus,
    AssetType,
    ConfidenceLevel,
    FindingSeverity,
    VerificationStatus,
)


def get_utc_now() -> datetime:
    return datetime.now(UTC)


class DiscoveredService(BaseModel):
    """Network port or protocol service discovered on an asset."""

    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(default="tcp", description="Protocol (tcp, udp, http, https)")
    service_name: str | None = Field(
        default=None, description="Identified service name (e.g., http, ssh)"
    )
    banner: str | None = Field(default=None, description="Service banner or version string")


class Assessment(BaseModel):
    """An authorized security assessment instance targeting a specific scope."""

    id: str = Field(..., min_length=1, description="Unique assessment identifier")
    name: str = Field(..., min_length=1, description="Descriptive assessment name")
    target: str = Field(
        ..., min_length=1, description="Primary authorized target domain, IP, or CIDR"
    )
    status: AssessmentStatus = Field(
        default=AssessmentStatus.PENDING, description="Current workflow state"
    )
    created_at: datetime = Field(
        default_factory=get_utc_now, description="Timestamp when assessment was initialized"
    )
    completed_at: datetime | None = Field(
        default=None, description="Timestamp when assessment concluded"
    )

    @model_validator(mode="after")
    def validate_completion_time(self) -> "Assessment":
        if self.completed_at and self.completed_at < self.created_at:
            raise ValueError("completed_at cannot be earlier than created_at")
        return self


class Asset(BaseModel):
    """An observed digital asset (domain, IP, host, or web application) discovered within scope."""

    id: str = Field(..., min_length=1, description="Unique asset identifier")
    assessment_id: str = Field(..., min_length=1, description="Parent assessment identifier")
    hostname_or_address: str = Field(
        ..., min_length=1, description="Fully qualified domain, IP, or URL"
    )
    asset_type: AssetType = Field(
        default=AssetType.WEB_APP, description="Classification of the asset"
    )
    discovered_services: list[DiscoveredService] = Field(
        default_factory=list, description="Services/ports identified on this asset"
    )
    source: str = Field(
        ..., min_length=1, description="Provenance tool or adapter (e.g., osint_dns, nmap)"
    )
    observed_at: datetime = Field(default_factory=get_utc_now, description="Observation timestamp")


class Evidence(BaseModel):
    """Verifiable proof, raw scanner response, or observation artifact."""

    id: str = Field(..., min_length=1, description="Unique evidence record identifier")
    source: str = Field(
        ..., min_length=1, description="Source tool or collector (e.g., nmap, zap, curl)"
    )
    description: str = Field(
        ..., min_length=1, description="Clear description of the observed data"
    )
    observed_at: datetime = Field(
        default_factory=get_utc_now, description="When evidence was captured"
    )
    asset_id: str | None = Field(
        default=None, description="Associated asset identifier if applicable"
    )
    reference_or_artifact_location: str | None = Field(
        default=None, description="Filesystem path, URL, or hash reference to raw artifact"
    )
    raw_data: str | None = Field(default=None, description="Inline raw snippet or header dump")


class Finding(BaseModel):
    """A candidate or verified security finding identified during testing."""

    id: str = Field(..., min_length=1, description="Unique finding identifier")
    assessment_id: str = Field(..., min_length=1, description="Parent assessment identifier")
    asset_id: str | None = Field(
        default=None, description="Affected asset identifier if applicable"
    )
    title: str = Field(
        ..., min_length=1, description="Concise, informative title of the vulnerability"
    )
    description: str = Field(..., min_length=1, description="Detailed technical description")
    severity: FindingSeverity = Field(..., description="Vulnerability severity level")
    confidence: ConfidenceLevel = Field(..., description="Scanner or analyst confidence level")
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNVERIFIED,
        description="Empirical verification state (confirmed, likely, unverified, false_positive)",
    )
    evidence_references: list[str] = Field(
        default_factory=list,
        description="IDs of supporting Evidence records. Must not be empty for confirmed findings.",
    )
    remediation: str | None = Field(default=None, description="Actionable remediation guidance")
    source_tool: str = Field(..., min_length=1, description="Originating scanner or adapter name")
    cve: str | None = Field(default=None, description="Standardized CVE identifier if known")
    cwe: str | None = Field(default=None, description="Standardized CWE identifier if known")
    first_seen: datetime = Field(
        default_factory=get_utc_now, description="First detection timestamp"
    )
    last_seen: datetime = Field(
        default_factory=get_utc_now, description="Most recent observation timestamp"
    )

    @model_validator(mode="after")
    def enforce_evidence_for_confirmed(self) -> "Finding":
        if (
            self.verification_status == VerificationStatus.CONFIRMED
            and not self.evidence_references
        ):
            raise ValueError(
                "A finding cannot have verification_status=CONFIRMED without at least one supporting evidence reference."
            )
        return self


class AIAnalysis(BaseModel):
    """
    AI-generated interpretation of empirical findings.
    Strictly grounded in provided evidence records to prevent hallucination.
    """

    model_config = ConfigDict(populate_by_name=True)

    summary: str = Field(
        ...,
        validation_alias=AliasChoices("summary", "concise_summary"),
        min_length=1,
        description="Concise executive summary of the finding",
    )
    evidence_facts: list[str] = Field(
        default_factory=list,
        description="Observed factual statements extracted directly from provided evidence",
    )
    interpretation: list[str] = Field(
        default_factory=list,
        description="Technical deductions, root causes, and security implications",
    )
    severity: FindingSeverity = Field(
        ...,
        validation_alias=AliasChoices("severity", "severity_assessment"),
        description="Severity assessment grounded in the input",
    )
    severity_justification: str = Field(
        ..., min_length=1, description="Explanation grounded in the input"
    )
    confidence: ConfidenceLevel = Field(
        ...,
        validation_alias=AliasChoices("confidence", "confidence_assessment"),
        description="Confidence level grounded in the evidence",
    )
    confidence_justification: str = Field(
        ..., min_length=1, description="Explanation grounded in the evidence"
    )
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNVERIFIED, description="Assessed verification status"
    )
    remediation: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("remediation", "recommended_remediation"),
        description="Prioritized, concrete technical remediation steps",
    )
    limitations: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("limitations", "limitations_and_missing_evidence"),
        description="Documented evidence gaps and limitations",
    )
    requires_human_review: bool = Field(
        default=True, description="Indicates whether human analyst review is mandatory"
    )
    cited_evidence_ids: list[str] = Field(
        default_factory=list,
        description="List of Evidence IDs explicitly cited in the reasoning. Must be a subset of known evidence.",
    )
    is_rule_based_fallback: bool = Field(
        default=False, description="Flag indicating analysis was produced by deterministic fallback"
    )
    analysis_provider: str = Field(
        default="deterministic_fallback", description="Provider or model used for generation"
    )

    @field_validator("remediation", mode="before")
    @classmethod
    def parse_remediation_input(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [line.strip() for line in v.strip().splitlines() if line.strip()]
        if isinstance(v, list):
            return [str(item) for item in v]
        return []

    @field_validator("interpretation", mode="before")
    @classmethod
    def parse_interpretation_input(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [line.strip() for line in v.strip().splitlines() if line.strip()]
        if isinstance(v, list):
            return [str(item) for item in v]
        return []

    @model_validator(mode="before")
    @classmethod
    def handle_legacy_inputs(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "concise_summary" in data and "summary" not in data:
                data["summary"] = data["concise_summary"]
            if "reasoning_summary" in data and not data.get("interpretation"):
                data["interpretation"] = [data["reasoning_summary"]]
            if "recommended_remediation" in data and "remediation" not in data:
                data["remediation"] = data["recommended_remediation"]
            if "limitations_and_missing_evidence" in data and "limitations" not in data:
                data["limitations"] = data["limitations_and_missing_evidence"]
        return data

    @property
    def concise_summary(self) -> str:
        return self.summary

    @property
    def reasoning_summary(self) -> str:
        if self.interpretation:
            return " ".join(self.interpretation)
        return self.severity_justification

    @property
    def severity_assessment(self) -> FindingSeverity:
        return self.severity

    @property
    def confidence_assessment(self) -> ConfidenceLevel:
        return self.confidence

    @property
    def recommended_remediation(self) -> str:
        return "\n".join(self.remediation)

    @property
    def limitations_and_missing_evidence(self) -> list[str]:
        return self.limitations

    def validate_citations(self, available_evidence_ids: set[str]) -> None:
        """
        Anti-Hallucination Guard: Validates that every cited evidence ID exists in the provided evidence set.
        Raises ValueError if the model references non-existent evidence.
        """
        invalid_ids = set(self.cited_evidence_ids) - available_evidence_ids
        if invalid_ids:
            raise ValueError(
                f"AI hallucination detected: cited evidence IDs {invalid_ids} do not exist in the available evidence store."
            )
