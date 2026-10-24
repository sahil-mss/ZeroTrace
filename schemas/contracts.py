from datetime import datetime, timezone
from typing import List, Optional, Set
from pydantic import BaseModel, Field, field_validator, model_validator

from schemas.enums import (
    AssessmentStatus,
    AssetType,
    ConfidenceLevel,
    FindingSeverity,
    VerificationStatus,
)


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DiscoveredService(BaseModel):
    """Network port or protocol service discovered on an asset."""
    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(default="tcp", description="Protocol (tcp, udp, http, https)")
    service_name: Optional[str] = Field(default=None, description="Identified service name (e.g., http, ssh)")
    banner: Optional[str] = Field(default=None, description="Service banner or version string")


class Assessment(BaseModel):
    """An authorized security assessment instance targeting a specific scope."""
    id: str = Field(..., min_length=1, description="Unique assessment identifier")
    name: str = Field(..., min_length=1, description="Descriptive assessment name")
    target: str = Field(..., min_length=1, description="Primary authorized target domain, IP, or CIDR")
    status: AssessmentStatus = Field(default=AssessmentStatus.PENDING, description="Current workflow state")
    created_at: datetime = Field(default_factory=get_utc_now, description="Timestamp when assessment was initialized")
    completed_at: Optional[datetime] = Field(default=None, description="Timestamp when assessment concluded")

    @model_validator(mode="after")
    def validate_completion_time(self) -> "Assessment":
        if self.completed_at and self.completed_at < self.created_at:
            raise ValueError("completed_at cannot be earlier than created_at")
        return self


class Asset(BaseModel):
    """An observed digital asset (domain, IP, host, or web application) discovered within scope."""
    id: str = Field(..., min_length=1, description="Unique asset identifier")
    assessment_id: str = Field(..., min_length=1, description="Parent assessment identifier")
    hostname_or_address: str = Field(..., min_length=1, description="Fully qualified domain, IP, or URL")
    asset_type: AssetType = Field(default=AssetType.WEB_APP, description="Classification of the asset")
    discovered_services: List[DiscoveredService] = Field(
        default_factory=list, description="Services/ports identified on this asset"
    )
    source: str = Field(..., min_length=1, description="Provenance tool or adapter (e.g., osint_dns, nmap)")
    observed_at: datetime = Field(default_factory=get_utc_now, description="Observation timestamp")


class Evidence(BaseModel):
    """Verifiable proof, raw scanner response, or observation artifact."""
    id: str = Field(..., min_length=1, description="Unique evidence record identifier")
    source: str = Field(..., min_length=1, description="Source tool or collector (e.g., nmap, zap, curl)")
    description: str = Field(..., min_length=1, description="Clear description of the observed data")
    observed_at: datetime = Field(default_factory=get_utc_now, description="When evidence was captured")
    asset_id: Optional[str] = Field(default=None, description="Associated asset identifier if applicable")
    reference_or_artifact_location: Optional[str] = Field(
        default=None, description="Filesystem path, URL, or hash reference to raw artifact"
    )
    raw_data: Optional[str] = Field(default=None, description="Inline raw snippet or header dump")


class Finding(BaseModel):
    """A candidate or verified security finding identified during testing."""
    id: str = Field(..., min_length=1, description="Unique finding identifier")
    assessment_id: str = Field(..., min_length=1, description="Parent assessment identifier")
    asset_id: Optional[str] = Field(default=None, description="Affected asset identifier if applicable")
    title: str = Field(..., min_length=1, description="Concise, informative title of the vulnerability")
    description: str = Field(..., min_length=1, description="Detailed technical description")
    severity: FindingSeverity = Field(..., description="Vulnerability severity level")
    confidence: ConfidenceLevel = Field(..., description="Scanner or analyst confidence level")
    verification_status: VerificationStatus = Field(
        default=VerificationStatus.UNVERIFIED,
        description="Empirical verification state (confirmed, likely, unverified, false_positive)"
    )
    evidence_references: List[str] = Field(
        default_factory=list,
        description="IDs of supporting Evidence records. Must not be empty for confirmed findings."
    )
    remediation: Optional[str] = Field(default=None, description="Actionable remediation guidance")
    source_tool: str = Field(..., min_length=1, description="Originating scanner or adapter name")
    cve: Optional[str] = Field(default=None, description="Standardized CVE identifier if known")
    cwe: Optional[str] = Field(default=None, description="Standardized CWE identifier if known")
    first_seen: datetime = Field(default_factory=get_utc_now, description="First detection timestamp")
    last_seen: datetime = Field(default_factory=get_utc_now, description="Most recent observation timestamp")

    @model_validator(mode="after")
    def enforce_evidence_for_confirmed(self) -> "Finding":
        if self.verification_status == VerificationStatus.CONFIRMED and not self.evidence_references:
            raise ValueError("A finding cannot have verification_status=CONFIRMED without at least one supporting evidence reference.")
        return self


class AIAnalysis(BaseModel):
    """
    AI-generated interpretation of empirical findings.
    Strictly grounded in provided evidence records to prevent hallucination.
    """
    concise_summary: str = Field(..., min_length=1, description="High-level executive summary of the finding")
    reasoning_summary: str = Field(
        ..., min_length=1, description="Logical reasoning derived strictly from supplied evidence"
    )
    severity_assessment: FindingSeverity = Field(
        ..., description="AI evaluation of severity based on contextual impact"
    )
    severity_justification: str = Field(..., min_length=1, description="Rationale for the assessed severity")
    confidence_assessment: ConfidenceLevel = Field(
        ..., description="AI confidence in this analysis based on evidence strength"
    )
    confidence_justification: str = Field(..., min_length=1, description="Rationale for confidence level")
    recommended_remediation: str = Field(
        ..., min_length=1, description="Prioritized, concrete technical remediation steps"
    )
    limitations_and_missing_evidence: List[str] = Field(
        default_factory=list,
        description="Explicit gaps, uncertainties, or further verification steps needed"
    )
    cited_evidence_ids: List[str] = Field(
        default_factory=list,
        description="List of Evidence IDs explicitly cited in the reasoning. Must be a subset of known evidence."
    )

    def validate_citations(self, available_evidence_ids: Set[str]) -> None:
        """
        Anti-Hallucination Guard: Validates that every cited evidence ID exists in the provided evidence set.
        Raises ValueError if the model references non-existent evidence.
        """
        invalid_ids = set(self.cited_evidence_ids) - available_evidence_ids
        if invalid_ids:
            raise ValueError(
                f"AI hallucination detected: cited evidence IDs {invalid_ids} do not exist in the available evidence store."
            )
