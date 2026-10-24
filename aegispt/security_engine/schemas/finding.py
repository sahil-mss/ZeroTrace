"""Normalized security finding and evidence schemas.

NOTE:
This model standardizes vulnerability findings discovered by Nmap, OWASP ZAP,
or Mock scanners so that Person 3 (AI analysis) and Person 1 (central backend)
can consume normalized data without vendor-specific parser dependencies.
"""

from datetime import datetime, timezone
from typing import Any
import uuid

from pydantic import BaseModel, Field, model_validator

from aegispt.security_engine.schemas.enums import Severity
from aegispt.security_engine.schemas.target import ScanTarget


class EvidenceReference(BaseModel):
    """Forensic evidence citation supporting a security finding.

    Links a normalized finding to raw scanner outputs, request/response dumps,
    or banner artifacts.
    """

    evidence_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique identifier for the evidence item.",
    )
    evidence_type: str = Field(
        ...,
        min_length=1,
        description="Category of evidence (e.g. 'http_request', 'http_response', 'port_banner', 'zap_alert_instance').",
    )
    content_snippet: str = Field(
        ...,
        min_length=1,
        description="Extracted verbatim snippet demonstrating finding existence.",
    )
    source_artifact_id: str | None = Field(
        default=None,
        description="ID of the stored raw scanner file (from RawScanEvidence).",
    )
    sha256_hash: str | None = Field(
        default=None,
        description="SHA-256 hash of the content snippet or raw source artifact.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual metadata (line number, xpath, header name, status code, attack vector).",
    )
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when evidence was observed.",
    )


class NormalizedFinding(BaseModel):
    """Vendor-agnostic normalized security finding.

    Standard representation of an identified vulnerability, exposure, or risk.
    """

    finding_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique identifier for the normalized finding.",
    )
    assessment_id: str | None = Field(
        default=None,
        description="Identifier of the assessment / job scope.",
    )
    asset_id: str | None = Field(
        default=None,
        description="Identifier of the affected asset (defaults to target.target_id).",
    )
    scanner_id: str = Field(
        ...,
        min_length=1,
        description="Identifier of the scanner that generated this finding (e.g. 'nmap', 'owasp_zap', 'mock_scanner').",
    )
    tool_name: str | None = Field(
        default=None,
        description="Formal tool name reporting the finding (mirrors scanner_id if omitted).",
    )
    tool_version: str | None = Field(
        default=None,
        description="Version string of the scanner tool/adapter.",
    )
    title: str = Field(
        ...,
        min_length=1,
        description="Concise, human-readable finding title.",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Detailed description of the vulnerability or observed state.",
    )
    severity: Severity = Field(
        default=Severity.INFO,
        description="Normalized severity rating (INFO, LOW, MEDIUM, HIGH, CRITICAL).",
    )
    original_severity: str | None = Field(
        default=None,
        description="Original, unmapped severity string reported by the scanner.",
    )
    confidence: str | None = Field(
        default=None,
        description="Scanner confidence rating (e.g. 'High', 'Medium', 'Low', 'False Positive').",
    )
    target: ScanTarget = Field(
        ...,
        description="Target asset upon which this finding was discovered.",
    )
    cwe_id: int | None = Field(
        default=None,
        ge=1,
        description="Common Weakness Enumeration ID as integer (e.g., 79 for XSS).",
    )
    cwe: str | None = Field(
        default=None,
        description="Common Weakness Enumeration identifier string (e.g., 'CWE-79').",
    )
    cve_id: str | None = Field(
        default=None,
        description="Common Vulnerabilities and Exposures ID (e.g., 'CVE-2023-1234').",
    )
    cve: str | None = Field(
        default=None,
        description="Common Vulnerabilities and Exposures identifier string.",
    )
    root_cause: str | None = Field(
        default=None,
        description="Underlying flaw causing the finding (e.g. 'Missing input sanitation').",
    )
    remediation: str | None = Field(
        default=None,
        description="Recommended mitigation guidance.",
    )
    evidence: list[EvidenceReference] = Field(
        default_factory=list,
        description="Verifiable evidence references supporting this finding.",
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="List of IDs referencing supporting evidence items.",
    )
    first_observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when finding was first identified.",
    )
    first_seen: datetime | None = Field(
        default=None,
        description="UTC timestamp when finding was first identified (mirrors first_observed_at).",
    )
    last_seen: datetime | None = Field(
        default=None,
        description="UTC timestamp of the most recent observation of this finding.",
    )
    verified: bool = Field(
        default=False,
        description="True if finding has been independently verified.",
    )
    verification_status: str = Field(
        default="UNVERIFIED",
        description="Verification state: 'UNVERIFIED', 'CONFIRMED', or 'FALSE_POSITIVE'.",
    )
    fingerprint: str | None = Field(
        default=None,
        description="Deterministic hash fingerprint for deduplication.",
    )

    @model_validator(mode="after")
    def sync_provisional_fields(self) -> "NormalizedFinding":
        """Synchronize complementary fields between schemas."""
        # Sync tool name and scanner id
        if not self.tool_name:
            self.tool_name = self.scanner_id

        # Sync asset ID
        if not self.asset_id and self.target:
            self.asset_id = self.target.target_id

        # Sync timestamps
        if not self.first_seen:
            self.first_seen = self.first_observed_at
        if not self.last_seen:
            self.last_seen = self.first_seen

        # Sync verification status
        if self.verified and self.verification_status == "UNVERIFIED":
            self.verification_status = "CONFIRMED"
        elif self.verification_status == "CONFIRMED" and not self.verified:
            self.verified = True

        # Sync CWE string
        if self.cwe_id and not self.cwe:
            self.cwe = f"CWE-{self.cwe_id}"
        elif self.cwe and not self.cwe_id:
            cleaned = self.cwe.upper().replace("CWE-", "").strip()
            if cleaned.isdigit():
                self.cwe_id = int(cleaned)

        # Sync CVE
        if self.cve_id and not self.cve:
            self.cve = self.cve_id
        elif self.cve and not self.cve_id:
            self.cve_id = self.cve

        # Sync evidence IDs
        if self.evidence and not self.evidence_ids:
            self.evidence_ids = [e.evidence_id for e in self.evidence]

        return self
