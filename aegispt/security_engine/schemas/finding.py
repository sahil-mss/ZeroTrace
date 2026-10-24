"""Normalized security finding and evidence schemas.

NOTE (PROVISIONAL MODEL):
This model is provisional for Person 2's security engine module.
It standardizes vulnerability findings discovered by Nmap, OWASP ZAP, or Mock
scanners so that Person 3 (AI analysis) can consume normalized data without
vendor-specific parser dependencies.
"""

from datetime import datetime, timezone
from typing import Any
import uuid

from pydantic import BaseModel, Field

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
        description="Category of evidence (e.g. 'http_request', 'http_response', 'port_banner', 'xml_node').",
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
        description="Contextual metadata (line number, xpath, header name, status code).",
    )
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when evidence was observed.",
    )


class NormalizedFinding(BaseModel):
    """Vendor-agnostic normalized security finding.

    Standard representation of an identified vulnerability, exposure, or service.
    """

    finding_id: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique identifier for the normalized finding.",
    )
    scanner_id: str = Field(
        ...,
        min_length=1,
        description="Identifier of the scanner that generated this finding (e.g. 'nmap', 'owasp_zap', 'mock_scanner').",
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
        description="Assigned severity rating.",
    )
    target: ScanTarget = Field(
        ...,
        description="Target asset upon which this finding was discovered.",
    )
    cwe_id: int | None = Field(
        default=None,
        ge=1,
        description="Common Weakness Enumeration ID if applicable (e.g., 79 for XSS).",
    )
    cve_id: str | None = Field(
        default=None,
        description="Common Vulnerabilities and Exposures ID if applicable (e.g., CVE-2023-1234).",
    )
    evidence: list[EvidenceReference] = Field(
        default_factory=list,
        description="Verifiable evidence references supporting this finding.",
    )
    remediation: str | None = Field(
        default=None,
        description="Recommended mitigation guidance.",
    )
    first_observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when finding was first identified.",
    )
    verified: bool = Field(
        default=False,
        description="True if finding has been non-destructively verified by verification module.",
    )
