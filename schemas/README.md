# ZeroTrace — Shared Schema Contracts

This package defines the unified data contracts shared across all three subsystems.
Every module (OSINT, Scanners, AI, Backend, Reporting, and Frontend) must adhere strictly to these schemas.

---

## The 5 Core Concepts

### 1. `Assessment`
Represents an authorized security engagement bounded by target scope and lifecycle status.
- **Fields**: `id`, `name`, `target`, `status`, `created_at`, `completed_at` (optional).
- **Status Enum**: `pending`, `in_progress`, `completed`, `failed`, `cancelled`.
- **Constraint**: `completed_at` cannot be earlier than `created_at`.

### 2. `Asset`
Represents an observed digital asset (domain, IP, URL, or service) identified within the authorized assessment.
- **Fields**: `id`, `assessment_id`, `hostname_or_address`, `asset_type`, `discovered_services`, `source`, `observed_at`.
- **Asset Types**: `domain`, `ip`, `web_app`, `api_endpoint`, `service`, `other`.
- **Discovered Services**: List of objects containing `port` (1–65535), `protocol`, `service_name`, and optional `banner`.

### 3. `Evidence`
Represents raw proof, scanner execution records, response dumps, or OSINT artifacts.
- **Fields**: `id`, `source`, `description`, `observed_at`, `asset_id` (optional), `reference_or_artifact_location` (optional), `raw_data` (optional snippet).
- **Provenance Rule**: Every observation or scanner finding must refer to one or more `evidence_id`s.

### 4. `Finding`
Represents a candidate or verified vulnerability.
- **Fields**: `id`, `assessment_id`, `asset_id` (optional), `title`, `description`, `severity`, `confidence`, `verification_status`, `evidence_references`, `remediation` (optional), `source_tool`, `cve` (optional), `cwe` (optional), `first_seen`, `last_seen`.
- **Severity**: `critical`, `high`, `medium`, `low`, `informational`.
- **Confidence**: `high`, `medium`, `low`.
- **Verification Status**: `confirmed`, `likely`, `unverified`, `false_positive`.
- **Hard Rule**: A finding CANNOT be marked `confirmed` without at least one non-empty reference in `evidence_references`.

### 5. `AIAnalysis`
Represents model-driven reasoning and remediation guidance derived strictly from empirical evidence.
- **Fields**: `concise_summary`, `reasoning_summary`, `severity_assessment`, `severity_justification`, `confidence_assessment`, `confidence_justification`, `recommended_remediation`, `limitations_and_missing_evidence`, `cited_evidence_ids`.
- **Anti-Hallucination Guard**: Call `analysis.validate_citations(available_evidence_ids)`. Any cited evidence ID not present in the supplied evidence set immediately raises a `ValueError`.

---

## Python Usage Example

```python
from schemas import (
    Assessment,
    Asset,
    Evidence,
    Finding,
    AIAnalysis,
    FindingSeverity,
    ConfidenceLevel,
    VerificationStatus,
)

# 1. Evidence recorded by Person 2's scanner adapter
evidence = Evidence(
    id="ev_zap_001",
    source="owasp_zap",
    description="Reflected XSS payload observed in query parameter 'q'",
    reference_or_artifact_location="/artifacts/zap_run_12.json",
    raw_data="HTTP/1.1 200 OK\n...<script>alert(1)</script>..."
)

# 2. Finding created with evidence reference
finding = Finding(
    id="fnd_001",
    assessment_id="asm_001",
    asset_id="ast_001",
    title="Reflected Cross-Site Scripting (XSS)",
    description="The 'q' parameter reflects untrusted user input without sanitization.",
    severity=FindingSeverity.HIGH,
    confidence=ConfidenceLevel.HIGH,
    verification_status=VerificationStatus.CONFIRMED,
    evidence_references=["ev_zap_001"],
    source_tool="owasp_zap",
    cwe="CWE-79"
)

# 3. AI Analysis grounded in evidence
analysis = AIAnalysis(
    concise_summary="Confirmed high-severity Reflected XSS in search endpoint.",
    reasoning_summary="Evidence ev_zap_001 demonstrates direct reflection of executable script in HTTP response.",
    severity_assessment=FindingSeverity.HIGH,
    severity_justification="Enables session hijacking and client-side credential theft.",
    confidence_assessment=ConfidenceLevel.HIGH,
    confidence_justification="Empirically confirmed through active reflection proof.",
    recommended_remediation="Apply context-aware contextual HTML entity encoding and implement Content-Security-Policy (CSP).",
    limitations_and_missing_evidence=["WAF bypass potential was not tested."],
    cited_evidence_ids=["ev_zap_001"]
)

# Enforce anti-hallucination check
analysis.validate_citations(available_evidence_ids={"ev_zap_001"})
```
