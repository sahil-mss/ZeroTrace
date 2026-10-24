# ZeroTrace Team Integration & Handoff Guide (Persons 2 & 3)

This guide documents the integration surfaces, contracts, and handoff procedures for **Person 2 (Scanner & Security Tools)** and **Person 3 (AI Triage & UI Reporting)** to integrate with the ZeroTrace backend.

---

## 1. Overview of Team Responsibilities

- **Person 1 (Completed)**: Core backend infrastructure, FastAPI REST API, database persistence, Alembic migrations, deterministic scope validation, evidence hashing, OSINT framework, job state machine, and immutable audit engine.
- **Person 2 (In Progress / Next)**: Active scanners (Nmap, ZAP, etc.), converting scanner tool outputs into canonical `Evidence` and `Finding` models, pre-scan scope checks.
  > *Note*: Active scanner integrations are currently under active development. The base interfaces, validation gates, and ingest endpoints are ready for Person 2.
- **Person 3 (In Progress / Next)**: Frontend user interface, grounded AI triage reasoning layer, and report generation/export.

---

## 2. Person 2 (Scanners & Security Tools) Integration

### 2.1 Scope Pre-Check Before Tool Execution
Before running any network tool (Nmap, curl, Nikto, OWASP ZAP), Person 2 **must** revalidate the target against the assessment's approved scope. Never execute a scan against an unvalidated target.

#### Python Service Usage:
```python
from aegis_common.enums import ScopeReasonCode
from backend.app.services.scope_validator import ScopeValidator

validator = ScopeValidator()
result = validator.validate_target(proposed_target, assessment.scope_rules)

if not result.allowed:
    raise PermissionError(f"Target {proposed_target} is out of scope! Reason: {result.reason_code}")
```

#### Via REST API:
```powershell
# Before starting a scan job, ensure the assessment is approved:
$headers = @{ "Authorization" = "Bearer dev-secret-token"; "Content-Type" = "application/json" }
$startBody = @{
    target_input = "target.example.test"
    permission_level = "NETWORK_SCAN"
} | ConvertTo-Json

$job = Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/$assessmentId/start" -Method Post -Headers $headers -Body $startBody
```
If the target is outside the approved scope or the assessment is not approved, the API immediately returns `400 Bad Request` or `403 Forbidden`.

---

### 2.2 Writing Evidence Before Creating Findings
Findings cannot exist without empirical evidence. Person 2 must store the raw scanner output (e.g. Nmap XML excerpt or ZAP JSON observation) in the evidence store first.

#### REST API Submission:
```powershell
$evidenceBody = @{
    asset_id = $assetId
    source_type = "PORT_SCAN"
    collection_method = "nmap_syn"
    raw_payload = @{
        port = 8080
        protocol = "tcp"
        service = "http-proxy"
        banner = "Apache-Coyote/1.1"
    }
} | ConvertTo-Json -Depth 5

$evidence = Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/$assessmentId/evidence" -Method Post -Headers $headers -Body $evidenceBody
$evidenceId = $evidence.id
```

---

### 2.3 Converting Scanner Results into Canonical Findings
Once evidence is persisted and an `evidence_id` is assigned, Person 2 converts the normalized scanner vulnerability into a canonical `Finding`:

#### Python Model Conversion:
```python
from aegis_common.enums import ConfidenceLevel, FindingSeverity, VerificationStatus
from aegis_common.models.finding import Finding

finding = Finding(
    assessment_id=assessment_id,
    asset_id=asset_id,
    title="Apache Coyote Debug Service Exposed",
    description="Port 8080 exposed with debug banner Apache-Coyote/1.1.",
    severity=FindingSeverity.MEDIUM,
    confidence=ConfidenceLevel.HIGH,
    verification_status=VerificationStatus.CONFIRMED,
    evidence_references=[evidence_id],  # MUST reference stored evidence!
    remediation="Disable debug listeners or bind service to localhost.",
)
```

#### REST API Submission:
```powershell
$findingBody = @{
    asset_id = $assetId
    title = "Apache Coyote Debug Service Exposed"
    description = "Port 8080 exposed with debug banner Apache-Coyote/1.1."
    severity = "MEDIUM"
    confidence = "HIGH"
    verification_status = "CONFIRMED"
    evidence_references = @($evidenceId)
    remediation = "Disable debug listeners or bind service to localhost."
} | ConvertTo-Json -Depth 4

$finding = Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/$assessmentId/findings" -Method Post -Headers $headers -Body $findingBody
```

> **Warning**: Submitting a finding with nonexistent or cross-assessment evidence references will be rejected with `400 Bad Request`.

---

## 3. Person 3 (AI Triage & UI Reporting) Integration

### 3.1 Reading Structured Assets, Findings, and Evidence
Person 3 consumes normalized findings and evidence directly through the backend REST endpoints to display the dashboard or supply LLM prompts:

```powershell
# Retrieve all findings for an assessment
$findings = Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/$assessmentId/findings" -Method Get -Headers $headers

# Retrieve all evidence records
$evidence = Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/$assessmentId/evidence" -Method Get -Headers $headers

# Retrieve discovered assets
$assets = Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/$assessmentId/assets" -Method Get -Headers $headers
```

---

### 3.2 Submitting AI Model Recommendations for Deterministic Validation
When an AI agent or analyst proposes a new task or test plan, it must be submitted to the job lifecycle engine:

```powershell
$jobBody = @{
    task_type = "mock_scan"
    parameters = @{
        target = "target.example.test"
        profile = "PASSIVE_RECON"
    }
} | ConvertTo-Json

$newJob = Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/$assessmentId/jobs" -Method Post -Headers $headers -Body $jobBody
```
The backend automatically executes `POLICY_CHECK` validation before placing the job into `QUEUED`. If the target is out of scope, the job is denied and marked `FAILED` with an audit event recorded.

---

### 3.3 Evidence-Grounded AI Analysis Endpoint
To triage a finding with zero hallucination:
```powershell
$analyzeBody = @{
    finding = $findings[0]
    evidence = $evidence
} | ConvertTo-Json -Depth 6

$analysis = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/ai/analyze" -Method Post -Headers $headers -Body $analyzeBody
```
The analysis endpoint verifies that all cited evidence IDs exist. If hallucinated citations are detected, it falls back to deterministic heuristic reasoning.

---

### 3.4 Handling Job State Transitions, Approvals, and Cancellations

#### 1. Approving an Assessment:
```powershell
$approveBody = @{ approver = "lead-analyst" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/$assessmentId/approve" -Method Post -Headers $headers -Body $approveBody
```

#### 2. Cancelling an Assessment or Job:
```powershell
# Cancel entire assessment (cancels all active jobs immediately):
Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/$assessmentId/cancel" -Method Post -Headers $headers

# Cancel a specific job:
Invoke-RestMethod -Uri "http://127.0.0.1:8000/jobs/$jobId/cancel" -Method Post -Headers $headers
```

#### 3. Generating Reports:
```powershell
# Honest report generated from persistent database records:
$report = Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/$assessmentId/report" -Method Get -Headers $headers
```
If no findings or assets have been collected, the report returns zero-count summaries rather than hallucinating dummy data.
