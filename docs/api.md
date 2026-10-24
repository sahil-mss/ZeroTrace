# ZeroTrace REST API Reference

The ZeroTrace backend exposes a REST API on `http://127.0.0.1:8000`. Protected endpoints require an `Authorization: Bearer <token>` header when `API_AUTH_TOKEN` is configured.

---

## 1. Authentication & Headers

Protected routes accept a Bearer token:
```http
Authorization: Bearer dev-secret-token
Content-Type: application/json
```
If an invalid token is provided, the API responds with:
```json
{
  "detail": "Invalid authentication token"
}
```

---

## 2. Health & Status

### `GET /health`
Returns system status, active version, and environment.

**Request (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -Method Get
```

**Response `200 OK`:**
```json
{
  "status": "healthy",
  "app_name": "ZeroTrace",
  "version": "0.1.0",
  "environment": "development"
}
```

---

## 3. Assessments

### `POST /assessments`
Creates a new assessment record. The assessment is created in `DRAFT` or `PENDING_APPROVAL` status. It is **never** automatically approved.

**Request (PowerShell):**
```powershell
$headers = @{ "Authorization" = "Bearer dev-secret-token"; "Content-Type" = "application/json" }
$body = @{
    name = "Lab Assessment"
    description = "Authorized penetration testing assessment"
    authorization_reference = "AUTH-SEC-2026-001"
    authorization_acknowledged = $true
    scope_rules = @{
        included_targets = @("target.example.test", "192.168.1.0/24")
        excluded_targets = @("prod.target.example.test")
    }
    permitted_test_profiles = @("PASSIVE_RECON", "NETWORK_SCAN")
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments" -Method Post -Headers $headers -Body $body
```

**Response `201 Created`:**
```json
{
  "id": "asm-9c8e11a2",
  "name": "Lab Assessment",
  "description": "Authorized penetration testing assessment",
  "authorization_reference": "AUTH-SEC-2026-001",
  "authorization_acknowledged": true,
  "status": "PENDING_APPROVAL",
  "scope_rules": {
    "included_targets": ["target.example.test", "192.168.1.0/24"],
    "excluded_targets": ["prod.target.example.test"]
  },
  "created_at": "2026-10-24T18:00:00Z"
}
```

---

### `GET /assessments`
Lists all assessment records. Supports pagination via `limit` and `offset`.

**Request (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments?limit=10&offset=0" -Method Get -Headers $headers
```

---

### `GET /assessments/{id}`
Retrieves a specific assessment by ID.

**Request (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/asm-9c8e11a2" -Method Get -Headers $headers
```

---

### `POST /assessments/{id}/approve`
Explicitly approves an assessment. Only approved assessments can execute jobs or scans.

**Request (PowerShell):**
```powershell
$body = @{ approver = "lead-security-engineer" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/asm-9c8e11a2/approve" -Method Post -Headers $headers -Body $body
```

**Response `200 OK`:**
```json
{
  "message": "Assessment approved successfully",
  "assessment_id": "asm-9c8e11a2",
  "status": "APPROVED",
  "approved_by": "lead-security-engineer"
}
```

---

### `POST /assessments/{id}/start`
Validates assessment approval and target scope, and launches an assessment job.

**Request (PowerShell):**
```powershell
$body = @{
    target_input = "target.example.test"
    permission_level = "PASSIVE_RECON"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/asm-9c8e11a2/start" -Method Post -Headers $headers -Body $body
```

**Response `200 OK`:**
```json
{
  "message": "Assessment started",
  "assessment_id": "asm-9c8e11a2",
  "job_id": "job-87123aa1",
  "status": "RUNNING"
}
```

---

### `POST /assessments/{id}/cancel`
Immediately requests cancellation of the assessment and terminates all active jobs.

**Request (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/asm-9c8e11a2/cancel" -Method Post -Headers $headers
```

**Response `200 OK`:**
```json
{
  "message": "Assessment cancelled",
  "assessment_id": "asm-9c8e11a2",
  "status": "CANCELLED"
}
```

---

## 4. Assets & Evidence

### `GET /assessments/{id}/assets`
Lists all discovered and normalized assets for the assessment.

**Response `200 OK`:**
```json
[
  {
    "id": "ast-0192a",
    "assessment_id": "asm-9c8e11a2",
    "target_value": "target.example.test",
    "asset_type": "DOMAIN",
    "scope_status": "IN_SCOPE",
    "first_seen": "2026-10-24T18:05:00Z",
    "last_seen": "2026-10-24T18:05:00Z"
  }
]
```

---

### `POST /assessments/{id}/evidence`
Ingests an empirical evidence record. Computes SHA-256 content hash and validates asset association.

**Request (PowerShell):**
```powershell
$body = @{
    asset_id = "ast-0192a"
    source_type = "OSINT"
    collection_method = "dns_enum"
    raw_payload = @{
        record_type = "A"
        answer = "192.168.1.50"
    }
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/asm-9c8e11a2/evidence" -Method Post -Headers $headers -Body $body
```

**Response `201 Created`:**
```json
{
  "id": "ev-5f4b21c0",
  "assessment_id": "asm-9c8e11a2",
  "asset_id": "ast-0192a",
  "source_type": "OSINT",
  "content_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
  "collected_at": "2026-10-24T18:06:00Z"
}
```

---

### `GET /assessments/{id}/evidence`
Lists all evidence records associated with the assessment.

---

## 5. Findings

### `POST /assessments/{id}/findings`
Submits a vulnerability finding. All `evidence_references` must point to valid evidence in this assessment. Cross-assessment evidence references or nonexistent evidence IDs are rejected.

**Request (PowerShell):**
```powershell
$body = @{
    asset_id = "ast-0192a"
    title = "Exposed Internal DNS Record"
    description = "Discovered DNS A record resolving to internal RFC 1918 address."
    severity = "LOW"
    confidence = "HIGH"
    verification_status = "CONFIRMED"
    evidence_references = @("ev-5f4b21c0")
    remediation = "Restrict public DNS visibility for internal assets."
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/asm-9c8e11a2/findings" -Method Post -Headers $headers -Body $body
```

**Response `201 Created`:**
```json
{
  "id": "fnd-10293847",
  "assessment_id": "asm-9c8e11a2",
  "asset_id": "ast-0192a",
  "title": "Exposed Internal DNS Record",
  "severity": "LOW",
  "confidence": "HIGH",
  "verification_status": "CONFIRMED",
  "evidence_references": ["ev-5f4b21c0"],
  "created_at": "2026-10-24T18:07:00Z"
}
```

---

### `GET /assessments/{id}/findings`
Lists all findings for the assessment.

---

## 6. Jobs & Orchestration

### `POST /assessments/{id}/jobs`
Creates a bounded background job (e.g. `mock_scan` or `osint_recon`).

**Request (PowerShell):**
```powershell
$body = @{
    task_type = "osint_recon"
    parameters = @{
        target = "target.example.test"
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/assessments/asm-9c8e11a2/jobs" -Method Post -Headers $headers -Body $body
```

---

### `POST /jobs/{id}/cancel`
Requests cancellation of an individual queued or running job.

**Request (PowerShell):**
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/jobs/job-87123aa1/cancel" -Method Post -Headers $headers
```

---

## 7. Audit Trail & Reporting

### `GET /assessments/{id}/events`
Returns the immutable, chronological audit trail for the assessment.

**Response `200 OK`:**
```json
[
  {
    "id": "evt-001",
    "assessment_id": "asm-9c8e11a2",
    "event_type": "ASSESSMENT_CREATED",
    "actor": "operator",
    "timestamp": "2026-10-24T18:00:00Z"
  },
  {
    "id": "evt-002",
    "assessment_id": "asm-9c8e11a2",
    "event_type": "ASSESSMENT_APPROVED",
    "actor": "lead-security-engineer",
    "timestamp": "2026-10-24T18:02:00Z"
  }
]
```

---

### `GET /assessments/{id}/report`
Generates or retrieves the aggregated assessment report. If no findings or completed runs exist, it returns an honest summary without fabricating findings.

**Response `200 OK`:**
```json
{
  "assessment_id": "asm-9c8e11a2",
  "name": "Lab Assessment",
  "status": "APPROVED",
  "summary": {
    "total_assets": 1,
    "total_evidence": 1,
    "total_findings": 1,
    "severity_counts": {
      "CRITICAL": 0,
      "HIGH": 0,
      "MEDIUM": 0,
      "LOW": 1,
      "INFORMATIONAL": 0
    }
  },
  "findings": [
    {
      "id": "fnd-10293847",
      "title": "Exposed Internal DNS Record",
      "severity": "LOW",
      "verification_status": "CONFIRMED",
      "evidence_references": ["ev-5f4b21c0"]
    }
  ]
}
```

---

## 8. AI Analysis & Upstream Normalization

### `POST /api/ai/analyze`
Submits a finding and empirical evidence for grounded AI triage.

### `POST /api/upstream/normalize`
Normalizes raw scanner outputs (Nmap, ZAP, etc.) into the canonical schema contracts.
