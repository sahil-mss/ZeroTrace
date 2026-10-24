# ZeroTrace Security Architecture & Engineering Policies

ZeroTrace is built with strict security boundaries designed to prevent unauthorized scanning, scope leakage, data fabrication, and arbitrary code execution. This document details our permanent security mechanisms and engineering policies.

---

## 1. Scope, Authorization & Policy Rules

### 1.1 Explicit Authorization Required
- **No Implicit Approval**: Every assessment requires an explicit authorization reference (contract, ticket ID) and `authorization_acknowledged = True`.
- **Default Deny**: Assessments are created in `PENDING_APPROVAL` or `DRAFT`. No job, scan, or network request can execute until an authorized operator explicitly issues an approval (`POST /assessments/{id}/approve`).
- **No Inferred Scope**: Subdomains, IP addresses, or redirect destinations discovered during reconnaissance are **never** automatically treated as authorized. They must be validated against the approved `ScopeRule` set before any active interaction.

### 1.2 Deterministic Scope Engine
- Scope validation is completely decoupled from AI model outputs. It is implemented purely with deterministic Python algorithms in `backend/app/services/scope_validator.py`.
- **Edge-Case Normalization**:
  - Trailing DNS dots are stripped (`example.test.` -> `example.test`).
  - Hostnames are converted to lowercase.
  - Internationalized Domain Names (IDNs) are converted to Punycode.
  - URLs are strictly parsed into scheme, hostname, port, and path.
- **Lookalike Domain Defense**:
  - Exact hostname matching or strict domain suffix matching (`*.example.test`) is enforced.
  - Suffix lookalikes (e.g., `example.test.evil.com` or `evil-example.test`) are rejected with `ScopeReasonCode.TARGET_NOT_IN_SCOPE`.
- **CIDR Subnet Containment**:
  - Target IPs are verified against allowed CIDR blocks using Python's standard `ipaddress.ip_network`.
  - Excluded targets always override included targets.

---

## 2. Model & Execution Boundaries

### 2.1 No Arbitrary Commands
- AI models and LLM agents **never** have shell execution, arbitrary CLI execution, or unrestricted filesystem capabilities.
- All backend tasks are predefined, strongly typed jobs (e.g. `task_type="osint_recon"`, `task_type="mock_scan"`).
- Arguments are validated strictly against Pydantic schemas before invocation.

### 2.2 Anti-Hallucination & Citation Grounding
- AI-driven triage cannot invent vulnerabilities or evidence.
- Every finding confirmed in the system must reference an existing `evidence_id` collected in the same assessment.
- Runtime citation validation (`AIAnalysis.validate_citations`) guarantees that any evidence ID referenced by the model exists in the provided context. Responses with invalid citations are rejected and fail over to deterministic rule-based analysis.

### 2.3 Resource Bounding & Potato-PC Friendliness
- Bounded execution timeouts (`timeout_seconds`, `AI_TIMEOUT_SECONDS`) are enforced across all adapters and model calls.
- Concurrency semaphores prevent CPU or memory exhaustion on modest hardware.

---

## 3. Secrets Management & Privacy

### 3.1 Zero Sensitive Commits
- No API keys, passwords, database credentials, or real customer assessment artifacts may be committed to version control.
- Git repositories are monitored with `.gitignore` rules excluding all `.env`, `.db`, `.log`, and credential files.

### 3.2 Secret Sanitization in API Responses & Logs
- The public `GET /health` endpoint reveals only service status, application name, version, and environment. It never exposes environment variables, database connection strings, or system paths.
- Audit logs and error messages sanitize authentication tokens, stripping `Authorization` header values before recording events.

---

## 4. Immutable Audit Trail

- Every state change, approval, job transition, target scope evaluation, and finding creation produces an immutable `AuditEventModel` record in the database.
- Audit events are append-only. No API endpoint exists to update or delete audit events.
- Audit entries record `event_type`, `actor`, `assessment_id`, structured `details`, and ISO-8601 timestamps.

---

## 5. Safe Offline Testing Standards

- **Deterministic Offline Testing**: All automated unit and integration tests run offline using synthetic data, mock adapters (`MockOSINTAdapter`), and temporary SQLite database fixtures.
- **Zero Live Scans in CI/CD**: Running automated Nmap, ZAP, or live DNS/WHOIS sweeps during testing, build, or startup is strictly forbidden.
- **Verification of Pass/Fail**: Test results must be explicitly observed from test runner exit codes and output logs. No test is marked passed based on assumptions.
