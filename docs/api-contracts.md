# ZeroTrace REST API Contracts & Integration Specification

**Owner:** Person 1 (Backend, Scope & Policy Enforcement, OSINT, Persistence)  
**Consumers:** Person 2 (Security Scanners & Verification), Person 3 (AI Orchestration, Frontend UI & Reporting)  
**Platform Version:** ZeroTrace v0.1.0 (Session 8 Complete)

---

## 1. Authentication & Security Policy

### Prototype Bearer Token Authentication
All endpoints except `/health` require an `Authorization` header containing a valid Bearer token:
```http
Authorization: Bearer <API_BEARER_TOKEN>
```

> [!IMPORTANT]
> **Prototype Warning:** A single shared API Bearer token is a development prototype for teammate integration and test automation, not a complete multi-user authentication system. Production deployments require role-based access control (RBAC), fine-grained tenant boundaries, user identity providers, and short-lived tokens.

### Security Guarantees
- **Fail-Closed:** When `API_BEARER_TOKEN` is unconfigured or empty in environment settings, all protected endpoints immediately reject incoming requests with HTTP `401 Unauthorized`.
- **Timing-Attack Resistance:** Token evaluation is performed using constant-time string comparison (`secrets.compare_digest`).
- **Secret Redaction:** Token values and sensitive request headers are scrubbed from logs and audit events.
- **Conservative CORS:** Default CORS origins are locked down to trusted local addresses (`localhost:3000`, `127.0.0.1:3000`). Wildcard `*` origins are disabled.

---

## 2. API Endpoint Reference

### System Health
| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | **No** (Public) | Returns minimal service health, app name (`ZeroTrace`), and version. Leaks no secrets or internal configuration. |

### Assessments
| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/assessments` | Yes | Creates an authorized assessment with explicit scope rules. Enforces `PENDING_APPROVAL` status; never launches scans on creation. |
| `GET` | `/assessments` | Yes | Paginated list of assessments (`?limit=50&offset=0`). |
| `GET` | `/assessments/{id}` | Yes | Retrieves full assessment domain model by ID. |
| `POST` | `/assessments/{id}/approve` | Yes | Formal operator approval sign-off. Transitions status to `APPROVED`. |

### Execution Control (Backed by `JobService`)
| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/assessments/{id}/start` | Yes | Validates approval, scope, and permissions, then creates and enqueues a bounded job via `JobService`. Never runs shell commands directly. |
| `POST` | `/assessments/{id}/cancel` | Yes | Triggers cooperative cancellation of all active worker jobs via `JobService` and records an immutable audit event. |

### Asset & Finding Retrieval
| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/assessments/{id}/assets` | Yes | Returns actual persisted assets for the assessment. Supports filtering by `scope_status` and `asset_type`, plus pagination. |
| `GET` | `/assessments/{id}/findings` | Yes | Returns actual persisted findings. Returns empty list `[]` when none exist; never returns fabricated demonstration data. |

### Evidence, Jobs & Audit Activity
| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/assessments/{id}/evidence` | Yes | Returns verified evidence records belonging strictly to the requested assessment. |
| `GET` | `/assessments/{id}/events` | Yes | Returns immutable audit trail entries in chronological order. |
| `GET` | `/assessments/{id}/jobs` | Yes | Returns worker jobs belonging to the assessment, with optional `status` filter. |

### Report Readiness
| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/assessments/{id}/report` | Yes | Checks report generation status. Returns explicit `NOT_READY` response since Person 3 reporting service is under implementation; never fabricates reports. |

### Partner Integration Endpoints (Person 2 & Person 3)
| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/assessments/{id}/evidence` | Yes | Ingests raw scanner observations, calculates SHA-256 content hashes, and links to target assets. |
| `POST` | `/assessments/{id}/findings` | Yes | Submits findings. Rejects submissions if referenced `evidence_ids` do not exist in the evidence store. |
| `POST` | `/assessments/{id}/assets` | Yes | Registers an asset candidate with deterministic scope classification. |
