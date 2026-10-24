# Person 1 Implementation Plan & Architecture Roadmap — AegisPT

**Owner:** Person 1 (Backend, Scope & Policy Engine, OSINT Intelligence, Data Contracts)  
**Target Platform:** Lightweight / Potato-PC Friendly (CPU-based, low memory footprint, zero GPU dependencies)  
**Technical Stack:** Python 3.12+ (Python 3.14.7 runtime), FastAPI, Pydantic v2, Synchronous SQLAlchemy 2, Alembic, SQLite, pytest, HTTPX, Ruff.

---

## 1. Repository Inspection & Current State

### Git & Environment
- **Branch:** `person1`
- **Runtime:** Python 3.14.7 (compatible with `>=3.11` specification in `pyproject.toml`)
- **Virtual Environment:** `.venv` configured and active.
- **Active Dependencies:** `fastapi`, `uvicorn`, `pydantic>=2.6`, `sqlalchemy>=2.0`, `httpx`, `dnspython`, `pytest`, `pytest-asyncio`.

### Existing Functionality (Must Be Preserved)
1. **Shared Contracts (`schemas/`):**
   - `schemas/enums.py`: `ScopeStatus`, `AssessmentStatus`, `TestPermissionLevel`, `AssetType`, `Severity`, `VerificationStatus`, `JobStatus`, `EvidenceSourceType`.
   - `schemas/models.py`: Strongly typed Pydantic v2 definitions for `Assessment`, `Asset`, `Evidence`, `Finding`, `Job`, `JobAuditEntry`, `AuditEvent`.
2. **Deterministic Scope & Policy Engine (`backend/policy/scope_validator.py`):**
   - Target canonicalization (URL, port, hostname extraction, trailing dot normalization).
   - CIDR subnet containment (`ipaddress.ip_network`), explicit IP matching, and wildcard domain matching (`*.domain.test`).
   - Hard exclusion enforcement (`excluded_targets`) and permission hierarchy validation.
3. **Cryptographic Evidence Store (`backend/storage/evidence_store.py`):**
   - SHA-256 payload calculation and data tampering validation.
   - Raw blob storage on disk named by digest hash.
4. **Synchronous Persistence Layer (`backend/storage/database.py`):**
   - SQLAlchemy 2 ORM models (`AssessmentModel`, `AssetModel`, `EvidenceModel`, `FindingModel`, `JobModel`, `AuditEventModel`) mapped to SQLite.
5. **Passive OSINT Adapters (`modules/osint/`):**
   - `dns_adapter.py`: A, AAAA, CNAME, MX, TXT, NS enumeration with local fallback.
   - `crtsh_adapter.py`: Certificate Transparency subdomain harvesting with rate limits & timeouts.
   - `http_adapter.py`: Non-intrusive HTTP header, banner, and security header auditing.
   - `normalizer.py`: Asset deduplication, relationship graph mapping (`domain -> IP/CNAME`), and scope tagging.
6. **Workflow & Orchestrator Skeleton (`backend/orchestrator/engine.py`):**
   - Job state transitions: `CREATED -> POLICY_CHECK -> QUEUED -> RUNNING -> REVIEW -> COMPLETED`.
   - Immediate cancellation controls and audit trail logging.
7. **Automated Test Suite (`tests/`):**
   - 8 unit and integration tests passing with synthetic test data.

---

## 2. Minimal Backend Architecture

To keep the system robust, potato-PC friendly, and free from distributed complexity (e.g., avoiding Redis or Celery):
- **Local Persistence:** SQLite database file (`./aegis_data/aegispt.db`) using SQLAlchemy 2.
- **In-Process Task Dispatcher:** Python `asyncio` task queue with concurrency semaphore (`max_concurrency`) and timeouts.
- **Blob Storage:** Local directory (`./aegis_data/evidence_blobs/`) using content-addressable SHA-256 naming.
- **Zero Live Network Tests:** All test suites use mock adapters and local fixtures.

### Proposed File Tree
```text
AegisPT/
├── AGENTS.md                  # Permanent security and engineering rules
├── README.md                  # Team integration guide
├── pyproject.toml             # Project metadata, dependencies, Ruff & pytest configs
├── run_backend.py             # Server launcher (FastAPI + Uvicorn)
├── .env.example               # Environment variables template
├── .gitignore                 # Exclusion rules
├── docs/
│   ├── person1-plan.md        # This implementation plan
│   └── api-contracts.md       # API specification for Persons 2 & 3
├── schemas/                   # Shared Data Contracts (Frozen)
│   ├── __init__.py
│   ├── enums.py
│   └── models.py
├── backend/                   # Person 1 Core Infrastructure
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── app.py             # FastAPI application router & endpoints
│   │   └── dependencies.py    # DB & EvidenceStore dependency injection
│   ├── policy/
│   │   ├── __init__.py
│   │   └── scope_validator.py # Deterministic scope validator
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py        # SQLAlchemy models & CRUD methods
│   │   └── evidence_store.py  # SHA-256 blob & evidence verification
│   └── orchestrator/
│       ├── __init__.py
│       └── engine.py          # State machine, cancellation & job queue
├── modules/
│   ├── __init__.py
│   ├── osint/                 # Person 1 Passive Intelligence
│   │   ├── __init__.py
│   │   ├── dns_adapter.py
│   │   ├── crtsh_adapter.py
│   │   ├── http_adapter.py
│   │   ├── normalizer.py
│   │   └── workflow.py
│   ├── scanners/              # Person 2 Security Scanners (Placeholder & Base Adapter)
│   │   ├── __init__.py
│   │   └── base_adapter.py
│   ├── ai/                    # Person 3 AI Specialists (Placeholder)
│   │   └── __init__.py
│   └── reporting/             # Person 3 Reporting (Placeholder)
│       └── __init__.py
├── tests/
│   ├── conftest.py            # Shared synthetic fixtures & mocks
│   ├── unit/
│   │   ├── test_scope_validator.py
│   │   ├── test_evidence_store.py
│   │   └── test_asset_normalizer.py
│   └── integration/
│       └── test_orchestrator_and_api.py
└── docker/
    ├── Dockerfile
    └── docker-compose.yml     # AegisPT + local OWASP Juice Shop lab target
```

---

## 3. Shared Interfaces for Person 2 and Person 3

The backend acts as the single source of truth for the entire team:

| Partner | Interface / Contract | Method / Target | Purpose |
| :--- | :--- | :--- | :--- |
| **Person 2** (Scanners) | `BaseScannerAdapter` | Python ABC in `modules/scanners/base_adapter.py` | Subclasses implement `validate_preconditions()` and `run_scan()`. |
| **Person 2** | `POST /assessments/{id}/evidence` | HTTP REST (`Evidence` payload) | Registers raw scanner evidence (Nmap XML, ZAP JSON) before reporting findings. |
| **Person 2** | `POST /assessments/{id}/findings` | HTTP REST (`Finding` payload) | Submits findings. Rejects submissions if referenced `evidence_ids` are missing. |
| **Person 3** (AI) | `GET /assessments/{id}/assets` | HTTP REST (`List[Asset]`) | Supplies in-scope discovered assets and technologies for test planning. |
| **Person 3** | `GET /assessments/{id}/evidence` | HTTP REST (`List[Evidence]`) | Feeds factual evidence into finding-analysis and explanation models. |
| **Person 3** | `POST /assessments/{id}/jobs` | HTTP REST (`Job` payload) | Allows AI planner to propose jobs, which pass deterministic policy checks before queueing. |
| **Person 3** (UI) | `GET /assessments/{id}/report` | HTTP REST (Summary JSON) | Exports aggregated executive summary, verified findings, evidence, and audit logs. |

---

## 4. Implementation Milestones in Dependency Order

### Milestone 1: Core Framework, Scope Engine Hardening & Alembic Setup
- **Goal:** Robust, deterministic policy validator and migration-ready database.
- **Tasks:**
  - Add Alembic migration environment (`alembic/`) for safe future schema evolution.
  - Implement dependency injection in `backend/api/dependencies.py` for session management.
  - Add Ruff linting/formatting configuration to `pyproject.toml`.
  - Add comprehensive unit tests covering edge cases: IPv6 in CIDR, port range validation, malformed URI handling.
- **Acceptance Criteria:**
  - 100% offline unit tests pass for `ScopeValidator`.
  - Out-of-scope targets rejected with explicit audit log entry.
  - Alembic recognizes initial tables without migration drift.

### Milestone 2: Evidence Store & Asset Normalization Pipeline
- **Goal:** Tamper-proof evidence storage and reliable asset relationship graph.
- **Tasks:**
  - Add mock response fixtures for `DnsLookupAdapter` and `CertTransparencyAdapter` in `tests/conftest.py` so tests never perform external queries.
  - Enforce timeout and max payload limits in OSINT adapters.
  - Refine `AssetNormalizer` to mark stale observations (`last_observed`) and track multi-hop relationships (`domain -> subdomain -> ip -> service`).
- **Acceptance Criteria:**
  - Tampering with an evidence payload immediately fails SHA-256 verification.
  - Ingesting duplicate assets updates existing records without creating orphaned entries.
  - Newly discovered assets are tagged `IN_SCOPE` or `OUT_OF_SCOPE` deterministically.

### Milestone 3: Job Lifecycle, Immediate Cancellation & Audit Engine
- **Goal:** Resilient job state machine with reliable cancellation controls.
- **Tasks:**
  - Implement task cancellation propagation (cancelling an assessment immediately cancels running asyncio tasks).
  - Add concurrency limiter to ensure potato-PC resource bounds.
  - Create audit event stream endpoint (`GET /assessments/{id}/events`) with chronological ordering.
- **Acceptance Criteria:**
  - Triggering `POST /assessments/{id}/cancel` stops execution within 500ms.
  - No job can transition from `FAILED` or `CANCELLED` back to `RUNNING`.
  - Every state transition produces a persistent `AuditEvent`.

### Milestone 4: Integration Surface & Partner Handshake
- **Goal:** Contract validation suite verifying Person 2 and Person 3 integration paths.
- **Tasks:**
  - Build synthetic integration tests simulating Person 2's Nmap/ZAP finding submissions.
  - Verify rejection when a candidate finding references non-existent evidence or claims `CONFIRMED` without high confidence.
  - Provide OpenAPI schema export (`openapi.json`) for Person 3's frontend generation.
- **Acceptance Criteria:**
  - An unverified finding submitted without valid evidence returns HTTP 400 Bad Request.
  - `GET /assessments/{id}/report` produces a complete, verifiable JSON report ready for UI rendering.

---

## 5. Integration Risks & Mitigation Strategies

| Risk | Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Scope Leakage** | Scanner touches unauthorized 3rd-party assets or cloud providers. | Strict pre-execution check: every target must pass `ScopeValidator.is_in_scope()` immediately before tool invocation. No discovered asset is auto-authorized. |
| **Hallucinated Findings** | AI model invents vulnerability findings or claims false confirmation. | Hard database constraint: `POST /assessments/{id}/findings` strictly validates that all `evidence_ids` exist in the evidence store and rejects `CONFIRMED` status if confidence is below 0.70. |
| **Flaky / Blocked Tests** | Tests fail due to external DNS or network timeouts. | All tests run strictly offline using synthetic mocks and local SQLite fixtures. Zero live external network calls during `pytest`. |
| **SQLite Concurrency Contention** | Multiple jobs or API requests cause database lock errors. | Use scoped sessions with WAL mode (`PRAGMA journal_mode=WAL;`), short retry timeouts, and clean session lifecycle management. |
| **Resource Exhaustion on Weak Hardware** | High concurrency or large outputs freeze potato PC. | Enforce job concurrency semaphore (`max_concurrency=3`), strict timeouts (`timeout_seconds`), and stream large outputs directly to hashed disk blobs rather than keeping them in memory. |
