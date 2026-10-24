# Person 1 Implementation Plan & Status — ZeroTrace

**Owner:** Person 1 (Backend, Scope & Policy Engine, OSINT Intelligence, Data Contracts, Storage, Job Orchestration)  
**Target Platform:** Lightweight / Potato-PC Friendly (CPU-based, low memory footprint, zero GPU dependencies)  
**Technical Stack:** Python 3.12+ (Python 3.14.7 runtime), FastAPI, Pydantic v2, Synchronous SQLAlchemy 2, Alembic, SQLite, pytest, HTTPX, Ruff.

---

## 1. Implementation Status Overview

All Person 1 sessions (Sessions 1 through 9) are fully implemented, tested, and verified.

| Session | Focus Area | Status | Verification Summary |
| :--- | :--- | :---: | :--- |
| **Session 1** | Minimum Backend Skeleton | ✅ Completed | FastAPI app, `GET /health`, centralized settings, pyproject dependencies. |
| **Session 2** | Versioned Shared Data Contracts | ✅ Completed | `aegis_common` package, Pydantic models, JSON Schemas under `schemas/v1/`. |
| **Session 3** | Database Persistence & Migrations | ✅ Completed | SQLAlchemy 2 ORM models, SQLite engine with foreign keys, Alembic migration scripts. |
| **Session 4** | Deterministic Scope Validator | ✅ Completed | Target canonicalization (trailing dot, IDN Punycode), CIDR check, lookalike rejection. |
| **Session 5** | Asset Normalizer & Evidence Store | ✅ Completed | Asset deduplication, SHA-256 evidence hashing, tamper detection, idempotency. |
| **Session 6** | Passive OSINT Framework | ✅ Completed | Modular OSINT protocol, `MockOSINTAdapter`, bounded execution context. |
| **Session 7** | Deterministic Job Lifecycle | ✅ Completed | State machine (`CREATED` -> `COMPLETED`/`CANCELLED`), illegal transition rejection. |
| **Session 8** | REST API Service Integration | ✅ Completed | Endpoints for `/assessments`, `/assets`, `/evidence`, `/findings`, `/jobs`, `/events`. |
| **Session 9** | End-to-End Tests & Handoff Docs | ✅ Completed | 15-step E2E integration test, 9 regression tests, full documentation suite. |
| **Session 10** | Passive Intelligence Adapters | ✅ Completed | DNSMetadataAdapter and CertificateTransparencyAdapter, bounded queries, rate limits, candidate scope checks. |

---

## 2. Verified Test Suite Results

The comprehensive test suite contains **140 tests**, all passing deterministically with **zero live network calls**:
- `tests/unit/test_session10_adapters.py` (11 tests) — DNS metadata and CT adapter tests, missing vs error distinction, rate limits, caching, and candidate classification.
- `tests/unit/test_osint_framework.py` (9 tests) — Mock collection, deduplication, malformed data, timeouts, cancellation.
- `tests/unit/test_scope_validator.py` (30 tests) — Scope rule edge cases, CIDR containment, IDN, lookalike domains.
- `tests/unit/test_evidence_store.py` (5 tests) — Cryptographic evidence integrity, SHA-256 checks.
- `tests/unit/test_asset_normalizer.py` (5 tests) — Asset deduplication and scope attribution.
- `tests/test_schemas.py` (7 tests) — Schema integrity, evidence clamping, anti-hallucination citation checks.
- `tests/test_ai_layer.py` (7 tests) — AI prompt formulation, timeouts, deterministic fallback.
- `tests/test_ai_and_reporting.py` (3 tests) — AI triage and report compilation pipeline.
- `tests/test_upstream_integration.py` (5 tests) — Upstream scanner and OSINT payload normalization.
- `tests/integration/test_orchestrator_and_api.py` (10 tests) — Orchestrator state transitions, cancellation, API routes.
- `tests/integration/test_api_endpoints.py` (14 tests) — Assessment lifecycle, authorization, asset/evidence listing.
- `tests/integration/test_end_to_end_session9.py` (10 tests) — 15-step end-to-end integration and 9 negative/regression scenarios.
- Additional test modules (24 tests) — Persistence, migrations, and model verification.

**Total Test Count:** 140 passed in ~15s.  
**Linter Status:** Ruff check: 0 errors; Ruff format: 100% compliant.

---

## 3. Architecture & Repository Structure

```text
ZeroTrace/
├── aegis_common/              # Canonical shared Pydantic v2 data contracts
│   ├── enums.py               # Canonical enum definitions
│   └── models/                # Assessment, Asset, Evidence, Finding, Job, AuditEvent
├── backend/                   # Person 1 Backend Services & Application
│   ├── app/
│   │   ├── main.py            # FastAPI main application entrypoint
│   │   ├── api/               # REST API route handlers
│   │   ├── core/              # Settings and security tokens
│   │   ├── db/                # SQLAlchemy ORM models, session manager, repositories
│   │   └── services/          # ScopeValidator, JobService, EvidenceService, AssetService, OSINT
│   └── orchestrator/          # Legacy orchestrator bridge
├── modules/
│   ├── ai/                    # Person 3 AI Triage and Reasoning Layer
│   ├── osint/                 # Passive OSINT adapters and normalizer
│   ├── reporting/             # Report generation engine
│   └── scanners/              # Person 2 Scanners integration interface
├── schemas/                   # Shared schema definitions & v1 JSON schemas
│   └── v1/                    # Exported JSON schemas for cross-language validation
├── tests/                     # Unit, integration, and end-to-end test suites
│   ├── unit/
│   └── integration/
│       └── test_end_to_end_session9.py
├── docs/                      # Developer and integration documentation
│   ├── architecture.md        # System architecture and Mermaid diagrams
│   ├── contracts.md           # Shared data contracts and versioning rules
│   ├── api.md                 # REST API reference and sample requests
│   ├── security.md            # Security, authorization, and scope rules
│   ├── integration.md         # Person 2 & 3 handoff guide
│   └── person1-plan.md        # Implementation plan and status (this document)
├── alembic/                   # Database migrations
├── pyproject.toml             # Project dependencies and tool configurations
└── README.md                  # Main project documentation and quickstart
```

---

## 4. Key Security & Engineering Guarantees Delivered

1. **Deterministic Scope Enforcement**: Target validation happens strictly algorithmically before any job or tool executes. Out-of-scope targets are unconditionally blocked.
2. **No Arbitrary Execution**: The platform strictly controls task types (`osint_recon`, `mock_scan`). No model or user can submit arbitrary shell commands.
3. **Evidence-Grounded Findings**: Findings cannot be confirmed without verifiable evidence rows in the database.
4. **Append-Only Audit Logging**: All approvals, cancellations, job transitions, and findings produce immutable audit events.
5. **Potato-PC Friendly**: Operates reliably on low-resource machines using SQLite, async task management, bounded timeouts, and local deterministic fallbacks.

---

## 5. Explicit Enablement Guide for Authorized Operators

By default, network-backed OSINT adapters (`dns_metadata` and `cert_transparency`) are **disabled** (`OSINT_NETWORK_ENABLED=False`, `OSINT_DNS_ENABLED=False`, `OSINT_CT_ENABLED=False`) to prevent unintentional external network egress during tests or initial setups.

### Step-by-Step Operator Enablement for Controlled Assessments:

1. **Verify Authorization Acknowledgement**:
   Ensure the target assessment is created with `authorization_acknowledged=True`, has an approved authorization reference, and is in `APPROVED` or `ACTIVE` state. Unapproved or expired assessments fail closed immediately.

2. **Configure Environment Variables (PowerShell)**:
   ```powershell
   # Enable network OSINT globally and activate desired adapters
   $env:OSINT_NETWORK_ENABLED = "true"
   $env:OSINT_DNS_ENABLED = "true"
   $env:OSINT_CT_ENABLED = "true"

   # Optional tuning: adjust timeouts and rate limits
   $env:OSINT_REQUEST_TIMEOUT_SECONDS = "10.0"
   $env:OSINT_MAX_RESPONSE_BYTES = "1000000"
   $env:OSINT_RATE_LIMIT_PER_MINUTE = "30"
   $env:OSINT_MAX_RECORDS_PER_COLLECTION = "100"
   ```

3. **Or configure via `.env` file**:
   ```ini
   OSINT_NETWORK_ENABLED=true
   OSINT_DNS_ENABLED=true
   OSINT_CT_ENABLED=true
   OSINT_REQUEST_TIMEOUT_SECONDS=10.0
   OSINT_RATE_LIMIT_PER_MINUTE=30
   OSINT_MAX_RECORDS_PER_COLLECTION=100
   ```

4. **Execute Collection via Python or API**:
   ```python
   from modules.osint.service import OSINTCollectionService

   service = OSINTCollectionService(session=db_session)
   summary = await service.run_collection(
       assessment_id=approved_assessment_id,
       target="approved.target.example.test",
       adapter_names=["dns_metadata", "cert_transparency"],
   )
   ```

5. **Review Discovered Candidate Assets**:
   Discovered hostnames from certificate transparency logs are tagged as `is_candidate=True` and validated against the assessment scope policy before classification (`IN_SCOPE` vs `OUT_OF_SCOPE`). They are **never** automatically scanned.
