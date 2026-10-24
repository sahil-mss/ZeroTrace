# 🛡️ AegisPT — AI-Assisted Cybersecurity Assessment Platform

> **Backend Foundation & Scaffolding (Person 1 - Session 1)**

AegisPT is a modular cybersecurity research platform designed for authorized security assessments of owned applications, local lab environments, and explicitly approved targets.

---

## 👥 3-Person Team Division & Ownership

| Person | Role & Subsystem | Responsibilities | Hardware Assignment |
| :--- | :--- | :--- | :--- |
| **Person 1 (Current Role)** | **Backend Foundations & OSINT** | Central FastAPI backend, configuration, scope enforcement, evidence storage, OSINT adapters, job lifecycle. | Potato PC Friendly |
| **Person 2** | **Security Testing & Scanners** | Tool adapters (Nmap, ZAP, Nuclei), finding normalization, verification in local labs. | GPU PC 1 |
| **Person 3** | **AI & User Experience** | Model planning, technical finding analysis, frontend dashboard, report generation. | GPU PC 2 |

---

## 💻 Windows PowerShell Setup Instructions

### 1. Prerequisites
- Python 3.12+ (or 3.14) installed on Windows.
- Windows PowerShell.

### 2. Create and Activate Virtual Environment
Open PowerShell in the project directory:

```powershell
# Create virtual environment
py -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# If script execution is restricted on your machine, enable it for current process:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

### 3. Install Dependencies
```powershell
pip install --upgrade pip
pip install -e ".[dev]"
```

### 4. Configure Environment
Copy the sample environment configuration:
```powershell
Copy-Item .env.example .env
```

---

## 🗄️ Database Persistence & Alembic Migrations (Session 3)

AegisPT uses **SQLAlchemy 2** for persistence with **SQLite** as the initial development database and full **Alembic** migration management.

### Centralized Configuration
- The database connection string is read from `DATABASE_URL` in `.env` (or environment variables).
- Default local path: `sqlite:///./aegis_data/aegispt.db`
- **SQLite Foreign-Key Enforcement**: Foreign-key checks are strictly enabled on all SQLite database connections via `PRAGMA foreign_keys=ON;`.

### Initializing the Database & Running Migrations
To apply the database schema migration to a fresh development environment:

```powershell
# Apply all pending Alembic migrations
alembic upgrade head

# Inspect current database revision
alembic current
```

### Creating Future Migrations
When ORM models in `backend/app/db/models.py` are modified:
```powershell
# Autogenerate a new migration script
alembic revision --autogenerate -m "describe_changes"

# Apply the new migration
alembic upgrade head
```

### Persistence Models & Integrity Rules
The database layer maps directly to the shared contracts (`aegis_common`) across 6 core entities:
1. **`assessments`**: Root authority records with portable JSON scope rules (`scope_rules_json`, `scope_json`) and lifecycle status.
2. **`assets`**: Discovered target assets with strict foreign keys to parent assessments and deduplication enforced via unique constraint `uq_asset_assessment_value`.
3. **`evidence`**: Immutable evidence records with cryptographic SHA-256 content hashes, cross-assessment asset verification, and sanitized payloads (no raw credentials stored).
4. **`findings`**: Normalized vulnerabilities requiring verified parent assessment, valid asset reference, and verified evidence provenance IDs.
5. **`jobs`**: Worker and scanner task execution records with resource budgets, timeouts, and atomic state transitions.
6. **`audit_events`**: Append-only immutable compliance audit trail. Overwrites or updates to existing audit events are strictly prohibited.

---

## 🚀 Application Startup

Start the backend server using the runner script:
```powershell
python run_backend.py
```

Alternatively, start directly with Uvicorn:
```powershell
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## 🩺 Health Check Verification

Once running, verify the API health status using PowerShell or a browser:

### Using PowerShell:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -Method Get
```

### Using curl:
```bash
curl http://127.0.0.1:8000/health
```

### Expected JSON Response:
```json
{
  "status": "healthy",
  "app_name": "AegisPT",
  "version": "0.1.0",
  "environment": "development"
}
```

Interactive OpenAPI documentation is available at:
- Swagger UI: `http://127.0.0.1:8000/docs`

---

## 🧪 Testing & Code Quality

Run tests with `pytest`:
```powershell
pytest -v
```

Run linting and style checks with `ruff`:
```powershell
ruff check .
```

---

## 🔒 Security and Engineering Standards
All development must adhere strictly to the rules documented in [`AGENTS.md`](./AGENTS.md). Assessments run only against authorized targets; no external scans or network calls are triggered during development or testing.
