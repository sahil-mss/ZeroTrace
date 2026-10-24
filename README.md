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
