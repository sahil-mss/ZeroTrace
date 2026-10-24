# AegisPT Lab Setup & Evaluation Guide

This guide details the installation, configuration, operational lifecycle, readiness checks, and troubleshooting for the **OWASP Juice Shop** security testing lab.

---

## 1. Overview & Security Policy

The lab uses [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (`bkimminich/juice-shop:v17.1.1`), an industry-standard deliberately vulnerable web application designed for security testing and educational research.

### Mandatory Security Controls
1. **Loopback Only (`127.0.0.1`):** The application binds strictly to the host loopback address on port `3000`. It is never bound to `0.0.0.0`.
2. **No Public Ingress:** The Docker bridge network is internal to the host machine.
3. **Synthetic Data:** Juice Shop provisions synthetic accounts (`admin@juice-sh.op`, `jim@juice-sh.op`) and dummy SQLite database records in memory. No real customer, credential, or sensitive data is ever used.
4. **No Destructive Exploits:** The testing engine operates exclusively in authorized assessment mode.

---

## 2. Prerequisites & Installation

### Option A: Running with Docker (Recommended)
1. **Install Docker Desktop for Windows:**
   - Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop/).
   - Ensure the WSL 2 backend is enabled.
2. **Verify Docker Installation:**
   ```powershell
   docker --version
   docker compose version
   ```

### Option B: Running without Docker (Node.js Direct)
If Docker cannot be installed in your environment, Juice Shop can also run directly via Node.js:
```powershell
# 1. Clone or download Juice Shop
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop

# 2. Install and run
npm install
npm start
```
By default, Node.js binds to `http://127.0.0.1:3000`.

---

## 3. Starting the Lab

To start the isolated container in the background:

```powershell
# Navigate to the lab folder
cd lab

# Start container in detached mode
docker compose up -d
```

### Verification via Docker CLI:
```powershell
docker compose ps
```
Output will show `aegispt-lab-juice-shop` with status `Up` and port mapping `127.0.0.1:3000->3000/tcp`.

---

## 4. Checking Lab Readiness via LabManager

The AegisPT Security Testing Engine includes a programmatic [`LabManager`](file:///c:/Users/JASIF/OneDrive/Desktop/Idea/aegispt/security_engine/evaluation/lab_manager.py) component to probe readiness before initiating scans:

### From Python CLI:
```powershell
python -c "from aegispt.security_engine.evaluation import LabManager; mgr = LabManager.from_file('lab/lab_config.json'); print(mgr.get_readiness_report().model_dump_json(indent=2))"
```

### Sample Readiness Output (when running):
```json
{
  "lab_name": "OWASP Juice Shop Local Lab",
  "target_url": "http://127.0.0.1:3000",
  "is_reachable": true,
  "is_ready": true,
  "application_version": "17.1.1",
  "status_code": 200,
  "response_time_ms": 14.8,
  "message": "Lab is READY for authorized testing (Version: 17.1.1, Response time: 14.8ms)",
  "details": {
    "status_code": 200,
    "version_endpoint": "/rest/admin/application-version",
    "synthetic_data_ready": true
  }
}
```

---

## 5. Stopping the Lab

To stop the running container without discarding data:

```powershell
cd lab
docker compose stop
```

To take down the container and network cleanly:

```powershell
cd lab
docker compose down
```

---

## 6. Resetting the Lab (Clean State Restoration)

During vulnerability testing, web applications accumulate state changes (modified orders, token invalidations, injected reviews). To restore Juice Shop back to a pristine, reproducible baseline:

```powershell
cd lab

# 1. Stop and remove container, volumes, and temporary networks
docker compose down -v

# 2. Restart container cleanly
docker compose up -d

# 3. Verify that the fresh instance is reachable
python -c "from aegispt.security_engine.evaluation import LabManager; print(LabManager.from_file('lab/lab_config.json').get_readiness_report().is_ready)"
```

Juice Shop reinitializes its in-memory SQLite schema automatically upon every fresh container startup.

---

## 7. Troubleshooting Common Problems

| Symptom | Cause | Solution |
|---|---|---|
| `docker : The term 'docker' is not recognized` | Docker is not installed or not in system PATH | Install Docker Desktop from docker.com, or ensure `C:\Program Files\Docker\Docker\resources\bin` is added to system PATH. |
| `Bind for 127.0.0.1:3000 failed: port is already allocated` | Another process (e.g. local dev server, previous Juice Shop) is occupying port 3000 | Find occupying process with `Get-NetTCPConnection -LocalPort 3000` and stop it, or edit `port` in `docker-compose.yml` and `lab/lab_config.json` to e.g. `3001`. |
| `Connection refused or host unreachable` | Container has not finished initializing, or Docker daemon is stopped | Wait 10-15 seconds for Node.js startup. Check `docker compose logs juice-shop`. |
| `Security Guardrail: Target resolves to a public internet IP` | `target_url` configured in `lab_config.json` is pointed to a public IP or internet host | Ensure `target_url` uses `http://127.0.0.1:3000` or `http://localhost:3000`. The engine refuses to scan public internet destinations. |
