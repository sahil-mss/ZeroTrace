# AegisPT Security Testing Lab (OWASP Juice Shop)

This directory contains the container orchestration and configuration for running an isolated, deliberately vulnerable local target application.

## Quick Start

```powershell
# Start lab on 127.0.0.1:3000
docker compose up -d

# Check readiness via Python LabManager
python -c "from aegispt.security_engine.evaluation import LabManager; print(LabManager.from_file('lab_config.json').get_readiness_report().message)"

# Reset lab to fresh state
docker compose down -v && docker compose up -d

# Stop lab
docker compose down
```

See [docs/LAB_SETUP.md](../docs/LAB_SETUP.md) for full configuration, security boundaries, and troubleshooting steps.
