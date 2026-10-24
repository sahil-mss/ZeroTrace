# ZeroTrace / AegisPT

**AegisPT** is a collaborative cybersecurity research and automated assessment platform.

## System Architecture & Module Division

The system is partitioned into three decoupled modules:

- **Person 1: Orchestration & Central Backend**
  - Assessment workflow engine, API gateway, job queue, persistence, and external client interfaces.
- **Person 2: Security Testing Engine** (`aegispt.security_engine`)
  - Target scope validation and safety guardrails.
  - Scanner integrations (Nmap network discovery, OWASP ZAP web vulnerability scanning).
  - Structured scanner output parsing (safe XML and JSON ingestion).
  - Common normalized finding schema (SARIF / unified vulnerability format).
  - Raw evidence collection, hash-based provenance, and safe verification.
  - Reproducible lab evaluation harness for benchmark targets.
- **Person 3: AI Analysis & Intelligence Layer**
  - Vulnerability correlation, attack-path reasoning, report synthesis, and remediation guidance.

## Person 2 Module Structure

```text
aegispt/
└── security_engine/
    ├── core/           # Configuration, safety controls, target validation
    ├── schemas/        # Common Pydantic data contracts (targets, findings, results)
    ├── integrations/   # Scanner harnesses (Nmap, OWASP ZAP)
    ├── verification/   # Safe non-destructive finding verification
    ├── storage/        # Raw artifact preservation & evidence tracking
    └── evaluation/     # Lab benchmarks and evaluation harness
```

For detailed architecture and interface contracts, refer to [docs/PERSON_2_MODULE_DESIGN.md](docs/PERSON_2_MODULE_DESIGN.md).

## Getting Started

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Git

### Installation
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

### Running Tests
```bash
pytest -v
```

### Running the End-to-End Demonstration
```bash
python scripts/run_demonstration.py
```

### Documentation & Reference Manual
For complete architecture documentation, configuration options, troubleshooting, and scanner guides, see:
- [Security Engine Operator & Developer Manual](docs/SECURITY_ENGINE_MANUAL.md)
- [Backend & AI Integration Guide](docs/BACKEND_AI_INTEGRATION.md)
- [Verification Engine Specification](docs/VERIFICATION_ENGINE.md)
- [Benchmark Evaluation Framework](docs/EVALUATION_FRAMEWORK.md)
- [Local Lab Setup Guide](docs/LAB_SETUP.md)
- [Nmap Adapter Specification](docs/NMAP_ADAPTER.md)
- [OWASP ZAP Adapter Specification](docs/ZAP_ADAPTER.md)
- [Finding Normalization Engine Specification](docs/NORMALIZATION_ENGINE.md)
```
