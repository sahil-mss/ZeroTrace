#!/usr/bin/env python3
"""CLI Entrypoint for AegisPT End-to-End Demonstration."""

import sys
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegispt.security_engine.demo import run_end_to_end_demonstration

if __name__ == "__main__":
    result = run_end_to_end_demonstration(verbose=True)
    sys.exit(0 if result["job_response"]["status"] == "COMPLETED" else 1)
