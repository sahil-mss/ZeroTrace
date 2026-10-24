"""Pytest configuration and global fixtures for AegisPT test suite."""

import sys
from pathlib import Path

# Ensure project root is in sys.path during test runs
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
