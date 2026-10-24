"""Module entrypoint for aegispt.security_engine."""

import sys
from aegispt.security_engine.demo import run_end_to_end_demonstration


def main() -> int:
    """Execute the security testing engine demonstration."""
    result = run_end_to_end_demonstration(verbose=True)
    return 0 if result["job_response"]["status"] == "COMPLETED" else 1


if __name__ == "__main__":
    sys.exit(main())
