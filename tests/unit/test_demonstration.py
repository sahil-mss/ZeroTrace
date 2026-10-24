"""Test for Stage 10 End-to-End Demonstration."""

import unittest

from aegispt.security_engine.demo import run_end_to_end_demonstration
from aegispt.security_engine.schemas.enums import JobStatus


class TestEndToEndDemonstration(unittest.TestCase):
    """Verifies that the reproducible 12-step demonstration runs to completion."""

    def test_run_demonstration_completes_successfully(self) -> None:
        """Run the full end-to-end demonstration and assert success."""
        result = run_end_to_end_demonstration(verbose=False)

        self.assertIn("job_response", result)
        self.assertEqual(result["job_response"]["status"], JobStatus.COMPLETED.value)
        self.assertGreater(result["observations_count"], 0)
        self.assertGreater(result["findings_count"], 0)
        self.assertIn("metrics", result)
        self.assertGreaterEqual(result["metrics"]["precision"], 0.0)
        self.assertGreater(len(result["evidence_sha256"]), 0)


if __name__ == "__main__":
    unittest.main()
