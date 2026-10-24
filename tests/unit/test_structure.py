"""Smoke test verifying module structure and package discovery."""

import importlib
import unittest


class TestProjectStructure(unittest.TestCase):
    """Verifies that the AegisPT security engine package layout is valid."""

    def test_aegispt_root_import(self) -> None:
        """Ensure top-level package imports and exports version."""
        import aegispt

        self.assertTrue(hasattr(aegispt, "__version__"))
        self.assertEqual(aegispt.__version__, "0.1.0")

    def test_security_engine_import(self) -> None:
        """Ensure security_engine package imports and exports metadata."""
        import aegispt.security_engine as se

        self.assertEqual(se.MODULE_NAME, "security_engine")
        self.assertEqual(se.MODULE_VERSION, "0.1.0")
        self.assertIn("Person 2", se.PERSON_RESPONSIBILITY)

    def test_subpackages_discoverable(self) -> None:
        """Ensure all planned subpackages are discoverable and loadable."""
        subpackages = [
            "aegispt.security_engine.core",
            "aegispt.security_engine.schemas",
            "aegispt.security_engine.integrations",
            "aegispt.security_engine.integrations.nmap",
            "aegispt.security_engine.integrations.zap",
            "aegispt.security_engine.verification",
            "aegispt.security_engine.storage",
            "aegispt.security_engine.evaluation",
        ]
        for pkg in subpackages:
            with self.subTest(package=pkg):
                mod = importlib.import_module(pkg)
                self.assertIsNotNone(mod.__doc__)
                self.assertTrue(len(mod.__doc__.strip()) > 0)


if __name__ == "__main__":
    unittest.main()
