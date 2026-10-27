"""
Integration tests for the ScannerEngine.

Tests recursive directory scanning, inline comment suppression (# nosec and # ast-guard: ignore),
severity filtering, and resilience against syntax errors.
"""

import tempfile
import unittest
from pathlib import Path

from ast_guard.engine import ScannerEngine
from ast_guard.models import Severity


class TestScannerEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_inline_nosec_suppression(self):
        code = (
            "import os\n"
            "os.system('ls') # nosec\n"
            "os.system('dir')\n"
        )
        test_file = self.base_path / "suppress_test.py"
        test_file.write_text(code, encoding="utf-8")

        engine = ScannerEngine()
        result = engine.scan_path(test_file)

        # Only the second os.system should be reported
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].location.line_number, 3)
        self.assertEqual(result.suppressed_count, 1)

    def test_specific_rule_suppression(self):
        code = (
            "import os, pickle\n"
            "os.system('ls') # ast-guard: ignore[AG-102]\n"
            "pickle.loads(b'foo')\n"
        )
        test_file = self.base_path / "rule_suppress.py"
        test_file.write_text(code, encoding="utf-8")

        engine = ScannerEngine()
        result = engine.scan_path(test_file)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_id, "AG-103")
        self.assertEqual(result.suppressed_count, 1)

    def test_syntax_error_resilience(self):
        code = "def broken_syntax(:\n   print('oops')\n"
        test_file = self.base_path / "broken.py"
        test_file.write_text(code, encoding="utf-8")

        engine = ScannerEngine()
        result = engine.scan_path(test_file)

        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.errors), 1)
        self.assertIn("SyntaxError", result.errors[0].error_message)

    def test_severity_filtering(self):
        code = (
            "import hashlib, pickle\n"
            "h = hashlib.md5(b'test').hexdigest()\n"  # MEDIUM
            "p = pickle.loads(b'data')\n"              # CRITICAL
        )
        test_file = self.base_path / "severity_test.py"
        test_file.write_text(code, encoding="utf-8")

        # Scan with min_severity = HIGH -> should exclude MEDIUM (hashlib.md5)
        engine = ScannerEngine(min_severity=Severity.HIGH)
        result = engine.scan_path(test_file)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_id, "AG-103")


if __name__ == "__main__":
    unittest.main()
