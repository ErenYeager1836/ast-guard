"""
Unit tests for the ast-guard CLI interface.

Tests exit code quality gates, output format exports, rule disabling, and CLI arguments.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ast_guard.cli import main


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("sys.stdout")
    def test_cli_clean_code_exits_zero(self, mock_stdout):
        code_file = self.base_path / "clean.py"
        code_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

        exit_code = main([str(code_file)])
        self.assertEqual(exit_code, 0)

    @patch("sys.stdout")
    def test_cli_vulnerability_exits_one(self, mock_stdout):
        code_file = self.base_path / "vuln.py"
        code_file.write_text("import os\nos.system('calc')\n", encoding="utf-8")

        exit_code = main([str(code_file), "--fail-on", "HIGH"])
        self.assertEqual(exit_code, 1)

    @patch("sys.stdout")
    def test_cli_fail_on_never_exits_zero(self, mock_stdout):
        code_file = self.base_path / "vuln.py"
        code_file.write_text("import os\nos.system('calc')\n", encoding="utf-8")

        exit_code = main([str(code_file), "--fail-on", "NEVER"])
        self.assertEqual(exit_code, 0)

    @patch("sys.stdout")
    def test_cli_sarif_export_file_created(self, mock_stdout):
        code_file = self.base_path / "app.py"
        code_file.write_text("import pickle\npickle.loads(b'data')\n", encoding="utf-8")

        sarif_file = self.base_path / "report.sarif"
        exit_code = main([str(code_file), "--sarif", str(sarif_file), "--fail-on", "NEVER"])

        self.assertEqual(exit_code, 0)
        self.assertTrue(sarif_file.exists())
        content = sarif_file.read_text(encoding="utf-8")
        self.assertIn('"version": "2.1.0"', content)
        self.assertIn("AG-103", content)

    @patch("sys.stdout")
    def test_cli_disabled_rule(self, mock_stdout):
        code_file = self.base_path / "crypto_app.py"
        code_file.write_text("import hashlib\nh = hashlib.md5(b'x').hexdigest()\n", encoding="utf-8")

        # Disable AG-104 rule
        exit_code = main([str(code_file), "--disable-rule", "AG-104", "--fail-on", "LOW"])
        self.assertEqual(exit_code, 0)

    @patch("sys.stdout")
    def test_cli_list_rules(self, mock_stdout):
        exit_code = main(["--list-rules"])
        self.assertEqual(exit_code, 0)

    @patch("sys.stdout")
    def test_cli_multiple_targets(self, mock_stdout):
        f1 = self.base_path / "f1.py"
        f2 = self.base_path / "f2.py"
        f1.write_text("x = 1\n", encoding="utf-8")
        f2.write_text("y = 2\n", encoding="utf-8")

        exit_code = main([str(f1), str(f2)])
        self.assertEqual(exit_code, 0)

    @patch("sys.stdout")
    def test_cli_multiple_targets_with_vulnerability(self, mock_stdout):
        f1 = self.base_path / "clean_target.py"
        f2 = self.base_path / "vuln_target.py"
        f1.write_text("x = 1\n", encoding="utf-8")
        f2.write_text("import os\nos.system('ls')\n", encoding="utf-8")

        exit_code = main([str(f1), str(f2), "--fail-on", "HIGH"])
        self.assertEqual(exit_code, 1)

    @patch("sys.stdout")
    def test_cli_excludes_test_dir_by_default_and_includes_with_flag(self, mock_stdout):
        test_dir = self.base_path / "tests"
        test_dir.mkdir(parents=True, exist_ok=True)
        (test_dir / "test_exploit.py").write_text("import os\nos.system('id')\n", encoding="utf-8")

        # Excluded by default
        exit_code_default = main([str(self.base_path), "--fail-on", "HIGH"])
        self.assertEqual(exit_code_default, 0)

        # Included with --include-tests
        exit_code_included = main([str(self.base_path), "--include-tests", "--fail-on", "HIGH"])
        self.assertEqual(exit_code_included, 1)


if __name__ == "__main__":
    unittest.main()
