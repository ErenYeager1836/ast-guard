"""
Unit tests for ast-guard formatters (Console, JSON, and SARIF 2.1.0).
"""

import json
import unittest

from ast_guard.formatters.console import format_console
from ast_guard.formatters.json_out import format_json
from ast_guard.formatters.sarif import format_sarif
from ast_guard.models import Confidence, Finding, Location, ScanResult, Severity


class TestFormatters(unittest.TestCase):
    def setUp(self):
        self.finding = Finding(
            rule_id="AG-101",
            rule_name="SQL Injection in Query Execution",
            cwe_id="CWE-89",
            owasp_category="A03:2021-Injection",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            message="Possible SQL injection detected in raw query formatting.",
            remediation="Use parameterized queries with bound variables.",
            location=Location(
                file_path="app/db.py",
                line_number=42,
                col_offset=4,
                code_snippet=" >   42 | cursor.execute(f'SELECT * FROM users WHERE id = {uid}')",
            ),
        )
        self.result = ScanResult(
            target_path="app/",
            files_scanned=5,
            lines_scanned=250,
            duration_seconds=0.05,
            findings=[self.finding],
        )

    def test_console_formatter(self):
        output = format_console(self.result, no_color=True)
        self.assertIn("=== ast-guard Security Scan Report ===", output)
        self.assertIn("AG-101", output)
        self.assertIn("CWE-89", output)
        self.assertIn("app/db.py:42:4", output)
        self.assertIn("cursor.execute", output)
        self.assertIn("Findings: 1", output)

    def test_json_formatter(self):
        raw_json = format_json(self.result)
        data = json.loads(raw_json)

        self.assertEqual(data["target_path"], "app/")
        self.assertEqual(data["summary"]["total_findings"], 1)
        self.assertEqual(data["summary"]["high"], 1)
        self.assertEqual(data["findings"][0]["rule_id"], "AG-101")
        self.assertEqual(data["findings"][0]["severity"], "HIGH")

    def test_sarif_v210_formatter(self):
        raw_sarif = format_sarif(self.result)
        sarif = json.loads(raw_sarif)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("oasis-tcs/sarif-spec", sarif["$schema"])
        self.assertEqual(len(sarif["runs"]), 1)

        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "ast-guard")

        # Verify rules catalog is present
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertIn("AG-101", rule_ids)

        # Verify results map correctly
        self.assertEqual(len(run["results"]), 1)
        res = run["results"][0]
        self.assertEqual(res["ruleId"], "AG-101")
        self.assertEqual(res["level"], "error")  # HIGH maps to 'error'
        self.assertEqual(res["locations"][0]["physicalLocation"]["region"]["startLine"], 42)


if __name__ == "__main__":
    unittest.main()
