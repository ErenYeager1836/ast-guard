"""
Rule AG-106: Insecure Temporary File Creation (CWE-377)

Detects the usage of tempfile.mktemp(), which returns an absolute pathname of a
file that didn't exist at the time the call was made, leaving a window for
time-of-check to time-of-use (TOCTOU) file race condition exploits.
"""

from __future__ import annotations

import ast
from typing import List

from ast_guard.context import RuleContext
from ast_guard.models import Confidence, Finding, Severity
from ast_guard.rules.base import BaseRule


class InsecureTempfileRule(BaseRule):
    """
    Flags calls to tempfile.mktemp().
    """

    rule_id = "AG-106"
    name = "Insecure Temporary File Creation (TOCTOU Race Condition)"
    cwe_id = "CWE-377"
    owasp_category = "A01:2021-Broken Access Control"
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH
    description = (
        "Insecure temporary file creation detected: tempfile.mktemp() is deprecated and "
        "vulnerable to TOCTOU race conditions where an attacker can hijack the filename before creation."
    )
    remediation = (
        "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() which securely creates and opens "
        "the file atomically with restrictive file permissions (0600)."
    )

    target_node_types = (ast.Call,)

    def check_node(self, node: ast.AST, context: RuleContext) -> List[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        if call_name in {"tempfile.mktemp", "mktemp"}:
            return [
                self.create_finding(
                    node,
                    context,
                    message="Use of insecure tempfile.mktemp() creates a TOCTOU race condition vulnerability.",
                )
            ]

        return []
