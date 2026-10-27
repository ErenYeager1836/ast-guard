"""
Rule AG-107: Insecure Debug Mode & All-Interface Binding (CWE-489 / CWE-1188)

Detects web frameworks configured with debug=True (which can expose interactive
debuggers with RCE consoles such as Werkzeug) or binding to all network
interfaces (0.0.0.0) without explicit configuration controls.
"""

from __future__ import annotations

import ast
from typing import List

from ast_guard.context import RuleContext
from ast_guard.models import Confidence, Finding, Severity
from ast_guard.rules.base import BaseRule


class InsecureDebugBindingRule(BaseRule):
    """
    Flags calls to app.run(...) with debug=True or host='0.0.0.0'.
    """

    rule_id = "AG-107"
    name = "Insecure Debug Mode or All-Interface Binding"
    cwe_id = "CWE-489"
    owasp_category = "A05:2021-Security Misconfiguration"
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH
    description = (
        "Insecure web server configuration detected: enabling debug=True exposes an interactive "
        "debugger console (often capable of arbitrary Python code execution), or binding to '0.0.0.0' "
        "exposes the service to all external network interfaces."
    )
    remediation = (
        "Never run web applications with debug=True in shared or production environments. "
        "Bind exclusively to '127.0.0.1' or manage the host and debug flags via environment variables."
    )

    target_node_types = (ast.Call,)

    def check_node(self, node: ast.AST, context: RuleContext) -> List[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        if not call_name:
            return []

        # Target app.run() or uvicorn.run()
        is_run_call = False
        if call_name.endswith(".run") or call_name == "run":
            is_run_call = True

        if not is_run_call:
            return []

        findings: List[Finding] = []

        for kw in node.keywords:
            # Check debug=True
            if kw.arg == "debug":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    msg = (
                        f"Server executed with debug=True via '{call_name}()'. "
                        "Interactive debug consoles permit remote code execution."
                    )
                    findings.append(
                        self.create_finding(
                            node,
                            context,
                            message=msg,
                            severity=Severity.HIGH,
                        )
                    )

            # Check host='0.0.0.0'
            elif kw.arg == "host":
                if isinstance(kw.value, ast.Constant) and kw.value.value in {"0.0.0.0", "::"}:
                    msg = (
                        f"Server bound to all interfaces ('{kw.value.value}') via '{call_name}()'. "
                        "May expose unintended services to the local network."
                    )
                    findings.append(
                        self.create_finding(
                            node,
                            context,
                            message=msg,
                            severity=Severity.MEDIUM,
                        )
                    )

        return findings
