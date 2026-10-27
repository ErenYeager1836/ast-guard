"""
Rule AG-105: Dynamic Code Execution Detection (CWE-95)

Detects the usage of dangerous built-in functions: eval(), exec(), or compile()
that dynamically evaluate raw strings as executable Python code.
"""

from __future__ import annotations

import ast
from typing import List

from ast_guard.context import RuleContext
from ast_guard.models import Confidence, Finding, Severity
from ast_guard.rules.base import BaseRule


class EvalExecRule(BaseRule):
    """
    Flags calls to eval, exec, and compile.
    """

    rule_id = "AG-105"
    name = "Dangerous Dynamic Code Execution"
    cwe_id = "CWE-95"
    owasp_category = "A03:2021-Injection"
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH
    description = (
        "Dynamic code execution function detected (eval, exec, or compile). "
        "Evaluating untrusted strings allows attackers to execute arbitrary system commands."
    )
    remediation = (
        "Avoid dynamic evaluation. If parsing structured data, use json.loads() or ast.literal_eval() "
        "which safely parses literal Python expressions without executing code."
    )

    target_node_types = (ast.Call,)

    DANGEROUS_BUILTINS = {"eval", "exec", "compile", "builtins.eval", "builtins.exec"}

    def check_node(self, node: ast.AST, context: RuleContext) -> List[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        if not call_name:
            return []

        if call_name in self.DANGEROUS_BUILTINS:
            # If literal_eval was called, that is safe!
            if call_name == "ast.literal_eval" or call_name == "literal_eval":
                return []

            return [
                self.create_finding(
                    node,
                    context,
                    message=f"Dangerous dynamic code evaluation via '{call_name}()'.",
                )
            ]

        return []
