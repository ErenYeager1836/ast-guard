"""
Rule AG-102: Command Injection Detection (CWE-78)

Detects the invocation of shell execution APIs such as os.system, os.popen,
or subprocess calls where shell=True is enabled.
"""

from __future__ import annotations

import ast
from typing import List

from ast_guard.context import RuleContext
from ast_guard.models import Confidence, Finding, Severity
from ast_guard.rules.base import BaseRule


class CommandInjectionRule(BaseRule):
    """
    Flags calls to operating system shell commands that could lead to remote
    code execution or command injection if supplied with untrusted inputs.
    """

    rule_id = "AG-102"
    name = "Command Injection / Insecure Shell Execution"
    cwe_id = "CWE-78"
    owasp_category = "A03:2021-Injection"
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH
    description = (
        "Insecure shell execution detected: command execution via os.system, os.popen, "
        "or subprocess with shell=True can allow arbitrary command execution."
    )
    remediation = (
        "Pass arguments as a sequence (list of strings) and set shell=False (e.g., "
        "subprocess.run(['command', arg1, arg2], check=True, shell=False)). Avoid os.system."
    )

    target_node_types = (ast.Call,)

    DANGEROUS_OS_FUNCS = {
        "os.system",
        "os.popen",
        "os.popen2",
        "os.popen3",
        "os.popen4",
        "posix.system",
    }

    SUBPROCESS_FUNCS = {
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "Popen",
        "run",
        "call",
        "check_call",
        "check_output",
    }

    def check_node(self, node: ast.AST, context: RuleContext) -> List[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        if not call_name:
            return []

        # Case 1: os.system / os.popen
        if call_name in self.DANGEROUS_OS_FUNCS:
            return [
                self.create_finding(
                    node,
                    context,
                    message=f"Direct shell invocation via '{call_name}' detected. Vulnerable to command injection.",
                )
            ]

        # Case 2: subprocess with shell=True keyword argument or positional bool
        is_attr_match = isinstance(node.func, ast.Attribute) and node.func.attr in {
            "Popen", "run", "call", "check_call", "check_output"
        }
        if call_name in self.SUBPROCESS_FUNCS or is_attr_match:
            for kw in node.keywords:
                if kw.arg == "shell":
                    # Check if shell is assigned True
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        return [
                            self.create_finding(
                                node,
                                context,
                                message=f"Subprocess invocation '{call_name}' has shell=True enabled.",
                            )
                        ]
                    # Also check non-constant truthy expressions
                    elif not isinstance(kw.value, ast.Constant):
                        return [
                            self.create_finding(
                                node,
                                context,
                                message=f"Subprocess invocation '{call_name}' has dynamic shell argument.",
                                confidence=Confidence.MEDIUM,
                            )
                        ]

        return []
