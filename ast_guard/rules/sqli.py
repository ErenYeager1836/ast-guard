"""
Rule AG-101: SQL Injection Detection (CWE-89)

Inspects database query execution calls to identify queries constructed via
string concatenation, %-formatting, .format(), or f-strings instead of
parameterized queries.
"""

from __future__ import annotations

import ast
from typing import List

from ast_guard.context import RuleContext
from ast_guard.models import Confidence, Finding, Severity
from ast_guard.rules.base import BaseRule


class SQLInjectionRule(BaseRule):
    """
    Flags database execution methods where SQL strings are dynamically formatted
    rather than parameterized with database adapter place-holders.
    """

    rule_id = "AG-101"
    name = "SQL Injection in Query Execution"
    cwe_id = "CWE-89"
    owasp_category = "A03:2021-Injection"
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH
    description = (
        "Possible SQL injection detected: SQL query is dynamically constructed using "
        "string formatting, concatenation, or f-strings instead of parameterized placeholders."
    )
    remediation = (
        "Use parameterized queries provided by your database driver (e.g., "
        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)) "
        "or an ORM like SQLAlchemy) to safely bind parameters and prevent SQL injection."
    )

    target_node_types = (ast.Call,)

    # Common database cursor / connection / session execution method names
    SQL_EXEC_METHODS = {
        "execute",
        "executemany",
        "raw",
        "cursor.execute",
        "db.execute",
        "session.execute",
        "connection.execute",
        "conn.execute",
    }

    def check_node(self, node: ast.AST, context: RuleContext) -> List[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        if not call_name:
            return []

        # Check if the call is an execution method (either bare or attribute)
        is_exec = False
        if call_name in self.SQL_EXEC_METHODS:
            is_exec = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany", "raw"}:
            is_exec = True

        if not is_exec:
            return []

        # Must have at least 1 argument (the SQL query)
        if not node.args:
            return []

        first_arg = node.args[0]

        # Case 1: First argument is directly formatted dynamically
        if self.is_string_formatting(first_arg):
            return [self.create_finding(node, context)]

        # Case 2: Intra-procedural variable inspection: first_arg is an identifier (ast.Name)
        # whose assigned value earlier in the file was constructed via dynamic string formatting
        if isinstance(first_arg, ast.Name) and getattr(context, "tree", None):
            var_name = first_arg.id
            call_line = getattr(node, "lineno", 0)
            for ast_node in ast.walk(context.tree):
                if isinstance(ast_node, ast.Assign):
                    assign_line = getattr(ast_node, "lineno", 0)
                    if assign_line < call_line:
                        for target in ast_node.targets:
                            if isinstance(target, ast.Name) and target.id == var_name:
                                if self.is_string_formatting(ast_node.value):
                                    msg = (
                                        f"Possible SQL injection detected: variable '{var_name}' "
                                        f"passed to '{call_name}()' was dynamically formatted on line {assign_line}."
                                    )
                                    return [
                                        self.create_finding(
                                            node,
                                            context,
                                            message=msg,
                                        )
                                    ]

        return []
