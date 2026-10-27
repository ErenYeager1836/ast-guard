"""
Base class and utilities for ast-guard security rules.

Each rule targets specific AST node types and produces standardized Finding instances.
"""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from typing import Any, List, Optional, Tuple

from ast_guard.context import RuleContext
from ast_guard.models import Confidence, Finding, Location, Severity


class BaseRule(ABC):
    """
    Abstract Base Class for all AST security inspection rules.
    """

    rule_id: str = "AG-000"
    name: str = "Base Security Rule"
    cwe_id: str = "CWE-000"
    owasp_category: str = "A00:2021-Unknown"
    default_severity: Severity = Severity.MEDIUM
    default_confidence: Confidence = Confidence.MEDIUM
    description: str = ""
    remediation: str = ""

    # Specific AST node types that trigger this rule (for fast dispatch)
    target_node_types: Tuple[type, ...] = (ast.AST,)

    def __init__(self, severity: Optional[Severity] = None, confidence: Optional[Confidence] = None):
        self.severity = severity or self.default_severity
        self.confidence = confidence or self.default_confidence

    @abstractmethod
    def check_node(self, node: ast.AST, context: RuleContext) -> List[Finding]:
        """
        Inspects an individual AST node and returns a list of findings (if any).
        """
        pass

    def create_finding(
        self,
        node: ast.AST,
        context: RuleContext,
        message: Optional[str] = None,
        remediation: Optional[str] = None,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
    ) -> Finding:
        """
        Factory helper to create a Finding associated with the node's source location.
        """
        line_no = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)
        end_line_no = getattr(node, "end_lineno", line_no)
        end_col_offset = getattr(node, "end_col_offset", None)

        snippet = context.get_snippet(line_no, context_lines=1)

        loc = Location(
            file_path=str(context.file_path),
            line_number=line_no,
            col_offset=col_offset,
            end_line_number=end_line_no,
            end_col_offset=end_col_offset,
            code_snippet=snippet,
        )

        return Finding(
            rule_id=self.rule_id,
            rule_name=self.name,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            message=message or self.description,
            remediation=remediation or self.remediation,
            location=loc,
        )

    # -------------------------------------------------------------------------
    # AST Helper Methods (Reusable across rules)
    # -------------------------------------------------------------------------

    @staticmethod
    def get_call_name(node: ast.Call) -> Optional[str]:
        """
        Resolves the full qualified name of a Call node function.
        Handles:
          - Simple calls: `eval(...)` -> 'eval'
          - Attribute calls: `os.system(...)` -> 'os.system'
          - Chained calls: `subprocess.Popen(...)` -> 'subprocess.Popen'
        """
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            parts = []
            curr: Any = func
            while isinstance(curr, ast.Attribute):
                parts.append(curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                parts.append(curr.id)
            parts.reverse()
            return ".".join(parts)
        return None

    @staticmethod
    def is_string_formatting(node: ast.AST) -> bool:
        """
        Detects whether an AST expression represents dynamic string interpolation:
          1. f-strings: `ast.JoinedStr`
          2. `%` operator: `ast.BinOp(op=ast.Mod(), left=str_or_any)`
          3. `.format()` call: `ast.Call(func=ast.Attribute(attr='format'))`
          4. String concatenation: `ast.BinOp(op=ast.Add())`
        """
        # Case 1: f-string e.g. f"SELECT * FROM users WHERE id = {user_id}"
        if isinstance(node, ast.JoinedStr):
            return True

        # Case 2: % formatting e.g. "SELECT * FROM users WHERE id = %s" % user_id
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True

        # Case 3: string concatenation e.g. "SELECT * FROM users WHERE id = " + user_id
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True

        # Case 4: str.format(...) e.g. "SELECT * FROM users WHERE id = {}".format(user_id)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                return True

        return False
