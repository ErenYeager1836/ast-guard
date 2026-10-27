"""
Rule AG-103: Insecure Deserialization Detection (CWE-502)

Detects the deserialization of untrusted data via pickle, _pickle, cPickle,
shelve, or unsafe yaml.load calls.
"""

from __future__ import annotations

import ast
from typing import List

from ast_guard.context import RuleContext
from ast_guard.models import Confidence, Finding, Severity
from ast_guard.rules.base import BaseRule


class InsecureDeserializationRule(BaseRule):
    """
    Flags calls to serialization libraries known to execute arbitrary code
    during object reconstruction if the payload is malicious.
    """

    rule_id = "AG-103"
    name = "Insecure Deserialization"
    cwe_id = "CWE-502"
    owasp_category = "A08:2021-Software and Data Integrity Failures"
    default_severity = Severity.CRITICAL
    default_confidence = Confidence.HIGH
    description = (
        "Insecure deserialization detected: unpickling untrusted data or using unsafe "
        "YAML loaders can result in arbitrary remote code execution (RCE)."
    )
    remediation = (
        "Avoid using pickle for untrusted data; use secure data interchange formats such as "
        "JSON or Protocol Buffers. For YAML, always use yaml.safe_load() or specify Loader=yaml.SafeLoader."
    )

    target_node_types = (ast.Call,)

    PICKLE_FUNCS = {
        "pickle.loads",
        "pickle.load",
        "_pickle.loads",
        "_pickle.load",
        "cPickle.loads",
        "cPickle.load",
        "shelve.open",
    }

    def check_node(self, node: ast.AST, context: RuleContext) -> List[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        if not call_name:
            return []

        # Case 1: pickle / shelve
        if call_name in self.PICKLE_FUNCS:
            msg = (
                f"Insecure deserialization via '{call_name}'. "
                "Pickle byte streams can execute arbitrary code during unpickling."
            )
            return [
                self.create_finding(
                    node,
                    context,
                    message=msg,
                )
            ]

        # Case 2: yaml.load without SafeLoader
        if call_name == "yaml.load":
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    # Check if Loader is SafeLoader or CSafeLoader
                    if isinstance(kw.value, ast.Attribute) and kw.value.attr in {"SafeLoader", "CSafeLoader"}:
                        has_safe_loader = True
                    elif isinstance(kw.value, ast.Name) and kw.value.id in {"SafeLoader", "CSafeLoader"}:
                        has_safe_loader = True

            # If Loader is missing or not SafeLoader, report finding
            if not has_safe_loader:
                msg = (
                    "yaml.load() called without SafeLoader. "
                    "Use yaml.safe_load() to prevent arbitrary Python object instantiation."
                )
                return [
                    self.create_finding(
                        node,
                        context,
                        message=msg,
                        remediation="Use yaml.safe_load(payload) or pass Loader=yaml.SafeLoader explicitly.",
                    )
                ]

        return []
