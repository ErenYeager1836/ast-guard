"""
Rule AG-104: Weak Cryptography / Insecure Hashing (CWE-327 / CWE-328)

Detects the usage of broken cryptographic primitives (MD5, SHA1) in security-sensitive contexts.
Respects the Python standard library 'usedforsecurity=False' keyword parameter to avoid false positives.
"""

from __future__ import annotations

import ast
from typing import List

from ast_guard.context import RuleContext
from ast_guard.models import Confidence, Finding, Severity
from ast_guard.rules.base import BaseRule


class WeakCryptoRule(BaseRule):
    """
    Flags calls to cryptographically broken hash algorithms (MD5, SHA1).
    """

    rule_id = "AG-104"
    name = "Weak Cryptography / Broken Hash Algorithm"
    cwe_id = "CWE-327"
    owasp_category = "A02:2021-Cryptographic Failures"
    default_severity = Severity.MEDIUM
    default_confidence = Confidence.HIGH
    description = (
        "Weak cryptographic hash algorithm detected (MD5 or SHA1). "
        "These algorithms are vulnerable to collision attacks and must not be used for security operations."
    )
    remediation = (
        "Upgrade to secure hash algorithms such as SHA-256, SHA-3, or BLAKE2 (e.g., hashlib.sha256()). "
        "If used strictly for non-cryptographic checksums or cache keys, explicitly declare 'usedforsecurity=False'."
    )

    target_node_types = (ast.Call,)

    WEAK_HASH_CALLS = {
        "hashlib.md5",
        "hashlib.sha1",
        "Crypto.Hash.MD5.new",
        "Crypto.Hash.SHA1.new",
        "Cryptodome.Hash.MD5.new",
        "Cryptodome.Hash.SHA1.new",
    }

    def check_node(self, node: ast.AST, context: RuleContext) -> List[Finding]:
        if not isinstance(node, ast.Call):
            return []

        call_name = self.get_call_name(node)
        if not call_name:
            return []

        # Check for direct hashlib.md5 or hashlib.sha1
        is_weak_hash = call_name in self.WEAK_HASH_CALLS

        # Check for hashlib.new("md5") or hashlib.new("sha1")
        if not is_weak_hash and call_name in {"hashlib.new", "new"}:
            if node.args and isinstance(node.args[0], ast.Constant):
                algo = str(node.args[0].value).lower()
                if algo in {"md5", "sha1"}:
                    is_weak_hash = True

        if not is_weak_hash:
            return []

        # Check for usedforsecurity=False keyword argument
        for kw in node.keywords:
            if kw.arg == "usedforsecurity":
                if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    # Non-security usage explicitly declared - skip finding
                    return []

        return [
            self.create_finding(
                node,
                context,
                message=f"Usage of broken hash function '{call_name}'. Susceptible to collision attacks.",
            )
        ]
