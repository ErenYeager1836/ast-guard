"""
Rule AG-108: Hardcoded Credentials & Sensitive Tokens (CWE-798)

Inspects AST Assignment nodes (ast.Assign, ast.AnnAssign) to detect hardcoded
passwords, API tokens, and private keys assigned to sensitive variable names.
Uses Shannon entropy and placeholder filtering to reduce false positives.
"""

from __future__ import annotations

import ast
import math
import re
from typing import List, Optional

from ast_guard.context import RuleContext
from ast_guard.models import Confidence, Finding, Severity
from ast_guard.rules.base import BaseRule


class HardcodedSecretRule(BaseRule):
    """
    Flags string literals assigned to sensitive variable identifiers.
    """

    rule_id = "AG-108"
    name = "Hardcoded Secret or API Credential"
    cwe_id = "CWE-798"
    owasp_category = "A07:2021-Identification and Authentication Failures"
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH
    description = (
        "Hardcoded secret detected: sensitive credential or API key is committed directly in source code."
    )
    remediation = (
        "Store secrets in environment variables or a dedicated secret management service "
        "(e.g., AWS Secrets Manager, HashiCorp Vault) and read them dynamically via os.environ."
    )

    target_node_types = (ast.Assign, ast.AnnAssign)

    SENSITIVE_VAR_REGEX = re.compile(
        r"(api[_-]?key|secret|password|passwd|auth[_-]?token|access[_-]?token|jwt[_-]?secret|private[_-]?key)",
        re.IGNORECASE,
    )

    IGNORE_PLACEHOLDERS = {
        "changeme",
        "placeholder",
        "your-secret-here",
        "your_secret_here",
        "example",
        "secret",
        "password",
        "admin",
        "root",
        "test",
        "demo",
        "default",
        "none",
        "null",
        "dummy",
    }

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """
        Calculates the Shannon entropy (bits per character) of a string.
        High entropy (> 3.2 for alphanumeric strings) indicates cryptographic randomness.
        """
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob)

    @staticmethod
    def mask_secret(secret: str) -> str:
        """
        Masks the middle of the secret so it can be safely referenced in reports without leaking.
        """
        if len(secret) <= 6:
            return "*" * len(secret)
        return secret[:3] + "..." + secret[-3:]

    def check_node(self, node: ast.AST, context: RuleContext) -> List[Finding]:
        target_name: Optional[str] = None
        value_node: Optional[ast.AST] = None

        if isinstance(node, ast.Assign):
            if node.targets and isinstance(node.targets[0], ast.Name):
                target_name = node.targets[0].id
            value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                target_name = node.target.id
            value_node = node.value

        if not target_name or not value_node:
            return []

        # Check if variable name matches sensitive keywords
        if not self.SENSITIVE_VAR_REGEX.search(target_name):
            return []

        # Must be assigned a string literal constant
        if not isinstance(value_node, ast.Constant) or not isinstance(value_node.value, str):
            return []

        val = value_node.value.strip()

        # Filter out short or placeholder strings
        if len(val) < 8 or val.lower() in self.IGNORE_PLACEHOLDERS:
            return []

        entropy = self.calculate_entropy(val)

        # High confidence if high entropy (> 3.0) or length >= 20
        confidence = Confidence.HIGH if (entropy >= 3.0 or len(val) >= 24) else Confidence.MEDIUM

        masked = self.mask_secret(val)
        return [
            self.create_finding(
                node,
                context,
                message=f"Hardcoded sensitive value assigned to variable '{target_name}' (value: '{masked}', entropy: {entropy:.2f}).",
                confidence=confidence,
            )
        ]
