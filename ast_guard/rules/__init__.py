"""
Rules registry for ast-guard.

Centralizes registration, configuration, and retrieval of AST security rules.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Type

from ast_guard.rules.base import BaseRule
from ast_guard.rules.command_injection import CommandInjectionRule
from ast_guard.rules.crypto import WeakCryptoRule
from ast_guard.rules.debug_binding import InsecureDebugBindingRule
from ast_guard.rules.deserialization import InsecureDeserializationRule
from ast_guard.rules.eval_exec import EvalExecRule
from ast_guard.rules.secrets import HardcodedSecretRule
from ast_guard.rules.sqli import SQLInjectionRule
from ast_guard.rules.tempfile_mktemp import InsecureTempfileRule

ALL_RULE_CLASSES: List[Type[BaseRule]] = [
    SQLInjectionRule,
    CommandInjectionRule,
    InsecureDeserializationRule,
    WeakCryptoRule,
    EvalExecRule,
    InsecureTempfileRule,
    InsecureDebugBindingRule,
    HardcodedSecretRule,
]


class RuleRegistry:
    """
    Registry that instantiates and indexes all security rules.
    """

    def __init__(self, rule_classes: Optional[List[Type[BaseRule]]] = None):
        self._rules: Dict[str, BaseRule] = {}
        classes = rule_classes or ALL_RULE_CLASSES
        for cls in classes:
            rule_instance = cls()
            self._rules[rule_instance.rule_id] = rule_instance

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[BaseRule]:
        return list(self._rules.values())

    def get_active_rules(self, disabled_rules: Optional[List[str]] = None) -> List[BaseRule]:
        disabled = set(disabled_rules or [])
        return [r for r_id, r in self._rules.items() if r_id not in disabled]


def get_default_registry() -> RuleRegistry:
    return RuleRegistry()
