"""
Core AST analysis and file traversal engine for ast-guard.

Coordinates file discovery, AST parsing, node-type dispatch optimization,
inline suppression evaluation, and result aggregation.
"""

from __future__ import annotations

import ast
import os
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Type

from ast_guard.context import RuleContext
from ast_guard.models import Finding, ScanError, ScanResult, Severity
from ast_guard.rules import RuleRegistry, get_default_registry
from ast_guard.rules.base import BaseRule


class ASTScannerVisitor(ast.NodeVisitor):
    """
    Single-pass AST Visitor that dispatches nodes to registered rules based on
    node type, eliminating redundant traversals and maximizing scanning speed.
    """

    def __init__(self, rules_by_type: Dict[Type[ast.AST], List[BaseRule]], context: RuleContext):
        self.rules_by_type = rules_by_type
        self.context = context
        self.raw_findings: List[Finding] = []

    def generic_visit(self, node: ast.AST) -> None:
        # Check if any rules subscribe to this exact node type or supertypes
        node_cls = type(node)
        applicable_rules = self.rules_by_type.get(node_cls, [])

        for rule in applicable_rules:
            findings = rule.check_node(node, self.context)
            if findings:
                self.raw_findings.extend(findings)

        super().generic_visit(node)


class ScannerEngine:
    """
    Main orchestration engine for ast-guard.
    """

    DEFAULT_IGNORED_DIRS: Set[str] = {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "build",
        "dist",
        "*.egg-info",
        ".eggs",
        ".pytest_cache",
        ".tox",
        "node_modules",
    }

    def __init__(
        self,
        registry: Optional[RuleRegistry] = None,
        disabled_rules: Optional[List[str]] = None,
        min_severity: Severity = Severity.LOW,
        custom_ignored_dirs: Optional[Set[str]] = None,
    ):
        self.registry = registry or get_default_registry()
        self.min_severity = min_severity
        self.ignored_dirs = set(self.DEFAULT_IGNORED_DIRS)
        if custom_ignored_dirs:
            self.ignored_dirs.update(custom_ignored_dirs)

        active_rules = self.registry.get_active_rules(disabled_rules)

        # Build type dispatch table for fast visitor execution
        self.rules_by_type: Dict[Type[ast.AST], List[BaseRule]] = defaultdict(list)
        for rule in active_rules:
            for node_type in rule.target_node_types:
                self.rules_by_type[node_type].append(rule)

    def scan_path(self, target_path: str | Path) -> ScanResult:
        """
        Scans a file or directory recursively and returns aggregated results.
        """
        path = Path(target_path).resolve()
        start_time = time.perf_counter()

        result = ScanResult(target_path=str(path))

        if not path.exists():
            result.errors.append(
                ScanError(file_path=str(path), error_message=f"Target path does not exist: {path}")
            )
            result.duration_seconds = time.perf_counter() - start_time
            return result

        target_files = self._collect_files(path)

        for file_path in target_files:
            self._scan_single_file(file_path, result)

        result.duration_seconds = time.perf_counter() - start_time
        return result

    def _collect_files(self, path: Path) -> List[Path]:
        """
        Finds all Python files to scan, respecting ignore lists.
        """
        if path.is_file():
            return [path] if path.suffix == ".py" else []

        collected: List[Path] = []
        for root, dirs, files in os.walk(path):
            # Prune ignored directories in-place to avoid descending into them
            dirs[:] = [d for d in dirs if d not in self.ignored_dirs and not d.endswith(".egg-info")]

            for file in files:
                if file.endswith(".py"):
                    collected.append(Path(root) / file)

        return collected

    def _scan_single_file(self, file_path: Path, result: ScanResult) -> None:
        """
        Reads, tokenizes, and parses an individual Python file into an AST.
        """
        try:
            source_code = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            result.errors.append(
                ScanError(file_path=str(file_path), error_message=f"Failed to read file: {e}")
            )
            return

        result.files_scanned += 1
        lines = source_code.splitlines()
        result.lines_scanned += len(lines)

        try:
            tree = ast.parse(source_code, filename=str(file_path))
        except SyntaxError as e:
            result.errors.append(
                ScanError(
                    file_path=str(file_path),
                    error_message=f"SyntaxError on line {e.lineno}: {e.msg}",
                )
            )
            return
        except Exception as e:
            result.errors.append(
                ScanError(file_path=str(file_path), error_message=f"Parse failure: {e}")
            )
            return

        context = RuleContext(file_path=file_path, source_code=source_code, tree=tree)
        visitor = ASTScannerVisitor(self.rules_by_type, context)
        visitor.visit(tree)

        # Filter suppressed and below-threshold findings
        for finding in visitor.raw_findings:
            line_no = finding.location.line_number
            if context.is_suppressed(line_no, finding.rule_id):
                result.suppressed_count += 1
                continue

            if finding.severity >= self.min_severity:
                result.findings.append(finding)
