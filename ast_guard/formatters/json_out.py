"""
JSON output formatter for ast-guard.

Exports scan results in machine-readable JSON for CI/CD artifact storage and reporting.
"""

from __future__ import annotations

from ast_guard.models import ScanResult


def format_json(result: ScanResult, indent: int = 2) -> str:
    """Renders scan results as formatted JSON string."""
    return result.to_json(indent=indent)
