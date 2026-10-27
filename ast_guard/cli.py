"""
Command Line Interface (CLI) for ast-guard.

Handles command-line options, rule configuration, CI gate exit codes,
and file output writing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from ast_guard import __version__
from ast_guard.engine import ScannerEngine
from ast_guard.formatters import format_console, format_json, format_sarif
from ast_guard.models import Severity
from ast_guard.rules import get_default_registry


def build_parser() -> argparse.ArgumentParser:
    """Builds the argument parser for ast-guard."""
    parser = argparse.ArgumentParser(
        prog="ast-guard",
        description="ast-guard: Lightweight AST-based Static Application Security Testing (SAST) Scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ast-guard src/
  ast-guard . --format sarif --output results.sarif
  ast-guard app.py --severity HIGH --fail-on HIGH
  ast-guard . --disable-rule AG-104 --sarif report.sarif
  ast-guard --list-rules
        """,
    )

    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to Python file or directory to scan (default: current directory).",
    )

    parser.add_argument(
        "-f",
        "--format",
        choices=["console", "json", "sarif"],
        default="console",
        help="Output format (default: console).",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Write scan output to the specified file path instead of stdout.",
    )

    parser.add_argument(
        "--sarif",
        type=str,
        default=None,
        help="Export SARIF 2.1.0 output to file (useful for GitHub Code Scanning CI).",
    )

    parser.add_argument(
        "--json",
        type=str,
        default=None,
        help="Export JSON output to file.",
    )

    parser.add_argument(
        "-s",
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity threshold to report (default: LOW).",
    )

    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEVER"],
        default="HIGH",
        help="Exit with code 1 if findings meet or exceed this severity (default: HIGH). Use NEVER to always exit 0.",
    )

    parser.add_argument(
        "--disable-rule",
        action="append",
        dest="disabled_rules",
        metavar="RULE_ID",
        help="Disable a specific rule (e.g., --disable-rule AG-104). Can be specified multiple times.",
    )

    parser.add_argument(
        "--ignore-dir",
        action="append",
        dest="custom_ignored_dirs",
        metavar="DIR",
        help="Additional directory name to ignore. Can be specified multiple times.",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in console output.",
    )

    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Display all available security inspection rules and exit.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"ast-guard v{__version__}",
    )

    return parser


def display_rules_table() -> None:
    """Prints a formatted table of all registered AST security rules."""
    registry = get_default_registry()
    rules = registry.get_all_rules()

    print("\nast-guard Registered Security Rules:\n")
    print(f"{'Rule ID':<10} {'Severity':<10} {'CWE':<10} {'Name':<35} {'OWASP Category'}")
    print("-" * 95)
    for rule in rules:
        print(
            f"{rule.rule_id:<10} {rule.default_severity.value:<10} {rule.cwe_id:<10} "
            f"{rule.name:<35} {rule.owasp_category}"
        )
    print("")


def main(argv: Optional[List[str]] = None) -> int:
    """Main execution routine for the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        display_rules_table()
        return 0

    min_severity = Severity(args.severity)
    registry = get_default_registry()

    engine = ScannerEngine(
        registry=registry,
        disabled_rules=args.disabled_rules,
        min_severity=min_severity,
        custom_ignored_dirs=set(args.custom_ignored_dirs or []),
    )

    result = engine.scan_path(args.target)

    # Handle primary output format
    if args.format == "json":
        primary_output = format_json(result)
    elif args.format == "sarif":
        primary_output = format_sarif(result, registry=registry)
    else:
        primary_output = format_console(result, no_color=args.no_color)

    if args.output:
        Path(args.output).write_text(primary_output, encoding="utf-8")
    else:
        print(primary_output)

    # Handle secondary export flags (--sarif, --json)
    if args.sarif:
        sarif_content = format_sarif(result, registry=registry)
        Path(args.sarif).write_text(sarif_content, encoding="utf-8")

    if args.json:
        json_content = format_json(result)
        Path(args.json).write_text(json_content, encoding="utf-8")

    # Determine exit code based on --fail-on
    if args.fail_on == "NEVER":
        return 0

    fail_severity = Severity(args.fail_on)
    should_fail = any(f.severity >= fail_severity for f in result.findings)

    return 1 if should_fail else 0


if __name__ == "__main__":
    sys.exit(main())
