"""
Console formatter for ast-guard.

Renders colored, human-readable terminal output complete with code snippets,
CWE references, and remediation guidance.
"""

from __future__ import annotations

import sys
from typing import List

from ast_guard.models import Finding, ScanResult, Severity


class Colors:
    """ANSI color codes for terminal styling."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"

    @classmethod
    def disable(cls) -> None:
        cls.RESET = ""
        cls.BOLD = ""
        cls.DIM = ""
        cls.RED = ""
        cls.YELLOW = ""
        cls.BLUE = ""
        cls.CYAN = ""
        cls.GREEN = ""
        cls.MAGENTA = ""
        cls.WHITE = ""


def get_severity_badge(severity: Severity) -> str:
    """Returns color-coded badge string for severity."""
    if severity == Severity.CRITICAL:
        return f"{Colors.BOLD}{Colors.RED}[CRITICAL]{Colors.RESET}"
    elif severity == Severity.HIGH:
        return f"{Colors.BOLD}{Colors.MAGENTA}[HIGH]{Colors.RESET}"
    elif severity == Severity.MEDIUM:
        return f"{Colors.BOLD}{Colors.YELLOW}[MEDIUM]{Colors.RESET}"
    elif severity == Severity.LOW:
        return f"{Colors.BOLD}{Colors.CYAN}[LOW]{Colors.RESET}"
    else:
        return f"{Colors.BOLD}{Colors.WHITE}[INFO]{Colors.RESET}"


def format_console(result: ScanResult, no_color: bool = False) -> str:
    """
    Renders the full scan report for console display.
    """
    if no_color or not sys.stdout.isatty():
        Colors.disable()

    output: List[str] = []

    # Header Banner
    output.append(f"{Colors.BOLD}{Colors.CYAN}=== ast-guard Security Scan Report ==={Colors.RESET}")
    output.append(f"Target: {result.target_path}")
    output.append("")

    if not result.findings and not result.errors:
        output.append(f"{Colors.GREEN}{Colors.BOLD}No security vulnerabilities identified!{Colors.RESET}")
        output.append("")
    else:
        # Render findings
        for idx, finding in enumerate(result.findings, 1):
            badge = get_severity_badge(finding.severity)
            loc = finding.location

            output.append(
                f"{Colors.BOLD}{idx}. {badge} {finding.rule_name} "
                f"({finding.rule_id} | {finding.cwe_id} | {finding.owasp_category}){Colors.RESET}"
            )
            output.append(f"   {Colors.DIM}Location:{Colors.RESET} {loc.file_path}:{loc.line_number}:{loc.col_offset}")
            output.append(f"   {Colors.DIM}Issue:{Colors.RESET}    {finding.message}")

            if loc.code_snippet:
                output.append(f"   {Colors.DIM}Snippet:{Colors.RESET}")
                for snippet_line in loc.code_snippet.splitlines():
                    output.append(f"     {snippet_line}")

            if finding.remediation:
                output.append(f"   {Colors.GREEN}{Colors.BOLD}Remediation:{Colors.RESET} {finding.remediation}")

            output.append("")

    # Errors section (if any)
    if result.errors:
        output.append(f"{Colors.BOLD}{Colors.RED}Scan Errors ({len(result.errors)}):{Colors.RESET}")
        for err in result.errors:
            output.append(f"  - {err.file_path}: {err.error_message}")
        output.append("")

    # Summary Statistics Footer
    output.append(f"{Colors.BOLD}------------------------------------------------------------{Colors.RESET}")
    output.append(
        f"Files Scanned: {result.files_scanned}  |  Lines: {result.lines_scanned}  |  "
        f"Duration: {result.duration_seconds:.2f}s"
    )
    output.append(
        f"Findings: {len(result.findings)} "
        f"({Colors.RED}Critical: {result.critical_count}{Colors.RESET}, "
        f"{Colors.MAGENTA}High: {result.high_count}{Colors.RESET}, "
        f"{Colors.YELLOW}Medium: {result.medium_count}{Colors.RESET}, "
        f"{Colors.CYAN}Low: {result.low_count}{Colors.RESET})  |  "
        f"Suppressed: {result.suppressed_count}"
    )
    output.append(f"{Colors.BOLD}------------------------------------------------------------{Colors.RESET}")

    return "\n".join(output)
