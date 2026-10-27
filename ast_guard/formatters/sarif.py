"""
SARIF v2.1.0 (Static Analysis Results Interchange Format) exporter for ast-guard.

Complies with OASIS SARIF v2.1.0 specification, enabling direct ingestion by
GitHub Code Scanning (via github/codeql-action/upload-sarif), GitLab SAST,
and the VS Code SARIF extension.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ast_guard import __version__
from ast_guard.models import Finding, ScanResult, Severity
from ast_guard.rules import RuleRegistry, get_default_registry


def severity_to_sarif_level(severity: Severity) -> str:
    """
    Maps internal Severity enum to SARIF result levels:
    - CRITICAL, HIGH -> 'error'
    - MEDIUM -> 'warning'
    - LOW, INFO -> 'note'
    """
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    elif severity == Severity.MEDIUM:
        return "warning"
    else:
        return "note"


def generate_sarif_rules(registry: RuleRegistry) -> List[Dict[str, Any]]:
    """
    Extracts rule metadata for inclusion in the SARIF tool.driver.rules array.
    """
    rules_data = []
    for rule in registry.get_all_rules():
        rules_data.append({
            "id": rule.rule_id,
            "name": rule.name,
            "shortDescription": {
                "text": rule.name,
            },
            "fullDescription": {
                "text": rule.description,
            },
            "help": {
                "text": f"{rule.description}\n\nRemediation:\n{rule.remediation}",
                "markdown": f"### {rule.name}\n\n{rule.description}\n\n**Remediation:**\n{rule.remediation}",
            },
            "properties": {
                "tags": [
                    "security",
                    rule.cwe_id.lower(),
                    rule.owasp_category.split(":")[0].lower(),
                ],
                "precision": "high",
                "problem.severity": "error" if rule.default_severity in {Severity.CRITICAL, Severity.HIGH} else "warning",
            },
        })
    return rules_data


def finding_to_sarif_result(finding: Finding, base_path: Path) -> Dict[str, Any]:
    """
    Converts an ast-guard Finding into a SARIF result item.
    Converts absolute file paths to relative URIs when inside base_path.
    """
    try:
        rel_path = Path(finding.location.file_path).relative_to(base_path).as_posix()
    except Exception:
        rel_path = Path(finding.location.file_path).as_posix()

    start_line = max(1, finding.location.line_number)
    start_col = max(1, finding.location.col_offset + 1)
    end_line = finding.location.end_line_number or start_line
    end_col = (finding.location.end_col_offset + 1) if finding.location.end_col_offset is not None else None

    region: Dict[str, Any] = {
        "startLine": start_line,
        "startColumn": start_col,
    }
    if end_line:
        region["endLine"] = end_line
    if end_col:
        region["endColumn"] = end_col

    if finding.location.code_snippet:
        region["snippet"] = {
            "text": finding.location.code_snippet
        }

    return {
        "ruleId": finding.rule_id,
        "level": severity_to_sarif_level(finding.severity),
        "message": {
            "text": finding.message,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": rel_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": region,
                }
            }
        ],
    }


def format_sarif(result: ScanResult, registry: RuleRegistry | None = None, indent: int = 2) -> str:
    """
    Generates a full SARIF 2.1.0 document for the scan results.
    """
    reg = registry or get_default_registry()
    base_path = Path(result.target_path) if Path(result.target_path).is_dir() else Path(result.target_path).parent

    sarif_doc: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ast-guard",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/ErenYeager1836/ast-guard",
                        "rules": generate_sarif_rules(reg),
                    }
                },
                "results": [finding_to_sarif_result(f, base_path) for f in result.findings],
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent)
