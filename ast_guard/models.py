"""
Data models for ast-guard.

Defines the core representations of security findings, severities,
confidences, code locations, and scan summary statistics.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """
    Vulnerability severity levels aligned with standard CVSS scoring bands.
    Ordering allows severity-based filtering in CI/CD quality gates.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting and threshold comparison."""
        ranks = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }
        return ranks.get(self.value, 0)

    def __ge__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: Severity) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


class Confidence(str, Enum):
    """
    Confidence score of static analysis rule matching.
    Distinguishes high-certainty syntax constructs from heuristic matches.
    """
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class Location:
    """
    Precise source code coordinate representing where a vulnerability was detected.
    Used for terminal highlighting and SARIF physicalLocation mapping.
    """
    file_path: str
    line_number: int
    col_offset: int = 0
    end_line_number: Optional[int] = None
    end_col_offset: Optional[int] = None
    code_snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "col_offset": self.col_offset,
            "end_line_number": self.end_line_number,
            "end_col_offset": self.end_col_offset,
            "code_snippet": self.code_snippet,
        }


@dataclass
class Finding:
    """
    An individual security vulnerability identified by an AST rule.
    """
    rule_id: str
    rule_name: str
    cwe_id: str
    owasp_category: str
    severity: Severity
    confidence: Confidence
    message: str
    remediation: str
    location: Location

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "message": self.message,
            "remediation": self.remediation,
            "location": self.location.to_dict(),
        }


@dataclass
class ScanError:
    """Records syntax errors or permission issues encountered while reading a file."""
    file_path: str
    error_message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "error_message": self.error_message,
        }


@dataclass
class ScanResult:
    """
    Aggregated outcome of an ast-guard scan run over a repository or file list.
    """
    target_path: str
    files_scanned: int = 0
    lines_scanned: int = 0
    duration_seconds: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
    suppressed_count: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "duration_seconds": round(self.duration_seconds, 4),
            "summary": {
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "suppressed": self.suppressed_count,
                "errors": len(self.errors),
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": [e.to_dict() for e in self.errors],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
