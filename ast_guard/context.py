"""
RuleContext manages file-level context during AST traversal.

Stores the source lines, file metadata, and extracted inline suppression comments
(e.g., `# nosec` or `# ast-guard: ignore[RULE_ID]`).
"""

from __future__ import annotations

import io
import tokenize
from pathlib import Path
from typing import Dict, List, Optional, Set


class RuleContext:
    """
    Context passed to rules during AST node inspection.
    """

    def __init__(self, file_path: Path, source_code: str, tree: Optional[Any] = None):
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.tree = tree
        self.suppressions: Dict[int, Set[str]] = self._parse_suppressions(source_code)

    def _parse_suppressions(self, source: str) -> Dict[int, Set[str]]:
        """
        Tokenizes source code to find developer comments containing suppressions:
        - `# nosec`: suppress all rules on this line
        - `# nosec: AG-101, AG-102`: suppress specific rules on this line
        - `# ast-guard: ignore[AG-101]`: suppress specific rule
        - `# ast-guard: ignore-all`: suppress all rules on this line
        """
        suppressions: Dict[int, Set[str]] = {}
        try:
            tokens = tokenize.tokenize(io.BytesIO(source.encode("utf-8")).readline)
            for tok in tokens:
                if tok.type == tokenize.COMMENT:
                    text = tok.string.strip()
                    line = tok.start[0]

                    # Pattern 1: # nosec / # nosec: RULE1, RULE2
                    if "# nosec" in text:
                        if line not in suppressions:
                            suppressions[line] = set()
                        after_nosec = text.split("# nosec", 1)[1].strip()
                        if after_nosec.startswith(":"):
                            rule_ids = [r.strip() for r in after_nosec[1:].split(",") if r.strip()]
                            suppressions[line].update(rule_ids)
                        else:
                            # Wildcard suppression on this line
                            suppressions[line].add("*")

                    # Pattern 2: # ast-guard: ignore[AG-101] or # ast-guard: ignore-all
                    elif "# ast-guard:" in text:
                        if line not in suppressions:
                            suppressions[line] = set()
                        cmd = text.split("# ast-guard:", 1)[1].strip()
                        if "ignore-all" in cmd:
                            suppressions[line].add("*")
                        elif "ignore[" in cmd and "]" in cmd:
                            rules_part = cmd.split("ignore[", 1)[1].split("]", 1)[0]
                            rule_ids = [r.strip() for r in rules_part.split(",") if r.strip()]
                            suppressions[line].update(rule_ids)
        except Exception:
            # Fallback if tokenization fails: scanner proceeds without suppressions
            pass

        return suppressions

    def is_suppressed(self, line: int, rule_id: str) -> bool:
        """
        Checks whether a finding at the specified line is suppressed by a developer comment.
        """
        if line in self.suppressions:
            rules = self.suppressions[line]
            if "*" in rules or rule_id in rules:
                return True
        return False

    def get_snippet(self, line: int, context_lines: int = 1) -> str:
        """
        Extracts code snippet surrounding line number for human-readable output.
        """
        if not self.source_lines or line < 1 or line > len(self.source_lines):
            return ""

        start = max(1, line - context_lines)
        end = min(len(self.source_lines), line + context_lines)

        snippet_parts = []
        for l in range(start, end + 1):
            prefix = " > " if l == line else "   "
            line_str = self.source_lines[l - 1]
            snippet_parts.append(f"{prefix}{l:4d} | {line_str}")

        return "\n".join(snippet_parts)
