# ast-guard

[![CI](https://github.com/ErenYeager1836/ast-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/ErenYeager1836/ast-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20runtime-brightgreen.svg)](pyproject.toml)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Compliant-orange.svg)](https://sarifweb.azurewebsites.net/)

> **A Lightweight, AST-Based Static Application Security Testing (SAST) Scanner for Python with SARIF 2.1.0 & GitHub Code Scanning Integration.**

---

## Security & Authorization Notice

> [!IMPORTANT]
> **Authorized Testing Notice**: `ast-guard` is strictly designed for analyzing source code repositories and local codebases that you own or have explicit authorization to test. It does not perform network exploitation or target external systems without authorization. No live credentials or production secrets are embedded in this repository.

---

## Overview

Most beginner security linters rely on regular expressions (`regex`), which suffer from catastrophic false-positive rates (matching harmless comments or docstrings) and miss real vulnerabilities split across statements.

`ast-guard` parses Python source code into Python's native **Abstract Syntax Tree (`ast`)**, performing structural syntactic analysis and intra-procedural assignment inspection to detect security vulnerabilities before code ever reaches production.

### Key Capabilities
- **Zero Runtime Dependencies**: Built entirely with Python's standard library (`ast`, `tokenize`, `argparse`, `dataclasses`, `pathlib`).
- **Single-Pass Node Dispatch**: Dispatches AST nodes directly to registered rules based on Python node types (`ast.Call`, `ast.Assign`), traversing the syntax tree in a single pass.
- **Architecture Decision Record**: [ADR 0001: AST Visitor vs. Regex Pattern Matching](docs/adr/0001-ast-visitor-vs-regex-sast.md).
- **OWASP Top 10 & CWE Mapping**: Detects SQL injection, command injection, insecure deserialization, broken crypto, dynamic code execution, TOCTOU race conditions, debug misconfigurations, and hardcoded credentials.
- **Intra-Procedural Variable Inspection**: Traces local variable assignments (e.g. `query = f"SELECT..."; cursor.execute(query)`) rather than naive direct call checks.
- **OASIS SARIF 2.1.0 Output**: Exports directly into the standard Static Analysis Results Interchange Format for native GitHub Security tab / Code Scanning alerts.
- **Developer-Friendly Suppressions**: Supports `# nosec` and `# ast-guard: ignore[RULE_ID]` inline comments via lexical tokenization.
- **CI/CD Quality Gates**: Configurable failure thresholds (`--fail-on HIGH`, `--fail-on MEDIUM`, or `--fail-on NEVER`).

---

## Architecture

```
                          Python Source Files (.py)
                                     |
                                     v
                       +---------------------------+
                       | Tokenizer & AST Parser    |
                       | - Extracts # nosec lines  |
                       | - ast.parse() into AST    |
                       +-------------+-------------+
                                     |
                                     v
                       +---------------------------+
                       | Single-Pass AST Dispatch  |
                       | - ast.Call   -> AG-101..7 |
                       | - ast.Assign -> AG-108    |
                       +-------------+-------------+
                                     |
                                     v
                       +---------------------------+
                       | Inline Suppression Filter |
                       | - Filters # nosec / tags  |
                       | - Applies severity floor  |
                       +-------------+-------------+
                                     |
                   +-----------------+-----------------+
                   |                                   |
                   v                                   v
       +-----------------------+           +-----------------------+
       |   Console Formatter   |           |    SARIF 2.1.0 & JSON |
       | - Color badges        |           | - GitHub Code Scanning|
       | - Code snippets (>)   |           | - CI/CD pipeline gate |
       | - Remediation steps   |           +-----------------------+
       +-----------------------+
```

---

## Detection Rules Reference

| Rule ID | Severity | CWE | OWASP Category | Vulnerability Detected | Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AG-101** | `HIGH` | CWE-89 | A03:2021-Injection | SQL Injection (f-strings, `.format()`, `%`, concatenation in queries) | Use parameterized queries (e.g., `cursor.execute("SELECT ... WHERE id = %s", (uid,))`) |
| **AG-102** | `HIGH` | CWE-78 | A03:2021-Injection | Command Injection (`os.system`, `os.popen`, `subprocess` with `shell=True`) | Pass arguments as a list with `shell=False` (`subprocess.run(["cmd", arg])`) |
| **AG-103** | `CRITICAL` | CWE-502 | A08:2021-Data Integrity | Insecure Deserialization (`pickle.loads`, `yaml.load` without `SafeLoader`) | Use `json.loads` or `yaml.safe_load()` |
| **AG-104** | `MEDIUM` | CWE-327 | A02:2021-Crypto Failures | Broken Cryptography / Hashes (MD5, SHA-1 in security context) | Upgrade to SHA-256; declare `usedforsecurity=False` for checksums |
| **AG-105** | `HIGH` | CWE-95 | A03:2021-Injection | Dangerous Dynamic Code Execution (`eval()`, `exec()`, `compile()`) | Use `ast.literal_eval()` or structured JSON parsing |
| **AG-106** | `MEDIUM` | CWE-377 | A01:2021-Broken Access | Insecure Temporary Files (`tempfile.mktemp()` TOCTOU race conditions) | Use `tempfile.NamedTemporaryFile()` or `tempfile.mkstemp()` |
| **AG-107** | `HIGH` | CWE-489 | A05:2021-Misconfiguration | Insecure Debug Mode / All-Interface Binding (`app.run(debug=True, host="0.0.0.0")`) | Bind strictly to `127.0.0.1` and disable `debug=True` in production |
| **AG-108** | `HIGH` | CWE-798 | A07:2021-Auth Failures | Hardcoded Secrets / High-Entropy API Keys assigned to sensitive identifiers | Read secrets via `os.environ` or a secrets manager |

---

## Why AST Over Regular Expressions?

In technical AppSec interviews, a common question is: *"Why can't you just scan for vulnerabilities with grep or regular expressions?"*

| Dimension | Regex Scanners (e.g. naive grep) | AST Scanners (`ast-guard`) |
| :--- | :--- | :--- |
| **Comment Immunity** | Regex flags vulnerable terms inside comments or documentation strings. | AST parser ignores comments entirely when traversing code statements. |
| **Context Awareness** | Regex cannot tell if `md5` is a function call, a variable name, or an imported module. | AST differentiates `ast.Call`, `ast.Name`, and `ast.Attribute`. |
| **Intra-Procedural Taint** | Cannot track if `query = f"..."` on line 10 is passed into `execute(query)` on line 12. | Inspects assignment nodes (`ast.Assign`) within the same AST scope. |
| **Keyword Arguments** | Regex struggles with arbitrary argument positions (e.g. `hashlib.md5(data, usedforsecurity=False)`). | AST cleanly inspects `ast.keyword(arg='usedforsecurity', value=ast.Constant(value=False))`. |

---

## Installation

> [!NOTE]
> `ast-guard` is not published to PyPI. Install from source or via git URL as shown below.

### From Source
Clone the repository and install locally:

```bash
git clone https://github.com/ErenYeager1836/ast-guard.git
cd ast-guard

# Run directly via Python without installing
python -m ast_guard --help

# Or install in editable mode
pip install -e .

# Or install directly from GitHub
pip install git+https://github.com/ErenYeager1836/ast-guard.git
```

---

## Usage

### 1. Basic Scan
Scan a directory or single Python file:

```bash
# Scan a directory
python -m ast_guard src/

# Scan a single file
python -m ast_guard examples/vulnerable_app.py
```

### 2. Export SARIF for GitHub Code Scanning
```bash
python -m ast_guard src/ --sarif results.sarif
```

### 3. Machine-Readable JSON Export
```bash
python -m ast_guard src/ --format json --output results.json
```

### 4. CI Quality Gates & Severity Thresholds
```bash
# Fail build (exit code 1) only if CRITICAL or HIGH vulnerabilities are found
python -m ast_guard src/ --fail-on HIGH

# Report only MEDIUM and above, ignoring LOW/INFO
python -m ast_guard src/ --severity MEDIUM

# Never fail build (exit code 0 always, useful for dry runs)
python -m ast_guard src/ --fail-on NEVER
```

### 5. Disable Specific Rules or Ignore Directories
```bash
# Disable MD5/SHA1 rule (AG-104) and ignore legacy migrations directory
python -m ast_guard src/ --disable-rule AG-104 --ignore-dir migrations
```

### 6. View All Rules
```bash
python -m ast_guard --list-rules
```

---

## Demo Output

Running `python -m ast_guard examples/vulnerable_app.py`:

```
=== ast-guard Security Scan Report ===
Target: examples/vulnerable_app.py

1. [HIGH] SQL Injection in Query Execution (AG-101 | CWE-89 | A03:2021-Injection)
   Location: examples/vulnerable_app.py:22:4
   Issue:    Possible SQL injection detected: variable 'query' passed to 'cursor.execute()' was dynamically formatted on line 21.
   Snippet:
          21 |     query = f"SELECT * FROM users WHERE id = {user_id}"
      >   22 |     cursor.execute(query)
          23 | 
   Remediation: Use parameterized queries provided by your database driver (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)) or an ORM like SQLAlchemy) to safely bind parameters and prevent SQL injection.

2. [HIGH] Command Injection / Insecure Shell Execution (AG-102 | CWE-78 | A03:2021-Injection)
   Location: examples/vulnerable_app.py:27:4
   Issue:    Direct shell invocation via 'os.system' detected. Vulnerable to command injection.
   Snippet:
          26 |     # AG-102: Command Injection via os.system and shell=True
      >   27 |     os.system("ping -c 1 " + target_host)
          28 |     subprocess.run(f"traceroute {target_host}", shell=True, check=True)
   Remediation: Pass arguments as a sequence (list of strings) and set shell=False (e.g., subprocess.run(['command', arg1, arg2], check=True, shell=False)). Avoid os.system.

3. [CRITICAL] Insecure Deserialization (AG-103 | CWE-502 | A08:2021-Software and Data Integrity Failures)
   Location: examples/vulnerable_app.py:33:10
   Issue:    Insecure deserialization via 'pickle.loads'. Pickle byte streams can execute arbitrary code during unpickling.
   Snippet:
          32 |     # AG-103: Insecure Deserialization via pickle and unsafe yaml
      >   33 |     obj = pickle.loads(payload)
          34 |     cfg = yaml.load("user: admin\nrole: root")
   Remediation: Avoid using pickle for untrusted data; use secure data interchange formats such as JSON or Protocol Buffers. For YAML, always use yaml.safe_load() or specify Loader=yaml.SafeLoader.

------------------------------------------------------------
Files Scanned: 1  |  Lines: 68  |  Duration: 0.00s
Findings: 11 (Critical: 2, High: 6, Medium: 3, Low: 0)  |  Suppressed: 0
------------------------------------------------------------
```

---

## Inline False-Positive Suppressions

Developers can suppress intentional or verified safe patterns using inline comments:

```python
# Suppress all rules on this line:
os.system("clear")  # nosec

# Suppress only a specific rule (e.g. AG-102 command injection):
os.system("clear")  # nosec: AG-102
# or using explicit syntax:
os.system("clear")  # ast-guard: ignore[AG-102]
```

---

## GitHub Actions CI Integration

### Option 1: Using the Composite Action (Recommended)
Integrate `ast-guard` directly into any GitHub workflow in 3 lines:

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  sast:
    name: Run ast-guard SAST
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Scan with ast-guard
        uses: ErenYeager1836/ast-guard@v1
        with:
          target: '.'
          format: 'sarif'
          output: 'ast-guard.sarif'
          severity: 'LOW'
          fail-on: 'HIGH'

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'ast-guard.sarif'
```

### Option 2: Direct Command Line Integration
```yaml
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Scan Codebase & Export SARIF
        run: |
          pip install git+https://github.com/ErenYeager1836/ast-guard.git
          ast-guard . --sarif results.sarif --fail-on HIGH
      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## Pre-commit Integration

Add `ast-guard` to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ErenYeager1836/ast-guard
    rev: v0.1.0  # Use release tag or commit SHA
    hooks:
      - id: ast-guard
        args: ["--fail-on", "HIGH"]
```

---

## Testing

Run the full automated test suite (52 unit and integration tests):

```bash
python -m unittest discover -s tests -v
```

All 52 tests execute in under 100 milliseconds without external network calls or dependencies.

---

## Limitations

- **Intra-Procedural Scope**: Tracks variable assignments within the same source file. Cross-file data flow and inter-procedural taint analysis across module imports are not yet modeled.
- **Python Only**: Analyzes Python AST (`.py` files). Does not scan JavaScript, Go, or configuration files.
- **Heuristic Entropy & Formatting**: High-entropy strings are strong indicators of secrets, but base64-encoded static binary blobs or non-sensitive hashes can trigger false positives without allowlist filtering.
- **Empirical False-Positive Rate on Real Code**:
  When evaluated against a real-world open-source Python codebase ([`scrapy`](https://github.com/scrapy/scrapy) v2.12.0, 543 files, 111,533 lines of code on an 11th Gen Intel Core i5-1135G7 @ 2.40GHz, Linux x86_64, Python 3.14.8):
  - Scan duration: 4.87 seconds (30 total findings across 111k LOC).
  - Manual review of 20 findings revealed that 17 of 20 (85%) occurred in test suites (`tests/test_*.py`) verifying serialization (`pickle.loads`), dynamic mock execution (`exec`, `compile`), and assertions; 2 of 20 (10%) were non-cryptographic hash usages for directory partitioning or URL GUIDs (`hashlib.md5`, `hashlib.sha1`) lacking Python 3.8+'s `usedforsecurity=False` keyword; and 1 of 20 (5%) was an interactive REPL debugging console (`scrapy/shell.py`).
  - Resulting empirical false-positive rate: 100% (20 of 20) of the hand-checked findings were non-vulnerabilities in runtime context. Without inter-procedural taint tracing and explicit test directory exclusions (`--ignore-dir tests`), syntactic AST pattern matching flags legitimate dynamic code and test assertions.

---

## Roadmap

- [ ] **Cross-file Taint Tracking**: Build symbol table resolving function imports across packages to track data flow from API route handlers to DB sinks.
- [ ] **Custom YAML Rule Definitions**: Allow security engineers to define new AST rules in declarative YAML.
- [x] **Pre-commit Hook Plugin**: Packaged as an official pre-commit hook in `.pre-commit-hooks.yaml`.
- [ ] **Multi-language AST Support**: Evaluate `tree-sitter` bindings for C/C++ and Go security scanning.

---

## License

This project is licensed under the [MIT License](LICENSE) &copy; 2026 Nithishvelan M (ErenYeager1836).
