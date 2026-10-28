# ast-guard

**Lightweight AST-based Static Application Security Testing (SAST) with native SARIF 2.1.0 output for GitHub Code Scanning.**

`ast-guard` parses Python source code into Abstract Syntax Trees using the compiler module (`ast`), traversing executable code structures to detect insecure patterns, dangerous function invocations, and cryptographic weaknesses with zero regex false positives.

---

## Key Features

* **Zero-Noise AST Traversal**: Unlike regex-based linters, docstrings and comments cannot trigger false alarms.
* **OASIS SARIF 2.1.0 Native**: Output reports integrate natively into GitHub Code Scanning security tabs and pull request annotations.
* **Sub-Second Execution**: Benchmarked on 100k+ LOC repositories in `< 1.2s`.
* **GitHub Action**: Ready for CI/CD gates via `ErenYeager1836/ast-guard@v1`.
