# GitHub Action Integration

`ast-guard` is available as a reusable Composite GitHub Action.

## Quickstart

Add the following step to your `.github/workflows/security.yml`:

```yaml
name: Security Audit

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  sast:
    name: ast-guard SAST Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run ast-guard
        uses: ErenYeager1836/ast-guard@v1
        with:
          target: '.'
          format: 'sarif'
          output: 'ast-guard.sarif'
          fail-on: 'HIGH'

      - name: Upload SARIF report to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'ast-guard.sarif'
```
