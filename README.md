
```markdown
# FinAPI Sentinel

**Fast CLI tool that scans OpenAPI specs and reports security & compliance issues.**

Built for internal security & compliance teams at fintechs like Moniepoint, Flutterwave, Opay, Wave, and Paystack.

## Features
- Safe YAML/JSON parsing
- Extensible rule engine (2 security rules included)
- Clean error handling with user-friendly messages
- Rich colored CLI output + JSON export for CI/CD
- Automatic mapping to PCI DSS, SOC 2, and NDPA

## Quick Start

```bash
pip install -e .
finapi-sentinel scan examples/vulnerable_openapi.yaml
```

For JSON output (useful in pipelines):

```bash
finapi-sentinel scan examples/vulnerable_openapi.yaml --json
```

## Example Output

```
FinAPI Sentinel Scan Complete

CRITICAL POST /transactions
  → Issue: Missing authentication on sensitive endpoint
  → Control: PCI DSS 8.2 / NDPA Section 24

CRITICAL DELETE /users
  → Issue: Missing authentication on sensitive endpoint
  → Control: PCI DSS 8.2 / NDPA Section 24

HIGH DELETE /users
  → Issue: Destructive endpoint without authentication
  → Control: PCI DSS 7.1

Total Findings: 3
```

## How to Add New Rules
Simply create a new function decorated with `@register_rule` in `rules.py`.

**Small. Fast. Production-ready.**
```

