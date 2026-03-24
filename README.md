# FinAPI Sentinel

 Fast CLI tool that scans OpenAPI specs for security vulnerabilities and compliance gaps.

Built for fintech backend teams operating under **PCI DSS**, **SOC 2**, and **Nigeria's NDPA** — where silent API security gaps are a regulatory risk, not just a technical one.

**Scope:** This tool performs automated screening of OpenAPI specs against known security misconfiguration patterns. Findings should be reviewed by a qualified engineer before any changes are made to a production API.

## Background

Working on backend systems for regulated industries, I kept seeing the same pattern,
APIs that had never been scanned before go-live, with auth gaps and unsafe endpoints
that only surfaced during audits. By then it's a compliance finding, not a development
fix.

FinAPI Sentinel is a tool to catch those issues earlier, at the spec level,
before they reach production.



## Features

- Scans OpenAPI 3.0 specs (YAML and JSON)
- 4 built-in security rules mapped to real compliance controls
- Extensible rule engine — add new rules with a single decorator
- Rich colored CLI output for humans
- Clean JSON export for CI/CD pipelines
- Test suite covering parser validation, authentication detection, HTTP scheme enforcement, and destructive endpoint rules



## Quick Start
```bash
pip install -e .
finapi-sentinel scan examples/vulnerable_openapi.yaml
```

JSON output for pipelines:
```bash
finapi-sentinel scan examples/vulnerable_openapi.yaml --json
```



## Example Output
```
FinAPI Sentinel Scan Complete

CRITICAL POST /transactions
  → Issue: Missing authentication on endpoint
  → Control: PCI DSS 8.2 / NDPA Section 24

CRITICAL DELETE /users
  → Issue: Missing authentication on endpoint
  → Control: PCI DSS 8.2 / NDPA Section 24

HIGH DELETE /users
  → Issue: Destructive endpoint without authentication
  → Control: PCI DSS 7.1

MEDIUM POST /transactions
  → Issue: No rate limiting headers defined on write endpoint
  → Control: PCI DSS 6.4 / SOC 2 CC6.6

Total Findings: 4
```



## Built-in Rules

| Rule | Risk | Control |
|------|------|---------|
| Missing authentication on endpoint | CRITICAL / HIGH | PCI DSS 8.2, NDPA Section 24 |
| Destructive endpoint without auth | HIGH | PCI DSS 7.1 |
| Server using HTTP instead of HTTPS | CRITICAL | PCI DSS 4.2.1, NDPA Section 24 |
| Write endpoint missing rate limiting | MEDIUM | PCI DSS 6.4, SOC 2 CC6.6 |


## How to Add New Rules

Create a new function decorated with `@register_rule` in `rules.py`:
```python
@register_rule
def check_your_rule(spec: dict) -> list[Finding]:
    findings = []
    # your logic here
    return findings
```

The rule is automatically picked up on the next scan.


## Running Tests
```bash
pip install pytest
pytest tests/ -v
```

Expected: all tests passing across parser validation, auth detection,
HTTP scheme checks, and delete endpoint rules.



## Project Structure
```
finapi_sentinel/
    cli.py        # Typer CLI entry point
    parser.py     # YAML/JSON spec loader
    rules.py      # Security rule engine
    models.py     # Finding and RiskLevel models
examples/
    vulnerable_openapi.yaml   # Sample spec for quick start
tests/
    fixtures/
        safe_openapi.yaml       # Authenticated spec for negative tests
        vulnerable_openapi.yaml # Vulnerable spec for positive tests
    test_rules.py
```



## Roadmap

- [ ] GitHub Actions workflow example, so teams can drop this into CI with minimal config
- [ ] OWASP API Security Top 10 rule mapping, the current rules cover common gaps,
      but a full OWASP mapping would make findings more actionable in security reviews