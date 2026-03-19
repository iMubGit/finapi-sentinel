from finapi_sentinel.models import Finding, RiskLevel

RULES = []

def register_rule(func):
    RULES.append(func)
    return func

@register_rule
def check_missing_auth(spec: dict) -> list[Finding]:
    findings = []
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if not details.get("security") and any(k in path.lower() for k in ["transaction", "payment", "user", "account"]):
                findings.append(Finding(
                    endpoint=path,
                    method=method.upper(),
                    issue="Missing authentication on sensitive endpoint",
                    risk=RiskLevel.CRITICAL,
                    control="PCI DSS 8.2 / NDPA Section 24",
                    description="Public access to sensitive data allowed"
                ))
    return findings

@register_rule
def check_unsafe_methods(spec: dict) -> list[Finding]:
    findings = []
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method in methods:
            if method.lower() == "delete" and not methods[method].get("security"):
                findings.append(Finding(
                    endpoint=path,
                    method="DELETE",
                    issue="Destructive endpoint without authentication",
                    risk=RiskLevel.HIGH,
                    control="PCI DSS 7.1",
                    description="Unauthorized deletion possible"
                ))
    return findings