from finapi_sentinel.models import Finding, RiskLevel

RULES = []

SENSITIVE_KEYWORDS = [
    "transaction", "payment", "transfer", "user", "account",
    "balance", "wallet", "kyc", "card", "withdraw", "deposit",
    "auth", "token", "secret", "admin", "pii", "identity"
]

SAFE_PATHS = [
    "health", "ping", "status", "docs", "openapi", "swagger", "metrics"
]


def register_rule(func):
    RULES.append(func)
    return func


def _is_safe_public_path(path: str) -> bool:
    """Paths that are legitimately public and don't need auth."""
    return any(k in path.lower() for k in SAFE_PATHS)


def _is_sensitive_path(path: str) -> bool:
    """Paths that are high-risk if unauthenticated."""
    return any(k in path.lower() for k in SENSITIVE_KEYWORDS)


def _has_auth(details: dict, spec: dict) -> bool:
    """
    Check if an endpoint has authentication defined.
    Checks endpoint-level security first, then falls back to global security.
    """
    # Endpoint-level security explicitly set to empty list means intentionally public
    if "security" in details:
        return len(details["security"]) > 0
    # Fall back to global security defined at spec level
    global_security = spec.get("security", [])
    return len(global_security) > 0


@register_rule
def check_missing_auth(spec: dict) -> list[Finding]:
    findings = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        if _is_safe_public_path(path):
            continue

        for method, details in methods.items():
            if not isinstance(details, dict):
                continue

            if not _has_auth(details, spec):
                is_sensitive = _is_sensitive_path(path)
                findings.append(Finding(
                    endpoint=path,
                    method=method.upper(),
                    issue="Missing authentication on endpoint",
                    risk=RiskLevel.CRITICAL if is_sensitive else RiskLevel.HIGH,
                    control="PCI DSS 8.2 / NDPA Section 24",
                    description=(
                        "Sensitive endpoint publicly accessible without authentication"
                        if is_sensitive else
                        "Endpoint accessible without authentication"
                    )
                ))

    return findings


@register_rule
def check_unsafe_delete(spec: dict) -> list[Finding]:
    findings = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if not isinstance(details, dict):
                continue
            if method.lower() == "delete" and not _has_auth(details, spec):
                findings.append(Finding(
                    endpoint=path,
                    method="DELETE",
                    issue="Destructive endpoint without authentication",
                    risk=RiskLevel.HIGH,
                    control="PCI DSS 7.1",
                    description="Unauthorized deletion possible"
                ))

    return findings


@register_rule
def check_http_scheme(spec: dict) -> list[Finding]:
    findings = []
    servers = spec.get("servers", [])

    for server in servers:
        url = server.get("url", "")
        if url.startswith("http://"):
            findings.append(Finding(
                endpoint=url,
                method="SERVER",
                issue="Server URL uses HTTP instead of HTTPS",
                risk=RiskLevel.CRITICAL,
                control="PCI DSS 4.2.1 / NDPA Section 24",
                description="All fintech API traffic must be encrypted in transit"
            ))

    return findings


@register_rule
def check_missing_rate_limit(spec: dict) -> list[Finding]:
    findings = []
    paths = spec.get("paths", {})

    for path, methods in paths.items():
        for method, details in methods.items():
            if not isinstance(details, dict):
                continue
            headers = {}
            for status, response in details.get("responses", {}).items():
                headers.update(
                    response.get("headers", {}) if isinstance(response, dict) else {}
                )
            has_rate_limit = any(
                "ratelimit" in h.lower() or "x-rate" in h.lower()
                for h in headers
            )
            if not has_rate_limit and method.lower() in ["post", "put", "patch"]:
                findings.append(Finding(
                    endpoint=path,
                    method=method.upper(),
                    issue="No rate limiting headers defined on write endpoint",
                    risk=RiskLevel.MEDIUM,
                    control="PCI DSS 6.4 / SOC 2 CC6.6",
                    description="Write endpoints without rate limiting are vulnerable to abuse"
                ))

    return findings