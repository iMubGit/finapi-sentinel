import pytest
from pathlib import Path
from finapi_sentinel.parser import parse_openapi
from finapi_sentinel.rules import (
    check_missing_auth,
    check_unsafe_delete,
    check_http_scheme,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ── Parser tests ──────────────────────────────────────────────────────────────

def test_parser_rejects_invalid_yaml(tmp_path):
    """Parser should raise ValueError on malformed YAML."""
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text(":: invalid: yaml: content :::")
    with pytest.raises(ValueError, match="Invalid YAML"):
        parse_openapi(bad_file)


def test_parser_rejects_missing_paths(tmp_path):
    """Parser should raise ValueError if OpenAPI spec has no paths section."""
    bad_file = tmp_path / "nopaths.yaml"
    bad_file.write_text("openapi: 3.0.0\ninfo:\n  title: Test\n")
    with pytest.raises(ValueError, match="missing 'paths'"):
        parse_openapi(bad_file)


def test_parser_accepts_valid_yaml():
    """Parser should successfully load a valid OpenAPI spec."""
    spec = parse_openapi(FIXTURES / "vulnerable_openapi.yaml")
    assert isinstance(spec, dict)
    assert "paths" in spec


# ── Auth rule tests ───────────────────────────────────────────────────────────

def test_flags_missing_auth_on_sensitive_endpoint():
    """check_missing_auth should flag unauthenticated sensitive endpoints."""
    spec = parse_openapi(FIXTURES / "vulnerable_openapi.yaml")
    findings = check_missing_auth(spec)
    endpoints = [f.endpoint for f in findings]
    assert "/transactions" in endpoints
    assert "/transfer" in endpoints


def test_no_false_positive_on_authenticated_spec():
    """check_missing_auth should produce zero findings on a fully authenticated spec."""
    spec = parse_openapi(FIXTURES / "safe_openapi.yaml")
    findings = check_missing_auth(spec)
    assert len(findings) == 0


def test_health_endpoint_not_flagged():
    """Public health check endpoints should never be flagged."""
    spec = parse_openapi(FIXTURES / "safe_openapi.yaml")
    findings = check_missing_auth(spec)
    endpoints = [f.endpoint for f in findings]
    assert "/health" not in endpoints


# ── Delete rule tests ─────────────────────────────────────────────────────────

def test_flags_unauthenticated_delete():
    """check_unsafe_delete should flag DELETE endpoints without auth."""
    spec = parse_openapi(FIXTURES / "vulnerable_openapi.yaml")
    findings = check_unsafe_delete(spec)
    assert any(f.endpoint == "/users" for f in findings)


def test_no_delete_finding_on_safe_spec():
    """check_unsafe_delete should produce zero findings on authenticated spec."""
    spec = parse_openapi(FIXTURES / "safe_openapi.yaml")
    findings = check_unsafe_delete(spec)
    assert len(findings) == 0


# ── HTTP scheme tests ─────────────────────────────────────────────────────────

def test_flags_http_server_url():
    """check_http_scheme should flag servers using HTTP instead of HTTPS."""
    spec = parse_openapi(FIXTURES / "vulnerable_openapi.yaml")
    findings = check_http_scheme(spec)
    assert len(findings) == 1
    assert "http://" in findings[0].endpoint


def test_no_http_finding_on_https_spec():
    """check_http_scheme should produce zero findings when server uses HTTPS."""
    spec = parse_openapi(FIXTURES / "safe_openapi.yaml")
    findings = check_http_scheme(spec)
    assert len(findings) == 0
