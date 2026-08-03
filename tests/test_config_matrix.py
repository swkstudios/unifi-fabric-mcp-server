"""Tests for the auth/transport/TLS config selector matrix (Phase 0).

Covers MCPTransportSettings validation (fail-closed) and the two pure builders
build_auth / build_uvicorn_config in server.py.
"""

from __future__ import annotations

import os
import ssl

import pytest
from pydantic import ValidationError

from unifi_fabric.config import MCPTransportSettings
from unifi_fabric.server import build_auth, build_uvicorn_config

HTTP = "streamable-http"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Isolate every test from ambient MCP_*/FASTMCP_* configuration."""
    for k in list(os.environ):
        if k.startswith(("MCP_", "FASTMCP_")):
            monkeypatch.delenv(k, raising=False)
    yield


def _settings(monkeypatch, **env: str) -> MCPTransportSettings:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return MCPTransportSettings()


# ---------------------------------------------------------------------------
# Valid combinations construct
# ---------------------------------------------------------------------------

VALID_CASES: dict[str, dict[str, str]] = {
    "default_none_stdio": {},
    "explicit_none": {"MCP_AUTH_MODE": "none"},
    "bearer_http": {"MCP_BEARER_TOKEN": "secret", "FASTMCP_TRANSPORT": HTTP},
    "explicit_bearer_http": {
        "MCP_AUTH_MODE": "bearer",
        "MCP_BEARER_TOKEN": "secret",
        "FASTMCP_TRANSPORT": HTTP,
    },
    "oauth_http": {
        "MCP_AUTH_MODE": "oauth",
        "MCP_OAUTH_ISSUER": "https://issuer.example",
        "MCP_OAUTH_JWKS_URI": "https://issuer.example/jwks",
        "MCP_OAUTH_AUDIENCE": "unifi-fabric",
        "MCP_OAUTH_BASE_URL": "https://mcp.example",
        "FASTMCP_TRANSPORT": HTTP,
    },
    "https_http": {
        "MCP_TLS_MODE": "https",
        "MCP_TLS_CERTFILE": "/c/cert.pem",
        "MCP_TLS_KEYFILE": "/c/key.pem",
        "FASTMCP_TRANSPORT": HTTP,
    },
    "mtls_http": {
        "MCP_TLS_MODE": "mtls",
        "MCP_TLS_CERTFILE": "/c/cert.pem",
        "MCP_TLS_KEYFILE": "/c/key.pem",
        "MCP_TLS_CA_CERTS": "/c/ca.pem",
        "MCP_TLS_CERT_REQS": "required",
        "FASTMCP_TRANSPORT": HTTP,
    },
}


@pytest.mark.parametrize("case", VALID_CASES.values(), ids=list(VALID_CASES))
def test_valid_combo_constructs(monkeypatch, case):
    cfg = _settings(monkeypatch, **case)
    assert cfg.auth_mode in ("none", "bearer", "oauth")
    assert cfg.tls_mode in ("none", "https", "mtls")


# ---------------------------------------------------------------------------
# Invalid combinations raise with a clear message (fail-closed validation)
# ---------------------------------------------------------------------------

INVALID_CASES: dict[str, tuple[dict[str, str], str]] = {
    "bearer_stdio_a2": ({"MCP_BEARER_TOKEN": "secret"}, "stdio"),
    "https_stdio_a2": (
        {"MCP_TLS_MODE": "https", "MCP_TLS_CERTFILE": "c", "MCP_TLS_KEYFILE": "k"},
        "stdio",
    ),
    "oauth_stdio_a2": (
        {
            "MCP_AUTH_MODE": "oauth",
            "MCP_OAUTH_ISSUER": "https://i",
            "MCP_OAUTH_JWKS_URI": "https://j",
            "MCP_OAUTH_AUDIENCE": "a",
            "MCP_OAUTH_BASE_URL": "https://b",
        },
        "stdio",
    ),
    "https_missing_key": (
        {"MCP_TLS_MODE": "https", "MCP_TLS_CERTFILE": "c", "FASTMCP_TRANSPORT": HTTP},
        "MCP_TLS_KEYFILE",
    ),
    "mtls_missing_ca": (
        {
            "MCP_TLS_MODE": "mtls",
            "MCP_TLS_CERTFILE": "c",
            "MCP_TLS_KEYFILE": "k",
            "FASTMCP_TRANSPORT": HTTP,
        },
        "MCP_TLS_CA_CERTS",
    ),
    "oauth_missing_fields": (
        {
            "MCP_AUTH_MODE": "oauth",
            "MCP_OAUTH_ISSUER": "https://i",
            "FASTMCP_TRANSPORT": HTTP,
        },
        "MCP_OAUTH_JWKS_URI",
    ),
    "bearer_no_token": (
        {"MCP_AUTH_MODE": "bearer", "FASTMCP_TRANSPORT": HTTP},
        "MCP_BEARER_TOKEN",
    ),
    "bad_auth_enum": (
        {"MCP_AUTH_MODE": "bogus", "FASTMCP_TRANSPORT": HTTP},
        "MCP_AUTH_MODE must be one of",
    ),
    "bad_tls_enum": (
        {"MCP_TLS_MODE": "ftps", "FASTMCP_TRANSPORT": HTTP},
        "MCP_TLS_MODE must be one of",
    ),
    "bad_cert_reqs_enum": (
        {
            "MCP_TLS_MODE": "mtls",
            "MCP_TLS_CERTFILE": "c",
            "MCP_TLS_KEYFILE": "k",
            "MCP_TLS_CA_CERTS": "ca",
            "MCP_TLS_CERT_REQS": "maybe",
            "FASTMCP_TRANSPORT": HTTP,
        },
        "MCP_TLS_CERT_REQS must be one of",
    ),
}


@pytest.mark.parametrize(("env", "needle"), INVALID_CASES.values(), ids=list(INVALID_CASES))
def test_invalid_combo_raises(monkeypatch, env, needle):
    with pytest.raises(ValidationError) as exc:
        _settings(monkeypatch, **env)
    assert needle in str(exc.value)


# ---------------------------------------------------------------------------
# Backward compatibility + resolution semantics
# ---------------------------------------------------------------------------


def test_token_only_resolves_to_bearer(monkeypatch):
    cfg = _settings(monkeypatch, MCP_BEARER_TOKEN="secret", FASTMCP_TRANSPORT=HTTP)
    assert cfg.auth_mode == "bearer"


def test_no_token_resolves_to_none(monkeypatch):
    cfg = _settings(monkeypatch)
    assert cfg.auth_mode == "none"


def test_explicit_none_overrides_token(monkeypatch):
    # Explicit selector wins over the legacy bearer_token compat path.
    cfg = _settings(monkeypatch, MCP_AUTH_MODE="none", MCP_BEARER_TOKEN="secret")
    assert cfg.auth_mode == "none"


# ---------------------------------------------------------------------------
# CSV parsing + oauth authorization-server default
# ---------------------------------------------------------------------------


def test_required_scopes_csv_parses(monkeypatch):
    cfg = _settings(
        monkeypatch,
        MCP_AUTH_MODE="oauth",
        MCP_OAUTH_ISSUER="https://i",
        MCP_OAUTH_JWKS_URI="https://j",
        MCP_OAUTH_AUDIENCE="a",
        MCP_OAUTH_BASE_URL="https://b",
        MCP_OAUTH_REQUIRED_SCOPES="read, write , net.admin",
        FASTMCP_TRANSPORT=HTTP,
    )
    assert cfg.oauth_required_scopes == ["read", "write", "net.admin"]


def test_authorization_servers_defaults_to_issuer(monkeypatch):
    cfg = _settings(
        monkeypatch,
        MCP_AUTH_MODE="oauth",
        MCP_OAUTH_ISSUER="https://issuer.example",
        MCP_OAUTH_JWKS_URI="https://j",
        MCP_OAUTH_AUDIENCE="a",
        MCP_OAUTH_BASE_URL="https://b",
        FASTMCP_TRANSPORT=HTTP,
    )
    assert cfg.oauth_authorization_servers == ["https://issuer.example"]


def test_authorization_servers_explicit_csv(monkeypatch):
    cfg = _settings(
        monkeypatch,
        MCP_AUTH_MODE="oauth",
        MCP_OAUTH_ISSUER="https://issuer.example",
        MCP_OAUTH_JWKS_URI="https://j",
        MCP_OAUTH_AUDIENCE="a",
        MCP_OAUTH_BASE_URL="https://b",
        MCP_OAUTH_AUTHORIZATION_SERVERS="https://as1.example, https://as2.example",
        FASTMCP_TRANSPORT=HTTP,
    )
    assert cfg.oauth_authorization_servers == [
        "https://as1.example",
        "https://as2.example",
    ]


# ---------------------------------------------------------------------------
# build_auth — one provider per mode
# ---------------------------------------------------------------------------


def test_build_auth_none(monkeypatch):
    cfg = _settings(monkeypatch, MCP_AUTH_MODE="none")
    assert build_auth(cfg) is None


def test_build_auth_bearer(monkeypatch):
    from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

    cfg = _settings(monkeypatch, MCP_BEARER_TOKEN="secret", FASTMCP_TRANSPORT=HTTP)
    auth = build_auth(cfg)
    assert isinstance(auth, StaticTokenVerifier)


def test_build_auth_oauth(monkeypatch):
    # oauth mode wires a resource-server provider (a RemoteAuthProvider over a
    # JWKS-backed JWTVerifier). Verifier construction is lazy, so no network call
    # happens here. This replaces the pre-Phase-2 NotImplementedError placeholder.
    from fastmcp.server.auth import RemoteAuthProvider

    cfg = _settings(
        monkeypatch,
        MCP_AUTH_MODE="oauth",
        MCP_OAUTH_ISSUER="https://i",
        MCP_OAUTH_JWKS_URI="https://j",
        MCP_OAUTH_AUDIENCE="a",
        MCP_OAUTH_BASE_URL="https://b",
        FASTMCP_TRANSPORT=HTTP,
    )
    auth = build_auth(cfg)
    assert isinstance(auth, RemoteAuthProvider)


# ---------------------------------------------------------------------------
# build_uvicorn_config — ssl kwargs per mode
# ---------------------------------------------------------------------------


def test_build_uvicorn_config_none(monkeypatch):
    cfg = _settings(monkeypatch)
    assert build_uvicorn_config(cfg) is None


def test_build_uvicorn_config_https(monkeypatch):
    cfg = _settings(
        monkeypatch,
        MCP_TLS_MODE="https",
        MCP_TLS_CERTFILE="/c/cert.pem",
        MCP_TLS_KEYFILE="/c/key.pem",
        MCP_TLS_KEY_PASSWORD="hunter2",
        FASTMCP_TRANSPORT=HTTP,
    )
    out = build_uvicorn_config(cfg)
    assert out == {
        "ssl_certfile": "/c/cert.pem",
        "ssl_keyfile": "/c/key.pem",
        "ssl_keyfile_password": "hunter2",
    }
    assert "ssl_ca_certs" not in out


def test_build_uvicorn_config_https_no_password(monkeypatch):
    cfg = _settings(
        monkeypatch,
        MCP_TLS_MODE="https",
        MCP_TLS_CERTFILE="/c/cert.pem",
        MCP_TLS_KEYFILE="/c/key.pem",
        FASTMCP_TRANSPORT=HTTP,
    )
    out = build_uvicorn_config(cfg)
    assert out["ssl_keyfile_password"] is None


def test_build_uvicorn_config_mtls(monkeypatch):
    cfg = _settings(
        monkeypatch,
        MCP_TLS_MODE="mtls",
        MCP_TLS_CERTFILE="/c/cert.pem",
        MCP_TLS_KEYFILE="/c/key.pem",
        MCP_TLS_CA_CERTS="/c/ca.pem",
        FASTMCP_TRANSPORT=HTTP,
    )
    out = build_uvicorn_config(cfg)
    assert out["ssl_certfile"] == "/c/cert.pem"
    assert out["ssl_keyfile"] == "/c/key.pem"
    assert out["ssl_ca_certs"] == "/c/ca.pem"
    assert out["ssl_cert_reqs"] == ssl.CERT_REQUIRED
