"""Startup/configuration and audit record security regressions."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from unifi_fabric.audit import AuditSink
from unifi_fabric.config import Settings, api_base_url_problem

SECRET = "startup-synthetic-key-1234567890"

URL_FIELDS = (
    "UNIFI_API_BASE_URL",
    "MCP_OAUTH_ISSUER",
    "MCP_OAUTH_JWKS_URI",
    "MCP_OAUTH_BASE_URL",
    "MCP_OAUTH_AUTHORIZATION_SERVERS",
)


def _entrypoint(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    # An isolated synthetic environment: never inherit real service credentials.
    return subprocess.run(  # noqa: S603 - fixed task-owned console entrypoint
        [str(Path(sys.executable).parent / "unifi-fabric-mcp")],
        env={
            "PATH": os.defpath,
            "UNIFI_API_KEY": SECRET,
            "FASTMCP_TRANSPORT": "streamable-http",
            **env,
        },
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("field", URL_FIELDS)
@pytest.mark.parametrize("bad_url", ["https://[SECRET]/", "https://host:SECRET/"])
def test_real_entrypoint_url_errors_never_echo_values(field, bad_url):
    value = bad_url.replace("SECRET", SECRET)
    result = _entrypoint({field: value})
    assert result.returncode == 1
    assert result.stdout == ""
    assert SECRET not in result.stderr
    assert value not in result.stderr
    assert "Traceback" not in result.stderr
    assert len(result.stderr.splitlines()) == 1
    assert field in result.stderr


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("MCP_TLS_MODE", "bogus"),
        ("MCP_BEARER_TOKEN", "a b"),
        ("MCP_AUTH_MODE", SECRET),
        ("MCP_TLS_CERT_REQS", SECRET),
        ("MCP_OAUTH_ALGORITHM", SECRET),
        ("MCP_OAUTH_REQUIRED_SCOPES", SECRET + " bad"),
        ("UNIFI_MCP_CACHE_TTL", SECRET),
        ("UNIFI_LOG_LEVEL", SECRET),
        ("UNIFI_AUDIT_LOG_FORMAT", SECRET),
    ],
)
def test_real_entrypoint_validation_is_one_safe_line(field, value):
    result = _entrypoint({field: value})
    assert result.returncode == 1
    assert result.stdout == ""
    assert value not in result.stderr
    assert SECRET not in result.stderr
    assert "Traceback" not in result.stderr
    assert len(result.stderr.splitlines()) == 1
    assert field in result.stderr


def test_unknown_api_key_mapping_fields_are_counted_not_echoed():
    with pytest.raises(ValueError) as error:
        Settings(api_keys=[{"key": SECRET, SECRET: "value", "another": "value"}])
    assert SECRET not in str(error.value)
    assert "2 unknown field(s)" in str(error.value)
    assert "allowed fields" in str(error.value)


def test_real_entrypoint_unknown_key_mapping_field_is_hidden():
    result = _entrypoint({"UNIFI_API_KEYS": json.dumps([{"key": SECRET, SECRET: "value"}])})
    assert result.returncode == 1
    assert SECRET not in result.stderr
    assert "1 unknown field(s)" in result.stderr
    assert len(result.stderr.splitlines()) == 1


@pytest.mark.parametrize(
    "value", ["https://[unclosed/", "https://host:not-a-port/", "https://host:999999/"]
)
def test_parser_reason_is_static(value):
    assert api_base_url_problem(value) == "is not a valid URL (invalid host, IPv6 address or port)"


@pytest.mark.parametrize("field", ["method", "path", "tool", "outcome"])
@pytest.mark.parametrize("injection", ["value\noutcome=forged", "value outcome=forged"])
def test_audit_text_quotes_every_free_text_field(tmp_path, field, injection):
    path = tmp_path / "audit.log"
    values = {
        "method": "POST",
        "path": "/network",
        "tool": "update_network",
        "outcome": "ok",
        "status": 200,
    }
    values[field] = injection
    AuditSink(str(path), fmt="text").record(**values)
    line = path.read_text()
    assert len(line.splitlines()) == 1
    assert f"{field}={json.dumps(injection)}" in line


def test_configuration_error_renderer_scrubs_validation_message(monkeypatch):
    from unifi_fabric import server

    monkeypatch.setenv("UNIFI_API_KEY", SECRET)
    line = server._configuration_error_line(ValueError("failure " + SECRET))
    assert SECRET not in line
    assert "failure" in line


def test_import_defers_transport_validation_until_app_creation(monkeypatch):
    import importlib

    from unifi_fabric import server

    monkeypatch.setenv("MCP_TLS_MODE", "bogus")
    srv = importlib.reload(server)
    try:
        assert srv._mcp_transport is None
        with pytest.raises(ValueError, match="MCP_TLS_MODE"):
            srv.mcp.http_app()
    finally:
        monkeypatch.delenv("MCP_TLS_MODE")
        importlib.reload(server)


def test_embedded_http_app_configures_auth_before_routes(monkeypatch):
    import importlib

    from unifi_fabric import server

    monkeypatch.setenv("MCP_BEARER_TOKEN", SECRET)
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    srv = importlib.reload(server)
    try:
        srv.mcp.http_app()
        assert srv.mcp.auth is not None
        assert srv._mcp_transport.bearer_token == SECRET
    finally:
        monkeypatch.delenv("MCP_BEARER_TOKEN")
        monkeypatch.delenv("FASTMCP_TRANSPORT")
        importlib.reload(server)


def test_transport_startup_validation_uses_safe_error_renderer(monkeypatch, capsys):
    from unifi_fabric import server

    monkeypatch.setenv("UNIFI_API_KEY", SECRET)
    monkeypatch.setattr(server, "get_settings", lambda: Settings(api_key=SECRET))

    def fail_startup(**kwargs):
        raise ValueError("transport startup rejected " + SECRET)

    monkeypatch.setattr(server.mcp, "run", fail_startup)
    with pytest.raises(SystemExit) as error:
        server.main()
    assert error.value.code == 1
    line = capsys.readouterr().err
    assert SECRET not in line
    assert "transport startup rejected" in line
    assert len(line.splitlines()) == 1
