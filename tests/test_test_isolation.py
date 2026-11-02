"""Regression for server reload state escaping an individual test."""

from __future__ import annotations

import importlib

from unifi_fabric import server


def test_reload_under_bearer_env(monkeypatch):
    """Same mutation performed by bearer, transport and FastMCP wiring tests."""
    monkeypatch.setenv("UNIFI_API_KEY", "isolation-test-key")
    monkeypatch.setenv("MCP_BEARER_TOKEN", "isolation-test-token")
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    importlib.reload(server)
    assert server._mcp_transport is None
    server.mcp.http_app()
    assert server.mcp.auth is not None
    assert server._mcp_transport.auth_mode == "bearer"


def test_next_test_has_default_transport_and_catalog():
    """The previous test's configured bearer app must not escape its fixture."""
    assert server.mcp.auth is None
    assert server._settings is None
    assert server._client is None
    assert server._registry is None
    server.mcp.http_app()
    assert server.mcp.auth is None
    assert server._mcp_transport.auth_mode == "none"
