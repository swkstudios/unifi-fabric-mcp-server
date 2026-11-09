"""Regression for server reload state escaping an individual test."""

from __future__ import annotations

import importlib
import logging
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

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


@pytest.mark.parametrize("operation", ["reload", "reimport"])
def test_server_import_namespace_is_restored(operation):
    """Exercise the real fixture boundary without depending on test scheduling."""
    import unifi_fabric
    from tests.conftest import _reset_server_singletons
    from unifi_fabric import policy

    original = server
    expected = vars(original).copy()
    patch = pytest.MonkeyPatch()
    boundary = _reset_server_singletons.__wrapped__(None, patch)
    next(boundary)
    try:
        if operation == "reload":
            changed = importlib.reload(original)
        else:
            del sys.modules["unifi_fabric.server"]
            del unifi_fabric.server
            changed = importlib.import_module("unifi_fabric.server")
        assert changed.AuditContextMiddleware is not expected["AuditContextMiddleware"]
        assert any(type(mw) is changed.AuditContextMiddleware for mw in changed.mcp.middleware)
        changed._isolation_added_binding = object()
        del original.AuditContextMiddleware
    finally:
        with pytest.raises(StopIteration):
            next(boundary)

    assert sys.modules["unifi_fabric.server"] is original
    assert unifi_fabric.server is original
    assert importlib.import_module("unifi_fabric.server") is original
    assert vars(original).keys() == expected.keys()
    for name, value in expected.items():
        if name in {"_settings", "_client", "_registry"}:
            assert getattr(original, name) is None
        else:
            assert getattr(original, name) is value, name
    assert any(type(mw) is original.AuditContextMiddleware for mw in original.mcp.middleware)

    audit_stream = Mock()
    original._client = SimpleNamespace(audit_stream=audit_stream)
    policy.emit("isolation-policy-record")
    audit_stream.policy_record.assert_called_once_with("isolation-policy-record")

    # Model a following test configuring only the restored server namespace.
    # The discarded re-import must not remain the log scrubber's provider.
    from unifi_fabric.config import Settings

    synthetic_key = "isolation-configured-log-key"
    original._settings = Settings(api_key=synthetic_key)
    logger = logging.getLogger("isolation.configured-secret")
    record = logger.makeRecord(
        logger.name, logging.INFO, __file__, 1, "configured key: %s", (synthetic_key,), None
    )
    assert record.getMessage() == "configured key: ***"
