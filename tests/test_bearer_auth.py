"""Tests for optional MCP_BEARER_TOKEN bearer-token authentication."""

from __future__ import annotations

import importlib

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TOKEN = "test-secret-token-1234"  # noqa: S105 — test-only value


def _reload_server(monkeypatch, *, token: str = ""):
    """Reload server module with MCP_BEARER_TOKEN set (or cleared)."""
    if token:
        monkeypatch.setenv("MCP_BEARER_TOKEN", token)
    else:
        monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)

    # Must also set a valid API key so Settings() doesn't fail at import time
    monkeypatch.setenv("UNIFI_API_KEY", "sk-reload-test")

    import unifi_fabric.server as srv

    importlib.reload(srv)
    return srv


# ---------------------------------------------------------------------------
# Config layer
# ---------------------------------------------------------------------------


class TestMCPTransportSettings:
    def test_reads_bearer_token_from_env(self, monkeypatch):
        monkeypatch.setenv("MCP_BEARER_TOKEN", TOKEN)
        from unifi_fabric.config import MCPTransportSettings

        cfg = MCPTransportSettings()
        assert cfg.bearer_token == TOKEN

    def test_defaults_to_empty(self, monkeypatch):
        monkeypatch.delenv("MCP_BEARER_TOKEN", raising=False)
        from unifi_fabric.config import MCPTransportSettings

        cfg = MCPTransportSettings()
        assert cfg.bearer_token == ""


# ---------------------------------------------------------------------------
# Server wiring
# ---------------------------------------------------------------------------


class TestBearerTokenServerWiring:
    def test_auth_enabled_when_token_set(self, monkeypatch):
        srv = _reload_server(monkeypatch, token=TOKEN)
        assert srv.mcp.auth is not None

    def test_auth_disabled_when_token_unset(self, monkeypatch):
        srv = _reload_server(monkeypatch, token="")
        assert srv.mcp.auth is None


# ---------------------------------------------------------------------------
# StaticTokenVerifier behaviour
# ---------------------------------------------------------------------------


class TestStaticTokenVerifier:
    async def test_correct_token_accepted(self):
        from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

        verifier = StaticTokenVerifier(tokens={TOKEN: {"client_id": "mcp", "scopes": []}})
        result = await verifier.verify_token(TOKEN)
        assert result is not None
        assert result.client_id == "mcp"

    async def test_wrong_token_rejected(self):
        from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

        verifier = StaticTokenVerifier(tokens={TOKEN: {"client_id": "mcp", "scopes": []}})
        result = await verifier.verify_token("wrong-token")
        assert result is None

    async def test_empty_token_rejected(self):
        from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

        verifier = StaticTokenVerifier(tokens={TOKEN: {"client_id": "mcp", "scopes": []}})
        result = await verifier.verify_token("")
        assert result is None


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompatibility:
    def test_no_auth_when_env_unset(self, monkeypatch):
        """Ensure existing deployments without MCP_BEARER_TOKEN keep working."""
        srv = _reload_server(monkeypatch, token="")
        # auth=None means no transport auth — same as pre-0.3.14 behaviour
        assert srv.mcp.auth is None
        # FastMCP instance still functional
        assert srv.mcp.name == "UniFi Fabric"
