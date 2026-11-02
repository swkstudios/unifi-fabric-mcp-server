"""Proxy Host regression through uvicorn and the real streamable HTTP sessions.

All sockets stay on loopback, all credentials are synthetic, and no UniFi tool
is invoked. ASGITransport alone omits the loopback server scope that triggered 421.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket

import httpx
import pytest
import uvicorn

from tests.test_auth_http import _server_app, post_initialize

_PROXY_HOST = "proxy.example.test:4444"
_TOKEN = "proxy-regression-synthetic-token-123456"  # noqa: S105


@contextlib.asynccontextmanager
async def _loopback_server(app):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False, ws="none"))
        serving = asyncio.create_task(server.serve(sockets=[sock]))
        try:
            while not server.started:
                if serving.done():
                    await serving
                    pytest.fail("HTTP server exited before startup")
                await asyncio.sleep(0)
            yield f"http://127.0.0.1:{sock.getsockname()[1]}"
        finally:
            server.should_exit = True
            await serving


@pytest.mark.parametrize("stateless", [True, False])
@pytest.mark.parametrize("auth_mode", ["bearer", "none"])
async def test_proxy_host_over_real_http(monkeypatch, stateless, auth_mode):
    _server_app(
        monkeypatch,
        auth_mode=auth_mode,
        env={"MCP_BEARER_TOKEN": _TOKEN},
    )
    # http_app defaults come from the singleton FastMCP settings, not env reloads.
    # Build with the session mode explicitly, as run_http_async does.
    from unifi_fabric import server

    app = server.mcp.http_app(stateless_http=stateless)
    async with (
        _loopback_server(app) as url,
        httpx.AsyncClient(base_url=url, trust_env=False, headers={"Host": _PROXY_HOST}) as client,
    ):
        authorization = f"Bearer {_TOKEN}" if auth_mode == "bearer" else None
        response = await post_initialize(client, authorization=authorization)
        if auth_mode == "none":
            assert response.status_code == 421
            assert "MCP_ALLOWED_HOSTS" in response.text
            client.headers["Host"] = "127.0.0.1"
            assert (await post_initialize(client)).status_code == 200
            return

        assert response.status_code == 200
        assert "serverInfo" in response.text
        session = response.headers.get("mcp-session-id")
        assert bool(session) is not stateless
        if session:
            client.headers["mcp-session-id"] = session
        client.headers.update(
            {
                "Authorization": authorization,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": "2025-06-18",
            }
        )
        initialized = await client.post(
            "/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}
        )
        assert initialized.status_code == 202
        tools = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert tools.status_code == 200
        assert '"tools"' in tools.text

        del client.headers["Authorization"]
        assert (await post_initialize(client)).status_code == 401
        client.headers["Origin"] = "https://untrusted.example.test"
        assert (await post_initialize(client, authorization=authorization)).status_code == 403


@pytest.mark.parametrize("stateless", [True, False])
async def test_authenticated_proxy_respects_explicit_hosts(monkeypatch, stateless):
    _server_app(
        monkeypatch,
        auth_mode="bearer",
        env={"MCP_BEARER_TOKEN": _TOKEN, "MCP_ALLOWED_HOSTS": _PROXY_HOST},
    )
    from unifi_fabric import server

    app = server.mcp.http_app(stateless_http=stateless)
    async with (
        _loopback_server(app) as url,
        httpx.AsyncClient(base_url=url, trust_env=False, headers={"Host": _PROXY_HOST}) as client,
    ):
        assert (await post_initialize(client, authorization=f"Bearer {_TOKEN}")).status_code == 200
        client.headers["Host"] = "unlisted.example.test"
        assert (await post_initialize(client, authorization=f"Bearer {_TOKEN}")).status_code == 421


@pytest.mark.parametrize("auth_mode", ["bearer", "oauth"])
def test_authenticated_host_policy_keeps_explicit_strict_mode(auth_mode):
    from unifi_fabric.config import MCPTransportSettings
    from unifi_fabric.transport_security import http_app_options

    # model_construct isolates option composition from OAuth startup validation.
    settings = MCPTransportSettings.model_construct(auth_mode=auth_mode)
    assert http_app_options(settings, {})["allowed_hosts"] == ["*"]
    assert http_app_options(settings, {"host_origin_protection": True})["allowed_hosts"] is None
    assert http_app_options(settings, {"allowed_hosts": ["proxy.example.test"]})[
        "allowed_hosts"
    ] == ["proxy.example.test"]


@pytest.mark.parametrize("auth_mode", ["bearer", "oauth"])
def test_upstream_host_settings_remain_effective(monkeypatch, auth_mode):
    import fastmcp

    from unifi_fabric.config import MCPTransportSettings
    from unifi_fabric.transport_security import http_app_options

    settings = MCPTransportSettings.model_construct(auth_mode=auth_mode)
    monkeypatch.setattr(fastmcp.settings, "http_allowed_hosts", ["proxy.example.test"])
    assert http_app_options(settings, {})["allowed_hosts"] == ["proxy.example.test"]
    assert http_app_options(settings, {"allowed_hosts": []})["allowed_hosts"] == []
    monkeypatch.setattr(fastmcp.settings, "http_allowed_hosts", None)
    monkeypatch.setattr(fastmcp.settings, "http_host_origin_protection", True)
    options = http_app_options(settings, {})
    assert options["host_origin_protection"] is True
    assert options["allowed_hosts"] is None
