"""Contract tests for the opt-in HTTP health route (``MCP_HEALTH_ROUTE``).

The route is opt-in (absent by default), HTTP-only (added by ``FabricMCP.http_app``,
which stdio never builds), never probes a UniFi console, and serves no metrics: the
body is exactly ``ok`` or ``degraded:<fixed reason token>``. Every request goes
through the in-process ASGI app (``httpx.ASGITransport``), with real network
transports patched to fail, so no socket or upstream call is possible.
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import logging
from collections.abc import AsyncIterator, Mapping
from pathlib import Path

import httpx
import httpx2
import pytest

_BASE_URL = "http://127.0.0.1"
_OWNED_ENV = (
    "MCP_AUTH_MODE",
    "MCP_BEARER_TOKEN",
    "MCP_HEALTH_ROUTE",
    "FASTMCP_TRANSPORT",
    "UNIFI_API_KEY",
    "UNIFI_TOOL_MODE",
    "UNIFI_AUDIT_LOG",
)


@contextlib.asynccontextmanager
async def _client(
    monkeypatch,
    *,
    enabled: bool,
    transport: str = "streamable-http",
    env: Mapping[str, str] | None = None,
) -> AsyncIterator[tuple[httpx.AsyncClient, list[str]]]:
    """An in-process client for the server's HTTP app, plus the upstream-call log."""
    from unifi_fabric import server
    from unifi_fabric.client import UniFiClient

    upstream: list[str] = []

    async def refuse_upstream(self, *args, **kwargs):
        upstream.append("UniFiClient.request")
        raise AssertionError("the health route must never call a UniFi console")

    async def refuse_network(self, request):
        upstream.append(str(request.url))
        raise AssertionError("health tests must not reach the network")

    with monkeypatch.context() as mp:
        for var in _OWNED_ENV:
            mp.delenv(var, raising=False)
        mp.setenv("UNIFI_API_KEY", "test-key-not-real")
        mp.setenv("FASTMCP_TRANSPORT", transport)
        mp.setenv("MCP_AUTH_MODE", "none")
        mp.setenv("UNIFI_TOOL_MODE", "full")
        if enabled:
            mp.setenv("MCP_HEALTH_ROUTE", "on")
        for key, value in (env or {}).items():
            mp.setenv(key, value)
        mp.setattr(UniFiClient, "request", refuse_upstream)
        mp.setattr(httpx.AsyncHTTPTransport, "handle_async_request", refuse_network)
        mp.setattr(httpx2.AsyncHTTPTransport, "handle_async_request", refuse_network)
        mp.setattr(server, "_mcp_transport", None)
        mp.setattr(server, "_cache_ttl", None)
        mp.setattr(server.mcp, "auth", None)
        mp.setattr(server.mcp, "instructions", server.mcp.instructions)
        mp.setattr(server.mcp._mcp_server, "cache_hints", {})  # noqa: SLF001
        app = server.mcp.http_app(transport="sse" if transport == "sse" else "http")
        inner = app.app
        async with inner.router.lifespan_context(inner):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=_BASE_URL
            ) as client:
                yield client, upstream


async def test_health_off_by_default_404(monkeypatch):
    async with _client(monkeypatch, enabled=False) as (client, upstream):
        resp = await client.get("/health")
    assert resp.status_code == 404
    assert upstream == []


async def test_health_opt_in_http_200(monkeypatch):
    async with _client(monkeypatch, enabled=True) as (client, upstream):
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.text == "ok\n"
    assert resp.headers["content-type"].startswith("text/plain")
    assert upstream == []


async def test_health_sse_same_route(monkeypatch):
    async with _client(monkeypatch, enabled=True, transport="sse") as (client, upstream):
        resp = await client.get("/health")
    assert (resp.status_code, resp.text) == (200, "ok\n")
    assert upstream == []


async def test_health_stdio_absent(monkeypatch):
    """stdio never builds the HTTP app, so the route has nowhere to exist."""
    from fastmcp import FastMCP

    from unifi_fabric import server

    monkeypatch.setenv("MCP_HEALTH_ROUTE", "on")
    monkeypatch.setenv("FASTMCP_TRANSPORT", "stdio")
    built: list[str] = []
    ran: list[str] = []

    def refuse_http_app(self, *args, **kwargs):
        built.append("http_app")
        raise AssertionError("stdio must not build the HTTP app")

    async def fake_stdio(self, *args, **kwargs):
        ran.append("stdio")

    monkeypatch.setattr(server.FabricMCP, "http_app", refuse_http_app)
    monkeypatch.setattr(FastMCP, "run_stdio_async", fake_stdio)
    monkeypatch.setattr(server, "_mcp_transport", None)
    monkeypatch.setattr(server.mcp, "auth", None)
    await server.mcp.run_async(transport="stdio")
    assert ran == ["stdio"]
    assert built == []


async def test_health_never_probes_unifi(monkeypatch):
    async with _client(monkeypatch, enabled=True) as (client, upstream):
        for _ in range(3):
            resp = await client.get("/health")
            assert resp.status_code == 200
    assert upstream == []


async def test_health_no_metrics_route(monkeypatch):
    async with _client(monkeypatch, enabled=True) as (client, _upstream):
        metrics = await client.get("/metrics")
        health = await client.get("/health")
    assert metrics.status_code == 404
    assert not any(ch.isdigit() for ch in health.text)


async def test_health_body_fixed_fields(monkeypatch):
    async with _client(monkeypatch, enabled=True) as (client, _upstream):
        resp = await client.get("/health")
        post = await client.post("/health")
        head = await client.head("/health")
    assert resp.text == "ok\n"
    assert post.status_code == 405
    assert head.status_code == 200


async def test_health_degraded_when_audit_sink_unwritable(monkeypatch, tmp_path):
    missing = tmp_path / "no-such-dir" / "audit.log"
    env = {"UNIFI_AUDIT_LOG": str(missing)}
    async with _client(monkeypatch, enabled=True, env=env) as (client, upstream):
        resp = await client.get("/health")
    assert resp.status_code == 503
    assert resp.text == "degraded:audit-sink-unwritable\n"
    assert str(tmp_path) not in resp.text
    assert upstream == []


async def test_health_ok_with_writable_audit_sink(monkeypatch, tmp_path):
    env = {"UNIFI_AUDIT_LOG": str(tmp_path / "audit.log")}
    async with _client(monkeypatch, enabled=True, env=env) as (client, _upstream):
        resp = await client.get("/health")
    assert (resp.status_code, resp.text) == (200, "ok\n")


def test_health_degraded_before_config_loaded_or_lifespan_not_running():
    from unifi_fabric.config import Settings
    from unifi_fabric.health import REASON_CONFIG, REASON_NOT_STARTED, ServerState, health_status

    settings = Settings.model_construct(audit_log="")
    assert health_status(ServerState(settings=None, running=False)) == REASON_CONFIG
    assert health_status(ServerState(settings=settings, running=False)) == REASON_NOT_STARTED
    assert health_status(ServerState(settings=settings, running=True)) is None


async def test_health_not_started_after_lifespan_ends(monkeypatch):
    """After the lifespan tears down (client closed), the route no longer says ok."""
    from unifi_fabric import server
    from unifi_fabric.health import REASON_NOT_STARTED, ServerState, health_status

    async with _client(monkeypatch, enabled=True) as (client, _upstream):
        assert (await client.get("/health")).status_code == 200
    state = ServerState(settings=server._settings, running=server._client is not None)  # noqa: SLF001
    assert health_status(state) in (REASON_NOT_STARTED, "config-not-loaded")


async def test_health_logged_by_access_log_not_bypassing_origin_guard(monkeypatch):
    from unifi_fabric.access_log import AccessLogMiddleware

    class _Collect(logging.Handler):
        def __init__(self) -> None:
            super().__init__(logging.INFO)
            self.lines: list[str] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.lines.append(record.getMessage())

    # The lifespan reconfigures the root logger (basicConfig force=True), which drops
    # caplog's root handler; collect from the access logger itself once startup is done.
    collector = _Collect()
    access = logging.getLogger("unifi_fabric.access")
    previous_level = access.level
    async with _client(monkeypatch, enabled=True) as (client, _upstream):
        access.addHandler(collector)
        access.setLevel(logging.INFO)
        try:
            assert isinstance(client._transport.app, AccessLogMiddleware)  # noqa: SLF001
            refused = await client.get("/health", headers={"Origin": "https://evil.example"})
            allowed = await client.get("/health", headers={"Origin": "http://localhost:3000"})
        finally:
            access.removeHandler(collector)
            access.setLevel(previous_level)
    assert refused.status_code == 403
    assert allowed.status_code == 200
    lines = collector.lines
    assert any("GET /health" in line and line.endswith(" 200") for line in lines)
    assert any("GET /health" in line and line.endswith(" 403") for line in lines)


async def test_health_host_check_applies(monkeypatch):
    env = {"MCP_ALLOWED_HOSTS": "mcp.example.test"}
    async with _client(monkeypatch, enabled=True, env=env) as (client, _upstream):
        evil = await client.get("/health", headers={"Host": "evil.example.test"})
        good = await client.get("/health", headers={"Host": "mcp.example.test"})
    assert evil.status_code == 421
    assert good.status_code == 200


async def test_health_needs_no_token_in_bearer_mode(monkeypatch):
    """The route answers without a token while the MCP endpoint still requires one."""
    env = {"MCP_AUTH_MODE": "bearer", "MCP_BEARER_TOKEN": "health-contract-not-a-secret"}
    async with _client(monkeypatch, enabled=True, env=env) as (client, upstream):
        health = await client.get("/health")
        mcp = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
    assert (health.status_code, health.text) == (200, "ok\n")
    assert mcp.status_code == 401
    assert upstream == []


@pytest.mark.parametrize("blank", ["", "  "])
def test_health_blank_setting_is_off(monkeypatch, blank):
    # docs/CONFIGURATION.md: an empty or whitespace-only MCP_* value counts as unset.
    from unifi_fabric.config import MCPTransportSettings

    monkeypatch.setenv("MCP_HEALTH_ROUTE", blank)
    assert MCPTransportSettings().health_route is False


def test_health_no_inner_deadline():
    from unifi_fabric import health

    tree = ast.parse(Path(inspect.getfile(health)).read_text())
    names = {
        node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute | ast.Name)
    }
    assert not names & {"wait_for", "timeout", "sleep", "deadline", "fail_after", "move_on_after"}
    assert "httpx" not in Path(inspect.getfile(health)).read_text()
