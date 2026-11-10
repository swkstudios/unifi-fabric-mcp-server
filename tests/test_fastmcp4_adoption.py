"""FastMCP 4 capabilities the server opts into: titles, version, cache hints, stateless HTTP.

Each test drives the real server module (reloaded under a controlled environment
where the setting is read at import) and, where the property is on the wire, the
streamable-HTTP ASGI app in-process (``httpx.ASGITransport`` -- no sockets).
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import re
from collections.abc import AsyncIterator, Mapping
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any

import httpx
import pytest

from unifi_fabric import server
from unifi_fabric.argument_errors import ArgumentErrorMiddleware
from unifi_fabric.config import MCPTransportSettings
from unifi_fabric.discovery import META_TOOLS
from unifi_fabric.families import apply_tool_family_filter
from unifi_fabric.local_components import tool_components
from unifi_fabric.tool_titles import ACRONYMS, acronym_title, install_tool_titles

_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
_LEGACY = "2025-06-18"
_MODERN = "2026-07-28"
_MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": _MODERN,
    "io.modelcontextprotocol/clientCapabilities": {},
}
_ROOT = Path(__file__).resolve().parents[1]


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _catalog_count(srv: Any) -> int:
    return len(tool_components(srv.mcp))


def _advertised_count(srv: Any) -> int:
    return len(META_TOOLS) if srv.get_settings().tool_mode == "discovery" else _catalog_count(srv)


def _reload(monkeypatch: pytest.MonkeyPatch, env: Mapping[str, str] | None = None) -> Any:
    monkeypatch.setenv("UNIFI_API_KEY", "sk-fastmcp4-adoption")
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_AUTH_MODE", "none")
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    import unifi_fabric.server as srv

    importlib.reload(srv)
    srv._configure_transport()
    return srv


@contextlib.asynccontextmanager
async def _client(srv: Any, **app_kwargs: Any) -> AsyncIterator[httpx.AsyncClient]:
    app = srv.mcp.http_app(**app_kwargs)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://fastmcp4.test"
        ) as client:
            yield client


def _body(resp: httpx.Response) -> dict[str, Any]:
    """Decode a JSON or single-event SSE response body."""
    text = resp.text
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        text = data[-1]
    return json.loads(text)


async def _legacy_initialize(client: httpx.AsyncClient) -> httpx.Response:
    return await client.post(
        "/mcp",
        headers=_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": _LEGACY,
                "capabilities": {},
                "clientInfo": {"name": "legacy-client", "version": "1.0"},
            },
        },
    )


async def _legacy_request(
    client: httpx.AsyncClient, method: str, params: dict[str, Any], session: str | None
) -> httpx.Response:
    headers = {**_HEADERS, "MCP-Protocol-Version": _LEGACY}
    if session:
        headers["Mcp-Session-Id"] = session
    return await client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 2, "method": method, "params": params},
    )


async def _modern_request(client: httpx.AsyncClient, method: str) -> httpx.Response:
    return await client.post(
        "/mcp",
        headers={**_HEADERS, "MCP-Protocol-Version": _MODERN, "Mcp-Method": method},
        json={"jsonrpc": "2.0", "id": 3, "method": method, "params": {"_meta": _MODERN_META}},
    )


# ---------------------------------------------------------------------------
# Tool titles
# ---------------------------------------------------------------------------


class TestToolTitles:
    def test_every_title_is_the_acronym_title(self) -> None:
        tools = _run(server.mcp.list_tools())
        assert len(tools) == _catalog_count(server)
        assert {t.name: t.title for t in tools} == {t.name: acronym_title(t.name) for t in tools}

    def test_no_plain_title_cased_acronyms(self) -> None:
        wrong = {word.capitalize() for word, spelled in ACRONYMS.items()}
        wrong |= {"Mc", "Sdwan", "Isp", "Acl", "Lag", "Lags"}
        bad = []
        for tool in _run(server.mcp.list_tools()):
            for word in (tool.title or "").split():
                if word in wrong and word not in ACRONYMS.values():
                    bad.append(f"{tool.name}: {tool.title}")
        assert bad == []

    @pytest.mark.parametrize(
        ("name", "title"),
        [
            ("query_isp_metrics", "Query ISP Metrics"),
            ("list_acl_rules", "List ACL Rules"),
            ("list_lags", "List LAGs"),
            ("get_lag", "Get LAG"),
            ("list_mc_lag_domains", "List MC-LAG Domains"),
            ("list_sdwan_configs", "List SD-WAN Configs"),
            ("list_rogue_aps", "List Rogue APs"),
            ("get_unifi_placement_snapshot", "Get UniFi Placement Snapshot"),
            ("get_innerspace_summary", "Get InnerSpace Summary"),
            ("list_radius_profiles", "List RADIUS Profiles"),
            ("list_wifi_broadcasts", "List WiFi Broadcasts"),
            ("ptz_goto_preset", "PTZ Goto Preset"),
            ("enable_arm", "Enable Arm"),
            ("list_hosts", "List Hosts"),
            ("set_poe_port_mode", "Set PoE Port Mode"),
            ("get_dhcp_ip_id", "Get DHCP IP ID"),
        ],
    )
    def test_acronym_title(self, name: str, title: str) -> None:
        assert acronym_title(name) == title

    def test_explicit_title_is_kept_and_install_is_idempotent(self) -> None:
        from fastmcp import FastMCP

        mcp = FastMCP("scratch")

        @mcp.tool(title="Custom Title")
        def list_isp_things() -> dict[str, Any]:
            return {}

        @mcp.tool()
        def get_acl_thing() -> dict[str, Any]:
            return {}

        assert install_tool_titles(mcp) == 1
        assert install_tool_titles(mcp) == 0
        titles = {t.name: t.title for t in _run(mcp.list_tools())}
        assert titles == {"list_isp_things": "Custom Title", "get_acl_thing": "Get ACL Thing"}

    def test_titles_coexist_with_redaction_and_argument_errors(self) -> None:
        tools = tool_components(server.mcp)
        assert all(getattr(t.fn, "_unifi_redaction_wrapped", False) for t in tools)
        assert all(t.title == acronym_title(t.name) for t in tools)
        assert any(isinstance(m, ArgumentErrorMiddleware) for m in server.mcp.middleware)

    def test_titles_survive_the_family_filter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        srv = _reload(monkeypatch)
        full_count = _catalog_count(srv)
        try:
            _run(apply_tool_family_filter(srv.mcp, "network"))
            tools = _run(srv.mcp.list_tools())
            assert 0 < len(tools) < full_count
            assert all(t.title == acronym_title(t.name) for t in tools)
        finally:
            importlib.reload(srv)  # restore the full roster for later tests


# ---------------------------------------------------------------------------
# serverInfo.version
# ---------------------------------------------------------------------------


class TestServerVersion:
    def test_server_version_is_the_package_version(self) -> None:
        assert server.mcp.version == package_version("unifi-fabric-mcp-server")

    def test_legacy_initialize_reports_package_version(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        srv = _reload(monkeypatch)

        async def go() -> dict[str, Any]:
            async with _client(srv) as client:
                resp = await _legacy_initialize(client)
                assert resp.status_code == 200
                return _body(resp)

        info = _run(go())["result"]["serverInfo"]
        assert info["version"] == package_version("unifi-fabric-mcp-server")


# ---------------------------------------------------------------------------
# Cache hints (UNIFI_MCP_CACHE_TTL)
# ---------------------------------------------------------------------------


class TestCacheHints:
    def _modern_tools_list(self, srv: Any) -> dict[str, Any]:
        async def go() -> dict[str, Any]:
            async with _client(srv) as client:
                resp = await _modern_request(client, "tools/list")
                assert resp.status_code == 200, resp.text
                return _body(resp)["result"]

        return _run(go())

    def test_default_hint_is_300_seconds_public(self, monkeypatch: pytest.MonkeyPatch) -> None:
        srv = _reload(monkeypatch)
        result = self._modern_tools_list(srv)
        assert result["ttlMs"] == 300_000
        assert result["cacheScope"] == "public"
        assert len(result["tools"]) == _advertised_count(srv)
        titles = {t["name"]: t.get("title") for t in result["tools"]}
        assert set(titles) == META_TOOLS
        assert titles["search_tools"] == "Search Tools"

    def test_custom_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = self._modern_tools_list(_reload(monkeypatch, {"UNIFI_MCP_CACHE_TTL": "60"}))
        assert result["ttlMs"] == 60_000

    def test_zero_sends_ttl_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        srv = _reload(monkeypatch, {"UNIFI_MCP_CACHE_TTL": "0"})
        assert srv._cache_ttl is None  # noqa: SLF001 - no server-level hint configured
        result = self._modern_tools_list(srv)
        # UNIFI_MCP_CACHE_TTL=0 -> the protocol default is sent: ttlMs 0 (do not
        # reuse) and private scope.
        assert result["ttlMs"] == 0
        assert result["cacheScope"] == "private"
        assert len(result["tools"]) == _advertised_count(srv)

    def test_legacy_tools_list_is_unaffected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        srv = _reload(monkeypatch)

        async def go() -> dict[str, Any]:
            async with _client(srv) as client:
                init = await _legacy_initialize(client)
                assert init.status_code == 200
                session = init.headers.get("mcp-session-id")
                resp = await _legacy_request(client, "tools/list", {}, session)
                assert resp.status_code == 200, resp.text
                return _body(resp)["result"]

        result = _run(go())
        assert len(result["tools"]) == _advertised_count(srv)
        assert "ttlMs" not in result
        assert "cacheScope" not in result

    @pytest.mark.parametrize("value", ["-1", "abc", "1.5"])
    def test_invalid_ttl_is_rejected(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("UNIFI_MCP_CACHE_TTL", value)
        with pytest.raises(ValueError, match="UNIFI_MCP_CACHE_TTL"):
            MCPTransportSettings()

    @pytest.mark.parametrize(
        ("value", "expected"), [(None, 300), ("", 300), ("0", 0), ("900", 900)]
    )
    def test_ttl_parsing(
        self, monkeypatch: pytest.MonkeyPatch, value: str | None, expected: int
    ) -> None:
        if value is not None:
            monkeypatch.setenv("UNIFI_MCP_CACHE_TTL", value)
        assert MCPTransportSettings().cache_ttl == expected


# ---------------------------------------------------------------------------
# Stateless HTTP (image default)
# ---------------------------------------------------------------------------


class TestStatelessHttp:
    def test_dockerfile_defaults_to_stateless_http(self) -> None:
        dockerfile = (_ROOT / "Dockerfile").read_text()
        assert re.search(r"^ENV FASTMCP_STATELESS_HTTP=true$", dockerfile, re.MULTILINE)

    def test_legacy_client_without_session(self, monkeypatch: pytest.MonkeyPatch) -> None:
        srv = _reload(monkeypatch)

        async def go() -> None:
            async with _client(srv, stateless_http=True) as client:
                init = await _legacy_initialize(client)
                assert init.status_code == 200
                assert "mcp-session-id" not in init.headers
                listed = await _legacy_request(client, "tools/list", {}, None)
                assert listed.status_code == 200, listed.text
                assert len(_body(listed)["result"]["tools"]) == _advertised_count(srv)
                call = await _legacy_request(
                    client, "tools/call", {"name": "get_host", "arguments": {}}, None
                )
                assert call.status_code == 200, call.text
                result = _body(call)["result"]
                assert result["isError"] is True
                assert "Invalid arguments for tool 'get_host'" in result["content"][0]["text"]

        _run(go())

    def test_modern_client_stateless(self, monkeypatch: pytest.MonkeyPatch) -> None:
        srv = _reload(monkeypatch)

        async def go() -> None:
            async with _client(srv, stateless_http=True) as client:
                resp = await _modern_request(client, "tools/list")
                assert resp.status_code == 200, resp.text
                assert len(_body(resp)["result"]["tools"]) == _advertised_count(srv)

        _run(go())

    def test_sse_turns_the_stateless_default_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import fastmcp

        monkeypatch.setattr(fastmcp.settings, "transport", "sse")
        monkeypatch.setattr(fastmcp.settings, "stateless_http", True)
        server._reconcile_stateless_http()
        assert fastmcp.settings.stateless_http is False

    def test_streamable_http_keeps_stateless(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import fastmcp

        monkeypatch.setattr(fastmcp.settings, "transport", "streamable-http")
        monkeypatch.setattr(fastmcp.settings, "stateless_http", True)
        server._reconcile_stateless_http()
        assert fastmcp.settings.stateless_http is True
