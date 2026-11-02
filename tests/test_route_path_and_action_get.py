"""Credential path metadata and state-changing GET relay regression coverage."""

from __future__ import annotations

import json
import logging
from unittest.mock import AsyncMock

import httpx
import pytest
import respx
from fastmcp import Client, FastMCP
from fastmcp.server.auth import AccessToken

from unifi_fabric import route_secrets as rs
from unifi_fabric import server
from unifi_fabric.client import RateLimitError, UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.discovery import apply_tool_mode
from unifi_fabric.read_only_tools import AreaOptOutMiddleware, ReadOnlyToolMiddleware
from unifi_fabric.secret_scrub import configured_secrets, scrub, secret_scope
from unifi_fabric.tools import connector, innerspace_internal
from unifi_fabric.transport_security import WriteScopeMiddleware

TOKEN = "00000000-0000-4000-8000-000000000001"
SITE = "00000000-0000-4000-8000-000000000002"
HOST = "console-path-regression"
BASE = "https://api.ui.com"
PREFIX = f"/v1/connector/consoles/{HOST}/proxy/"
SHARED = f"innerspace/api/import/projects/{TOKEN}"
ACTIONS = ["enable-control", "disable-control"]


@pytest.fixture
def registry():
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = HOST
    return registry


@pytest.mark.parametrize("prefix", ["", "/", PREFIX])
def test_registered_path_credential_binding_and_exact_span_masking(prefix):
    path = prefix + SHARED + f"/?siteId={SITE}"
    assert rs.request_path_secrets("POST", path) == (TOKEN,)
    assert rs.request_path_secrets("GET", path) == ()
    assert rs.mask_request_path("POST", path, redact_secrets=False) == path
    assert rs.mask_request_path("POST", path, redact_secrets=True) == path.replace(TOKEN, rs.MASK)
    assert TOKEN in rs.tool_call_secrets("fabric_connector_post", {"path": path})
    with secret_scope(()):
        rs.bind_request("POST", path, None)
        assert TOKEN not in scrub(f"failed {path}", configured_secrets())
    ordinary = PREFIX + f"innerspace/api/projects/{TOKEN}"
    assert rs.mask_request_path("POST", ordinary, redact_secrets=True) == ordinary


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("surface", ["typed", "relay"])
async def test_shared_project_dry_run_masks_all_emitted_path_metadata(registry, redact, surface):
    client = UniFiClient(
        Settings(api_key="synthetic-path-key", dry_run=True, redact_secrets=redact)
    )
    with respx.mock(assert_all_called=False) as router:
        if surface == "typed":
            result = await innerspace_internal.import_innerspace_shared_project(
                client, registry, HOST, TOKEN, SITE
            )
            preview = result["preview"]
        else:
            result = await connector.connector_write(
                client, registry, HOST, "POST", SHARED, params={"siteId": SITE}
            )
            preview = result["body"]["preview"]
            assert result["path"] == (SHARED.replace(TOKEN, rs.MASK) if redact else SHARED)
        assert (TOKEN not in json.dumps(result)) is redact
        assert SITE in json.dumps(result)
        assert preview["path"] == PREFIX + SHARED.replace(TOKEN, rs.MASK if redact else TOKEN)
        assert not router.calls


@pytest.mark.parametrize("redact", [False, True])
async def test_shared_project_relay_errors_and_audit_scrub_token(
    registry, redact, tmp_path, caplog
):
    audit = tmp_path / "writes.log"
    client = UniFiClient(
        Settings(api_key="synthetic-path-key", redact_secrets=redact, audit_log=str(audit))
    )
    with respx.mock as router, caplog.at_level(logging.INFO):
        route = router.post(BASE + PREFIX + SHARED).respond(
            400, json={"message": f"shared project {TOKEN} expired"}
        )
        result = await connector.connector_write(client, registry, HOST, "POST", SHARED)
        assert result["status"] == 400
        assert "expired" in result["body"]["message"]
        assert (TOKEN not in json.dumps(result)) is redact
        assert TOKEN not in caplog.text
        assert TOKEN not in audit.read_text()
        assert route.call_count == 1
    await client.close()


@pytest.mark.parametrize("redact", [False, True])
async def test_shared_project_client_exception_scrubs_path_token(redact):
    client = UniFiClient(Settings(api_key="synthetic-path-key", redact_secrets=redact))
    with respx.mock as router:
        router.post(BASE + PREFIX + SHARED).respond(400, text=f"expired token {TOKEN}")
        with pytest.raises(UniFiConnectionError) as failure:
            await client.request("POST", PREFIX + SHARED)
        assert (TOKEN not in str(failure.value)) is redact
        assert "expired token" in str(failure.value)
    await client.close()


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize(
    "gate", ["UNIFI_READ_ONLY", "UNIFI_ENABLE_CONNECTOR_WRITE", "UNIFI_PROTECT_MUTATIONS_ENABLED"]
)
async def test_action_get_refused_before_host_resolution(monkeypatch, registry, action, gate):
    monkeypatch.setenv(gate, "1" if gate == "UNIFI_READ_ONLY" else "0")
    client = UniFiClient(Settings(api_key="synthetic-action-key", dry_run=True))
    with pytest.raises((ValueError, RuntimeError), match=gate):
        await connector.connector_get(client, registry, HOST, f"protect/api/cameras/fake/{action}")
    registry.resolve_key_for_host.assert_not_awaited()
    registry.resolve_host_id.assert_not_awaited()


@pytest.mark.parametrize("action", ACTIONS)
async def test_action_get_dry_run_is_audited_without_upstream(registry, action, tmp_path):
    audit = tmp_path / "writes.log"
    client = UniFiClient(
        Settings(api_key="synthetic-action-key", dry_run=True, audit_log=str(audit))
    )
    with respx.mock(assert_all_called=False) as router:
        result = await connector.connector_get(
            client, registry, HOST, f"protect/api/cameras/fake/{action}"
        )
        assert result["body"]["status"] == "dry_run"
        assert result["body"]["preview"]["method"] == "GET"
        assert "dry_run" in audit.read_text()
        assert not router.calls


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("surface", ["client", "relay", "discovery"])
async def test_action_get_429_is_sent_once(registry, action, surface, monkeypatch):
    client = UniFiClient(Settings(api_key="synthetic-action-key"))
    path = f"protect/api/cameras/fake/{action}"
    sleep = AsyncMock()
    monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", sleep)
    with respx.mock as router:
        route = router.get(BASE + PREFIX + path).respond(429, text="synthetic action rate limit")
        if surface == "discovery":
            app = await _relay_app(monkeypatch, registry, client, ["unifi.read", "unifi.write"])
            await apply_tool_mode(app, "discovery")
            async with Client(app) as mcp:
                result = await mcp.call_tool(
                    "call_write_tool",
                    {"name": "fabric_connector_get", "arguments": {"host": HOST, "path": path}},
                    raise_on_error=False,
                )
                assert result.is_error and "synthetic action rate limit" in result.content[0].text
        else:
            with pytest.raises(RateLimitError, match="synthetic action rate limit"):
                if surface == "relay":
                    await connector.connector_get(client, registry, HOST, path)
                else:
                    await client.request("GET", PREFIX + path)
        assert route.call_count == 1
        sleep.assert_not_awaited()
    await client.close()


async def test_ordinary_get_keeps_retries_and_ignores_write_opt_outs(registry, monkeypatch):
    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    monkeypatch.setenv("UNIFI_ENABLE_CONNECTOR_WRITE", "0")
    monkeypatch.setenv("UNIFI_PROTECT_MUTATIONS_ENABLED", "0")
    client = UniFiClient(Settings(api_key="synthetic-action-key", dry_run=True))
    path = "protect/api/cameras/fake"
    monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", AsyncMock())
    with respx.mock as router:
        route = router.get(BASE + PREFIX + path).mock(
            side_effect=[httpx.Response(429), httpx.Response(200, json={"id": "fake"})]
        )
        result = await connector.connector_get(client, registry, HOST, path)
        assert result["status"] == 200 and result["body"] == {"id": "fake"}
        assert route.call_count == 2
    await client.close()


async def _relay_app(monkeypatch, registry, client, scopes):
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    monkeypatch.setattr(server, "_settings", client._settings)
    token = AccessToken(token="synthetic", client_id="synthetic", scopes=scopes)
    monkeypatch.setattr("fastmcp.server.dependencies.get_access_token", lambda: token)
    app = FastMCP("action-get-regression")
    app.add_tool(await server.mcp.get_tool("fabric_connector_get"))
    app.add_middleware(ReadOnlyToolMiddleware(app))
    app.add_middleware(WriteScopeMiddleware(app, lambda: "unifi.write"))
    app.add_middleware(AreaOptOutMiddleware(app, lambda: client._settings.enable_connector_write))
    return app


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("surface", ["direct", "discovery"])
@pytest.mark.parametrize(
    "gate",
    ["oauth", "UNIFI_READ_ONLY", "UNIFI_ENABLE_CONNECTOR_WRITE", "UNIFI_PROTECT_MUTATIONS_ENABLED"],
)
async def test_registered_action_get_authorization_and_discovery(
    monkeypatch, registry, action, surface, gate
):
    if gate != "oauth":
        monkeypatch.setenv(gate, "1" if gate == "UNIFI_READ_ONLY" else "0")
    client = UniFiClient(Settings(api_key="synthetic-action-key", dry_run=True))
    scopes = ["unifi.read"] if gate == "oauth" else ["unifi.read", "unifi.write"]
    app = await _relay_app(monkeypatch, registry, client, scopes)
    if surface == "discovery":
        await apply_tool_mode(app, "discovery")
    name = "fabric_connector_get"
    arguments = {"host": HOST, "path": f"protect/api/cameras/fake/{action}"}
    if surface == "discovery":
        arguments = {"name": name, "arguments": arguments}
        name = "call_write_tool"
    async with Client(app) as mcp:
        result = await mcp.call_tool(name, arguments, raise_on_error=False)
    text = " ".join(block.text for block in result.content if hasattr(block, "text"))
    assert result.is_error
    assert ("MCP_OAUTH_WRITE_SCOPE" if gate == "oauth" else gate) in text
    registry.resolve_key_for_host.assert_not_awaited()


@pytest.mark.parametrize("action", ACTIONS)
async def test_discovery_action_get_requires_write_dispatch_and_scope(
    monkeypatch, registry, action
):
    client = UniFiClient(Settings(api_key="synthetic-action-key", dry_run=True))
    app = await _relay_app(monkeypatch, registry, client, ["unifi.read", "unifi.write"])
    await apply_tool_mode(app, "discovery")
    arguments = {
        "name": "fabric_connector_get",
        "arguments": {"host": HOST, "path": f"protect/api/cameras/fake/{action}"},
    }
    async with Client(app) as mcp:
        refused = await mcp.call_tool("call_read_tool", arguments, raise_on_error=False)
        assert refused.is_error and "call_write_tool" in refused.content[0].text
        registry.resolve_key_for_host.assert_not_awaited()
        result = await mcp.call_tool("call_write_tool", arguments)
        assert result.data["body"]["status"] == "dry_run"


@pytest.mark.parametrize("surface", ["direct", "discovery"])
async def test_registered_ordinary_get_needs_no_write_scope(monkeypatch, registry, surface):
    client = UniFiClient(Settings(api_key="synthetic-action-key"))
    app = await _relay_app(monkeypatch, registry, client, ["unifi.read"])
    if surface == "discovery":
        await apply_tool_mode(app, "discovery")
    arguments = {"host": HOST, "path": "protect/api/cameras/fake"}
    name = "fabric_connector_get"
    if surface == "discovery":
        arguments = {"name": name, "arguments": arguments}
        name = "call_read_tool"
    with respx.mock as router:
        route = router.get(BASE + PREFIX + "protect/api/cameras/fake").respond(
            200, json={"id": "fake"}
        )
        async with Client(app) as mcp:
            result = await mcp.call_tool(name, arguments)
            assert result.data["status"] == 200
        assert route.call_count == 1
    await client.close()


@pytest.mark.parametrize("action", ACTIONS)
async def test_action_get_uses_nonfirst_host_key(multikey_client, multikey_registry, action):
    from tests.conftest import MULTIKEY_HOSTS_BY_LABEL

    path = f"protect/api/cameras/fake/{action}"
    with respx.mock as router:
        for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
            router.get(BASE + "/v1/hosts", headers={"X-API-KEY": f"k-{label}"}).respond(
                200, json={"data": hosts}
            )
        route = router.get(
            BASE + "/v1/connector/consoles/console-beta-1/proxy/" + path,
            headers={"X-API-KEY": "k-beta"},
        ).respond(200, json={"enabled": action == "enable-control"})
        result = await connector.connector_get(
            multikey_client, multikey_registry, "Beta-Branch", path
        )
        assert result["body"] == {"enabled": action == "enable-control"}
        assert route.call_count == 1
    await multikey_client.close()
