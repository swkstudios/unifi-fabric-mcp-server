"""Matter cloud routes, native bodies, secret inputs and pre-request guards."""

from __future__ import annotations

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from pydantic import SecretStr

from unifi_fabric import server
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.secret_scrub import configured_secrets, secret_scope
from unifi_fabric.tools import matter

HOST = "console"
SITE = "default"
NODE = "999999999999999999"
BASE = f"/v1/connector/consoles/{HOST}/proxy/network/v2/api/site/{SITE}"


def registry(key=None):
    return AsyncMock(
        **{
            "resolve_key_for_host.return_value": key or APIKeyConfig(key="test-key", label="beta"),
            "resolve_host_id.return_value": HOST,
            "resolve_site_slug.return_value": SITE,
        }
    )


def client(handler, **settings):
    c = UniFiClient(Settings(api_key="test-key", **settings))
    c._clients[
        (
            "beta",
            __import__("unifi_fabric.client", fromlist=["_key_fingerprint"])._key_fingerprint(
                "test-key"
            ),
        )
    ] = httpx.AsyncClient(base_url="https://api.ui.com", transport=httpx.MockTransport(handler))
    return c


@pytest.mark.parametrize(
    "tool,path",
    [
        (matter.list_thread_networks, "/thread-networks"),
        (matter.list_matter_nodes, "/matter/nodes"),
    ],
)
@pytest.mark.parametrize(
    "body", [[], [{"network_name": "mesh", "border_routers": [], "unknown": {"value": True}}]]
)
async def test_native_bare_arrays_verbatim(tool, path, body):
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json=body)

    c = client(handler)
    try:
        assert await tool(c, registry(), HOST, SITE) == body
        assert len(seen) == 1 and seen[0].url.path == BASE + path
        assert not seen[0].url.query
    finally:
        await c.close()


@pytest.mark.parametrize("tool", [matter.list_thread_networks, matter.list_matter_nodes])
async def test_offset_envelope_drained_and_fields_kept(tool):
    seen = []

    def handler(req):
        offset = int(req.url.params.get("offset", 0))
        seen.append(offset)
        return httpx.Response(
            200,
            json={
                "data": [{"id": str(offset)}],
                "offset": offset,
                "limit": 1,
                "count": 1,
                "totalCount": 3,
                "traceId": "trace-native",
            },
        )

    c = client(handler)
    try:
        result = await tool(c, registry(), HOST, SITE)
        assert result["data"] == [{"id": "0"}, {"id": "1"}, {"id": "2"}]
        assert result["traceId"] == "trace-native" and result["totalCount"] == 3
        assert seen == [0, 0, 1, 2]
    finally:
        await c.close()


@pytest.mark.parametrize(
    "method,tool,args,expected",
    [
        (
            "POST",
            matter.commission_matter_node,
            (SecretStr("34970112332"),),
            {"setup_code": "34970112332"},
        ),
        ("PUT", matter.rename_matter_node, (NODE, "Desk lamp"), {"name": "Desk lamp"}),
        ("DELETE", matter.remove_matter_node, (NODE,), None),
    ],
)
@pytest.mark.parametrize("body", [None, True, 7, [], {"data": {"native": True}, "traceId": "keep"}])
async def test_write_verbatim_and_one_request(method, tool, args, expected, body):
    seen = []

    def handler(req):
        seen.append(req)
        if req.method == "GET":
            return httpx.Response(200, json=[{"id": NODE, "name": "Desk lamp"}])
        return httpx.Response(204) if body is None else httpx.Response(200, json=body)

    c = client(handler)
    try:
        result = await tool(c, registry(), HOST, SITE, *args)
        if method == "DELETE":
            assert result["deleted"] is True
            assert result["response"] == body
            assert set(result) == {"deleted", "message", "response"}
        else:
            assert result == body
        if method == "POST":
            assert len(seen) == 1
        else:
            assert [request.method for request in seen] == ["GET", method]
            assert seen[0].url.path == BASE + "/matter/nodes"
        request = seen[-1]
        assert (json.loads(request.content) if request.content else None) == expected
        assert request.url.path == BASE + "/matter/nodes" + ("" if method == "POST" else "/" + NODE)
    finally:
        await c.close()


@pytest.mark.parametrize(
    "tool,args",
    [
        (matter.commission_matter_node, (SecretStr("34970112332"),)),
        (matter.rename_matter_node, (NODE, "lamp")),
        (matter.remove_matter_node, (NODE,)),
    ],
)
@pytest.mark.parametrize("redact", [False, True])
async def test_dry_run_preview_no_write(tool, args, redact):
    def handler(req):
        if tool is matter.commission_matter_node:
            pytest.fail("dry-run must send no write")
        assert req.method == "GET"
        return httpx.Response(200, json=[{"id": NODE, "name": "Desk lamp"}])

    c = client(handler, dry_run=True, redact_secrets=redact)
    try:
        result = await tool(c, registry(), HOST, SITE, *args)
        if tool is matter.remove_matter_node:
            # A remove returns the deletion_result dry-run shape with the preview under response.
            assert result["status"] == "dry_run" and result["deleted"] is False
            assert result["message"]
            result = result["response"]
        assert result["dryRun"] is True
        if tool is matter.commission_matter_node:
            assert result["preview"]["body"] == {
                "setup_code": REDACTION_MASK if redact else "34970112332"
            }
            assert ("34970112332" in json.dumps(result)) == (not redact)
    finally:
        await c.close()


@pytest.mark.parametrize("env", ["UNIFI_READ_ONLY", "UNIFI_ENABLE_NETWORK_WRITE"])
@pytest.mark.parametrize(
    "tool,args",
    [
        (matter.commission_matter_node, (SecretStr("34970112332"),)),
        (matter.rename_matter_node, (NODE, "lamp")),
        (matter.remove_matter_node, (NODE,)),
    ],
)
async def test_write_optout_before_resolution(monkeypatch, env, tool, args):
    monkeypatch.setenv(env, "1" if env == "UNIFI_READ_ONLY" else "0")
    r = registry()
    with pytest.raises(Exception, match=env):
        await tool(AsyncMock(), r, HOST, SITE, *args)
    r.resolve_key_for_host.assert_not_awaited()


@pytest.mark.parametrize(
    "tool,args",
    [
        (matter.commission_matter_node, (7,)),
        (matter.rename_matter_node, ("../bad", "lamp")),
        (matter.rename_matter_node, (NODE, 7)),
        (matter.remove_matter_node, ("../bad",)),
    ],
)
async def test_invalid_inputs_before_resolution(tool, args):
    r = registry()
    with pytest.raises(ValueError):
        await tool(AsyncMock(), r, HOST, SITE, *args)
    r.resolve_key_for_host.assert_not_awaited()


async def test_call_secret_scopes_are_nested_and_isolated():
    async def run(value):
        with secret_scope((value,)):
            await asyncio.sleep(0)
            assert value in configured_secrets()
            assert ({"call-a", "call-b"} - {value}).isdisjoint(configured_secrets())
            with secret_scope(("nested",)):
                assert {value, "nested"} <= set(configured_secrets())
            assert "nested" not in configured_secrets()

    await asyncio.gather(run("call-a"), run("call-b"))
    assert {"call-a", "call-b", "nested"}.isdisjoint(configured_secrets())


async def test_framework_validation_never_echoes_setup_code(monkeypatch, caplog):
    code = "sentinel-setup-code/+=escaped"
    # The real audit_refusal hook is synchronous; preserve that interface so the
    # refusal middleware does not leave an AsyncMock coroutine unawaited.
    mock_client = AsyncMock()
    mock_client.audit_refusal = MagicMock()
    monkeypatch.setattr(server, "_client", mock_client)
    monkeypatch.setattr(server, "_registry", registry())
    with caplog.at_level(logging.DEBUG), pytest.raises(Exception) as caught:
        await server.mcp.call_tool(
            "commission_matter_node",
            {"host": HOST, "site": SITE, "setup_code": code, "extra": code},
        )
    assert code not in str(caught.value) + caplog.text


async def test_commission_audit_never_records_setup_code(tmp_path):
    code = "synthetic-matter-audit-code/+=escaped"
    audit = tmp_path / "audit.jsonl"
    c = client(
        lambda req: httpx.Response(200, json={"accepted": True}),
        audit_log=str(audit),
        audit_log_format="json",
    )
    try:
        assert await matter.commission_matter_node(c, registry(), HOST, SITE, SecretStr(code)) == {
            "accepted": True
        }
        records = [json.loads(line) for line in audit.read_text().splitlines()]
        assert len(records) == 1 and records[0]["method"] == "POST"
        assert code not in audit.read_text() and "setup_code" not in audit.read_text()
    finally:
        await c.close()


def test_network_write_opt_out_defaults_on(monkeypatch):
    from unifi_fabric import switches

    monkeypatch.delenv("UNIFI_ENABLE_NETWORK_WRITE", raising=False)
    assert switches.NETWORK_WRITES.enabled()
    assert Settings(api_key="synthetic-key").enable_network_write is True


@pytest.mark.parametrize("area", ["protect", "mobility", "carrier"])
def test_network_opt_out_does_not_cover_other_area_switches(monkeypatch, area):
    from unifi_fabric import switches
    from unifi_fabric.tools.connector import area_write_refusal

    for switch in switches.AREA_WRITE_SWITCHES:
        monkeypatch.delenv(switch.env, raising=False)
    monkeypatch.setenv("UNIFI_ENABLE_NETWORK_WRITE", "0")
    assert area_write_refusal("network") is not None
    assert area_write_refusal(area) is None
    assert not switches.NETWORK_WRITES.governs(area)
