"""VPN client tools: list, create, update and delete through the real server.

Hermetic: the in-process upstream serves synthetic Classic ``rest/networkconf`` records
(including a ``vpn-client`` one) and records every write; nothing contacts a controller. The
tools share the networkconf purpose guards with vpn.py; this file proves the four tools of
``families/vpn/vpn_clients.py`` themselves.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.families.vpn import vpn_clients
from unifi_fabric.shared_shapes._keys import context_value

_call = cti._call
TOOLS_OF_MODULE = {
    "list_vpn_clients",
    "create_vpn_client",
    "update_vpn_client",
    "delete_vpn_client",
}
WRITES = TOOLS_OF_MODULE - {"list_vpn_clients"}
BASE = {"host": uh.HOST, "site": uh.SITE}
CLIENT_ID = "00000000-0000-4000-9000-0000000000c1"
NETWORKCONF = "/rest/networkconf"


def _writes(up: uh.FakeUpstream) -> list[Any]:
    return [s for s in up.served if s.method != "GET" and not s.resolution]


def _text(result: Any) -> str:
    return json.dumps(result.structured_content or result.content, default=str)


async def test_registered_access_matches_the_tool_kind() -> None:
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    assert TOOLS_OF_MODULE <= set(tools)
    for name in sorted(TOOLS_OF_MODULE):
        read_only = tools[name].annotations.read_only_hint
        assert read_only is (name not in WRITES), name
        assert {"host", "site"} <= set(tools[name].parameters["required"]), name
    assert "Consequence" in (tools["delete_vpn_client"].description or "")


async def test_list_adds_a_vpn_client_view_without_filtering_upstream_data(monkeypatch) -> None:
    up = uh.FakeUpstream()
    result = await _call(monkeypatch, "list_vpn_clients", up, dict(BASE))
    assert _writes(up) == []
    body = result.structured_content or {}
    records = body.get("_vpn_clients")
    assert records, _text(result)
    assert {record.get("purpose") for record in records} == {"vpn-client"}
    assert any(record.get("purpose") != "vpn-client" for record in body["data"])


@pytest.mark.parametrize(
    ("typed", "sent"),
    [
        ("wireguard", "wireguard-client"),
        ("OpenVPN", "openvpn-client"),
        ("pptp", "pptp-client"),
        ("l2tp-client", "l2tp-client"),
    ],
)
async def test_create_posts_a_vpn_client_networkconf_with_the_controller_type(
    monkeypatch, typed, sent
) -> None:
    up = uh.FakeUpstream()
    await _call(
        monkeypatch,
        "create_vpn_client",
        up,
        {**BASE, "name": "probe-client", "vpn_type": typed, "enabled": False},
    )
    writes = _writes(up)
    assert [w.method for w in writes] == ["POST"], up.served
    assert writes[0].path.endswith(NETWORKCONF)
    body = writes[0].sent_json
    assert body["purpose"] == "vpn-client"
    assert body["name"] == "probe-client"
    assert body["vpn_type"] == sent
    assert body["enabled"] is False


async def test_a_body_naming_another_purpose_is_sent_as_given_and_hints_on_error(
    monkeypatch,
) -> None:
    # Strict pass-through: the caller's purpose is not rewritten or refused client-side; an
    # upstream rejection then carries the purpose this tool expects.
    args = {
        **BASE,
        "name": "probe-client",
        "vpn_type": "wireguard",
        "fields": {"purpose": "corporate"},
    }
    up = uh.FakeUpstream()
    await _call(monkeypatch, "create_vpn_client", up, args)
    writes = _writes(up)
    assert len(writes) == 1 and writes[0].sent_json["purpose"] == "corporate", writes
    rejected = uh.FakeUpstream(
        write_status=400,
        error_body=json.dumps({"meta": {"rc": "error", "msg": "api.err.InvalidPayload"}}),
    )
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, "create_vpn_client", rejected, args)
    assert "api.err.InvalidPayload" in str(exc.value)
    assert "purpose 'vpn-client'" in str(exc.value)


async def test_update_resolves_the_id_then_puts_the_addressed_record(monkeypatch) -> None:
    up = uh.FakeUpstream()
    await _call(
        monkeypatch,
        "update_vpn_client",
        up,
        {**BASE, "vpn_client_id": CLIENT_ID, "fields": {"name": "probe-renamed"}},
    )
    writes = _writes(up)
    assert [w.method for w in writes] == ["PUT"], up.served
    assert NETWORKCONF + "/" in writes[0].path
    assert writes[0].sent_json["name"] == "probe-renamed"
    assert writes[0].sent_json["purpose"] == "vpn-client"
    assert any(s.method == "GET" and s.path.endswith(NETWORKCONF) for s in up.served)


async def test_delete_resolves_the_id_then_deletes_the_networkconf(monkeypatch) -> None:
    up = uh.FakeUpstream()
    result = await _call(monkeypatch, "delete_vpn_client", up, {**BASE, "vpn_client_id": CLIENT_ID})
    writes = _writes(up)
    assert [w.method for w in writes] == ["DELETE"], up.served
    assert NETWORKCONF + "/" in writes[0].path
    assert "deleted" in _text(result)


@pytest.mark.parametrize("name", ["update_vpn_client", "delete_vpn_client"])
async def test_an_unknown_vpn_client_sends_no_write(monkeypatch, name) -> None:
    up = uh.FakeUpstream()
    args = {**BASE, "vpn_client_id": "00000000-0000-4000-9000-0000000000ff"}
    if name == "update_vpn_client":
        args["fields"] = {"name": "probe-renamed"}
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert _writes(up) == []
    assert "list_vpn_clients" in str(exc.value)


@pytest.mark.parametrize(
    ("name", "extra"),
    [
        ("create_vpn_client", {"name": "probe-client", "vpn_type": "wireguard"}),
        ("update_vpn_client", {"vpn_client_id": CLIENT_ID, "fields": {"name": "probe-renamed"}}),
        ("delete_vpn_client", {"vpn_client_id": CLIENT_ID}),
    ],
)
async def test_dry_run_previews_without_writing(monkeypatch, name, extra) -> None:
    up = uh.FakeUpstream()
    result = await _call(
        monkeypatch, name, up, {**BASE, **extra}, env={"UNIFI_WRITE_POLICY": "dry-run"}
    )
    assert _writes(up) == []
    assert "dry_run" in _text(result)


@pytest.mark.parametrize("collision", [False, True])
async def test_list_preserves_the_entire_upstream_envelope(collision) -> None:
    records = [
        {"_id": "0000000000000000000000a1", "purpose": "corporate", "future": [None]},
        {"_id": "0000000000000000000000b1", "purpose": "vpn-client", "future": {"x": 1}},
    ]
    body = {"meta": {"rc": "ok", "future": True}, "data": records, "traceId": "synthetic"}
    if collision:
        body["_vpn_clients"] = {"upstream": "preserved"}
    client = AsyncMock()
    client.get.return_value = body
    registry = AsyncMock()
    registry.resolve_host_id.return_value = "console-synthetic"
    registry.resolve_site_slug.return_value = "default"
    result = await vpn_clients._list_vpn_clients(client, registry, "host", "Default")
    assert all(result[key] == value for key, value in body.items())
    assert result["data"] is records
    assert context_value(result, "_vpn_clients", strict=True) == [records[1]]
    assert client.get.await_count == 1
