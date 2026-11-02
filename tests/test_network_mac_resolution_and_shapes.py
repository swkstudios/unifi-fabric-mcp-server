"""Network MAC resolution and result shapes.

A real 404 behind a cached MAC is the upstream error (no repeat), client tools resolve a
MAC given as client_id, VPN/Teleport clients have no MAC, a null MAC in a device list is
skipped, the MAC cache honours UNIFI_CACHE_TTL_SECONDS, empty-body successes are an
explicit null, get_device_port_state invents no keys, list tools pass offset/limit
through, and registry record lists with non-object items are a shape error."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.client import UniFiConnectionError, object_records
from unifi_fabric.config import Settings
from unifi_fabric.list_results import (
    _make_structured_fn,
    output_schema_admits_null_payload,
    to_structured_null_result,
)
from unifi_fabric.tools.device_mgmt import _mac_cache_for, _mac_uuid_cache

OTHER_ID = "00000000-0000-4000-8000-0000000000bb"
CACHED_DEVICE_ID = "00000000-0000-4000-8000-0000000000cc"
CACHED_DEVICE_MAC = "02:00:5e:00:00:cc"
DUPLICATE_MAC = "02:00:5e:00:00:dd"


async def _call(monkeypatch, up: uh.FakeUpstream, name: str, **args: Any):
    uh.install(monkeypatch, up)
    base = {"host": uh.HOST, "site": uh.SITE}
    if name == "list_pending_devices" or name == "list_countries":
        base = {"host": uh.HOST}
    return await server.mcp.call_tool(name, {**base, **args})


class _Upstream(uh.FakeUpstream):
    """FakeUpstream with per-test overrides: ``detail_404`` answers 404 for the device
    detail path; ``clients`` / ``devices`` replace the client / device list records;
    ``client_body`` replaces the client detail body."""

    detail_404: bool = False
    write_404: bool = False
    detail_id: str = uh.ARG_ID
    clients: list[Any] | None = None
    devices: list[Any] | None = None
    client_body: Any = None

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if self.write_404 and req.method == "POST" and f"/devices/{self.detail_id}/" in path:
            body = {"code": "api.err.NotFound", "message": "probe: no such device"}
            self._record(req, 404, body, False)
            return httpx.Response(404, json=body)
        if req.method == "GET" and not uh.is_resolution(path):
            if self.detail_404 and path.endswith(f"/devices/{self.detail_id}"):
                body = {"code": "api.err.NotFound", "message": "probe: no such device"}
                self._record(req, 404, body, False)
                return httpx.Response(404, json=body)
            listing = (
                self.clients
                if path.endswith("/clients")
                else self.devices
                if path.endswith("/devices")
                else None
            )
            if listing is not None:
                body = {
                    "offset": 0,
                    "limit": 200,
                    "count": len(listing),
                    "totalCount": len(listing),
                    "data": listing,
                }
                self._record(req, 200, body, False)
                return httpx.Response(200, json=body)
            if self.client_body is not None and "/clients/" in path:
                self._record(req, 200, self.client_body, False)
                return httpx.Response(200, json=self.client_body)
        return super().__call__(req)


def _usage_workflows() -> str:
    return (
        (Path(__file__).resolve().parents[1] / "docs/TOOL-USAGE.md")
        .read_text()
        .split("## create_network")[0]
    )


def _gets(up: uh.FakeUpstream, suffix: str) -> list[Any]:
    return [s for s in up.served if s.method == "GET" and s.path.endswith(suffix)]


# ================================================ a real 404 is the upstream error
@pytest.mark.parametrize("tool", ["get_device", "restart_device"])
async def test_real_404_behind_a_cached_mac_is_raised_unchanged_and_not_repeated(monkeypatch, tool):
    _mac_uuid_cache.clear()
    up = _Upstream()
    up.detail_id = CACHED_DEVICE_ID
    up.devices = [{"id": CACHED_DEVICE_ID, "name": "ap", "macAddress": CACHED_DEVICE_MAC}]
    args = {"device_id": CACHED_DEVICE_MAC}
    await _call(monkeypatch, up, tool, **args)  # caches MAC -> ARG_ID from the device list
    up.served.clear()
    if tool == "restart_device":
        up.write_404 = True
    else:
        up.detail_404 = True
    with pytest.raises(ToolError) as err:  # same client: the id now comes from the cache
        await server.mcp.call_tool(tool, {"host": uh.HOST, "site": uh.SITE, **args})
    msg = str(err.value)
    assert "HTTP 404 from" in msg and "probe: no such device" in msg
    assert "stale" not in msg and "cache" not in msg
    assert _gets(up, "/devices"), "the cached id was not re-checked against the device list"
    target = [s for s in up.served if f"/devices/{CACHED_DEVICE_ID}" in s.path]
    assert len(target) == 1, f"the request was repeated: {[s.path for s in target]}"


# ================================================ a MAC given as client_id
@pytest.mark.parametrize("mac", [uh.ARG_MAC.upper(), uh.ARG_MAC.replace(":", "-"), "02005E0000AA"])
async def test_get_client_resolves_a_mac_in_any_form(monkeypatch, mac):
    up = uh.FakeUpstream(replay_recordings=False)
    res = await _call(monkeypatch, up, "get_client", client_id=mac)
    lists = _gets(up, "/clients")
    assert lists and "macAddress.eq%28%2702%3A00%3A5e%3A00%3A00%3Aaa%27%29" in lists[0].query
    assert _gets(up, f"/clients/{uh.ARG_ID}")
    assert uh.result_payload(res)["id"] == uh.ARG_ID


async def test_block_client_by_mac_sends_the_normalized_mac_without_a_client_get(monkeypatch):
    up = uh.FakeUpstream()
    await _call(monkeypatch, up, "block_client", client_id="02-00-5E-00-00-AA")
    assert [w.sent_json for w in up.writes()] == [{"cmd": "block-sta", "mac": uh.ARG_MAC}]
    assert not [s for s in up.served if "/clients/" in s.path]


@pytest.mark.parametrize("tool", ["get_client", "execute_client_action"])
async def test_unknown_client_mac_lists_valid_clients_and_writes_nothing(monkeypatch, tool):
    """Tools that need the Integration client id (block / unblock / reconnect send a MAC
    to stamgr as is: tests/test_network_client_commands.py)."""
    up = _Upstream()
    up.clients = [{"id": OTHER_ID, "name": "laptop", "macAddress": "02:00:5e:00:00:bb"}]
    extra = {"action": {"action": "UNAUTHORIZE_GUEST_ACCESS"}} if tool.startswith("exec") else {}
    with pytest.raises(ToolError) as err:
        await _call(monkeypatch, up, tool, client_id="02:00:5e:00:00:cc", **extra)
    msg = str(err.value)
    assert "02:00:5e:00:00:cc" in msg and OTHER_ID in msg and "laptop" in msg
    assert up.writes() == []


async def test_execute_client_action_by_mac_writes_to_the_resolved_id(monkeypatch):
    up = uh.FakeUpstream(replay_recordings=False)
    await _call(
        monkeypatch,
        up,
        "execute_client_action",
        client_id=uh.ARG_MAC.upper(),
        action={"action": "UNAUTHORIZE_GUEST_ACCESS"},
    )
    assert [w.path.endswith(f"/clients/{uh.ARG_ID}/actions") for w in up.writes()] == [True]


async def test_mac_matching_several_clients_lists_the_matches(monkeypatch):
    up = _Upstream()
    up.clients = [
        {"id": uh.ARG_ID, "name": "a", "macAddress": DUPLICATE_MAC},
        {"id": OTHER_ID, "name": "b", "macAddress": DUPLICATE_MAC.upper()},
    ]
    with pytest.raises(ToolError) as err:
        await _call(monkeypatch, up, "get_client", client_id=DUPLICATE_MAC)
    assert uh.ARG_ID in str(err.value) and OTHER_ID in str(err.value)
    assert up.writes() == []


def test_instructions_block_workflow_names_the_id_or_mac():
    text = _usage_workflows()
    assert "`block_client` → block by client id or MAC (a MAC is sent as is" in text
    assert "`unblock_client` → unblock by MAC" in text and "list_known_clients" in text
    assert "find the client MAC\n" not in text


# ================================================ VPN clients; MAC normalized
@pytest.mark.parametrize(("ctype", "kind"), [("VPN", "VPN"), ("TELEPORT", "Teleport VPN")])
async def test_vpn_client_without_mac_gets_an_accurate_error(monkeypatch, ctype, kind):
    up = _Upstream(replay_recordings=False)
    up.client_body = {"id": uh.ARG_ID, "type": ctype, "name": "remote"}
    with pytest.raises(ToolError) as err:
        await _call(monkeypatch, up, "block_client", client_id=uh.ARG_ID)
    assert str(err.value).endswith(
        f"client {uh.ARG_ID} is a {kind} client and has no MAC; "
        "block/unblock/reconnect apply to wired and wireless clients only"
    )
    assert up.writes() == []


async def test_client_mac_is_sent_in_lowercase_colon_form(monkeypatch):
    up = _Upstream()
    up.client_body = {"id": uh.ARG_ID, "type": "WIRED", "macAddress": "02-00-5E-00-00-AA"}
    await _call(monkeypatch, up, "unblock_client", client_id=uh.ARG_ID)
    assert [w.sent_json for w in up.writes()] == [{"cmd": "unblock-sta", "mac": uh.ARG_MAC}]


# ================================================ null MACs in the device list
async def test_null_mac_entries_are_skipped_and_the_target_still_resolves(monkeypatch):
    _mac_uuid_cache.clear()
    up = _Upstream()
    up.devices = [
        {"id": OTHER_ID, "name": "no-mac", "macAddress": None, "mac": None},
        {"id": "x", "name": "int-mac", "macAddress": 7},
        {"id": uh.ARG_ID, "name": "ap", "macAddress": uh.ARG_MAC},
    ]
    res = await _call(monkeypatch, up, "get_device", device_id=uh.ARG_MAC.upper())
    assert uh.result_payload(res)["id"] == uh.ARG_ID


async def test_unresolvable_mac_with_null_entries_fails_actionably(monkeypatch):
    _mac_uuid_cache.clear()
    up = _Upstream()
    up.devices = [
        {"id": OTHER_ID, "name": "no-mac", "macAddress": None},
        {"id": uh.ARG_ID, "name": "ap", "macAddress": uh.ARG_MAC},
    ]
    with pytest.raises(ToolError) as err:
        await _call(
            monkeypatch,
            up,
            "restart_device",
            device_id="02:00:5e:00:00:cc",
        )
    msg = str(err.value)
    assert "not found" in msg and uh.ARG_ID in msg and "without a usable MAC skipped" in msg
    assert up.writes() == []


# ================================================ MAC cache TTL
def test_mac_cache_ttl_follows_unifi_cache_ttl_seconds():
    from unifi_fabric.client import UniFiClient

    _mac_uuid_cache.clear()
    client = UniFiClient(Settings(api_key="k", cache_ttl_seconds=42))
    assert _mac_cache_for(client).ttl == 42
    off = UniFiClient(Settings(api_key="k", cache_ttl_seconds=0))
    assert _mac_cache_for(off) is None
    default = UniFiClient(Settings(api_key="k"))
    assert _mac_cache_for(default).ttl == 900


async def test_cache_ttl_zero_resolves_the_mac_every_call(monkeypatch):
    up = uh.FakeUpstream(replay_recordings=False)  # device_id stays the ARG_MAC to resolve
    s = Settings(api_key="k-test", cache_ttl_seconds=0)
    uh.install(monkeypatch, up)
    monkeypatch.setattr(server._client, "_settings", s)
    for _ in range(2):
        await server.mcp.call_tool(
            "get_device", {"host": uh.HOST, "site": uh.SITE, "device_id": uh.ARG_MAC}
        )
    assert len(_gets(up, "/devices")) == 2


def test_readme_cache_section_covers_the_mac_cache():
    text = (Path(__file__).resolve().parents[1] / "docs" / "CONFIGURATION.md").read_text()
    row = next(line for line in text.splitlines() if line.startswith("| `UNIFI_CACHE_TTL_SECONDS`"))
    assert "MAC" in row


# ================================================ explicit null results
def test_null_result_is_text_null_plus_structured_content():
    res = to_structured_null_result()
    assert [b.text for b in res.content] == ["null"]
    assert res.structured_content == {"result": None}


@pytest.mark.parametrize(
    ("schema", "admits"),
    [
        (None, True),
        ({"type": "object", "additionalProperties": True}, True),
        ({"type": "object", "properties": {"result": {"type": "string"}}}, False),
        ({"type": "object", "properties": {"result": {"anyOf": [{"type": "null"}]}}}, True),
        ({"type": "object", "additionalProperties": False}, False),
    ],
)
def test_null_payload_schema_gate(schema, admits):
    assert output_schema_admits_null_payload(schema) is admits


async def test_wrapper_converts_none_only_when_enabled():
    async def none() -> None:
        return None

    assert (await _make_structured_fn(none, nulls=False)()) is None
    res = await _make_structured_fn(none)()
    assert res.structured_content == {"result": None}


# ================================================ no invented port/lldp tables
async def test_port_state_omits_tables_the_device_record_lacks(monkeypatch):
    up = uh.FakeUpstream(recorded_routes={})
    res = await _call(monkeypatch, up, "get_device_port_state", device_id=uh.ARG_MAC)
    payload = uh.result_payload(res)
    assert "port_table" not in payload and "lldp_table" not in payload
    assert payload["_device_record"]["mac"] == uh.ARG_MAC


# ================================================ INFO: paging pass-through
@pytest.mark.parametrize(
    "tool",
    [
        "list_wifi_broadcasts",
        "list_acl_rules",
        "list_traffic_matching_lists",
        "list_site_to_site_tunnels",
        "list_wan_interfaces",
        "list_pending_devices",
        "list_countries",
    ],
)
async def test_list_tools_page_on_request_and_drain_by_default(monkeypatch, tool):
    up = uh.FakeUpstream(mode="paged")
    drained = uh.result_payload(await _call(monkeypatch, up, tool))
    assert "offset" not in drained and drained["totalCount"] == len(drained["data"])
    assert not up.undrained()
    up = uh.FakeUpstream(mode="paged")
    page = uh.result_payload(await _call(monkeypatch, up, tool, offset=3, limit=3))
    assert page["offset"] == 3 and page["limit"] == 3 and len(page["data"]) == 3
    if tool == "list_wan_interfaces":
        assert "_health" in page


# ================================================ shape errors in registry record lists
def test_object_records_names_the_request_and_item():
    assert object_records([{"a": 1}], "GET /v1/sites") == [{"a": 1}]
    with pytest.raises(UniFiConnectionError) as err:
        object_records([{"a": 1}, None, "x"], "GET /v1/sites")
    assert str(err.value) == (
        "Unexpected response shape from GET /v1/sites: expected an array of objects, but 2 of 3 "
        "item(s) are not objects (item 1 is NoneType)"
    )


@pytest.mark.parametrize("shape", uh.ITEM_SHAPES)
@pytest.mark.parametrize(
    "tool", ["get_site_health_summary", "list_all_clients", "query_isp_metrics", "list_sites"]
)
async def test_v1_sites_list_of_scalars_or_nulls_is_a_shape_error(monkeypatch, tool, shape):
    up = uh.FakeUpstream(item_shape=shape)
    uh.install(monkeypatch, up)
    from tests import tool_args

    args = tool_args.generated_args(dict((t.name, t) for t in await server.mcp.list_tools())[tool])
    try:
        res = await server.mcp.call_tool(tool, args)
    except ToolError as exc:
        assert "Unexpected" in str(exc) and "has no attribute" not in str(exc)
        return
    text = json.dumps(uh.result_payload(res))
    assert "has no attribute" not in text


async def test_registry_never_caches_a_list_with_non_object_items():
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.registry import Registry

    reg = Registry(UniFiClient(Settings(api_key="k")), ttl_seconds=900)
    await reg.set_ea_sites(["junk"])  # type: ignore[list-item]
    assert reg._ea_sites == {} or all(
        all(isinstance(s, dict) for s in v) for v in reg._ea_sites.values()
    )
