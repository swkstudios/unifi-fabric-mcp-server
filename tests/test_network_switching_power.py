"""Network switching / power tools: routes, validation, verification and registration.

Hermetic: synthetic upstream bodies only, no controller is contacted.
"""

from __future__ import annotations

import copy
from typing import Any

import httpx
import pytest
from fastmcp import FastMCP

from tests import upstream_harness as uh
from unifi_fabric import refusals
from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiConnectionError
from unifi_fabric.families.network import network_switching_power as power

HOST = "console-a"
SITE = "Default"
IDENTIFIER = "65f1c0ffee0123456789abcd"
OTHER = "65f1c0ffee0123456789abce"
V2 = "/v1/connector/consoles/host-1/proxy/network/v2/api/site/default"

TOOL_NAMES = {
    "list_energy_saving_policies",
    "create_energy_saving_policy",
    "update_energy_saving_policy",
    "delete_energy_saving_policy",
    "list_power_supervisors",
    "create_power_supervisor",
    "update_power_supervisor",
    "delete_power_supervisor",
    "create_power_supervisor_link",
    "update_power_supervisor_link",
    "delete_power_supervisor_link",
    "query_power_supervisor_logs",
    "get_port_history",
    "query_switch_mac_tables",
    "list_port_anomalies",
    "query_port_system_logs",
    "list_wireless_links",
    "get_device_tx_retries",
    "get_infrastructure_history",
}
WRITES = {
    name
    for name in TOOL_NAMES
    if name.split("_", 1)[0] in {"create", "update", "delete"}
    or name in {"query_power_supervisor_logs", "query_switch_mac_tables", "query_port_system_logs"}
}


class Registry:
    def __init__(self) -> None:
        self.calls = 0

    async def resolve_key_for_host(self, host: str) -> None:
        assert host == HOST
        self.calls += 1
        return None

    async def resolve_host_id(self, host: str, *, key: None) -> str:
        self.calls += 1
        return "host-1"

    async def resolve_site_slug(self, site: str, host_id: str, *, key: None) -> str:
        assert (site, host_id) == (SITE, "host-1")
        self.calls += 1
        return "default"


class Client:
    def __init__(self, rows: Any = None, *, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.rows = (
            rows
            if rows is not None
            else [{"_id": IDENTIFIER, "name": "original", "settings": {"keep": True}}]
        )
        self.calls: list[tuple[str, str, Any, Any]] = []

    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None, params))
        if path.endswith(("-policies", "/power-supervisors", "/links")):
            return copy.deepcopy(self.rows)
        return {"path": path}

    def _write(self, method: str, path: str, body: Any) -> Any:
        self.calls.append((method, path, body, None))
        if self.dry_run:
            return {
                "status": "dry_run",
                "dryRun": True,
                "message": DRY_RUN_MESSAGE,
                "preview": {"method": method, "path": path, "params": None, "body": body},
            }
        return {"echo": body, "path": path}

    async def post(self, path: str, *, key: None, json: Any) -> Any:
        return self._write("POST", path, json)

    async def put(self, path: str, *, key: None, json: Any) -> Any:
        return self._write("PUT", path, json)

    async def delete(self, path: str, *, key: None) -> Any:
        return self._write("DELETE", path, None)


async def test_every_tool_uses_its_inventoried_v2_route() -> None:
    client, registry = Client(), Registry()
    await power.list_energy_saving_policies(client, registry, HOST, SITE)
    await power.create_energy_saving_policy(client, registry, HOST, SITE, {"name": "n"})
    await power.update_energy_saving_policy(client, registry, HOST, SITE, IDENTIFIER, {"name": "x"})
    await power.delete_energy_saving_policy(client, registry, HOST, SITE, IDENTIFIER)
    await power.list_power_supervisors(client, registry, HOST, SITE)
    await power.create_power_supervisor(client, registry, HOST, SITE, {"control_mode": "manual"})
    await power.update_power_supervisor(client, registry, HOST, SITE, IDENTIFIER, {"name": "x"})
    await power.delete_power_supervisor(client, registry, HOST, SITE, IDENTIFIER)
    await power.create_power_supervisor_link(client, registry, HOST, SITE, {"enabled": False})
    await power.update_power_supervisor_link(client, registry, HOST, SITE, IDENTIFIER, {"a": 1})
    await power.delete_power_supervisor_link(client, registry, HOST, SITE, IDENTIFIER)
    await power.query_power_supervisor_logs(client, registry, HOST, SITE, IDENTIFIER, {"limit": 1})
    await power.get_port_history(client, registry, HOST, SITE, 1760000000)
    await power.get_port_history(client, registry, HOST, SITE, 1760000000, IDENTIFIER)
    await power.query_switch_mac_tables(
        client, registry, HOST, SITE, [{"mac": "02:00:5e:00:53:01", "ports": [1]}]
    )
    await power.list_port_anomalies(client, registry, HOST, SITE)
    await power.query_port_system_logs(client, registry, HOST, SITE, {"limit": 1})
    await power.list_wireless_links(client, registry, HOST, SITE)
    await power.list_wireless_links(client, registry, HOST, SITE, IDENTIFIER)
    await power.get_device_tx_retries(client, registry, HOST, SITE, IDENTIFIER, {"radio": "na"})
    await power.get_infrastructure_history(client, registry, HOST, SITE, 1760000000)

    sent = {(method, path.removeprefix(V2)) for method, path, _, _ in client.calls}
    assert sent == {
        ("GET", "/energy-saving-policies"),
        ("POST", "/energy-saving-policies"),
        ("PUT", f"/energy-saving-policies/{IDENTIFIER}"),
        ("DELETE", f"/energy-saving-policies/{IDENTIFIER}"),
        ("GET", "/power-supervisors"),
        ("POST", "/power-supervisors"),
        ("PUT", f"/power-supervisors/{IDENTIFIER}"),
        ("DELETE", f"/power-supervisors/{IDENTIFIER}"),
        ("GET", "/power-supervisors/links"),
        ("POST", "/power-supervisors/links"),
        ("PUT", f"/power-supervisors/links/{IDENTIFIER}"),
        ("DELETE", f"/power-supervisors/links/{IDENTIFIER}"),
        ("POST", f"/power-supervisors/{IDENTIFIER}/system-logs"),
        ("GET", "/ports/history/at/1760000000000"),
        ("GET", f"/ports/history/{IDENTIFIER}/at/1760000000000"),
        ("POST", "/ports/mac-tables"),
        ("GET", "/ports/port-anomalies"),
        ("POST", "/ports/system-logs"),
        ("GET", "/device/wireless-links"),
        ("GET", f"/device/{IDENTIFIER}/wireless-links"),
        ("GET", f"/device/{IDENTIFIER}/24hr-tx-retries"),
        ("GET", "/infrastructure/history/at/1760000000000"),
    }
    assert all(path.startswith(V2) for _, path, _, _ in client.calls)
    retries = [c for c in client.calls if c[1].endswith("24hr-tx-retries")]
    assert retries[0][3] == {"radio": "na"}


async def test_bodies_and_list_results_pass_through_verbatim() -> None:
    rows = [{"_id": IDENTIFIER, "x_unknown": [1, {"n": None}]}]
    client = Client(rows)
    assert await power.list_power_supervisors(client, Registry(), HOST, SITE) == rows
    body = {"name": "n", "settings": {"enabled": False}, "_extra": 1}
    result = await power.create_energy_saving_policy(client, Registry(), HOST, SITE, body)
    assert result["echo"] == body


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: power.update_power_supervisor(c, r, HOST, SITE, "bad id", {"name": "n"}),
        lambda c, r: power.update_power_supervisor(c, r, HOST, SITE, IDENTIFIER, {}),
        lambda c, r: power.update_energy_saving_policy(c, r, HOST, SITE, IDENTIFIER, {"id": "x"}),
        lambda c, r: power.delete_power_supervisor_link(c, r, HOST, SITE, "a/b"),
        lambda c, r: power.query_power_supervisor_logs(c, r, HOST, SITE, "../x", {}),
        lambda c, r: power.get_port_history(c, r, HOST, SITE, True),
        lambda c, r: power.get_port_history(c, r, HOST, SITE, 1, "bad id"),
        lambda c, r: power.get_infrastructure_history(c, r, HOST, SITE, 1.5),
        lambda c, r: power.list_wireless_links(c, r, HOST, SITE, "bad id"),
    ],
)
async def test_invalid_input_fails_before_any_resolution_or_request(call: Any) -> None:
    client, registry = Client(), Registry()
    with pytest.raises(ValueError):
        await call(client, registry)
    assert client.calls == []
    assert registry.calls == 0


async def test_update_merges_requested_leaves_and_verifies_type_strictly() -> None:
    client = Client()
    result = await power.update_energy_saving_policy(
        client, Registry(), HOST, SITE, IDENTIFIER.upper(), {"settings": {"level": 1}}
    )
    assert [method for method, *_ in client.calls] == ["GET", "PUT", "GET"]
    assert client.calls[1][1].endswith(f"/energy-saving-policies/{IDENTIFIER}")
    assert client.calls[1][2] == {
        "_id": IDENTIFIER,
        "name": "original",
        "settings": {"keep": True, "level": 1},
    }
    # The synthetic upstream did not apply the change: the read-back must say so.
    assert result["_verified"] is False
    assert "_readAfterError" not in result


async def test_energy_update_excludes_list_only_fields_but_preserves_requested_fields() -> None:
    row = {
        "_id": IDENTIFIER,
        "name": "old",
        "enabled": False,
        "action": "SLEEP_MODE",
        "scope": {"type": "DEVICE_CLASS", "device_classes": ["access"]},
        "schedule": {"weekly": [], "exceptions": []},
        "device_names": [],
        "estimated_energy_savings": 0,
    }
    client = Client([row])
    result = await power.update_energy_saving_policy(
        client, Registry(), HOST, SITE, IDENTIFIER, {"name": "new", "future_option": True}
    )
    assert client.calls[1][2] == {
        key: value
        for key, value in row.items()
        if key not in {"device_names", "estimated_energy_savings", "name"}
    } | {"name": "new", "future_option": True}
    assert result["_verified"] is False


@pytest.mark.parametrize("registered", [False, True])
async def test_energy_update_preserves_unmentioned_extensions_and_explicit_fields(
    registered: bool,
) -> None:
    row = {
        "_id": IDENTIFIER,
        "name": "before",
        "future_option": 42,
        "settings": {"keep": {"nested": True}, "change": 1},
        "_future_private": {"preserve": True},
        "device_names": ["read-only"],
        "estimated_energy_savings": 17,
    }
    changes = {"name": "after", "settings": {"change": 2}, "_caller_option": 3}
    client, registry = Client([row]), Registry()
    if registered:
        mcp = FastMCP("energy-preservation")
        power.register(mcp, lambda: (client, registry))
        tool = next(t for t in await mcp.list_tools() if t.name == "update_energy_saving_policy")
        result = await tool.fn(HOST, SITE, IDENTIFIER, changes)
    else:
        result = await power.update_energy_saving_policy(
            client, registry, HOST, SITE, IDENTIFIER, changes
        )
    collection = f"{V2}/energy-saving-policies"
    assert client.calls == [
        ("GET", collection, None, None),
        (
            "PUT",
            f"{collection}/{IDENTIFIER}",
            {
                "_id": IDENTIFIER,
                "name": "after",
                "future_option": 42,
                "settings": {"keep": {"nested": True}, "change": 2},
                "_future_private": {"preserve": True},
            },
            None,
        ),
        ("GET", collection, None, None),
    ]
    assert result["_verified"] is False


async def test_energy_update_forwards_explicit_list_metadata() -> None:
    client = Client([{"_id": IDENTIFIER, "device_names": ["old"], "estimated_energy_savings": 1}])
    changes = {"device_names": ["caller"], "estimated_energy_savings": 2}
    await power.update_energy_saving_policy(client, Registry(), HOST, SITE, IDENTIFIER, changes)
    assert client.calls[1][2] == {"_id": IDENTIFIER, **changes}


async def test_update_verified_true_when_read_back_matches() -> None:
    client = Client([{"id": IDENTIFIER, "enabled": True}])
    result = await power.update_power_supervisor_link(
        client, Registry(), HOST, SITE, IDENTIFIER, {"enabled": True}
    )
    assert result["_verified"] is True


async def test_update_read_after_failure_reports_error_not_raise() -> None:
    client = Client()
    original_get = client.get
    count = 0

    async def flaky(path: str, *, key: None, params: Any = None) -> Any:
        nonlocal count
        count += 1
        if count == 2:
            raise UniFiConnectionError("read-back failed")
        return await original_get(path, key=key, params=params)

    client.get = flaky  # type: ignore[method-assign]
    result = await power.update_power_supervisor(
        client, Registry(), HOST, SITE, IDENTIFIER, {"name": "x"}
    )
    assert result["_verified"] is None
    assert "read-back failed" in result["_readAfterError"]


@pytest.mark.parametrize("tool", ["update", "delete"])
async def test_unknown_id_fails_listing_every_valid_id_and_never_writes(tool: str) -> None:
    client = Client([{"_id": OTHER}, {"id": IDENTIFIER}])
    with pytest.raises(ValueError, match=f"not found; valid choices: id={IDENTIFIER}, _id={OTHER}"):
        if tool == "update":
            await power.update_power_supervisor(
                client, Registry(), HOST, SITE, "0000000000000000000000ff", {"name": "x"}
            )
        else:
            await power.delete_power_supervisor(
                client, Registry(), HOST, SITE, "0000000000000000000000ff"
            )
    assert [method for method, *_ in client.calls] == ["GET"]


@pytest.mark.parametrize("rows", [{"unexpected": True}, "text", [1, 2]])
async def test_unexpected_collection_shape_raises_with_shape(rows: Any) -> None:
    client = Client(rows)
    with pytest.raises(UniFiConnectionError, match="Unexpected response shape"):
        await power.delete_energy_saving_policy(client, Registry(), HOST, SITE, IDENTIFIER)
    assert [method for method, *_ in client.calls] == ["GET"]


async def test_classic_data_envelope_is_accepted_for_resolution() -> None:
    client = Client({"meta": {"rc": "ok"}, "data": [{"_id": IDENTIFIER}]})
    await power.delete_power_supervisor_link(client, Registry(), HOST, SITE, IDENTIFIER)
    assert client.calls[-1][0] == "DELETE"


async def test_dry_run_returns_preview_without_read_after() -> None:
    client = Client(dry_run=True)
    result = await power.update_power_supervisor(
        client, Registry(), HOST, SITE, IDENTIFIER, {"name": "x"}
    )
    assert result["status"] == "dry_run"
    assert "_verified" not in result
    assert [method for method, *_ in client.calls] == ["GET", "PUT"]
    preview = await power.query_port_system_logs(client, Registry(), HOST, SITE, {"limit": 1})
    assert preview["preview"]["body"] == {"limit": 1}


async def test_history_adds_epoch_warning_for_millisecond_values() -> None:
    result = await power.get_infrastructure_history(Client(), Registry(), HOST, SITE, 1760000000000)
    assert result["_warnings"]
    assert result["_warnings"][0]["code"] == "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"
    assert result["path"].endswith("/infrastructure/history/at/1760000000000000")


class HistoryUpstream(Client):
    """The two history routes as Network 11.0.89 answered them live (2026-10-28): the
    path time is epoch MILLISECONDS. A seconds value answers 404 "No infrastructure
    snapshot exists at or before ..." (infrastructure) or HTTP 200 [] (ports)."""

    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None, params))
        at = int(path.rsplit("/", 1)[1])
        if at < 100_000_000_000:
            if "/infrastructure/history/" in path:
                raise UniFiConnectionError(
                    f"HTTP 404 from GET {path}: "
                    '{"errorCode":404,"message":"No infrastructure snapshot exists at or '
                    f'before {at} for site 98ea3e0a-0000-4000-8000-000000000001"}}',
                    status=404,
                )
            return []
        if "/infrastructure/history/" in path:
            return {"timestamp": at - 5000, "devices": [{"mac": "02:00:5e:00:00:01"}]}
        return [{"mac": "02:00:5e:00:00:01", "timestamp": at - 5000, "ports": [{"port_idx": 1}]}]


async def test_history_tools_send_the_documented_seconds_as_milliseconds() -> None:
    """E2E 0.7.0 bug 6: at in epoch seconds (as documented) reached the route unchanged."""
    client = HistoryUpstream()
    snapshot = await power.get_infrastructure_history(client, Registry(), HOST, SITE, 1793191985)
    assert snapshot == {"timestamp": 1793191980000, "devices": [{"mac": "02:00:5e:00:00:01"}]}
    ports = await power.get_port_history(client, Registry(), HOST, SITE, 1793191985)
    assert ports == [
        {"mac": "02:00:5e:00:00:01", "timestamp": 1793191980000, "ports": [{"port_idx": 1}]}
    ]
    device = await power.get_port_history(client, Registry(), HOST, SITE, 1793191985, IDENTIFIER)
    assert device[0]["ports"] == [{"port_idx": 1}]
    assert [path.removeprefix(V2) for _, path, _, _ in client.calls] == [
        "/infrastructure/history/at/1793191985000",
        "/ports/history/at/1793191985000",
        f"/ports/history/{IDENTIFIER}/at/1793191985000",
    ]


async def test_registers_nineteen_typed_documented_tools_with_derived_access() -> None:
    mcp = FastMCP("switching-power")
    power.register(mcp, lambda: (Client(), Registry()))
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    assert set(tools) == TOOL_NAMES
    for name, tool in tools.items():
        assert len(tool.description or "") <= 2048
        for field in tool.parameters["properties"].values():
            assert "e.g." in field.get("description", ""), (name, field)
            assert field.get("type") or field.get("anyOf"), (name, field)
        read_only = tool.annotations.read_only_hint if tool.annotations else None
        assert read_only is (name not in WRITES), name
        if name in WRITES:
            assert "dry-run preview" in (tool.description or "")


async def test_all_tools_are_registered_on_the_real_server() -> None:
    from unifi_fabric import server

    assert TOOL_NAMES <= {tool.name for tool in await server.mcp.list_tools()}


async def test_non_first_key_owned_host_routes_to_that_key(
    monkeypatch: pytest.MonkeyPatch, multikey_client: Any, multikey_registry: Any
) -> None:
    up = uh.FakeUpstream(hosts_by_key={"k-alpha": [], "k-beta": [copy.deepcopy(uh.HOST_RECORD)]})

    async def http_session(key: Any) -> httpx.AsyncClient:
        if key.label not in multikey_client._clients:
            multikey_client._clients[key.label] = httpx.AsyncClient(
                base_url=multikey_client._settings.api_base_url,
                headers={"X-API-KEY": key.key},
                transport=httpx.MockTransport(up),
            )
        return multikey_client._clients[key.label]

    monkeypatch.setattr(multikey_client, "_get_client", http_session)
    await power.list_power_supervisors(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    served = [s for s in up.served if not s.resolution]
    assert served and all(s.api_key == "k-beta" for s in served)
    assert any("/v2/api/site/" in s.path for s in served)
    await multikey_client.close()


async def test_mac_tables_query_is_sent_as_the_json_array_the_route_deserializes() -> None:
    # Network 11.0.89 web app: ports/mac-tables is posted [{mac, ports: [port_idx]}]; an
    # object answers HTTP 400 "Cannot deserialize ... ArrayList ... from Object value".
    client, registry = Client(), Registry()
    query = [{"mac": "02:00:5e:00:53:01", "ports": [1, 24]}]
    await power.query_switch_mac_tables(client, registry, HOST, SITE, query)
    method, path, body, _ = client.calls[-1]
    assert (method, path.removeprefix(V2)) == ("POST", "/ports/mac-tables")
    assert body == query


@pytest.mark.parametrize(
    "arguments,body",
    [
        # The documented legacy object: the route answers HTTP 400 to an object, so the
        # tool sends it as the one-item array the web app posts.
        (
            {"query": {"mac": "02:00:5e:00:53:01", "ports": [1, 2]}},
            [{"mac": "02:00:5e:00:53:01", "ports": [1, 2]}],
        ),
        (
            {"queries": [{"mac": "02:00:5e:00:53:01", "ports": [1]}]},
            [{"mac": "02:00:5e:00:53:01", "ports": [1]}],
        ),
        # Any other legacy value is forwarded unchanged (the controller judges it).
        ({"query": {"future": {"nested": [None, 7]}}}, {"future": {"nested": [None, 7]}}),
    ],
)
async def test_mac_tables_tool_sends_the_documented_legacy_object_as_an_array(arguments, body):
    client, registry = Client(), Registry()
    mcp = FastMCP("mac-tables")
    power.register(mcp, lambda: (client, registry))
    tool = next(t for t in await mcp.list_tools() if t.name == "query_switch_mac_tables")
    await tool.run({"host": HOST, "site": SITE, **arguments})
    posts = [c for c in client.calls if c[0] == "POST"]
    assert len(posts) == 1
    method, path, sent, _ = posts[0]
    assert path.removeprefix(V2) == "/ports/mac-tables"
    assert sent == body


@pytest.mark.parametrize(
    "query,match",
    [
        ({"macs": ["02:00:5e:00:53:01"]}, "must be a JSON array of"),
        ([], "non-empty list"),
        (["02:00:5e:00:53:01"], r"'query\[0\]' must be a JSON object"),
    ],
)
async def test_mac_tables_query_that_is_not_an_array_of_objects_sends_nothing(query, match):
    client, registry = Client(), Registry()
    with pytest.raises(ValueError, match=match) as info:
        await power.query_switch_mac_tables(client, registry, HOST, SITE, query)
    assert client.calls == []
    assert refusals.classify(str(info.value)) is not None
