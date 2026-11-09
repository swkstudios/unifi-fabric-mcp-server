"""Network routing / topology tools: routes, validation, verification and registration.

Hermetic: synthetic upstream bodies only, no controller is contacted.
"""

from __future__ import annotations

import copy
from typing import Any

import httpx
import pytest
from fastmcp import FastMCP

from tests import upstream_harness as uh
from unifi_fabric import route_secrets as rs
from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiConnectionError
from unifi_fabric.tools import network_routing_topology as rt

HOST = "console-a"
SITE = "Default"
IDENTIFIER = "65f1c0ffee0123456789abcd"
OTHER = "65f1c0ffee0123456789abce"
NET_UUID = "00000000-0000-4000-8000-0000000000c1"
CONSOLE = "/v1/connector/consoles/host-1/proxy/network"
V2 = f"{CONSOLE}/v2/api/site/default"
CLASSIC_NETS = f"{CONSOLE}/api/s/default/rest/networkconf"

TOOL_NAMES = {
    "get_bgp_status",
    "create_bgp_config",
    "update_bgp_config",
    "delete_bgp_config",
    "get_ospf_status",
    "create_ospf_router",
    "update_ospf_router",
    "delete_ospf_router",
    "get_global_network_config",
    "update_global_network_config",
    "get_mdns_settings",
    "migrate_network_to_layer3",
    "suggest_network_settings",
    "generate_vlan_plan",
    "import_dhcp_reservations",
    "detach_from_orchestration",
    "manage_virtual_network",
    "get_loop_detection_status",
    "recover_loop_blocked_ports",
    "manage_mclag_group",
    "update_switch_stack",
}
READS = {
    "get_bgp_status",
    "get_ospf_status",
    "get_global_network_config",
    "get_mdns_settings",
    "suggest_network_settings",
    "get_loop_detection_status",
}
WRITES = TOOL_NAMES - READS
COLLECTIONS = ("/bgp/config/all", "/ospf/router", "/mclag-groups", "/stacking")


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
    def __init__(self, rows: Any = None, *, singleton: Any = None, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.rows = (
            rows
            if rows is not None
            else [{"_id": IDENTIFIER, "name": "original", "settings": {"keep": True}}]
        )
        self.singleton = singleton if singleton is not None else {"ipv6_enabled": False, "keep": 1}
        self.networks: Any = {
            "meta": {"rc": "ok"},
            "data": [{"_id": IDENTIFIER, "external_id": NET_UUID, "name": "LAN"}],
        }
        self.calls: list[tuple[str, str, Any, Any]] = []

    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None, params))
        if path.endswith("/bgp/config"):
            return []
        if path.endswith(COLLECTIONS):
            return copy.deepcopy(self.rows)
        if path.endswith("/global/config/network"):
            return copy.deepcopy(self.singleton)
        if path == CLASSIC_NETS:
            return copy.deepcopy(self.networks)
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


def _sent(client: Client) -> list[tuple[str, str]]:
    return [
        (method, path.removeprefix(V2) if path.startswith(V2) else path)
        for method, path, _, _ in client.calls
    ]


async def test_every_tool_uses_its_inventoried_route() -> None:
    c, r = Client(), Registry()
    await rt.get_bgp_status(c, r, HOST, SITE)
    await rt.get_bgp_status(c, r, HOST, SITE, "neighbors")
    await rt.create_bgp_config(c, r, HOST, SITE, {"name": "b"})
    await rt.update_bgp_config(c, r, HOST, SITE, IDENTIFIER, {"name": "x"})
    await rt.delete_bgp_config(c, r, HOST, SITE, IDENTIFIER)
    await rt.get_ospf_status(c, r, HOST, SITE)
    await rt.get_ospf_status(c, r, HOST, SITE, "neighbors")
    await rt.create_ospf_router(c, r, HOST, SITE, {"name": "o"})
    await rt.update_ospf_router(c, r, HOST, SITE, IDENTIFIER, {"name": "x"})
    await rt.delete_ospf_router(c, r, HOST, SITE, IDENTIFIER)
    await rt.get_global_network_config(c, r, HOST, SITE)
    await rt.update_global_network_config(c, r, HOST, SITE, {"ipv6_enabled": True})
    await rt.get_mdns_settings(c, r, HOST, SITE)
    await rt.migrate_network_to_layer3(c, r, HOST, SITE, NET_UUID, {"name": "L3"})
    await rt.suggest_network_settings(c, r, HOST, SITE)
    await rt.generate_vlan_plan(c, r, HOST, SITE)
    await rt.import_dhcp_reservations(c, r, HOST, SITE, [{"mac": "02:00:5e:00:00:a1"}])
    await rt.detach_from_orchestration(c, r, HOST, SITE, "network", IDENTIFIER)
    await rt.detach_from_orchestration(c, r, HOST, SITE, "settings", OTHER)
    await rt.manage_virtual_network(c, r, HOST, SITE, "create", {"name": "v"})
    await rt.manage_virtual_network(c, r, HOST, SITE, "update", {"name": "v"}, OTHER)
    await rt.get_loop_detection_status(c, r, HOST, SITE)
    await rt.recover_loop_blocked_ports(c, r, HOST, SITE)
    await rt.manage_mclag_group(c, r, HOST, SITE, "create", group={"name": "m"})
    await rt.manage_mclag_group(c, r, HOST, SITE, "update", IDENTIFIER, {"name": "x"})
    await rt.manage_mclag_group(c, r, HOST, SITE, "delete", IDENTIFIER)
    await rt.update_switch_stack(c, r, HOST, SITE, IDENTIFIER, {"unit_order": ["a"]})

    assert set(_sent(c)) == {
        ("GET", "/bgp/config/all"),
        ("GET", "/bgp/config"),
        ("GET", "/bgp/neighbors"),
        ("POST", "/bgp/config"),
        ("POST", f"/bgp/config/{IDENTIFIER}"),
        ("DELETE", f"/bgp/config/{IDENTIFIER}"),
        ("GET", "/ospf/router"),
        ("GET", "/ospf/neighbors"),
        ("POST", "/ospf/router"),
        ("PUT", f"/ospf/router/{IDENTIFIER}"),
        ("DELETE", f"/ospf/router/{IDENTIFIER}"),
        ("GET", "/global/config/network"),
        ("PUT", "/global/config/network"),
        ("GET", "/lan/mdns"),
        ("GET", CLASSIC_NETS),
        ("POST", f"/lan/migrate-to-layer3/{IDENTIFIER}"),
        ("GET", "/network/suggest"),
        ("POST", "/network/generate-vlans"),
        ("POST", "/dhcp-import"),
        ("POST", f"/orchestration/network/{IDENTIFIER}/detach"),
        ("POST", f"/orchestration/{OTHER}/settings/detach"),
        ("POST", "/visual-programming/virtual-network"),
        ("PUT", f"/visual-programming/virtual-network/{OTHER}"),
        ("GET", "/loop-detection/info"),
        ("POST", "/loop-detection/recover-all-ports"),
        ("GET", "/mclag-groups"),
        ("POST", "/mclag-groups"),
        ("PUT", f"/mclag-groups/{IDENTIFIER}"),
        ("DELETE", f"/mclag-groups/{IDENTIFIER}"),
        ("GET", "/stacking"),
        ("PUT", f"/stacking/{IDENTIFIER}"),
    }


async def test_bodies_pass_through_verbatim_and_bodiless_actions_send_none() -> None:
    c = Client()
    body = {"name": "n", "neighbors": [{"password": "probe-secret"}], "_extra": 1}
    result = await rt.create_bgp_config(c, Registry(), HOST, SITE, body)
    assert result["echo"] == body
    rows = [{"_id": IDENTIFIER, "x_unknown": [1, {"n": None}]}]
    assert await rt.get_bgp_status(Client(rows), Registry(), HOST, SITE) == rows
    for call in (
        rt.recover_loop_blocked_ports(c, Registry(), HOST, SITE),
        rt.generate_vlan_plan(c, Registry(), HOST, SITE),
        rt.detach_from_orchestration(c, Registry(), HOST, SITE, "settings", OTHER),
    ):
        assert (await call)["echo"] is None
    plan = await rt.generate_vlan_plan(c, Registry(), HOST, SITE, {"purpose": "corporate"})
    assert plan["echo"] == {"purpose": "corporate"}
    migrate = await rt.migrate_network_to_layer3(
        c, Registry(), HOST, SITE, IDENTIFIER, {"cmd": "x", "name": "L3"}
    )
    assert migrate["echo"] == {"cmd": "x", "name": "L3"}


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: rt.get_bgp_status(c, r, HOST, SITE, "all"),
        lambda c, r: rt.get_ospf_status(c, r, HOST, SITE, ""),
        lambda c, r: rt.update_bgp_config(c, r, HOST, SITE, "bad id", {"name": "n"}),
        lambda c, r: rt.update_bgp_config(c, r, HOST, SITE, IDENTIFIER, {}),
        lambda c, r: rt.update_ospf_router(c, r, HOST, SITE, IDENTIFIER, {"_id": "x"}),
        lambda c, r: rt.delete_ospf_router(c, r, HOST, SITE, "a/b"),
        lambda c, r: rt.delete_bgp_config(c, r, HOST, SITE, ""),
        lambda c, r: rt.update_global_network_config(c, r, HOST, SITE, {}),
        lambda c, r: rt.update_switch_stack(c, r, HOST, SITE, IDENTIFIER, {"id": "x"}),
        lambda c, r: rt.migrate_network_to_layer3(c, r, HOST, SITE, "../x", {"name": "n"}),
        lambda c, r: rt.detach_from_orchestration(c, r, HOST, SITE, "zone", IDENTIFIER),
        lambda c, r: rt.detach_from_orchestration(c, r, HOST, SITE, "network", "a b"),
        lambda c, r: rt.manage_virtual_network(c, r, HOST, SITE, "delete", {"name": "v"}),
        lambda c, r: rt.manage_virtual_network(c, r, HOST, SITE, "update", {"name": "v"}),
        lambda c, r: rt.manage_virtual_network(c, r, HOST, SITE, "create", {"a": 1}, OTHER),
        lambda c, r: rt.manage_virtual_network(c, r, HOST, SITE, "create", {}),
        lambda c, r: rt.manage_mclag_group(c, r, HOST, SITE, "list"),
        lambda c, r: rt.manage_mclag_group(c, r, HOST, SITE, "create", OTHER, {"a": 1}),
        lambda c, r: rt.manage_mclag_group(c, r, HOST, SITE, "create"),
        lambda c, r: rt.manage_mclag_group(c, r, HOST, SITE, "update", IDENTIFIER, {}),
        lambda c, r: rt.manage_mclag_group(c, r, HOST, SITE, "update", None, {"a": 1}),
        lambda c, r: rt.manage_mclag_group(c, r, HOST, SITE, "delete", IDENTIFIER, {"a": 1}),
        lambda c, r: rt.get_mdns_settings(c, r, " ", SITE),
        lambda c, r: rt.create_ospf_router(c, r, HOST, "", {"a": 1}),
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
    result = await rt.update_ospf_router(
        client, Registry(), HOST, SITE, IDENTIFIER.upper(), {"settings": {"area": 0}}
    )
    assert [method for method, *_ in client.calls] == ["GET", "PUT", "GET"]
    assert client.calls[1][1].endswith(f"/ospf/router/{IDENTIFIER}")
    assert client.calls[1][2] == {
        "_id": IDENTIFIER,
        "name": "original",
        "settings": {"keep": True, "area": 0},
    }
    # The synthetic upstream did not apply the change: the read-back must say so.
    assert result["_verified"] is False
    assert "_readAfterError" not in result


async def test_update_verified_true_when_read_back_matches() -> None:
    client = Client([{"id": IDENTIFIER, "enabled": True}])
    result = await rt.manage_mclag_group(
        client, Registry(), HOST, SITE, "update", IDENTIFIER, {"enabled": True}
    )
    assert result["_verified"] is True
    stack = await rt.update_switch_stack(client, Registry(), HOST, SITE, IDENTIFIER, {"enabled": 1})
    assert stack["_verified"] is False  # 1 is not true


async def test_bgp_update_posts_the_merged_record_to_its_id_route() -> None:
    client = Client()
    result = await rt.update_bgp_config(client, Registry(), HOST, SITE, IDENTIFIER, {"asn": 65001})
    assert [m for m, *_ in client.calls] == ["GET", "GET", "POST", "GET"]
    assert client.calls[2][2]["asn"] == 65001 and client.calls[2][2]["name"] == "original"
    assert result["_verified"] is False


async def test_global_config_merges_into_the_singleton_and_verifies() -> None:
    client = Client(singleton={"ipv6_enabled": True, "keep": 1})
    result = await rt.update_global_network_config(
        client, Registry(), HOST, SITE, {"ipv6_enabled": True}
    )
    assert client.calls[1][2] == {"ipv6_enabled": True, "keep": 1}
    assert result["_verified"] is True
    listed = Client(singleton=[{"ipv6_enabled": False}])
    out = await rt.update_global_network_config(
        listed, Registry(), HOST, SITE, {"ipv6_enabled": True}
    )
    assert listed.calls[1][2] == {"ipv6_enabled": True}
    assert out["_verified"] is False


@pytest.mark.parametrize("singleton", [[], [1], [{"a": 1}, {"b": 2}], "text"])
async def test_global_config_unexpected_shape_raises_before_write(singleton: Any) -> None:
    client = Client(singleton=singleton)
    with pytest.raises(UniFiConnectionError, match="did not answer one settings record"):
        await rt.update_global_network_config(client, Registry(), HOST, SITE, {"a": 1})
    assert [m for m, *_ in client.calls] == ["GET"]


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
    result = await rt.update_switch_stack(client, Registry(), HOST, SITE, IDENTIFIER, {"a": 1})
    assert result["_verified"] is None
    assert "read-back failed" in result["_readAfterError"]


@pytest.mark.parametrize("tool", ["update", "delete"])
async def test_unknown_id_fails_listing_every_valid_id_and_never_writes(tool: str) -> None:
    client = Client([{"_id": OTHER}, {"id": IDENTIFIER}])
    with pytest.raises(
        ValueError, match=f"not found; valid: None \\(_id={OTHER}\\); None \\(id={IDENTIFIER}\\)"
    ):
        if tool == "update":
            await rt.update_bgp_config(
                client, Registry(), HOST, SITE, "0000000000000000000000ff", {"name": "x"}
            )
        else:
            await rt.manage_mclag_group(
                client, Registry(), HOST, SITE, "delete", "0000000000000000000000ff"
            )
    assert [method for method, *_ in client.calls] == ["GET"]


async def test_unknown_network_fails_listing_choices_and_never_writes() -> None:
    client = Client()
    with pytest.raises(
        ValueError, match=f"network '{OTHER}' not found; valid: 'LAN' \\(_id={IDENTIFIER}\\)"
    ):
        await rt.migrate_network_to_layer3(client, Registry(), HOST, SITE, OTHER, {"name": "n"})
    assert [method for method, *_ in client.calls] == ["GET"]


@pytest.mark.parametrize("rows", [{"unexpected": True}, "text", [1, 2]])
async def test_unexpected_collection_shape_raises_with_shape(rows: Any) -> None:
    client = Client(rows)
    with pytest.raises(UniFiConnectionError, match="Unexpected response shape"):
        await rt.delete_bgp_config(client, Registry(), HOST, SITE, IDENTIFIER)
    assert [method for method, *_ in client.calls] == ["GET"]


async def test_data_envelope_is_accepted_for_resolution() -> None:
    client = Client({"data": [{"_id": IDENTIFIER}]})
    await rt.delete_ospf_router(client, Registry(), HOST, SITE, IDENTIFIER)
    assert [call[0] for call in client.calls] == ["GET", "DELETE", "GET"]


async def test_dry_run_returns_preview_without_read_after() -> None:
    client = Client(dry_run=True)
    result = await rt.update_ospf_router(client, Registry(), HOST, SITE, IDENTIFIER, {"name": "x"})
    assert result["status"] == "dry_run"
    assert "_verified" not in result
    assert [method for method, *_ in client.calls] == ["GET", "PUT"]
    preview = await rt.update_global_network_config(client, Registry(), HOST, SITE, {"a": 1})
    assert preview["preview"]["body"] == {"ipv6_enabled": False, "keep": 1, "a": 1}
    action = await rt.recover_loop_blocked_ports(client, Registry(), HOST, SITE)
    assert action["status"] == "dry_run" and action["preview"]["body"] is None


def test_bgp_and_ospf_secret_routes_are_registered_unverified() -> None:
    for name, path in (
        ("bgp-config-password", "network/v2/api/site/default/bgp/config/all"),
        ("ospf-router-password", f"network/v2/api/site/default/ospf/router/{IDENTIFIER}"),
    ):
        entry = next(e for e in rs.ROUTE_SECRETS if e.name == name)
        assert entry.verified is False
        assert entry.matches("GET", path)


async def test_registers_twenty_one_typed_documented_tools_with_derived_access() -> None:
    mcp = FastMCP("routing-topology")
    rt.register(mcp, lambda: (Client(), Registry()))
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
            assert "Consequence" in (tool.description or "") or name == "generate_vlan_plan"


async def test_registered_tools_call_through_the_typed_wrappers() -> None:
    mcp = FastMCP("routing-topology")
    client = Client()
    rt.register(mcp, lambda: (client, Registry()))
    calls: dict[str, dict[str, Any]] = {
        "get_bgp_status": {},
        "create_bgp_config": {"config": {"a": 1}},
        "update_bgp_config": {"config_id": IDENTIFIER, "config": {"a": 1}},
        "delete_bgp_config": {"config_id": IDENTIFIER},
        "get_ospf_status": {"view": "neighbors"},
        "create_ospf_router": {"router": {"a": 1}},
        "update_ospf_router": {"router_id": IDENTIFIER, "router": {"a": 1}},
        "delete_ospf_router": {"router_id": IDENTIFIER},
        "get_global_network_config": {},
        "update_global_network_config": {"config": {"a": 1}},
        "get_mdns_settings": {},
        "migrate_network_to_layer3": {"network_id": IDENTIFIER, "request": {"name": "n"}},
        "suggest_network_settings": {},
        "generate_vlan_plan": {},
        "import_dhcp_reservations": {"reservations": {"a": 1}},
        "detach_from_orchestration": {"target": "settings", "object_id": OTHER},
        "manage_virtual_network": {"action": "create", "virtual_network": {"a": 1}},
        "get_loop_detection_status": {},
        "recover_loop_blocked_ports": {},
        "manage_mclag_group": {"action": "delete", "group_id": IDENTIFIER},
        "update_switch_stack": {"stack_id": IDENTIFIER, "stack": {"a": 1}},
    }
    assert set(calls) == TOOL_NAMES
    for name, args in calls.items():
        before = len(client.calls)
        await mcp.call_tool(name, {"host": HOST, "site": SITE, **args})
        assert len(client.calls) > before, name


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
    await rt.get_loop_detection_status(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    await rt.update_switch_stack(
        multikey_client, multikey_registry, uh.HOST, uh.SITE, uh.ARG_ID, {"name": "renamed"}
    )
    served = [s for s in up.served if not s.resolution]
    assert served and all(s.api_key == "k-beta" for s in served)
    assert any(s.path.endswith("/loop-detection/info") for s in served)
    assert any(s.method == "PUT" and "/stacking/" in s.path for s in served)
    await multikey_client.close()


async def test_delete_bgp_null_response_and_still_listed_is_not_success() -> None:
    class NoopDelete(Client):
        async def delete(self, path: str, *, key: None) -> Any:
            self.calls.append(("DELETE", path, None, None))
            return None

    client = NoopDelete(rows=[{"id": IDENTIFIER}])
    result = await rt.delete_bgp_config(client, Registry(), HOST, SITE, IDENTIFIER)
    assert result == {
        "deleted": False,
        "message": f"BGP config {IDENTIFIER} is still listed after delete.",
        "response": None,
    }
    assert [call[0] for call in client.calls] == ["GET", "GET", "DELETE", "GET"]


async def test_delete_readback_absent_and_read_failure() -> None:
    class Deleted(Client):
        async def delete(self, path: str, *, key: None) -> Any:
            result = await super().delete(path, key=key)
            self.rows = []
            return result

    client = Deleted()
    result = await rt.delete_ospf_router(client, Registry(), HOST, SITE, IDENTIFIER)
    assert result["deleted"] is True
    assert result["response"] == {"echo": None, "path": f"{V2}/ospf/router/{IDENTIFIER}"}

    class FailedRead(Client):
        async def get(self, path: str, *, key: None, params: Any = None) -> Any:
            if len(self.calls) == 3:
                raise RuntimeError("read failed")
            return await super().get(path, key=key, params=params)

    result = await rt.delete_bgp_config(FailedRead(), Registry(), HOST, SITE, IDENTIFIER)
    assert result["deleted"] is None
    assert result["readAfterError"] == "RuntimeError: read failed"
    assert result["response"] == {"echo": None, "path": f"{V2}/bgp/config/{IDENTIFIER}"}


async def test_gateway_bgp_uses_singleton_routes_and_verifies_changes() -> None:
    class Gateway(Client):
        async def get(self, path: str, *, key: None, params: Any = None) -> Any:
            if path.endswith("/bgp/config"):
                self.calls.append(("GET", path, None, params))
                return copy.deepcopy(self.rows)
            return await super().get(path, key=key, params=params)

        async def post(self, path: str, *, key: None, json: Any) -> Any:
            assert path == f"{V2}/bgp/config"
            self.rows = [copy.deepcopy(json)]
            return self._write("POST", path, json)

        async def delete(self, path: str, *, key: None) -> Any:
            assert path == f"{V2}/bgp/config"
            self.rows = []
            self.calls.append(("DELETE", path, None, None))
            return None

    c = Gateway(rows=[{"_id": IDENTIFIER, "description": "original", "enabled": False}])
    updated = await rt.update_bgp_config(
        c, Registry(), HOST, SITE, IDENTIFIER, {"description": "updated"}
    )
    assert updated["_verified"] is True
    assert updated["echo"] == {"_id": IDENTIFIER, "description": "updated", "enabled": False}
    deleted = await rt.delete_bgp_config(c, Registry(), HOST, SITE, IDENTIFIER)
    assert deleted["deleted"] is True
    assert deleted["response"] is None
    assert c.rows == []


async def test_virtual_network_create_keeps_identity_update_drops_masks():
    from unifi_fabric.redaction import REDACTION_MASK, write_redaction_scope

    client, registry = Client(), Registry()
    with write_redaction_scope(True):
        await rt.manage_virtual_network(
            client, registry, HOST, SITE, "create", {"name": "v", "id": IDENTIFIER}
        )
        await rt.manage_virtual_network(
            client, registry, HOST, SITE, "update", {"name": "v", "password": REDACTION_MASK}, OTHER
        )
    assert client.calls[0][2] == {"name": "v", "id": IDENTIFIER}
    assert client.calls[1][2] == {"name": "v"}
