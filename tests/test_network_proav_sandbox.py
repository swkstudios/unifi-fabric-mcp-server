"""Network ProAV / Shadow Mode / sandbox tools: routes, validation, verification, registration.

Hermetic: synthetic upstream bodies only, no controller is contacted. Routes are the
Network 11.0.81 private-API inventory rows (tests/fixtures/private_api/
inventory_network_11.0.81.json).
"""

from __future__ import annotations

import copy
import inspect
import json
from typing import Any

import httpx
import pytest
from fastmcp import FastMCP

from tests import upstream_harness as uh
from unifi_fabric.client import DRY_RUN_MESSAGE, ClassicApiError, UniFiConnectionError
from unifi_fabric.families.network import network_proav_sandbox as sandbox

HOST = "console-a"
SITE = "Default"
IDENTIFIER = "65f1c0ffee0123456789abcd"
OTHER = "65f1c0ffee0123456789abce"
MAC = "02:00:5e:00:00:a1"
CONSOLE = "/v1/connector/consoles/host-1/proxy/network"
V2 = f"{CONSOLE}/v2/api/site/default"
AT_MS = 1760000000000

TOOL_NAMES = {
    "get_proav_matrix",
    "get_proav_snapshot",
    "create_proav_group",
    "update_proav_group",
    "delete_proav_group",
    "set_tv_wall_calibration",
    "get_shadow_mode_status",
    "control_shadow_mode_adoption",
    "list_test_configs",
    "create_test_config",
    "delete_test_config",
    "apply_test_config",
    "get_port_forward_statistics",
    "get_digital_twin_layout",
    "update_digital_twin_layout",
    "delete_digital_twin_layout",
    "get_5g_topology",
    "get_multicast_insights",
}
WRITES = {
    "create_proav_group",
    "update_proav_group",
    "delete_proav_group",
    "set_tv_wall_calibration",
    "control_shadow_mode_adoption",
    "create_test_config",
    "delete_test_config",
    "apply_test_config",
    "update_digital_twin_layout",
    "delete_digital_twin_layout",
    "get_multicast_insights",
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
    def __init__(
        self,
        rows: Any = None,
        *,
        layout: Any = None,
        dry_run: bool = False,
        classic: Any = None,
    ) -> None:
        self.dry_run = dry_run
        self.rows = rows if rows is not None else [{"_id": IDENTIFIER, "name": "trial"}]
        self.layout = (
            layout if layout is not None else {"zoom": 1, "nodes": {"keep": True}, "x_extra": [1]}
        )
        self.classic = classic if classic is not None else {"meta": {"rc": "ok"}, "data": []}
        self.calls: list[tuple[str, str, Any, Any]] = []

    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None, params))
        if path.endswith("/test-configs"):
            return copy.deepcopy(self.rows)
        if path.endswith("/digital-twin/layout"):
            return copy.deepcopy(self.layout)
        return {"path": path}

    async def request(self, method: str, path: str, *, key: None) -> httpx.Response:
        self.calls.append((method, path, None, None))
        body = self.classic
        content = body if isinstance(body, bytes) else json.dumps(body).encode()
        return httpx.Response(200, content=content, request=httpx.Request(method, "https://x"))

    def _write(self, method: str, path: str, body: Any, params: Any = None) -> Any:
        self.calls.append((method, path, body, params))
        if self.dry_run:
            return {
                "status": "dry_run",
                "dryRun": True,
                "message": DRY_RUN_MESSAGE,
                "preview": {"method": method, "path": path, "params": params, "body": body},
            }
        return {"echo": body, "path": path}

    async def post(self, path: str, *, key: None, json: Any = None, params: Any = None) -> Any:
        return self._write("POST", path, json, params)

    async def put(self, path: str, *, key: None, json: Any) -> Any:
        if path.endswith("/digital-twin/layout") and not self.dry_run:
            self.layout = copy.deepcopy(json)
        return self._write("PUT", path, json)

    async def delete(self, path: str, *, key: None) -> Any:
        return self._write("DELETE", path, None)


def _as_inventory(method: str, path: str) -> tuple[str, str]:
    """The inventory row for a sent request (ids and timestamps as ``{}``)."""
    route = path.replace(CONSOLE, "/proxy/network").replace("/site/default", "/site/{site}")
    route = route.replace("/api/s/default/", "/api/s/{site}/")
    for value in (IDENTIFIER, MAC, str(AT_MS)):
        route = route.replace(value, "{}")
    return method, route


async def _call_every_route(client: Client) -> None:
    registry = Registry()
    for kind in sandbox.PROAV_KINDS:
        await sandbox.get_proav_matrix(client, registry, HOST, SITE, kind)
        await sandbox.create_proav_group(client, registry, HOST, SITE, kind, {"name": "g"})
        await sandbox.update_proav_group(client, registry, HOST, SITE, kind, IDENTIFIER, {"a": 1})
        await sandbox.delete_proav_group(client, registry, HOST, SITE, kind, IDENTIFIER)
    await sandbox.get_proav_snapshot(client, registry, HOST, SITE, IDENTIFIER)
    for action in ("set", "unset"):
        await sandbox.set_tv_wall_calibration(client, registry, HOST, SITE, action, {"r": 2})
    for view in ("info", "managed_group"):
        await sandbox.get_shadow_mode_status(client, registry, HOST, SITE, view)
    for action in ("begin", "complete", "rollback"):
        await sandbox.control_shadow_mode_adoption(client, registry, HOST, SITE, action)
    await sandbox.list_test_configs(client, registry, HOST, SITE)
    await sandbox.create_test_config(client, registry, HOST, SITE, {"name": "trial"})
    await sandbox.delete_test_config(client, registry, HOST, SITE, IDENTIFIER)
    for action in ("apply", "commit"):
        await sandbox.apply_test_config(client, registry, HOST, SITE, IDENTIFIER, action)
    await sandbox.get_port_forward_statistics(client, registry, HOST, SITE)
    await sandbox.get_digital_twin_layout(client, registry, HOST, SITE)
    await sandbox.update_digital_twin_layout(client, registry, HOST, SITE, {"zoom": 2})
    await sandbox.delete_digital_twin_layout(client, registry, HOST, SITE)
    await sandbox.get_5g_topology(client, registry, HOST, SITE, MAC, AT_MS)
    for view in ("client", "clients", "history"):
        mac = MAC if view == "client" else None
        await sandbox.get_multicast_insights(client, registry, HOST, SITE, view, mac)


async def test_free_form_bodies_and_reads_pass_through_verbatim() -> None:
    rows = [{"_id": IDENTIFIER, "x_unknown": [1, {"n": None}], "nested": {"a": 1.5}}]
    client = Client(rows)
    assert await sandbox.list_test_configs(client, Registry(), HOST, SITE) == rows
    body = {"name": "n", "members": [{"mac": MAC}], "_extra": 1}
    for result in (
        await sandbox.create_proav_group(client, Registry(), HOST, SITE, "audio", body),
        await sandbox.create_test_config(client, Registry(), HOST, SITE, body),
        await sandbox.control_shadow_mode_adoption(client, Registry(), HOST, SITE, "begin", body),
        await sandbox.set_tv_wall_calibration(client, Registry(), HOST, SITE, "set", body),
        await sandbox.apply_test_config(client, Registry(), HOST, SITE, IDENTIFIER, "apply", body),
    ):
        assert result["echo"] == body
    unset = await sandbox.set_tv_wall_calibration(client, Registry(), HOST, SITE, "unset")
    assert unset["echo"] is None  # omitted body: none is invented


async def test_update_proav_group_puts_complete_body_without_read() -> None:
    client = Client()
    body = {"name": "wall", "members": []}
    result = await sandbox.update_proav_group(
        client, Registry(), HOST, SITE, "video", IDENTIFIER, body
    )
    assert [c[0] for c in client.calls] == ["PUT"]
    assert result["echo"] == body


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: sandbox.get_proav_matrix(c, r, HOST, SITE, "lighting"),
        lambda c, r: sandbox.get_proav_matrix(c, r, HOST, SITE, ""),
        lambda c, r: sandbox.get_proav_snapshot(c, r, HOST, SITE, "../x"),
        lambda c, r: sandbox.create_proav_group(c, r, HOST, SITE, "video", ["x"]),
        lambda c, r: sandbox.update_proav_group(c, r, HOST, SITE, "video", IDENTIFIER, {}),
        lambda c, r: sandbox.update_proav_group(c, r, HOST, SITE, "video", "a/b", {"a": 1}),
        lambda c, r: sandbox.update_proav_group(c, r, HOST, SITE, "video", IDENTIFIER, {"id": 1}),
        lambda c, r: sandbox.delete_proav_group(c, r, HOST, SITE, "audio", ""),
        lambda c, r: sandbox.set_tv_wall_calibration(c, r, HOST, SITE, "reset"),
        lambda c, r: sandbox.set_tv_wall_calibration(c, r, HOST, SITE, "set", "x"),
        lambda c, r: sandbox.get_shadow_mode_status(c, r, HOST, SITE, "managed"),
        lambda c, r: sandbox.control_shadow_mode_adoption(c, r, HOST, SITE, "start"),
        lambda c, r: sandbox.control_shadow_mode_adoption(c, r, HOST, SITE, "begin", [1]),
        lambda c, r: sandbox.create_test_config(c, r, HOST, SITE, "text"),
        lambda c, r: sandbox.delete_test_config(c, r, HOST, SITE, "bad id"),
        lambda c, r: sandbox.apply_test_config(c, r, HOST, SITE, IDENTIFIER, "rollback"),
        lambda c, r: sandbox.apply_test_config(c, r, HOST, SITE, IDENTIFIER, "apply", 1),
        lambda c, r: sandbox.update_digital_twin_layout(c, r, HOST, SITE, {}),
        lambda c, r: sandbox.update_digital_twin_layout(c, r, HOST, SITE, [1]),
        lambda c, r: sandbox.get_5g_topology(c, r, HOST, SITE, "bad id", AT_MS),
        lambda c, r: sandbox.get_5g_topology(c, r, HOST, SITE, MAC, True),
        lambda c, r: sandbox.get_5g_topology(c, r, HOST, SITE, MAC, 1.5),
        lambda c, r: sandbox.get_multicast_insights(c, r, HOST, SITE, "groups"),
        lambda c, r: sandbox.get_multicast_insights(c, r, HOST, SITE, "client"),
        lambda c, r: sandbox.get_multicast_insights(c, r, HOST, SITE, "client", "not-a-mac"),
        lambda c, r: sandbox.get_multicast_insights(c, r, HOST, SITE, "history", MAC),
        lambda c, r: sandbox.get_multicast_insights(c, r, HOST, SITE, "clients", None, [1]),
        lambda c, r: sandbox.get_multicast_insights(
            c, r, HOST, SITE, "clients", None, {"nested": {"a": 1}}
        ),
        lambda c, r: sandbox.list_test_configs(c, r, "", SITE),
        lambda c, r: sandbox.get_digital_twin_layout(c, r, HOST, " "),
    ],
)
async def test_invalid_input_fails_before_any_resolution_or_request(call: Any) -> None:
    client, registry = Client(), Registry()
    with pytest.raises(ValueError):
        await call(client, registry)
    assert client.calls == []
    assert registry.calls == 0


async def test_invalid_input_messages_name_the_argument_and_are_registered() -> None:
    from unifi_fabric import refusals

    cases = [
        (sandbox.get_proav_matrix(Client(), Registry(), HOST, SITE, "x"), "kind"),
        (sandbox.get_multicast_insights(Client(), Registry(), HOST, SITE, "client"), "client_mac"),
        (sandbox.get_5g_topology(Client(), Registry(), HOST, SITE, MAC, False), "at"),
        (sandbox.create_test_config(Client(), Registry(), HOST, SITE, 3), "test_config"),
        (
            sandbox.get_multicast_insights(
                Client(), Registry(), HOST, SITE, "clients", None, {"a": None}
            ),
            "query_params",
        ),
    ]
    for coro, arg in cases:
        with pytest.raises(ValueError) as info:
            await coro
        message = str(info.value)
        assert arg in message
        refusal = refusals.classify(message)
        assert refusal is not None and refusal.category != refusals.UPSTREAM_JUDGED, message


async def test_layout_update_merges_requested_leaves_and_verifies() -> None:
    client = Client()
    result = await sandbox.update_digital_twin_layout(
        client, Registry(), HOST, SITE, {"nodes": {"moved": [1, 2]}}
    )
    assert [c[0] for c in client.calls] == ["GET", "PUT", "GET"]
    assert client.calls[1][2] == {
        "zoom": 1,
        "nodes": {"keep": True, "moved": [1, 2]},
        "x_extra": [1],
    }
    assert result["_verified"] is True
    assert "_readAfterError" not in result
    assert result["echo"] == client.calls[1][2]


async def test_layout_update_not_applied_is_never_verified() -> None:
    class Ignoring(Client):
        async def put(self, path: str, *, key: None, json: Any) -> Any:
            return self._write("PUT", path, json)

    result = await sandbox.update_digital_twin_layout(
        Ignoring(), Registry(), HOST, SITE, {"zoom": True}
    )
    assert result["_verified"] is False


async def test_layout_update_int_is_not_bool() -> None:
    client = Client(layout={"zoom": 1})
    result = await sandbox.update_digital_twin_layout(
        client, Registry(), HOST, SITE, {"zoom": True}
    )
    # The synthetic upstream stored the merged body, so True round-trips as True.
    assert result["_verified"] is True
    client.layout = {"zoom": 1}

    async def stale_get(path: str, *, key: None, params: Any = None) -> Any:
        return {"zoom": 1}

    client.get = stale_get  # type: ignore[method-assign]
    result = await sandbox.update_digital_twin_layout(
        client, Registry(), HOST, SITE, {"zoom": True}
    )
    assert result["_verified"] is False


@pytest.mark.parametrize("current", [[], "text", 7])
async def test_layout_without_an_object_sends_the_requested_layout(current: Any) -> None:
    client = Client(layout=current)
    await sandbox.update_digital_twin_layout(client, Registry(), HOST, SITE, {"zoom": 2})
    assert client.calls[1][:3] == ("PUT", f"{V2}/digital-twin/layout", {"zoom": 2})


async def test_layout_read_after_failure_is_unknown_with_reason() -> None:
    client = Client()
    original = client.get
    count = 0

    async def flaky(path: str, *, key: None, params: Any = None) -> Any:
        nonlocal count
        count += 1
        if count == 2:
            raise UniFiConnectionError("synthetic read-back failure")
        return await original(path, key=key, params=params)

    client.get = flaky  # type: ignore[method-assign]
    result = await sandbox.update_digital_twin_layout(client, Registry(), HOST, SITE, {"zoom": 3})
    assert result["_verified"] is None
    assert "synthetic read-back failure" in result["_readAfterError"]


async def test_dry_run_returns_previews_and_never_verifies_or_deletes() -> None:
    client = Client(dry_run=True)
    layout = await sandbox.update_digital_twin_layout(client, Registry(), HOST, SITE, {"zoom": 3})
    assert layout["status"] == "dry_run" and layout["dryRun"] is True
    assert "_verified" not in layout
    assert [c[0] for c in client.calls] == ["GET", "PUT"]
    for result in (
        await sandbox.delete_digital_twin_layout(client, Registry(), HOST, SITE),
        await sandbox.delete_proav_group(client, Registry(), HOST, SITE, "audio", IDENTIFIER),
        await sandbox.delete_test_config(client, Registry(), HOST, SITE, IDENTIFIER),
    ):
        # A delete returns the deletion_result dry-run shape; the preview is under response.
        assert set(result) == {"status", "deleted", "message", "response"}
        assert result["status"] == "dry_run" and result["deleted"] is False
        assert result["message"] == DRY_RUN_MESSAGE
        assert result["response"]["preview"]["method"] == "DELETE"
    preview = await sandbox.get_multicast_insights(
        client, Registry(), HOST, SITE, "history", None, {"start": 1}
    )
    assert preview["preview"]["params"] == {"start": 1}
    assert preview["preview"]["body"] is None


async def test_deletes_report_the_upstream_body() -> None:
    result = await sandbox.delete_digital_twin_layout(Client(), Registry(), HOST, SITE)
    assert result["deleted"] is True
    assert result["response"] == {"echo": None, "path": f"{V2}/digital-twin/layout"}


@pytest.mark.parametrize("tool", ["delete", "apply"])
async def test_unknown_test_config_fails_listing_every_valid_id_and_never_writes(tool: str) -> None:
    client = Client([{"_id": OTHER, "name": "a"}, {"_id": IDENTIFIER, "name": "b"}])
    with pytest.raises(ValueError, match=f"not found; valid: 'a' \\(_id={OTHER}\\); 'b'"):
        if tool == "delete":
            await sandbox.delete_test_config(
                client, Registry(), HOST, SITE, "0000000000000000000000ff"
            )
        else:
            await sandbox.apply_test_config(
                client, Registry(), HOST, SITE, "0000000000000000000000ff"
            )
    assert [c[0] for c in client.calls] == ["GET"]


async def test_test_config_id_resolves_case_insensitively_from_data_envelope() -> None:
    client = Client({"meta": {"rc": "ok"}, "data": [{"_id": IDENTIFIER}]})
    await sandbox.apply_test_config(client, Registry(), HOST, SITE, IDENTIFIER.upper(), "commit")
    assert client.calls[-1][:2] == ("POST", f"{V2}/test-configs/{IDENTIFIER}/commit")


@pytest.mark.parametrize("rows", [{"unexpected": True}, "text", [1, 2]])
async def test_unexpected_test_config_list_shape_raises_with_shape(rows: Any) -> None:
    client = Client(rows)
    with pytest.raises(UniFiConnectionError, match="Unexpected response shape"):
        await sandbox.delete_test_config(client, Registry(), HOST, SITE, IDENTIFIER)
    assert [c[0] for c in client.calls] == ["GET"]


async def test_port_forward_statistics_requires_affirmative_rc() -> None:
    body = {"meta": {"rc": "ok"}, "data": [{"rule": "web", "rx_bytes": 1}]}
    assert (
        await sandbox.get_port_forward_statistics(Client(classic=body), Registry(), HOST, SITE)
        == body
    )
    for bad, reason in (
        ({"data": []}, "without the Classic meta envelope"),
        ({"meta": {"rc": "error", "msg": "api.err.Invalid"}, "data": []}, "api.err.Invalid"),
    ):
        with pytest.raises(ClassicApiError) as info:
            await sandbox.get_port_forward_statistics(Client(classic=bad), Registry(), HOST, SITE)
        assert reason in str(info.value)
        assert json.dumps(bad) in str(info.value)  # the full upstream body, never truncated


async def test_5g_topology_normalises_mac_and_warns_epoch_unit() -> None:
    client = Client()
    result = await sandbox.get_5g_topology(
        client, Registry(), HOST, SITE, "02-00-5E-00-00-A1", AT_MS
    )
    assert client.calls[0][1] == f"{V2}/observability/5g/{MAC}/topology/at/{AT_MS}"
    assert result["_warnings"][0]["code"] == "EPOCH_MILLISECONDS"
    assert "looks like epoch seconds" not in result["_warnings"][0]["message"]
    seconds = await sandbox.get_5g_topology(client, Registry(), HOST, SITE, IDENTIFIER, 1760000000)
    assert "looks like epoch seconds" in seconds["_warnings"][0]["message"]
    assert client.calls[1][1].endswith(f"/5g/{IDENTIFIER}/topology/at/1760000000")


class NotServedUpstream(Client):
    """The 5G topology route as Network 11.0.89 answered it live (2026-10-28) for an
    adopted 5G device that is not the site's internet connection: the bare Tomcat 404
    page an unserved path gets."""

    page = (
        '<!doctype html><html lang="en"><head><title>HTTP Status 404 \u2013 Not Found'
        "</title></head><body><h1>HTTP Status 404 \u2013 Not Found</h1></body></html>"
    )

    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None, params))
        if "/observability/5g/" in path:
            raise UniFiConnectionError(f"HTTP 404 from GET {path}: {self.page}", status=404)
        if "/throttled/" in path:
            raise UniFiConnectionError(f"HTTP 429 from GET {path}: throttled", status=429)
        return {"path": path}


async def test_5g_topology_404_keeps_the_upstream_page_and_adds_an_actionable_hint() -> None:
    """E2E 0.7.0 bug 13: the bare 404 reached the caller with no way forward."""
    client = NotServedUpstream()
    with pytest.raises(UniFiConnectionError) as info:
        await sandbox.get_5g_topology(client, Registry(), HOST, SITE, MAC, AT_MS)
    message = str(info.value)
    assert message.startswith(
        f"HTTP 404 from GET {V2}/observability/5g/{MAC}/topology/at/{AT_MS}: "
        + NotServedUpstream.page
    )
    assert "-- Hint: a 404 here means the console served no 5G topology" in message
    assert "list_devices, type umbb" in message
    assert len(client.calls) == 1


async def test_5g_topology_json_device_not_found_404_gets_the_same_actionable_hint() -> None:
    """Network 11.1.47 answers a MAC that is not a 5G device with JSON
    ``api.err.DeviceNotFound`` (the Network v2 error body: code, errorCode, message), not the
    HTML page. The hint must be true for that body and for the 11.0.89 HTML 404, which an
    adopted U5G Max in failover mode with no SIM also got: it must not say the device is not
    5G or that the site has none."""
    body = '{"code":"api.err.DeviceNotFound","errorCode":404,"message":"Device not found"}'

    class JsonNotFound(Client):
        async def get(self, path: str, *, key: None, params: Any = None) -> Any:
            raise UniFiConnectionError(f"HTTP 404 from GET {path}: {body}", status=404)

    with pytest.raises(UniFiConnectionError) as info:
        await sandbox.get_5g_topology(JsonNotFound(), Registry(), HOST, SITE, MAC, AT_MS)
    message = str(info.value)
    assert message.startswith(
        f"HTTP 404 from GET {V2}/observability/5g/{MAC}/topology/at/{AT_MS}: {body}"
    )
    hint = message.split(" -- Hint: ", 1)[1]
    assert (
        "Network 11.1.47 answers JSON api.err.DeviceNotFound when the MAC is not a 5G device"
        in hint
    )
    assert (
        "Network 11.0.89 answered its HTML 404 page even for an adopted U5G Max in failover "
        "mode with no SIM"
    ) in hint
    assert "Pass the MAC of a 5G device (list_devices, type umbb)" in hint
    assert "if list_devices shows no umbb device, the site has no 5G" in hint
    # The old wording blamed the device or the site on every 404, which was false on 11.0.89.
    assert "not a 5G device or the site has none" not in hint


async def test_5g_topology_other_upstream_errors_pass_through_unchanged() -> None:
    class Throttled(NotServedUpstream):
        async def get(self, path: str, *, key: None, params: Any = None) -> Any:
            return await super().get(path.replace("/observability/5g/", "/throttled/"), key=key)

    with pytest.raises(UniFiConnectionError) as info:
        await sandbox.get_5g_topology(Throttled(), Registry(), HOST, SITE, MAC, AT_MS)
    assert "Hint" not in str(info.value)
    assert info.value.status == 429


async def test_multicast_client_view_is_a_get_with_query() -> None:
    client = Client()
    await sandbox.get_multicast_insights(
        client, Registry(), HOST, SITE, "client", MAC.upper(), {"window": "1h"}
    )
    assert client.calls == [
        ("GET", f"{V2}/insights/multicast/client/{MAC}", None, {"window": "1h"})
    ]


async def test_multicast_list_views_post_query_parameters_without_body() -> None:
    client = Client()
    await sandbox.get_multicast_insights(client, Registry(), HOST, SITE, "clients", None, {"a": 1})
    assert client.calls == [("POST", f"{V2}/insights/multicast/clients", None, {"a": 1})]


async def test_registers_eighteen_typed_documented_tools_with_derived_access() -> None:
    from unifi_fabric._read_only_audit import derive_write_tools

    mcp = FastMCP("proav-sandbox")
    sandbox.register(mcp, lambda: (Client(), Registry()))
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    assert set(tools) == TOOL_NAMES
    assert derive_write_tools(list(tools.values())) == WRITES
    for name, tool in tools.items():
        description = tool.description or ""
        assert 0 < len(description) <= 2048, name
        assert "Args:" in (inspect.unwrap(tool.fn).__doc__ or ""), name
        assert {"host", "site"} <= set(tool.parameters.get("required", [])), name
        for field in tool.parameters["properties"].values():
            assert "e.g." in field.get("description", ""), (name, field)
            assert field.get("type") or field.get("anyOf"), (name, field)
        read_only = tool.annotations.read_only_hint if tool.annotations else None
        assert read_only is (name not in WRITES), name
        if name in WRITES:
            assert "dry-run preview" in description, name
            assert "Consequence:" in description, name


async def test_all_tools_are_registered_on_the_real_server() -> None:
    from unifi_fabric import server

    assert TOOL_NAMES <= {tool.name for tool in await server.mcp.list_tools()}


async def test_real_server_refuses_invalid_enum_before_any_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from unifi_fabric import server

    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    with pytest.raises(Exception, match="kind"):
        await server.mcp.call_tool(
            "get_proav_matrix", {"host": uh.HOST, "site": uh.SITE, "kind": "lighting"}
        )
    assert up.served == []


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
    await sandbox.list_test_configs(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    await sandbox.get_port_forward_statistics(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    await sandbox.delete_test_config(
        multikey_client, multikey_registry, uh.HOST, uh.SITE, uh.ARG_HEX
    )
    served = [s for s in up.served if not s.resolution]
    assert served and all(s.api_key == "k-beta" for s in served)
    assert any("/v2/api/site/" in s.path for s in served)
    assert any(s.path.endswith("/stat/portforward") for s in served)
    assert any(s.method == "DELETE" for s in served)
    await multikey_client.close()


async def test_multicast_query_params_accept_scalars_including_booleans() -> None:
    client = Client()
    params = {"window": "1h", "limit": 5, "ratio": 0.5, "includeIdle": True}
    await sandbox.get_multicast_insights(
        client, Registry(), HOST, SITE, "history", None, dict(params)
    )
    assert client.calls[0][3] == params


@pytest.mark.parametrize("tool", ["delete", "apply"])
async def test_test_config_uuid_id_from_live_v2_shape(tool: str) -> None:
    config_id = "00000000-0000-4000-8000-0000000000c1"
    client = Client(
        [{"conflicts": [], "entries": [], "id": config_id, "site_id": "site", "status": "STAGED"}]
    )
    if tool == "delete":
        await sandbox.delete_test_config(client, Registry(), HOST, SITE, config_id)
        assert client.calls[-1][:2] == ("DELETE", f"{V2}/test-configs/{config_id}")
    else:
        await sandbox.apply_test_config(client, Registry(), HOST, SITE, config_id)
        assert client.calls[-1][:2] == ("POST", f"{V2}/test-configs/{config_id}/apply")


class MulticastNotServed(Client):
    """Network 11.1.47 answered the multicast insight routes with the bare Tomcat 404 page."""

    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None, params))
        raise UniFiConnectionError(
            f"HTTP 404 from GET {path}: {NotServedUpstream.page}", status=404
        )

    async def post(self, path: str, *, key: None, params: Any = None, json: Any = None) -> Any:
        self.calls.append(("POST", path, json, params))
        raise UniFiConnectionError(
            f"HTTP 404 from POST {path}: {NotServedUpstream.page}", status=404
        )


@pytest.mark.parametrize(
    ("view", "mac", "method"),
    [("clients", None, "POST"), ("history", None, "POST"), ("client", MAC, "GET")],
)
async def test_multicast_404_keeps_the_upstream_page_and_adds_an_actionable_hint(
    view, mac, method
) -> None:
    client = MulticastNotServed()
    with pytest.raises(UniFiConnectionError) as info:
        await sandbox.get_multicast_insights(client, Registry(), HOST, SITE, view, mac)
    message = str(info.value)
    assert message.startswith(f"HTTP 404 from {method} {V2}/insights/multicast/")
    assert NotServedUpstream.page in message  # the upstream body stays verbatim
    assert (
        "-- Hint: an HTML 404 here means this console's Network application does not serve"
        in message
    )
    assert "get_network_application_info" in message
    assert len(client.calls) == 1 and info.value.status == 404


async def test_multicast_other_upstream_errors_pass_through_without_the_hint() -> None:
    class Throttled(MulticastNotServed):
        async def post(self, path: str, *, key: None, params: Any = None, json: Any = None) -> Any:
            raise UniFiConnectionError(f"HTTP 429 from POST {path}: throttled", status=429)

    with pytest.raises(UniFiConnectionError) as info:
        await sandbox.get_multicast_insights(Throttled(), Registry(), HOST, SITE, "clients")
    assert "Hint" not in str(info.value) and info.value.status == 429
