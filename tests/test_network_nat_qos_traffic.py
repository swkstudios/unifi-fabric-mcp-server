"""NAT / QoS / content-filter / traffic tools (GS3 lane NC): routes, validation, drains,
verification, dry-run, binary export, registration and multi-key routing.

Hermetic: synthetic upstream bodies only; no controller is contacted.
"""

from __future__ import annotations

import base64
import copy
from typing import Any

import httpx
import pytest
from fastmcp import FastMCP

from tests import upstream_harness as uh
from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiConnectionError
from unifi_fabric.tools import network_nat_qos_traffic as nc

HOST = "console-a"
SITE = "Default"
IDENTIFIER = "65f1c0ffee0123456789abcd"
OTHER = "65f1c0ffee0123456789abce"
V2 = "/v1/connector/consoles/host-1/proxy/network/v2/api/site/default"

TOOL_NAMES = {
    "list_nat_rules",
    "create_nat_rule",
    "update_nat_rule",
    "delete_nat_rule",
    "list_qos_rules",
    "create_qos_rule",
    "update_qos_rule",
    "delete_qos_rule",
    "reorder_qos_rules",
    "list_content_filters",
    "create_content_filter",
    "update_content_filter",
    "delete_content_filter",
    "list_content_filter_categories",
    "get_traffic_stats",
    "get_latest_traffic_flow_stats",
    "query_traffic_flows",
    "export_traffic_flows",
    "query_app_traffic_rates",
    "get_poe_info",
    "get_topology_snapshot",
}
WRITES = {
    name
    for name in TOOL_NAMES
    if name.split("_", 1)[0] in {"create", "update", "delete", "reorder"}
} | {"export_traffic_flows", "query_app_traffic_rates"}
NO_ROUTE = {"get_country_traffic", "get_network_dpi_statistics"}


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


class _Resp:
    def __init__(self, content: bytes, content_type: str | None) -> None:
        self.content = content
        self.headers = {"content-type": content_type} if content_type else {}
        self.status_code = 200

    @property
    def text(self) -> str:
        return self.content.decode()

    def json(self) -> Any:
        import json

        return json.loads(self.content)


class Client:
    """A synthetic upstream: collections at the three list routes, an echo elsewhere."""

    def __init__(
        self,
        rows: Any = None,
        *,
        dry_run: bool = False,
        pages: list[Any] | None = None,
        export: _Resp | None = None,
        max_pages: int | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.paginate_max_pages = max_pages
        self.rows = (
            rows
            if rows is not None
            else [{"_id": IDENTIFIER, "name": "original", "settings": {"keep": True}}]
        )
        self.pages = pages
        self.export = export
        self.calls: list[tuple[str, str, Any, Any]] = []

    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None, params))
        if path.endswith(("/nat", "/qos-rules", "/content-filtering")):
            return copy.deepcopy(self.rows)
        return {"path": path}

    def _write(self, method: str, path: str, body: Any, params: Any = None) -> Any:
        self.calls.append((method, path, body, params))
        if self.dry_run:
            return {
                "status": "dry_run",
                "dryRun": True,
                "message": DRY_RUN_MESSAGE,
                "preview": {"method": method, "path": path, "params": params, "body": body},
            }
        if self.pages is not None and path.endswith(("/traffic-flows", "/export")):
            number = (body or {}).get("pageNumber", 0)
            return copy.deepcopy(self.pages[min(number, len(self.pages) - 1)])
        return {"echo": body, "path": path}

    async def post(self, path: str, *, key: None, json: Any, params: Any = None) -> Any:
        return self._write("POST", path, json, params)

    async def put(self, path: str, *, key: None, json: Any) -> Any:
        return self._write("PUT", path, json)

    async def delete(self, path: str, *, key: None) -> Any:
        return self._write("DELETE", path, None)

    async def request(
        self, method: str, path: str, *, key: None, json: Any = None, accept: str | None = None
    ) -> Any:
        if self.export is not None and self.pages is None and not self.dry_run:
            self.calls.append((method, path, json, None))
            return self.export
        body = self._write(method, path, json)
        import json as _json

        return _Resp(_json.dumps(body).encode(), "application/json")


def _page(number: int, total: int, data: list[Any]) -> dict[str, Any]:
    return {
        "data": data,
        "has_next": number + 1 < total,
        "page_number": number,
        "total_element_count": 5,
        "total_page_count": total,
    }


async def test_every_tool_uses_its_inventoried_v2_route() -> None:
    client, registry = Client(), Registry()
    args = (client, registry, HOST, SITE)
    await nc.list_nat_rules(*args)
    await nc.create_nat_rule(*args, {"description": "n"})
    await nc.update_nat_rule(*args, IDENTIFIER, {"enabled": False})
    await nc.delete_nat_rule(*args, IDENTIFIER)
    await nc.list_qos_rules(*args)
    await nc.create_qos_rule(*args, {"name": "q"})
    await nc.update_qos_rule(*args, IDENTIFIER, {"enabled": False})
    await nc.delete_qos_rule(*args, [IDENTIFIER])
    await nc.reorder_qos_rules(*args, [IDENTIFIER])
    await nc.list_content_filters(*args)
    await nc.create_content_filter(*args, {"name": "c"})
    await nc.update_content_filter(*args, IDENTIFIER, {"enabled": False})
    await nc.delete_content_filter(*args, IDENTIFIER)
    await nc.list_content_filter_categories(*args)
    await nc.get_traffic_stats(
        *args, {"start": 1710000000000, "end": 1710003600000, "includeUnidentified": True}
    )
    await nc.get_latest_traffic_flow_stats(*args, "DAY", 10)
    await nc.query_traffic_flows(*args, {"timestampFrom": 1})
    await nc.export_traffic_flows(*args, {"timestampFrom": 1})
    await nc.query_app_traffic_rates(*args, {"period": "day"})
    await nc.get_poe_info(*args, {"mac": "02:00:5e:00:00:a1"})
    await nc.get_topology_snapshot(*args)
    await nc.get_topology_snapshot(*args, "timeline", 1710000000000, 1710003600000)
    await nc.get_topology_snapshot(*args, "timestamps", 1710000000000, 1710003600000)
    await nc.get_topology_snapshot(*args, "at", at=1710000000000)

    sent = {(method, path.removeprefix(V2)) for method, path, _, _ in client.calls}
    assert sent == {
        ("GET", "/nat"),
        ("POST", "/nat"),
        ("PUT", f"/nat/{IDENTIFIER}"),
        ("DELETE", f"/nat/{IDENTIFIER}"),
        ("GET", "/qos-rules"),
        ("POST", "/qos-rules"),
        ("PUT", f"/qos-rules/{IDENTIFIER}"),
        ("POST", "/qos-rules/batch-delete"),
        ("PUT", "/qos-rules/batch-reorder"),
        ("GET", "/content-filtering"),
        ("POST", "/content-filtering/create"),
        ("PUT", f"/content-filtering/{IDENTIFIER}"),
        ("DELETE", f"/content-filtering/{IDENTIFIER}"),
        ("GET", "/content-filtering/categories"),
        ("GET", "/traffic"),
        ("GET", "/traffic-flow-latest-statistics"),
        ("POST", "/traffic-flows"),
        ("POST", "/traffic-flows/export"),
        ("POST", "/app-traffic-rate"),
        ("GET", "/poe-info"),
        ("GET", "/topology/snapshot/live"),
        ("GET", "/topology/snapshot/history/timeline"),
        ("GET", "/topology/snapshot/history/timestamps"),
        ("GET", "/topology/snapshot/history/at/1710000000000"),
    }
    assert all(path.startswith(V2) for _, path, _, _ in client.calls)
    queries = {path.removeprefix(V2): params for _, path, _, params in client.calls if params}
    assert queries["/traffic"] == {
        "start": 1710000000000,
        "end": 1710003600000,
        "includeUnidentified": True,
    }
    assert queries["/traffic-flow-latest-statistics"] == {"period": "DAY", "top": 10}
    assert queries["/poe-info"] == {"mac": "02:00:5e:00:00:a1"}
    assert queries["/app-traffic-rate"] == {"period": "day"}
    assert queries["/topology/snapshot/history/timeline"] == {
        "start": 1710000000000,
        "end": 1710003600000,
    }


async def test_bodies_and_list_results_pass_through_verbatim() -> None:
    rows = [{"_id": IDENTIFIER, "x_unknown": [1, {"n": None}], "pfx": "198.51.100.0/24"}]
    client = Client(rows)
    assert await nc.list_nat_rules(client, Registry(), HOST, SITE) == rows
    body = {"description": "d", "rules": [{"port": 443}], "_extra": 1}
    result = await nc.create_nat_rule(client, Registry(), HOST, SITE, body)
    assert result["echo"] == body
    reorder = [OTHER, IDENTIFIER]
    result = await nc.reorder_qos_rules(client, Registry(), HOST, SITE, reorder)
    assert result["echo"] == reorder


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: nc.list_nat_rules(c, r, "", SITE),
        lambda c, r: nc.list_qos_rules(c, r, HOST, "  "),
        lambda c, r: nc.create_nat_rule(c, r, HOST, SITE, "not-an-object"),
        lambda c, r: nc.update_nat_rule(c, r, HOST, SITE, "bad id", {"enabled": True}),
        lambda c, r: nc.update_qos_rule(c, r, HOST, SITE, IDENTIFIER, {}),
        lambda c, r: nc.update_content_filter(c, r, HOST, SITE, IDENTIFIER, {"_id": "x"}),
        lambda c, r: nc.delete_content_filter(c, r, HOST, SITE, "a/b"),
        lambda c, r: nc.delete_nat_rule(c, r, HOST, SITE, "../x"),
        lambda c, r: nc.delete_qos_rule(c, r, HOST, SITE, "text"),
        lambda c, r: nc.reorder_qos_rules(c, r, HOST, SITE, 7),
        lambda c, r: nc.get_traffic_stats(c, r, HOST, SITE, ["x"]),
        lambda c, r: nc.get_poe_info(c, r, HOST, SITE, "x"),
        lambda c, r: nc.get_latest_traffic_flow_stats(c, r, HOST, SITE, 5),
        lambda c, r: nc.get_latest_traffic_flow_stats(c, r, HOST, SITE, None, True),
        lambda c, r: nc.get_latest_traffic_flow_stats(c, r, HOST, SITE, None, 1.5),
        lambda c, r: nc.query_traffic_flows(c, r, HOST, SITE, ["x"]),
        lambda c, r: nc.export_traffic_flows(c, r, HOST, SITE, "x"),
        lambda c, r: nc.query_app_traffic_rates(c, r, HOST, SITE, None, ["x"]),
        lambda c, r: nc.get_topology_snapshot(c, r, HOST, SITE, "history"),
        lambda c, r: nc.get_topology_snapshot(c, r, HOST, SITE, "live", 1),
        lambda c, r: nc.get_topology_snapshot(c, r, HOST, SITE, "at"),
        lambda c, r: nc.get_topology_snapshot(c, r, HOST, SITE, "at", 1, at=1),
        lambda c, r: nc.get_topology_snapshot(c, r, HOST, SITE, "timeline", 1),
        lambda c, r: nc.get_topology_snapshot(c, r, HOST, SITE, "timeline", 1, 2, 3),
        lambda c, r: nc.get_topology_snapshot(c, r, HOST, SITE, "timeline", True, 2),
        lambda c, r: nc.get_topology_snapshot(c, r, HOST, SITE, "at", at=1.5),
    ],
)
async def test_invalid_input_fails_before_any_resolution_or_request(call: Any) -> None:
    from unifi_fabric import refusals

    client, registry = Client(), Registry()
    with pytest.raises(ValueError) as excinfo:
        await call(client, registry)
    assert client.calls == []
    assert registry.calls == 0
    refusal = refusals.classify(str(excinfo.value))
    assert refusal is not None and refusal.category != refusals.UPSTREAM_JUDGED


async def test_update_merges_requested_leaves_and_verifies_type_strictly() -> None:
    client = Client()
    result = await nc.update_nat_rule(
        client, Registry(), HOST, SITE, IDENTIFIER.upper(), {"settings": {"level": 1}}
    )
    assert [method for method, *_ in client.calls] == ["GET", "PUT", "GET"]
    assert client.calls[1][1].endswith(f"/nat/{IDENTIFIER}")
    assert client.calls[1][2] == {
        "_id": IDENTIFIER,
        "name": "original",
        "settings": {"keep": True, "level": 1},
    }
    # The synthetic upstream did not apply the change: the read-back must say so.
    assert result["_verified"] is False
    assert "_readAfterError" not in result
    assert result["echo"] == client.calls[1][2]


async def test_update_verified_true_only_for_type_equal_leaves() -> None:
    client = Client([{"id": IDENTIFIER, "enabled": True}])
    result = await nc.update_qos_rule(client, Registry(), HOST, SITE, IDENTIFIER, {"enabled": True})
    assert result["_verified"] is True
    client = Client([{"_id": IDENTIFIER, "enabled": 1}])
    result = await nc.update_content_filter(
        client, Registry(), HOST, SITE, IDENTIFIER, {"enabled": True}
    )
    assert result["_verified"] is False


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
    result = await nc.update_content_filter(
        client, Registry(), HOST, SITE, IDENTIFIER, {"name": "x"}
    )
    assert result["_verified"] is None
    assert "read-back failed" in result["_readAfterError"]


async def test_update_non_object_write_response_is_kept_beside_the_verdict() -> None:
    client = Client()

    async def put(path: str, *, key: None, json: Any) -> Any:
        client.calls.append(("PUT", path, json, None))
        return None

    client.put = put  # type: ignore[method-assign]
    result = await nc.update_nat_rule(client, Registry(), HOST, SITE, IDENTIFIER, {"name": "x"})
    assert result["response"] is None and result["_verified"] is False


@pytest.mark.parametrize("tool", ["update", "delete", "batch-delete"])
async def test_unknown_id_fails_listing_every_valid_id_and_never_writes(tool: str) -> None:
    client = Client([{"_id": OTHER}, {"id": IDENTIFIER}])
    missing = "0000000000000000000000ff"
    with pytest.raises(ValueError, match=f"not found; valid choices: id={IDENTIFIER}, _id={OTHER}"):
        if tool == "update":
            await nc.update_nat_rule(client, Registry(), HOST, SITE, missing, {"name": "x"})
        elif tool == "delete":
            await nc.delete_content_filter(client, Registry(), HOST, SITE, missing)
        else:
            await nc.delete_qos_rule(client, Registry(), HOST, SITE, [IDENTIFIER, missing])
    assert [method for method, *_ in client.calls] == ["GET"]


async def test_delete_returns_upstream_body_and_object_batch_body_is_sent_as_given() -> None:
    client = Client()
    result = await nc.delete_nat_rule(client, Registry(), HOST, SITE, IDENTIFIER)
    assert result["deleted"] is True
    assert result["response"]["path"].endswith(f"/nat/{IDENTIFIER}")
    batch = {"ids": [IDENTIFIER]}
    result = await nc.delete_qos_rule(client, Registry(), HOST, SITE, batch)
    assert result["response"]["echo"] == batch
    # an object body is free-form: no resolution GET precedes it
    assert [m for m, *_ in client.calls[-1:]] == ["POST"]
    assert client.calls[-2][0] == "DELETE"


@pytest.mark.parametrize("rows", [{"unexpected": True}, "text", [1, 2]])
async def test_unexpected_collection_shape_raises_with_shape(rows: Any) -> None:
    client = Client(rows)
    with pytest.raises(UniFiConnectionError, match="Unexpected response shape"):
        await nc.delete_nat_rule(client, Registry(), HOST, SITE, IDENTIFIER)
    assert [method for method, *_ in client.calls] == ["GET"]


async def test_classic_data_envelope_is_accepted_for_resolution() -> None:
    client = Client({"meta": {"rc": "ok"}, "data": [{"_id": IDENTIFIER}]})
    await nc.delete_content_filter(client, Registry(), HOST, SITE, IDENTIFIER)
    assert client.calls[-1][0] == "DELETE"


async def test_dry_run_returns_preview_for_every_write_without_read_after() -> None:
    client = Client(dry_run=True)
    args = (client, Registry(), HOST, SITE)
    previews = [
        await nc.create_nat_rule(*args, {"description": "d"}),
        await nc.update_qos_rule(*args, IDENTIFIER, {"name": "x"}),
        await nc.delete_nat_rule(*args, IDENTIFIER),
        await nc.delete_qos_rule(*args, [IDENTIFIER]),
        await nc.reorder_qos_rules(*args, [IDENTIFIER]),
        await nc.export_traffic_flows(*args, {"a": 1}),
        await nc.query_app_traffic_rates(*args, {"period": "day"}, {"a": 1}),
    ]
    for preview in previews:
        if "deleted" in preview:
            # A delete returns the deletion_result dry-run shape; the preview is under response.
            assert set(preview) == {"status", "deleted", "message", "response"}, preview
            assert preview["status"] == "dry_run" and preview["deleted"] is False
            assert preview["message"] == DRY_RUN_MESSAGE
            preview = preview["response"]
        assert preview["status"] == "dry_run" and preview["dryRun"] is True
        assert preview["message"] == DRY_RUN_MESSAGE
        assert set(preview["preview"]) == {"method", "path", "params", "body"}
        assert "_verified" not in preview and "deleted" not in preview
    assert previews[-1]["preview"]["params"] == {"period": "day"}
    # GETs: the update's read-before and the two delete resolutions; no read-after
    methods = [m for m, *_ in client.calls]
    assert methods == ["POST", "GET", "PUT", "GET", "DELETE", "GET", "POST", "PUT"] + ["POST"] * 2


async def test_query_traffic_flows_drains_every_page_in_order() -> None:
    pages = [_page(0, 3, [{"f": 0}, {"f": 1}]), _page(1, 3, [{"f": 2}]), _page(2, 3, [{"f": 3}])]
    client = Client(pages=pages)
    body = {"timestampFrom": 1710000000000, "pageSize": 1000}
    result = await nc.query_traffic_flows(client, Registry(), HOST, SITE, body)
    assert result["data"] == [{"f": 0}, {"f": 1}, {"f": 2}, {"f": 3}]
    assert result["_pages"] == 3
    assert result["has_next"] is False and "incomplete" not in result
    sent = [c[2] for c in client.calls]
    assert sent == [
        body,
        {**body, "pageSize": 2, "pageNumber": 1},
        {**body, "pageSize": 2, "pageNumber": 2},
    ]
    assert result["_pageSize"] == {
        "requested": 1000,
        "sent": [1000, 2, 2],
        "effective": 2,
        "returned": 4,
    }


async def test_query_traffic_flows_starts_at_the_requested_page_and_uses_total_count() -> None:
    pages = [
        {"data": [{"f": 0}], "total_page_count": 3},
        {"data": [{"f": 1}], "total_page_count": 3},
        {"data": [{"f": 2}], "total_page_count": 3},
    ]
    client = Client(pages=pages)
    result = await nc.query_traffic_flows(client, Registry(), HOST, SITE, {"pageNumber": 1})
    assert result["data"] == [{"f": 1}, {"f": 2}]
    assert [c[2]["pageNumber"] for c in client.calls] == [1, 2]


async def test_single_page_response_is_returned_verbatim() -> None:
    page = _page(0, 1, [{"f": 0}])
    client = Client(pages=[page])
    assert await nc.query_traffic_flows(client, Registry(), HOST, SITE) == page
    assert client.calls[0][2] is None


async def test_repeated_page_stops_with_incomplete() -> None:
    first = _page(0, 3, [{"f": 0}])
    repeat = {**_page(0, 3, [{"f": 0}])}
    client = Client(pages=[first, repeat])
    result = await nc.query_traffic_flows(client, Registry(), HOST, SITE, {})
    assert result["incomplete"] is True
    assert "repeated page 0" in result["incompleteReason"]
    assert result["data"] == [{"f": 0}]


async def test_empty_page_claiming_more_stops_with_incomplete() -> None:
    client = Client(pages=[_page(0, 9, [])])
    result = await nc.query_traffic_flows(client, Registry(), HOST, SITE, {})
    assert result["incomplete"] is True and "empty" in result["incompleteReason"]


async def test_traffic_flows_drains_every_page_even_with_global_cap() -> None:
    pages = [_page(n, 5, [{"f": n}]) for n in range(5)]
    client = Client(pages=pages, max_pages=2)
    result = await nc.query_traffic_flows(client, Registry(), HOST, SITE, {})
    assert result["data"] == [{"f": n} for n in range(5)]
    assert "incomplete" not in result


@pytest.mark.parametrize(
    "page",
    [
        {"data": [1], "has_next": "yes"},
        {"data": [1], "total_page_count": "3"},
        {"data": "x", "has_next": True},
    ],
)
async def test_wrong_typed_page_controls_raise_naming_the_shape(page: dict[str, Any]) -> None:
    client = Client(pages=[page])
    with pytest.raises(UniFiConnectionError, match="Unexpected response shape from POST"):
        await nc.query_traffic_flows(client, Registry(), HOST, SITE, {})


async def test_non_object_follow_up_page_raises() -> None:
    client = Client(pages=[_page(0, 2, [{"f": 0}]), ["not", "a", "page"]])
    with pytest.raises(UniFiConnectionError, match="page 1 expected an object"):
        await nc.query_traffic_flows(client, Registry(), HOST, SITE, {})


async def test_export_binary_is_base64_with_content_type() -> None:
    raw = bytes(range(256))
    client = Client(export=_Resp(raw, "application/octet-stream"))
    result = await nc.export_traffic_flows(client, Registry(), HOST, SITE, {"a": 1})
    assert result["contentType"] == "application/octet-stream"
    assert base64.b64decode(result["bodyBase64"]) == raw
    assert result["sizeBytes"] == 256


async def test_export_text_is_returned_whole() -> None:
    csv = "src,dst\n" + "192.0.2.1,198.51.100.2\n" * 5000
    client = Client(export=_Resp(csv.encode(), "text/csv; charset=utf-8"))
    result = await nc.export_traffic_flows(client, Registry(), HOST, SITE)
    assert result["body"] == csv and result["sizeBytes"] == len(csv)


async def test_export_paged_json_is_drained() -> None:
    import json

    first = _page(0, 2, [{"f": 0}])
    client = Client(
        pages=[first, _page(1, 2, [{"f": 1}])],
        export=_Resp(json.dumps(first).encode(), "application/json"),
    )
    result = await nc.export_traffic_flows(client, Registry(), HOST, SITE, {})
    assert result["data"] == [{"f": 0}, {"f": 1}]


async def test_topology_history_adds_epoch_millisecond_warnings() -> None:
    result = await nc.get_topology_snapshot(
        Client(), Registry(), HOST, SITE, "timeline", 1710000000000, 1710003600000
    )
    codes = {(w["code"], w["argument"]) for w in result["_warnings"]}
    assert codes == {("EPOCH_MILLISECONDS", "start"), ("EPOCH_MILLISECONDS", "end")}
    live = await nc.get_topology_snapshot(Client(), Registry(), HOST, SITE)
    assert "_warnings" not in live


async def test_registers_typed_documented_tools_with_derived_access() -> None:
    from unifi_fabric._read_only_audit import derive_write_tools

    mcp = FastMCP("nat-qos-traffic")
    nc.register(mcp, lambda: (Client(), Registry()))
    listed = await mcp.list_tools()
    tools = {tool.name: tool for tool in listed}
    assert set(tools) == TOOL_NAMES
    assert not NO_ROUTE & set(tools)
    assert derive_write_tools(list(listed)) == WRITES
    for name, tool in tools.items():
        description = tool.description or ""
        assert len(description) <= 2048, name
        assert "Required arguments: host, site" in description
        for field in tool.parameters["properties"].values():
            assert "e.g." in field.get("description", ""), (name, field)
            assert field.get("type") or field.get("anyOf"), (name, field)
        read_only = tool.annotations.read_only_hint if tool.annotations else None
        assert read_only is (name not in WRITES), name
        if name in WRITES:
            assert "dry-run preview" in description, name
            assert "simulat" not in description.lower(), name
        if name.startswith(("create_", "update_", "delete_", "reorder_")):
            assert "Consequence:" in description, name


async def test_tools_call_through_the_registered_wrappers() -> None:
    client = Client()
    mcp = FastMCP("nat-qos-traffic")
    nc.register(mcp, lambda: (client, Registry()))
    await mcp.call_tool("list_content_filter_categories", {"host": HOST, "site": SITE})
    await mcp.call_tool("get_topology_snapshot", {"host": HOST, "site": SITE, "view": "live"})
    await mcp.call_tool(
        "update_nat_rule",
        {"host": HOST, "site": SITE, "rule_id": IDENTIFIER, "rule": {"enabled": False}},
    )
    assert [m for m, *_ in client.calls] == ["GET", "GET", "GET", "PUT", "GET"]


_TOMCAT_400 = (
    '<!doctype html><html lang="en"><head><title>HTTP Status 400 \u2013 Bad Request</title>'
    "</head><body><h1>HTTP Status 400 \u2013 Bad Request</h1></body></html>"
)


class LiveNetworkUpstream(Client):
    """The three v2 routes as Network 11.0.89 answered them live (2026-10-28):

    - /traffic: HTTP 400 unless both start and end (epoch ms) are in the query;
    - /traffic-flow-latest-statistics: HTTP 400 unless period is HOUR, DAY, WEEK or MONTH
      (an omitted period, "day" and top alone all answer 400);
    - /poe-info: HTTP 400 without mac, {} for a MAC not in lowercase colon form, the
      device's PoE body for its lowercase colon MAC.
    """

    POE = {"poe_host_device_info": {"mac": "00:00:5e:00:53:01", "max_poe_usage": 45.0}}

    async def get(self, path: str, *, key: None, params: Any = None) -> Any:
        self.calls.append(("GET", path, None, params))
        query = dict(params or {})
        route = path.removeprefix(V2)
        bad = UniFiConnectionError(f"HTTP 400 from GET {path}: {_TOMCAT_400}", status=400)
        if route == "/traffic":
            if "start" not in query or "end" not in query:
                raise bad
            return {"client_usage_by_app": [], "total_usage_by_app": []}
        if route == "/traffic-flow-latest-statistics":
            if query.get("period") not in {"HOUR", "DAY", "WEEK", "MONTH"}:
                raise bad
            return {"all_count_by_region": {"DE": 13889}}
        if route == "/poe-info":
            if "mac" not in query:
                raise bad
            return copy.deepcopy(self.POE) if query["mac"] == "00:00:5e:00:53:01" else {}
        return await super().get(path, key=key, params=params)


async def test_latest_flow_stats_default_and_documented_period_reach_a_served_query() -> None:
    """E2E 0.7.0 bug 14: the default call and the documented period "day" answered 400."""
    client = LiveNetworkUpstream()
    mcp = FastMCP("nat-qos-traffic")
    nc.register(mcp, lambda: (client, Registry()))
    default = await mcp.call_tool("get_latest_traffic_flow_stats", {"host": HOST, "site": SITE})
    assert default.structured_content == {"all_count_by_region": {"DE": 13889}}
    hour = await mcp.call_tool(
        "get_latest_traffic_flow_stats", {"host": HOST, "site": SITE, "period": "HOUR", "top": 5}
    )
    assert hour.structured_content == {"all_count_by_region": {"DE": 13889}}
    assert [params for *_, params in client.calls] == [
        {"period": "DAY"},
        {"period": "HOUR", "top": 5},
    ]
    schema = {t.name: t for t in await mcp.list_tools()}["get_latest_traffic_flow_stats"]
    period = schema.parameters["properties"]["period"]
    assert {b["type"] for b in period["anyOf"]} == {"string", "null"}
    assert period["default"] == "DAY"
    assert '"day"' not in (schema.description or "")


async def test_traffic_stats_legacy_query_and_valid_window() -> None:
    client = LiveNetworkUpstream()
    mcp = FastMCP("nat-qos-traffic")
    nc.register(mcp, lambda: (client, Registry()))
    schema = {t.name: t for t in await mcp.list_tools()}["get_traffic_stats"]
    assert set(schema.parameters["required"]) == {"host", "site"}
    params = {"start": 1793188385000, "end": 1793191985000, "future": [1, 2]}
    result = await mcp.call_tool(
        "get_traffic_stats", {"host": HOST, "site": SITE, "params": params}
    )
    assert {k: v for k, v in result.structured_content.items() if k != "_warnings"} == {
        "client_usage_by_app": [],
        "total_usage_by_app": [],
    }
    assert [
        (w["argument"], w["value"], w["code"]) for w in result.structured_content["_warnings"]
    ] == [
        ("start", 1793188385000, "EPOCH_MILLISECONDS"),
        ("end", 1793191985000, "EPOCH_MILLISECONDS"),
    ]
    assert client.calls == [("GET", f"{V2}/traffic", None, params)]
    client.calls.clear()
    with pytest.raises(UniFiConnectionError) as info:
        await nc.get_traffic_stats(client, Registry(), HOST, SITE)
    assert info.value.status == 400
    assert client.calls == [("GET", f"{V2}/traffic", None, None)]


async def test_poe_info_legacy_query_and_valid_mac() -> None:
    client = LiveNetworkUpstream()
    mcp = FastMCP("nat-qos-traffic")
    nc.register(mcp, lambda: (client, Registry()))
    schema = {t.name: t for t in await mcp.list_tools()}["get_poe_info"]
    assert set(schema.parameters["required"]) == {"host", "site"}
    params = {"mac": "00:00:5e:00:53:01", "future": [1]}
    result = await mcp.call_tool("get_poe_info", {"host": HOST, "site": SITE, "params": params})
    assert result.structured_content == LiveNetworkUpstream.POE
    assert client.calls == [("GET", f"{V2}/poe-info", None, params)]
    client.calls.clear()
    with pytest.raises(UniFiConnectionError) as info:
        await nc.get_poe_info(client, Registry(), HOST, SITE)
    assert info.value.status == 400
    assert client.calls == [("GET", f"{V2}/poe-info", None, None)]


async def test_all_tools_are_registered_on_the_real_server() -> None:
    from unifi_fabric import server

    names = {tool.name for tool in await server.mcp.list_tools()}
    assert TOOL_NAMES <= names
    assert not NO_ROUTE & names


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
    await nc.list_nat_rules(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    await nc.update_qos_rule(
        multikey_client, multikey_registry, uh.HOST, uh.SITE, uh.ARG_HEX, {"name": "renamed"}
    )
    await nc.query_traffic_flows(multikey_client, multikey_registry, uh.HOST, uh.SITE, {})
    served = [s for s in up.served if not s.resolution]
    assert served and all(s.api_key == "k-beta" for s in served)
    assert any(s.method == "PUT" and "/v2/api/site/" in s.path for s in served)
    await multikey_client.close()


def test_traffic_flow_body_without_body_or_selectors_sends_no_body() -> None:
    assert nc._traffic_flow_body(None, None, None, None, None) is None


def test_traffic_flow_body_preserves_explicit_keys() -> None:
    body = {"timestampFrom": 1, "direction": "caller", "other": 42}
    result = nc._traffic_flow_body(body, "5m", "outgoing", "allowed", ["high"])
    assert result is not None
    assert result["timestampFrom"] == 1 and result["direction"] == "caller"
    assert result["other"] == 42 and result["action"] == ["allowed"]
    assert result["risk"] == ["high"] and isinstance(result["timestampTo"], int)
    assert body == {"timestampFrom": 1, "direction": "caller", "other": 42}


async def test_app_traffic_rate_without_body_sends_the_empty_object_the_route_requires() -> None:
    # Live: no body answers HTTP 400 "Required request body is missing"; the Network 11.0.89
    # web app posts {} when it filters no app or client.
    client, registry = Client(), Registry()
    await nc.query_app_traffic_rates(
        client, registry, HOST, SITE, {"start": 1, "end": 2, "includeUnidentified": True}
    )
    method, path, body, params = client.calls[-1]
    assert (method, path.removeprefix(V2)) == ("POST", "/app-traffic-rate")
    assert body == {}
    assert params == {"start": 1, "end": 2, "includeUnidentified": True}
