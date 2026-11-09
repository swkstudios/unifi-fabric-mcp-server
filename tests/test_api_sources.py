"""API-source classification (app / source / access) and UNIFI_EXCLUDE.

Properties:

* every registered tool has exactly one class ``app/source/access`` in its metadata, and
  its touched pairs are a valid subset of :data:`api_sources.APP_SOURCES`;
* the committed table equals the classification re-derived from the routes every tool
  actually calls on the hermetic fake upstream (so the classifier agrees with the route,
  and a new or re-routed tool fails here until ``python -m tests.api_sources_gen --write``);
* the access level equals the derived write set (``derive_write_tools``);
* the disable switch parses like every setting (empty is unset; unknown or repeated values
  fail fast listing the valid ones) and removes exactly the covered tools.
"""

from __future__ import annotations

import asyncio
import json
import logging

import pytest

from tests import api_sources_gen
from unifi_fabric import _read_only_audit, api_sources, policy, request_policy, server

CONSOLE = "/v1/connector/consoles/HOST:1/proxy"


def _tools() -> list:
    return list(asyncio.run(server.mcp.list_tools()))


@pytest.mark.parametrize(
    ("path", "pair"),
    [
        ("/v1/hosts", "site_manager/official"),
        ("/v1/isp-metrics/5m/query", "site_manager/official"),
        ("/ea/sites/000000000000000000000001/rest/firewallrule", "site_manager/private"),
        ("/v1/mobility/workspaces/w/devices", "mobility/official"),
        ("/v1/carrier/subscribers", "carrier_fabric/official"),
        (f"{CONSOLE}/network/integration/v1/sites", "network/official"),
        (f"{CONSOLE}/protect/integration/v1/cameras", "protect/official"),
        (f"{CONSOLE}/innerspace/integration/v1/floor_plans", "innerspace/official"),
        (f"{CONSOLE}/network/api/s/default/rest/networkconf", "network/private.classic"),
        (f"{CONSOLE}/network/api/self", "network/private.classic"),
        (f"{CONSOLE}/network/v2/api/site/default/trafficroutes", "network/private.v2"),
        (f"{CONSOLE}/network/status", "network/private.other"),
        (f"{CONSOLE}/protect/api/events?start=1", "protect/private"),
        (f"{CONSOLE}/protect/ws/livestream", "protect/private"),
        (f"{CONSOLE}/innerspace/api/x", "innerspace/private"),
        (f"{CONSOLE}/access/api/v1/doors", "console/private"),
        (f"{CONSOLE}/access/integration/v1/doors", "console/private"),
    ],
)
def test_route_source(path, pair):
    assert api_sources.route_source(path) == pair


def test_primary_pair_is_most_private_and_prefers_the_tool_app():
    assert api_sources.primary_pair(["site_manager/official", "network/official"]) == (
        "network/official"
    )
    assert (
        api_sources.primary_pair(
            ["site_manager/official", "network/official", "network/private.classic"]
        )
        == "network/private.classic"
    )
    assert api_sources.tool_pairs("fabric_connector_get", ["/v1/hosts"]) == ("relay/generic",)
    assert api_sources.tool_pairs("list_configured_api_keys", []) == ("server/local",)


def test_every_tool_has_exactly_one_valid_class():
    table = api_sources.table()
    for tool in _tools():
        meta = tool.meta or {}
        cls = meta.get(api_sources.META_CLASS)
        assert isinstance(cls, str), f"{tool.name}: no {api_sources.META_CLASS}"
        app, source, access = cls.split("/")
        assert source in api_sources.APP_SOURCES[app], cls
        assert access in api_sources.ACCESS, cls
        pairs = table[tool.name]
        for pair in pairs:
            p_app, p_source = pair.split("/", 1)
            assert p_source in api_sources.APP_SOURCES[p_app], (tool.name, pair)
        assert api_sources.primary_pair(pairs) == f"{app}/{source}"
    assert set(table) == {t.name for t in _tools()}, "table and catalog differ"


def test_substantive_source_overrides_are_present_in_the_route_table():
    table = api_sources.table()
    for name, dependencies in api_sources.TOOL_SUBSTANTIVE_SOURCES.items():
        assert name in table
        assert set(dependencies) <= set(table[name]), name


async def test_table_matches_routes_each_tool_calls(caplog):
    committed = api_sources.table()
    seen = set()
    drift = {}
    # Expected refusals exercise fallback routes. Their FastMCP error records
    # render expensive Rich/Pygments tracebacks and retain their frames (clients,
    # response bodies and tools) in pytest log handlers. Only paths enter this
    # audit's assertions, so avoid those errors while streaming the catalog.
    with caplog.at_level(logging.CRITICAL, logger="fastmcp"):
        async for name, pairs in api_sources_gen.iter_derived_async():
            seen.add(name)
            if committed.get(name) != pairs:
                drift[name] = (committed.get(name), pairs)
    for name in committed.keys() - seen:
        drift[name] = (committed[name], None)
    assert not drift, f"run python -m tests.api_sources_gen --write: {drift}"


async def test_port_reset_source_audit_covers_mac_and_device_lookup():
    tool = next(tool for tool in await server.mcp.list_tools() if tool.name == "reset_switch_port")
    direct = await api_sources_gen._paths("reset_switch_port", tool)
    device = api_sources_gen.uh.recorded("network_classic/network_api_s_SITE_stat_device.json")[
        "body"
    ]["data"][0]["name"]
    resolved = await api_sources_gen._paths("reset_switch_port", tool, overrides={"device": device})
    assert not any("/stat/device" in path for path in direct)
    assert any("/stat/device" in path for path in resolved)
    assert any("/ports/" in path and path.endswith("/reset") for path in resolved)


def test_access_level_matches_derived_write_set():
    tools = _tools()
    assert "list_hosts" in {tool.name for tool in tools}
    writes = _read_only_audit.derive_write_tools(tools)
    for tool in tools:
        expected = api_sources.WRITE if tool.name in writes else api_sources.READ
        if tool.name in api_sources.SELECTED_AS_READ:
            expected = api_sources.READ
        assert tool.meta[api_sources.META_CLASS].endswith("/" + expected), tool.name


@pytest.mark.parametrize("value", [None, "", "   ", " , "])
def test_unset_or_blank_disables_nothing(value):
    assert api_sources.parse_disabled_sources(value) == ()


@pytest.mark.parametrize(
    "value",
    [
        "network",
        "network/private",
        "network/private.classic",
        "network/private/write",
        "network/private.v2/read",
        "protect/write",
        "protect/private",
        "*/write",
        "*/private",
        "*/official/read",
        "relay",
        "site_manager/private",
        " Network/Private ",
        "site_manager/official,protect/private",
    ],
)
def test_valid_selectors_parse(value):
    assert api_sources.parse_disabled_sources(value)


@pytest.mark.parametrize(
    "value",
    [
        "netwrk",
        "network/private.foo",
        "protect/private.classic",
        "*",
        "network/read/write",
        "network/official/private",
        "network,network",
        "a/b/c/d",
    ],
)
def test_invalid_selectors_fail_fast_listing_valid_values(value):
    problem = api_sources.disabled_sources_problem(value)
    assert problem and "network/private.classic" in problem and "*/write" in problem
    with pytest.raises(ValueError):
        api_sources.parse_disabled_sources(value)
    assert api_sources.DISABLE_ENV in problem


def test_unknown_value_is_never_echoed():
    sentinel = "sk-live-sentinel-0123456789"
    problem = api_sources.disabled_sources_problem(f"network,{sentinel}")
    assert problem and sentinel not in problem and "item 1" in problem


def test_selector_matching():
    (sel,) = api_sources.parse_disabled_sources("network/private/write")
    assert sel.matches("network/private.classic", "write")
    assert not sel.matches("network/private.classic", "read")
    assert not sel.matches("network/official", "write")
    (sel,) = api_sources.parse_disabled_sources("*/write")
    assert sel.matches("protect/official", "write") and not sel.matches("protect/official", "read")
    # An official pair touched only for resolution never disables a tool.
    sels = api_sources.parse_disabled_sources("site_manager")
    assert not api_sources.is_disabled(("site_manager/official", "network/official"), "read", sels)
    # Any private surface a tool calls disables it.
    sels = api_sources.parse_disabled_sources("network/private.classic")
    assert api_sources.is_disabled(
        ("site_manager/official", "network/official", "network/private.classic"), "read", sels
    )
    # The placement snapshot consumes Protect data; this official source is not
    # merely shared host identity resolution.
    pairs = api_sources.table()["get_unifi_placement_snapshot"]
    sels = api_sources.parse_disabled_sources("protect/official/read")
    assert api_sources.is_disabled(pairs, "read", sels, tool_name="get_unifi_placement_snapshot")
    assert not api_sources.is_disabled(pairs, "read", sels)


@pytest.mark.parametrize(
    "value",
    [
        "network/private.classic",
        "protect/private",
        "protect/official",
        "protect/official/read",
        "*/write",
        "network",
        "relay",
    ],
)
async def test_filter_removes_exactly_the_covered_tools(value):
    from fastmcp import FastMCP

    table = api_sources.table()
    tools = {t.name: t for t in await server.mcp.list_tools()}
    selectors = api_sources.parse_disabled_sources(value)
    expected = {
        name
        for name, tool in tools.items()
        if api_sources.is_disabled(
            table[name], api_sources.selection_access(tool), selectors, tool_name=name
        )
    }
    assert expected, f"{value} covers no tool"
    app = FastMCP("copy")
    for tool in tools.values():
        app.add_tool(tool.model_copy())
    removed = await api_sources.apply_api_source_filter(app, value)
    assert set(removed) == expected
    remaining = {t.name for t in await app.list_tools()}
    assert remaining == set(tools) - expected


async def test_filter_default_is_a_no_op():
    from fastmcp import FastMCP

    app = FastMCP("copy")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool.model_copy())
    assert await api_sources.apply_api_source_filter(app, "") == []
    assert len(await app.list_tools()) == len(await server.mcp.list_tools())


@pytest.mark.parametrize("selector", ["protect", "protect/official", "protect/official/read"])
async def test_protect_source_selector_removes_placement_from_registration_and_discovery(selector):
    from fastmcp import FastMCP

    from unifi_fabric.discovery import apply_tool_mode

    tools = await server.mcp.list_tools()
    app = FastMCP("placement Protect dependency")
    for tool in tools:
        app.add_tool(tool.model_copy())

    removed = await api_sources.apply_api_source_filter(app, selector)
    assert "get_unifi_placement_snapshot" in removed
    registered = {tool.name for tool in await app.list_tools()}
    assert "get_unifi_placement_snapshot" not in registered

    restore = await apply_tool_mode(app, "discovery")
    try:
        assert {tool.name for tool in await app.list_tools()} >= {
            "search_tools",
            "describe_tool",
            "call_read_tool",
        }
        result = await app.call_tool(
            "search_tools", {"query": "unifi placement snapshot", "limit": None}
        )
        rows = json.loads(result.content[0].text)
        assert "get_unifi_placement_snapshot" not in {row["name"] for row in rows}
    finally:
        restore()


def test_wildcard_generic_and_local_are_advertised():
    assert {"*/generic", "*/local"} <= set(api_sources.valid_selectors())
    for selector in ("*/generic", "*/local"):
        assert api_sources.parse_disabled_sources(selector)


@pytest.mark.parametrize(
    "name",
    [
        "get_innerspace_project",
        "get_innerspace_asset",
        "get_innerspace_summary",
    ],
)
async def test_conditional_fallback_source_supports_per_tool_override(name):
    from fastmcp import FastMCP

    tools = {t.name: t for t in await server.mcp.list_tools()}
    paths = await api_sources_gen._paths(name, tools[name], fail_first_path=True)
    if name == "get_innerspace_asset":
        assert any("/innerspace/integration/v1/assets/" in path for path in paths)
        assert api_sources_gen.PAIR_OVERRIDES[name] == ("innerspace/private",)
    else:
        assert any("/innerspace/api/project" in path for path in paths)
        assert name not in api_sources_gen.PAIR_OVERRIDES
    assert "innerspace/private" in api_sources.table()[name]
    app = FastMCP("conditional fallback override")
    app.add_tool(tools[name].model_copy())
    assert await api_sources.apply_api_source_filter(app, "innerspace/private") == [name]


@pytest.mark.parametrize(("selector", "removed"), [("*/write", True), ("*/read", False)])
async def test_unclassified_tool_is_treated_as_write_and_logs_error(selector, removed, caplog):
    from fastmcp import FastMCP

    app = FastMCP("unclassified")

    @app.tool(annotations={"readOnlyHint": True})
    def unclassified_probe() -> str:
        return "synthetic"

    actual = await api_sources.apply_api_source_filter(app, selector)
    assert actual == (["unclassified_probe"] if removed else [])
    assert any(
        record.levelname == "ERROR"
        and "classification" in record.message.lower()
        and "unclassified_probe" in record.message
        for record in caplog.records
    )


def test_generic_relays_are_not_disabled_by_private_source():
    pairs = ("relay/generic",)
    assert not api_sources.is_disabled(
        pairs, "write", api_sources.parse_disabled_sources("*/private")
    )
    for selector in ("relay", "*/generic"):
        assert api_sources.is_disabled(pairs, "write", api_sources.parse_disabled_sources(selector))


@pytest.mark.parametrize("selector", ["*/write", "relay/write", "relay/generic/write"])
async def test_write_selector_keeps_mixed_get_relay(selector):
    from fastmcp import FastMCP

    app = FastMCP("mixed-relay-source-selection")
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    for name in ("fabric_connector_get", "fabric_connector_post"):
        app.add_tool(tools[name].model_copy())
    assert api_sources.tool_access(tools["fabric_connector_get"]) == api_sources.WRITE
    assert await api_sources.apply_api_source_filter(app, selector) == ["fabric_connector_post"]
    assert {tool.name for tool in await app.list_tools()} == {"fabric_connector_get"}


async def test_mixed_get_relay_published_class_matches_selector_filtering():
    from fastmcp import FastMCP

    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    tool = tools["fabric_connector_get"]
    assert api_sources.tool_access(tool) == api_sources.WRITE
    assert api_sources.selection_access(tool) == api_sources.READ
    assert api_sources.selection_access(tools["fabric_connector_post"]) == api_sources.WRITE
    published = tool.meta[api_sources.META_CLASS]
    assert published == "relay/generic/read"
    pair = api_sources.table()["fabric_connector_get"]
    assert published == api_sources.class_id(pair, api_sources.selection_access(tool))
    for selector in (published, "relay/read", "*/read"):
        parsed = api_sources.parse_disabled_sources(selector)
        assert api_sources.is_disabled(
            pair, api_sources.selection_access(tool), parsed, tool_name=tool.name
        )
        app = FastMCP("class-agreement")
        app.add_tool(tool.model_copy())
        assert await api_sources.apply_api_source_filter(app, selector) == ["fabric_connector_get"]
    write_class = "relay/generic/write"
    assert not api_sources.is_disabled(
        pair,
        api_sources.selection_access(tool),
        api_sources.parse_disabled_sources(write_class),
        tool_name=tool.name,
    )


@pytest.mark.parametrize("selector", ["*/read", "relay/read", "relay/generic/read", "relay"])
async def test_read_or_relay_selector_removes_mixed_get_relay(selector):
    from fastmcp import FastMCP

    app = FastMCP("mixed-relay-source-selection")
    tool = await server.mcp.get_tool("fabric_connector_get")
    app.add_tool(tool.model_copy())
    assert await api_sources.apply_api_source_filter(app, selector) == ["fabric_connector_get"]
    assert not await app.list_tools()


@pytest.mark.parametrize("name", ["authorize_guest", "revoke_guest_access"])
def test_guest_fallback_advertises_classic_source(name):
    from unifi_fabric._api_source_table import TOOL_API_SOURCES

    assert "network/private.classic" in TOOL_API_SOURCES[name]


async def test_camera_snapshot_ts_branch_is_classified_protect_private():
    """``ts`` reaches the private recording-snapshot route, so protect/private covers it."""
    tool = next(t for t in await server.mcp.list_tools() if t.name == "get_camera_snapshot")
    live = await api_sources_gen._paths("get_camera_snapshot", tool)
    past = await api_sources_gen._paths(
        "get_camera_snapshot",
        tool,
        overrides=api_sources_gen.ARG_VARIANTS["get_camera_snapshot"][0],
    )
    assert not any(path.endswith("/recording-snapshot") for path in live)
    assert any(path.endswith("/recording-snapshot") for path in past)
    assert "protect/private" in api_sources.table()["get_camera_snapshot"]
    selectors = api_sources.parse_disabled_sources("protect/private")
    tool_access = api_sources.selection_access(tool)
    assert api_sources.is_disabled(
        api_sources.table()["get_camera_snapshot"],
        tool_access,
        selectors,
        tool_name="get_camera_snapshot",
    )


@pytest.mark.parametrize(
    "name,pair",
    [
        ("list_known_clients", "network/private.v2"),
        ("restart_device", "network/private.classic"),
    ],
)
async def test_optional_argument_private_branches_are_classified(name, pair):
    """An optional argument that switches to a private route keeps that source listed."""
    tool = next(t for t in await server.mcp.list_tools() if t.name == name)
    paths = []
    for variant in api_sources_gen.ARG_VARIANTS[name]:
        paths += await api_sources_gen._paths(name, tool, overrides=variant)
    assert pair in api_sources.tool_pairs(name, paths)
    assert pair in api_sources.table()[name]
    selectors = api_sources.parse_disabled_sources(pair)
    access = api_sources.selection_access(tool)
    assert api_sources.is_disabled(api_sources.table()[name], access, selectors, tool_name=name)


async def test_list_clients_official_private_split_classifies_and_selects_independently():
    """The official list stays available when its private v2 counterpart is excluded."""
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    assert set(tools["list_clients"].parameters["properties"]) == {
        "host",
        "site",
        "offset",
        "limit",
        "client_type",
        "filter",
    }
    assert set(tools["list_active_clients"].parameters["properties"]) == {
        "host",
        "site",
        "include_matter_thread_clients",
        "include_traffic_usage",
        "include_unifi_devices",
    }
    official_paths = await api_sources_gen._paths("list_clients", tools["list_clients"])
    private_paths = await api_sources_gen._paths(
        "list_active_clients", tools["list_active_clients"]
    )
    official_pairs = api_sources.tool_pairs("list_clients", official_paths)
    private_pairs = api_sources.tool_pairs("list_active_clients", private_paths)

    assert "network/official" in official_pairs
    assert not any(api_sources.is_private(pair.split("/", 1)[1]) for pair in official_pairs)
    assert "network/private.v2" in private_pairs
    assert api_sources.primary_pair(official_pairs) == "network/official"
    assert api_sources.primary_pair(private_pairs) == "network/private.v2"

    selectors = api_sources.parse_disabled_sources("network/private.v2")
    assert not api_sources.is_disabled(official_pairs, "read", selectors, tool_name="list_clients")
    assert api_sources.is_disabled(
        private_pairs, "read", selectors, tool_name="list_active_clients"
    )

    catalog = request_policy.catalog_from_tools(tools.values())
    unofficial = policy.operator_policy({"UNIFI_EXCLUDE": "unofficial"}, catalog)
    assert policy.is_exposed(unofficial, catalog.tools["list_clients"])
    assert not policy.is_exposed(unofficial, catalog.tools["list_active_clients"])
