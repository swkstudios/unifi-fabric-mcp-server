"""Catalog regression audit tests.

Two layers:

1. **Hermetic (always in CI).** Unit tests for the pure comparison logic in
   ``unifi_fabric._catalog_audit`` plus guards that run against the *live registered*
   tool set (introspected from the imported FastMCP instance — no network, no creds):
   the gateway name transform must be collision-free and round-trip losslessly, a
   catalog that exactly mirrors the registrations must diff clean, and a deliberately
   dropped / injected name must be caught. These lock the naming contract the deployed
   catalog depends on and the drift-detection logic, without reaching the gateway.

2. **Mock deployed protocol (always in CI).** Exercise the real CLI fetch helper
   through hermetic initialize/list responses and diff the full registered catalog.
   Real deployed checks remain an explicit manual CLI operation, outside release tests.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
from pathlib import Path

import httpx
import pytest

from unifi_fabric import server
from unifi_fabric._catalog_audit import (
    DEFAULT_GATEWAY_SLUG,
    CatalogDiff,
    base_tool_name,
    catalog_base_names,
    diff_catalog,
    extract_catalog_names,
    federated_tool_name,
)

# Make scripts/ importable so the hermetic protocol test reuses the CLI fetch implementation.
_SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))


def _registered_tool_names() -> list[str]:
    """Authoritative registered tool names from the imported FastMCP instance."""
    result = server.mcp.list_tools()
    if inspect.isawaitable(result):
        result = asyncio.run(result)
    return [tool.name for tool in result]


# ---------------------------------------------------------------------------
# Pure transform: federated_tool_name / base_tool_name
# ---------------------------------------------------------------------------


def test_federated_tool_name_prefixes_and_hyphenates() -> None:
    assert federated_tool_name("list_lags", "unifi-fabric") == "unifi-fabric-list-lags"
    assert (
        federated_tool_name("list_mc_lag_domains", "unifi-fabric")
        == "unifi-fabric-list-mc-lag-domains"
    )
    # default slug is the generic gateway slug
    assert federated_tool_name("get_lag") == "unifi-fabric-get-lag"


def test_base_tool_name_inverts_transform() -> None:
    assert base_tool_name("unifi-fabric-list-lags", "unifi-fabric") == "list_lags"
    assert (
        base_tool_name("unifi-fabric-list-mc-lag-domains", "unifi-fabric") == "list_mc_lag_domains"
    )


def test_base_tool_name_returns_none_for_foreign_gateway() -> None:
    # A name from a different federated gateway must not be attributed to this one.
    assert base_tool_name("other-gateway-list-lags", "unifi-fabric") is None
    assert base_tool_name("example-mcp-recall", "unifi-fabric") is None


def test_transform_round_trips_for_every_registered_name() -> None:
    names = _registered_tool_names()
    assert "list_hosts" in names
    for name in names:
        assert base_tool_name(federated_tool_name(name)) == name


def test_federation_is_collision_free_across_registered_names() -> None:
    # Two distinct registered names must never collapse to the same federated name;
    # if they did, the deployed catalog would silently drop one of them.
    names = _registered_tool_names()
    federated = [federated_tool_name(n) for n in names]
    assert len(set(federated)) == len(names), "gateway name transform collides two tools"


# ---------------------------------------------------------------------------
# catalog_base_names / extract_catalog_names
# ---------------------------------------------------------------------------


def test_catalog_base_names_filters_foreign_and_maps_own() -> None:
    catalog = [
        "unifi-fabric-list-lags",
        "unifi-fabric-get-lag",
        "other-gateway-list-lags",  # foreign gateway -> dropped
        "example-mcp-recall",  # foreign gateway -> dropped
    ]
    assert catalog_base_names(catalog, "unifi-fabric") == {"list_lags", "get_lag"}


def test_extract_catalog_names_from_bare_list() -> None:
    assert extract_catalog_names(["a-b", "a-c"]) == ["a-b", "a-c"]


def test_extract_catalog_names_from_mcp_tools_list_result() -> None:
    payload = {"result": {"tools": [{"name": "gw-list_x"}, {"name": "gw-get_y"}]}}
    assert extract_catalog_names(payload) == ["gw-list_x", "gw-get_y"]


def test_extract_catalog_names_from_unwrapped_tools() -> None:
    payload = {"tools": [{"name": "gw-list_x"}]}
    assert extract_catalog_names(payload) == ["gw-list_x"]


def test_extract_catalog_names_from_data_envelope() -> None:
    assert extract_catalog_names({"data": ["gw-list_x", {"name": "gw-get_y"}]}) == [
        "gw-list_x",
        "gw-get_y",
    ]


def test_extract_catalog_names_rejects_unknown_shape() -> None:
    with pytest.raises(ValueError, match="unrecognised catalog snapshot shape"):
        extract_catalog_names({"unexpected": 1})
    with pytest.raises(ValueError, match="unrecognised catalog snapshot shape"):
        extract_catalog_names(42)


def test_extract_catalog_names_rejects_nameless_entry() -> None:
    with pytest.raises(ValueError, match="no string name"):
        extract_catalog_names([{"id": "x"}])


# ---------------------------------------------------------------------------
# diff_catalog + CatalogDiff
# ---------------------------------------------------------------------------


def test_diff_clean_when_catalog_mirrors_registrations() -> None:
    registered = _registered_tool_names()
    catalog = [federated_tool_name(n) for n in registered]
    diff = diff_catalog(registered, catalog)
    assert diff.is_clean, diff.summary()
    assert diff.missing_from_catalog == []
    assert diff.unexpected_in_catalog == []
    assert "in sync" in diff.summary()


def test_diff_flags_dropped_and_phantom_against_live_registrations() -> None:
    registered = _registered_tool_names()
    dropped = sorted(registered)[0]
    catalog = [federated_tool_name(n) for n in registered if n != dropped]
    catalog.append(federated_tool_name("zzz_synthetic_phantom_tool"))
    diff = diff_catalog(registered, catalog)
    assert not diff.is_clean
    assert dropped in diff.missing_from_catalog
    assert "zzz_synthetic_phantom_tool" in diff.unexpected_in_catalog
    summary = diff.summary()
    assert "DRIFT" in summary
    assert dropped in summary
    assert "zzz_synthetic_phantom_tool" in summary


def test_diff_missing_only() -> None:
    diff = diff_catalog(["list_a", "get_b"], ["unifi-fabric-list-a"])
    assert diff.missing_from_catalog == ["get_b"]
    assert diff.unexpected_in_catalog == []
    assert not diff.is_clean


def test_diff_unexpected_only() -> None:
    diff = diff_catalog(["list_a"], ["unifi-fabric-list-a", "unifi-fabric-get-stale"])
    assert diff.missing_from_catalog == []
    assert diff.unexpected_in_catalog == ["get_stale"]


def test_diff_ignores_other_gateways_entries() -> None:
    # A foreign-gateway entry in a mixed catalog is neither missing nor unexpected here.
    diff = diff_catalog(
        ["list_a"],
        ["unifi-fabric-list-a", "other-gateway-list-a"],
        gateway_slug="unifi-fabric",
    )
    assert diff.is_clean, diff.summary()


def test_catalog_diff_default_is_clean() -> None:
    assert CatalogDiff().is_clean


def test_default_gateway_slug_constant() -> None:
    assert DEFAULT_GATEWAY_SLUG == "unifi-fabric"


def test_deployed_catalog_matches_registered(respx_mock) -> None:
    """The deployed-catalog reader is exercised without ambient credentials or skips."""
    from check_catalog_regression import fetch_deployed_catalog_names

    registered = _registered_tool_names()
    endpoint = "https://catalog.invalid/mcp"

    def respond(request):
        message = json.loads(request.content)
        if message["method"] == "notifications/initialized":
            return httpx.Response(202)
        if message["method"] == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
        else:
            assert message["method"] == "tools/list"
            result = {"tools": [{"name": federated_tool_name(name)} for name in registered]}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})

    route = respx_mock.post(endpoint).mock(side_effect=respond)
    catalog_names = fetch_deployed_catalog_names(endpoint)
    diff = diff_catalog(registered, catalog_names, gateway_slug=DEFAULT_GATEWAY_SLUG)
    assert route.call_count == 3
    assert diff.is_clean, diff.summary()


@pytest.mark.parametrize("discovery", [False, True])
@pytest.mark.parametrize("gateway_slug", [DEFAULT_GATEWAY_SLUG, "custom-gateway"])
def test_live_catalog_comparison_caller_handles_mode_and_gateway_slug(
    respx_mock, discovery: bool, gateway_slug: str
) -> None:
    """Exercise fetch plus comparison against full and hidden discovery inventories."""
    from check_catalog_regression import compare_catalog, fetch_deployed_catalog_names

    registered = ["list_hosts", "get_site"]
    endpoint = "https://catalog-caller.invalid/mcp"
    domain_tools = [
        {"name": name, "inputSchema": {"type": "object", "properties": {}}} for name in registered
    ]
    meta_tools = [
        {"name": f"{gateway_slug}-{name.replace('_', '-')}"}
        for name in sorted(
            {
                "search_tools",
                "describe_tool",
                "call_read_tool",
                "call_write_tool",
                "list_tool_families",
            }
        )
    ]

    def respond(request):
        message = json.loads(request.content)
        method = message["method"]
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}}
        elif method == "tools/list":
            result = {
                "tools": meta_tools
                if discovery
                else [
                    {**tool, "name": f"{gateway_slug}-{tool['name'].replace('_', '-')}"}
                    for tool in domain_tools
                ]
            }
        else:
            assert discovery
            wire_name = message["params"]["name"]
            assert wire_name.startswith(f"{gateway_slug}-")
            name = wire_name.removeprefix(f"{gateway_slug}-").replace("-", "_")
            if name == "search_tools":
                data = [{"name": tool["name"]} for tool in domain_tools]
            else:
                assert name == "describe_tool"
                data = next(
                    t for t in domain_tools if t["name"] == message["params"]["arguments"]["name"]
                )
            result = {"content": [{"type": "text", "text": json.dumps(data)}]}
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": message.get("id"), "result": result},
        )

    route = respx_mock.post(endpoint).mock(side_effect=respond)
    names = fetch_deployed_catalog_names(endpoint, gateway_slug=gateway_slug)
    diff = compare_catalog(registered, names, gateway_slug)
    assert diff.is_clean, diff.summary()
    assert route.call_count == (3 + len(domain_tools) + 1 if discovery else 3)
