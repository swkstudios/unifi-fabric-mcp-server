"""Catalog-wide per-key shape boundaries retain every healthy key's results."""

from __future__ import annotations

from pathlib import Path

import pytest

from unifi_fabric.client import DrainedItems
from unifi_fabric.tools import aggregation, carrier_fabric, mobility, site_manager

#: The repository root: every file this module reads is anchored here, never the cwd.
ROOT = Path(__file__).resolve().parents[1]

CATALOG = [
    (site_manager.list_hosts, True, {}),
    (site_manager.list_sites, True, {}),
    (site_manager.list_devices, True, {}),
    (site_manager.list_all_sites_aggregated, True, {}),
    (site_manager.list_sdwan_configs, False, {}),
    (site_manager.get_isp_metrics, False, {"interval": "5m"}),
    (mobility.list_mobility_workspaces, False, {}),
    (carrier_fabric.list_carrier_service_plans, False, {}),
    (carrier_fabric.list_carrier_subscribers, False, {}),
    (aggregation._list_all_devices_fleet, False, {}),
    (aggregation._search_device, False, {"query": "healthy"}),
    (aggregation._fleet_summary, True, {}),
    (aggregation._list_all_clients_fleet, True, {}),
]


@pytest.mark.parametrize(
    "tool,needs_registry,kwargs", CATALOG, ids=[x[0].__name__ for x in CATALOG]
)
@pytest.mark.parametrize("bad", [7, "broken", []])
async def test_all_fanout_record_lists_isolate_malformed_key(
    multikey_client, multikey_registry, monkeypatch, tool, needs_registry, kwargs, bad
):
    client, registry = multikey_client, multikey_registry

    def records(path, key):
        healthy = {
            "id": "host-beta",
            "hostId": "host-beta",
            "siteId": "site-beta",
            "name": "healthy",
            "status": "online",
            "productLine": "network",
        }
        if path.endswith("/sites") and path != "/v1/sites":
            healthy["id"] = "00000000-0000-4000-8000-000000000001"
        item = bad if key.label == "alpha" else healthy
        return (
            [{"hostId": "host-" + key.label, "devices": [item]}]
            if path == "/v1/devices"
            else [item]
        )

    async def paginate(path, *, key=None, **kw):
        return DrainedItems(records(path, key), envelope={"traceId": key.label})

    async def get(path, *, key=None, **kw):
        return {"data": records(path, key), "meta": {"hasMore": False}}

    monkeypatch.setattr(client, "paginate", paginate)
    monkeypatch.setattr(client, "get", get)
    monkeypatch.setattr(client, "paginate_offset", paginate)
    args = (client, registry) if needs_registry else (client,)
    result = await tool(*args, **kwargs)
    assert result["_key_labels"] == ["beta"], result
    assert len(result["errors"]) == 1 and "alpha:" in result["errors"][0], result
    if tool is aggregation._fleet_summary:
        assert result["devices"]["total"] == 1
    else:
        assert len(result["data"]) == 1, result
        assert result["data"][0]["_keyLabel"] == "beta", result


@pytest.mark.parametrize("field", ["status", "state", "productLine", "type"])
@pytest.mark.parametrize("bad", [[], {}, 42, True])
async def test_summary_breakdown_validation_is_inside_key_boundary(
    multikey_client, multikey_registry, monkeypatch, field, bad
):
    client, registry = multikey_client, multikey_registry

    async def paginate(path, *, key=None, **kw):
        if path != "/v1/devices":
            return [{"id": key.label, "hostId": key.label}]
        return [
            {
                "hostId": key.label,
                "devices": [{"name": "healthy", field: bad if key.label == "alpha" else "online"}],
            }
        ]

    monkeypatch.setattr(client, "paginate", paginate)
    result = await aggregation._fleet_summary(client, registry)
    assert result["_key_labels"] == ["beta"]
    assert result["devices"]["total"] == 1
    assert "alpha:" in result["errors"][0]


@pytest.mark.parametrize("bad", [None, [], "bad", 7])
async def test_fleet_clients_malformed_rows_are_site_errors(
    multikey_client, multikey_registry, monkeypatch, bad
):
    client, registry = multikey_client, multikey_registry

    async def pairs(registry, *, key, **kw):
        return [
            {
                "hostId": key.label,
                "siteId": "00000000-0000-4000-8000-000000000001",
                "hostName": key.label,
                "siteName": key.label,
            }
        ]

    async def paginate(path, *, key, **kw):
        return [{"id": "good", "name": "healthy"}] if key.label == "beta" else [bad]

    monkeypatch.setattr(aggregation, "_get_all_host_site_pairs", pairs)
    monkeypatch.setattr(client, "paginate_offset", paginate)
    result = await aggregation._list_all_clients_fleet(client, registry)
    assert result["_sitesFailed"] == 1, result
    assert result["_sitesSucceeded"] == 1, result
    assert result["data"] == [
        {
            "id": "good",
            "name": "healthy",
            "_hostId": "beta",
            "_hostName": "beta",
            "_siteId": "00000000-0000-4000-8000-000000000001",
            "_siteName": "beta",
            "_keyLabel": "beta",
        }
    ]
    assert len(result["errors"]) == 1 and "alpha:" in result["errors"][0]


@pytest.mark.parametrize("bad", [None, [], "bad", 7])
async def test_site_search_malformed_scope_rows_are_errors(
    multikey_client, multikey_registry, monkeypatch, bad
):
    client, registry = multikey_client, multikey_registry
    uuid = "00000000-0000-4000-8000-000000000001"

    async def sites(*, key):
        return [{"hostId": "h1", "siteId": "s1", "name": "healthy"}] if key.label == "beta" else []

    async def proxy_site(registry, record, key):
        return {"id": uuid, "name": "healthy"}

    async def paginate(path, *, key, **kw):
        return [bad] if path.endswith("/devices") else [{"id": "good", "name": "healthy"}]

    monkeypatch.setattr(registry, "get_ea_sites", sites)
    monkeypatch.setattr(site_manager, "_proxy_site_for_ea", proxy_site)
    monkeypatch.setattr(client, "paginate_offset", paginate)
    result = await site_manager.search_across_sites(client, registry, "healthy")
    assert len(result["errors"]) == 1, result
    assert result["errors"][0]["scope"] == "devices", result
    assert len(result["data"]) == 1, result


async def test_comparison_keeps_healthy_site_on_malformed_health_body(
    multikey_client, multikey_registry, monkeypatch
):
    async def health(client, registry, site):
        if site == "bad":
            raise site_manager.UniFiConnectionError("Unexpected GET /health response: null")
        return {"data": [{"subsystem": "wan", "status": "ok"}]}

    monkeypatch.setattr(site_manager, "get_site_health_summary", health)
    result = await site_manager.compare_site_performance(
        multikey_client, multikey_registry, ["bad", "good"]
    )
    assert "error" in result["_comparison"][0]
    assert result["_comparison"][1]["data"] == [{"subsystem": "wan", "status": "ok"}]


@pytest.mark.parametrize("bad", [[], "bad", 7])
async def test_query_isp_metrics_routes_and_validates_inside_each_key(
    multikey_client, multikey_registry, monkeypatch, bad
):

    from unifi_fabric import server

    client, registry = multikey_client, multikey_registry
    monkeypatch.setattr(server, "_require", lambda: (client, registry))

    async def owner(host):
        return client.get_key_by_label(host)

    async def host_id(host, *, key):
        return host

    async def site_id(site, *, host_id, key):
        return site

    async def post(path, *, key, **kw):
        return {
            "data": {"metrics": [bad] if key.label == "alpha" else [{"id": "good", "periods": []}]}
        }

    monkeypatch.setattr(registry, "resolve_key_for_host", owner)
    monkeypatch.setattr(registry, "resolve_host_id", host_id)
    monkeypatch.setattr(registry, "resolve_ea_site_id", site_id)
    monkeypatch.setattr(client, "post", post)
    result = await server.query_isp_metrics(
        "5m", sites=[{"hostId": "alpha", "siteId": "s1"}, {"hostId": "beta", "siteId": "s2"}]
    )
    assert result["_key_labels"] == ["beta"], result
    assert len(result["errors"]) == 1 and "alpha:" in result["errors"][0]
    assert result["data"]["metrics"] == [{"id": "good", "periods": [], "_keyLabel": "beta"}]


def test_every_fanout_site_has_a_catalog_property():
    import ast

    roots = {
        "fan_out",
        "fan_out_scopes",
        "_aggregate_lists_over_keys",
        "key_scopes",
        "_fleet_devices",
        "_fleet_summary",
        "_list_all_clients_fleet",
    }
    discovered = set()
    for path in (ROOT / "src" / "unifi_fabric").rglob("*.py"):
        if path.name == "_keys.py":
            continue
        for node in ast.parse(path.read_text()).body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = {
                call.func.id if isinstance(call.func, ast.Name) else call.func.attr
                for call in ast.walk(node)
                if isinstance(call, ast.Call) and isinstance(call.func, (ast.Name, ast.Attribute))
            }
            if roots & calls:
                discovered.add((path.stem, node.name))
    covered = {(fn.__module__.rsplit(".", 1)[-1], fn.__name__) for fn, _, _ in CATALOG}
    covered |= {
        ("server", "query_isp_metrics"),
        ("site_manager", "search_across_sites"),
        ("aggregation", "_fleet_devices"),  # exercised through both public consumers
        ("aggregation", "register"),  # wrappers delegate to the tested handlers
    }
    assert discovered == covered, (
        f"Fanout catalog changed; add properties for {discovered ^ covered}"
    )


@pytest.mark.parametrize(
    "tool,needs_registry,kwargs",
    [
        row
        for row in CATALOG
        if row[0]
        in {
            site_manager.list_hosts,
            site_manager.list_sdwan_configs,
            aggregation._fleet_summary,
            mobility.list_mobility_workspaces,
            carrier_fabric.list_carrier_service_plans,
            carrier_fabric.list_carrier_subscribers,
        }
    ],
)
async def test_nonnullable_fanout_items_still_reject_null(
    multikey_client, multikey_registry, monkeypatch, tool, needs_registry, kwargs
):
    await test_all_fanout_record_lists_isolate_malformed_key(
        multikey_client, multikey_registry, monkeypatch, tool, needs_registry, kwargs, None
    )


def _nullable_response_arrays(spec_name, path, method):
    import json

    spec = json.loads((ROOT / "tests" / "fixtures" / "openapi" / spec_name).read_text())
    schema = spec["paths"][path][method]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]

    def walk(node, location=()):
        if "$ref" in node:
            ref = node["$ref"]
            node = spec
            for part in ref.split("/")[1:]:
                node = node[part]
        if node.get("type") == "array":
            if node["items"].get("nullable"):
                yield location
            yield from walk(node["items"], (*location, 0))
        for name, child in node.get("properties", {}).items():
            yield from walk(child, (*location, name))

    # All current pinned response schemas are inline; refs remain an explicit failure.
    return list(walk(schema))


FANOUT_ROUTES = [
    (row, "site-manager-1.0.0.json", path, "get")
    for row in CATALOG
    for path in {
        site_manager.list_hosts: ["/v1/hosts"],
        site_manager.list_sites: ["/v1/sites"],
        site_manager.list_devices: ["/v1/devices"],
        site_manager.list_all_sites_aggregated: ["/v1/sites"],
        site_manager.list_sdwan_configs: ["/v1/sd-wan-configs"],
        site_manager.get_isp_metrics: ["/v1/isp-metrics/{type}"],
        aggregation._list_all_devices_fleet: ["/v1/devices"],
        aggregation._search_device: ["/v1/devices"],
        aggregation._fleet_summary: ["/v1/hosts", "/v1/sites", "/v1/devices"],
        aggregation._list_all_clients_fleet: ["/v1/sites"],
    }.get(row[0], [])
]
FANOUT_ROUTES += [
    (
        (mobility.list_mobility_workspaces, False, {}),
        "mobility-1.0.0.json",
        "/v1/mobility/workspaces",
        "get",
    ),
    (
        (carrier_fabric.list_carrier_service_plans, False, {}),
        "carrier-fabric-1.0.0.json",
        "/v1/carrier/service-plans",
        "get",
    ),
    (
        (carrier_fabric.list_carrier_subscribers, False, {}),
        "carrier-fabric-1.0.0.json",
        "/v1/carrier/subscribers",
        "get",
    ),
    (
        (site_manager.search_across_sites, True, {"query": "healthy"}),
        "site-manager-1.0.0.json",
        "/v1/sites",
        "get",
    ),
]
NULLABLE_FANOUT_CASES = [
    (row, path, location)
    for row, spec, path, method in FANOUT_ROUTES
    for location in _nullable_response_arrays(spec, path, method)
]


@pytest.mark.parametrize("row,path,location", NULLABLE_FANOUT_CASES)
async def test_spec_nullable_fanout_items_preserve_healthy_keys(
    multikey_client, multikey_registry, monkeypatch, row, path, location
):
    import copy

    client, registry = multikey_client, multikey_registry
    tool, needs_registry, kwargs = row
    uuid = "00000000-0000-4000-8000-000000000001"

    def body(route, key):
        item = {
            "id": key.label,
            "hostId": key.label,
            "siteId": uuid,
            "name": "healthy",
            "status": "online",
            "productLine": "network",
        }
        if route.endswith("/sites") and route != "/v1/sites":
            item["id"] = uuid
        if route == "/v1/devices":
            data = [{"hostId": key.label, "devices": [item]}]
        elif route == "/v1/isp-metrics/5m":
            data = [{**item, "periods": [{"metricTime": "fixture"}]}]
        else:
            data = [item]
        payload = {"data": copy.deepcopy(data)}
        if key.label == "alpha" and route == path.replace("{type}", "5m"):
            array = payload
            for part in location:
                array = array[part]
            array.insert(0, None)
        return payload

    async def paginate(route, *, key=None, **kw):
        return DrainedItems(body(route, key)["data"], envelope={"traceId": key.label})

    async def get(route, *, key=None, **kw):
        return body(route, key)

    async def proxy_site(registry, record, key):
        return {"id": uuid, "name": "healthy"}

    monkeypatch.setattr(client, "paginate", paginate)
    monkeypatch.setattr(client, "paginate_offset", paginate)
    monkeypatch.setattr(client, "get", get)
    monkeypatch.setattr(site_manager, "_proxy_site_for_ea", proxy_site)
    args = (client, registry) if needs_registry else (client,)
    result = await tool(*args, **kwargs)
    assert result["_key_labels"] == ["alpha", "beta"], result
    assert not result.get("errors"), result
    if tool in {
        site_manager.list_sites,
        site_manager.list_all_sites_aggregated,
        site_manager.list_devices,
        aggregation._list_all_devices_fleet,
        site_manager.get_isp_metrics,
    }:
        if tool is aggregation._list_all_devices_fleet:
            # the fleet list flattens every console's devices: the null leads it
            assert result["data"][0] is None, (location, result)
        else:
            # the null the spec allows is forwarded at the array it was served in
            array = result
            for part in location:
                array = array[part]
            assert array[0] is None, (location, result)
    if tool is site_manager.list_devices:
        assert result["_count"] == 2
    if tool is aggregation._fleet_summary:
        assert result["devices"]["total"] == 2
        assert result["sites"] == 2


@pytest.mark.parametrize(
    "location",
    _nullable_response_arrays("site-manager-1.0.0.json", "/v1/isp-metrics/{type}/query", "post"),
)
async def test_query_isp_spec_nullable_items(
    multikey_client, multikey_registry, monkeypatch, location
):
    from unifi_fabric import server

    client, registry = multikey_client, multikey_registry
    monkeypatch.setattr(server, "_require", lambda: (client, registry))

    async def owner(host):
        return client.get_key_by_label(host)

    async def host_id(host, *, key):
        return host

    async def site_id(site, *, host_id, key):
        return site

    async def post(path, *, key, **kw):
        payload = {"data": {"metrics": [{"id": key.label, "periods": [{}]}]}}
        if key.label == "alpha":
            array = payload
            for part in location:
                array = array[part]
            array.insert(0, None)
        return payload

    monkeypatch.setattr(registry, "resolve_key_for_host", owner)
    monkeypatch.setattr(registry, "resolve_host_id", host_id)
    monkeypatch.setattr(registry, "resolve_ea_site_id", site_id)
    monkeypatch.setattr(client, "post", post)
    result = await server.query_isp_metrics(
        "5m", sites=[{"hostId": "alpha", "siteId": "s1"}, {"hostId": "beta", "siteId": "s2"}]
    )
    assert result["_key_labels"] == ["alpha", "beta"], result
    assert not result.get("errors"), result
    metrics = result["data"]["metrics"]
    if location == ("data", "metrics"):
        assert metrics[0] is None and metrics[1]["_keyLabel"] == "alpha"
    else:
        assert metrics[0]["periods"][0] is None


def test_changelog_documents_explicit_null_behavior():
    release = (ROOT / "CHANGELOG.md").read_text().split("## [0.7.0]", 1)[1]
    release = release.split("## [", 1)[0]
    guide = (ROOT / "docs" / "MIGRATING-0.7.md").read_text()
    assert "explicit null forwarding for Carrier and Mobility fields" in guide
    assert "Migration details" in release
    for field in (
        "name",
        "email",
        "notes",
        "service_address",
        "plan_id",
        "host_address",
        "dhcp_range_start",
        "dhcp_range_stop",
        "dhcp_lease_time",
        "dhcp_mode",
    ):
        assert f"`{field}`" in release
    assert "per-field null for unobservable fields (DHCP fields and password)" in release


def test_file_reads_are_anchored_to_the_repository_not_the_cwd():
    """Run from another directory, a cwd-relative ``Path("src/...")`` scans the wrong tree."""
    import ast

    relative = [
        f"line {node.lineno}: {node.args[0].value!r}"
        for node in ast.walk(ast.parse(Path(__file__).read_text()))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Path"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and not Path(node.args[0].value).is_absolute()
    ]
    assert relative == [], relative
