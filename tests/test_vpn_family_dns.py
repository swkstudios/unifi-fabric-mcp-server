"""The vpn family's DNS tools in the family-owned layout (public #42 step 4, the DNS pilot).

Layout: ``families/vpn/handlers.py`` (the handlers), ``schemas.py`` (routes, lookup and
argument shapes), ``registrar.py`` (the tool wrappers), registered through the loader map
at the place the tools held. Hermetic: synthetic upstream bodies only.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import typing
from typing import Any

import pytest

from tests import tool_args
from tests.test_network_vpn_dns import HOST, RECORD, SITE, V2, Client, Registry
from unifi_fabric import server
from unifi_fabric.catalog import load_catalog
from unifi_fabric.catalog.loaders import LOADERS
from unifi_fabric.families import (
    MODULE_FAMILY,
    build_family_index,
    build_module_index,
    tool_function_module,
)
from unifi_fabric.families.vpn import handlers, network_vpn_dns, schemas

DNS_TOOLS = (
    "list_static_dns_records",
    "create_static_dns_record",
    "update_static_dns_record",
    "delete_static_dns_record",
    "list_doh_servers",
)


def _tools() -> dict[str, Any]:
    return {t.name: t for t in asyncio.run(server.mcp.list_tools(run_middleware=False))}


# --------------------------------------------------------------------------- layout


def test_the_dns_tools_are_registered_by_the_vpn_registrar():
    tools = _tools()
    for name in DNS_TOOLS:
        fn = inspect.unwrap(tools[name].fn)
        assert fn.__module__ == "unifi_fabric.families.vpn.registrar", name
        # The DNS pilot's step is the second registrar step once the whole family moved.
        assert fn.__qualname__.startswith("register_2.<locals>."), name
    # The family's other tools are in the same registrar, in their own steps (L1-C).
    other = inspect.unwrap(tools["get_ipsec_settings"].fn)
    assert other.__module__ == "unifi_fabric.families.vpn.registrar"
    assert other.__qualname__.startswith("register_3.<locals>.")


def test_handlers_live_in_handlers_and_keep_their_import_path():
    for name in DNS_TOOLS:
        handler = getattr(handlers, name)
        assert handler.__module__ == "unifi_fabric.families.vpn.handlers", name
        assert getattr(network_vpn_dns, name) is handler, name
    assert not hasattr(network_vpn_dns, "_STATIC_DNS")


def test_shapes_come_from_schemas_and_the_family_helper():
    hints = typing.get_type_hints(handlers.update_static_dns_record)
    assert hints["record"] == schemas.StaticDnsRecord
    assert schemas.StaticDnsRecord == dict[str, Any]
    assert handlers.STATIC_DNS is schemas.STATIC_DNS == "/static-dns"
    assert handlers.v2_get.__module__ == "unifi_fabric.families.vpn._v2_records"
    # The VPN tools use the same shared shapes under their former private names.
    assert network_vpn_dns._v2_get is handlers.v2_get
    assert network_vpn_dns._merge is handlers.merge_leaves


def test_the_registrar_step_holds_the_dns_tools_place_in_the_loader_map():
    vpn = [(e.module, e.function, e.deps, e.origin) for e in LOADERS if e.family == "vpn"]
    assert vpn == [
        ("registrar", "register", "bound", "vpn"),
        ("registrar", "register_2", "bound", "network_vpn_dns"),
        ("registrar", "register_3", "bound", "network_vpn_dns"),
        ("registrar", "register_4", "bound", "radius_profiles"),
        ("registrar", "register_5", "bound", "vpn_clients"),
    ]
    refs = [e.ref for e in LOADERS]
    at = refs.index("unifi_fabric.families.vpn.registrar:register")
    assert refs[at + 1] == "unifi_fabric.families.vpn.registrar:register_2"
    assert refs[at + 2] == "unifi_fabric.families.vpn.registrar:register_3"


def test_family_ids_and_module_index_do_not_move():
    families, modules = build_family_index(), build_module_index()
    catalog = load_catalog().by_name()
    tools = _tools()
    for name in DNS_TOOLS:
        assert families[name] == "vpn", name
        assert catalog[name].id == f"vpn.{name}", name
        # The discovery vocabulary keys on the module: the step's origin, not "registrar".
        assert modules[name] == "network_vpn_dns", name
        assert tool_function_module(inspect.unwrap(tools[name].fn)) == "network_vpn_dns", name
    assert MODULE_FAMILY["vpn/registrar"] == "vpn"
    assert "registrar" not in MODULE_FAMILY


# --------------------------------------------------------------------------- handlers


async def test_handlers_use_the_v2_routes_and_pass_bodies_through():
    client, registry = Client(), Registry()
    assert await handlers.list_static_dns_records(client, registry, HOST, SITE) == client.dns
    record = {"key": "a.example.com", "value": "192.0.2.30", "x": [1]}
    await handlers.create_static_dns_record(client, registry, HOST, SITE, copy.deepcopy(record))
    doh = await handlers.list_doh_servers(client, registry, HOST, SITE)
    assert doh == {"path": f"{V2}/settings/doh/available-server-names"}
    assert client.writes() == [("POST", f"{V2}/static-dns", record)]


async def test_update_merges_leaves_and_verifies_and_delete_resolves_the_id():
    client, registry = Client(), Registry()
    result = await handlers.update_static_dns_record(
        client, registry, HOST, SITE, RECORD, {"value": "192.0.2.21"}
    )
    assert result["_verified"] is True
    assert client.writes()[0][2] == {"_id": RECORD, "key": "nas.example.com", "value": "192.0.2.21"}
    deleted = await handlers.delete_static_dns_record(client, registry, HOST, SITE, RECORD)
    assert deleted["deleted"] is True
    assert client.writes()[-1][:2] == ("DELETE", f"{V2}/static-dns/{RECORD}")


async def test_unknown_id_and_empty_update_send_nothing():
    client, registry = Client(), Registry()
    with pytest.raises(Exception, match="nas.example.com"):
        await handlers.delete_static_dns_record(client, registry, HOST, SITE, "0" * 24)
    with pytest.raises(ValueError):
        await handlers.update_static_dns_record(client, registry, HOST, SITE, RECORD, {})
    assert client.writes() == []


async def test_dry_run_returns_the_bare_preview():
    client, registry = Client(dry_run=True), Registry()
    preview = await handlers.create_static_dns_record(client, registry, HOST, SITE, {"key": "k"})
    assert preview["status"] == "dry_run" and preview["preview"]["method"] == "POST"


# --------------------------------------------------------------------------- tool surface


async def _call(name: str, arguments: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "scripts" / "dump_tool_baseline.py"
    spec = importlib.util.spec_from_file_location("dump_tool_baseline_dns", path)
    assert spec and spec.loader
    dump = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dump)
    async with dump._session("full", env) as client:
        return await dump._call(client, name, arguments)


async def test_tools_answer_and_refuse_as_vpn_tools():
    tools = {t.name: t for t in await server.mcp.list_tools(run_middleware=False)}
    args = dict(tool_args.generated_args(tools["list_static_dns_records"]))
    read = await _call("list_static_dns_records", args, {})
    assert read["isError"] is False
    for env in ({"UNIFI_EXCLUDE": "family:vpn"}, {"UNIFI_FAMILY_ALLOW": "network"}):
        refused = await _call("list_static_dns_records", args, env)
        assert refused["isError"] is True, env
        error = json.loads(refused["content"][0]["text"])["error"]
        assert error["code"] == "tool_not_exposed", env
    kept = await _call("list_static_dns_records", args, {"UNIFI_FAMILY_ALLOW": "vpn"})
    assert kept == read


def test_annotations_and_schemas_of_the_moved_wrappers():
    tools = _tools()
    for name in DNS_TOOLS:
        tool = tools[name]
        read = name.startswith("list_")
        assert tool.annotations.read_only_hint is read, name
        assert {"host", "site"} <= set(tool.parameters["required"]), name
    record = tools["create_static_dns_record"].parameters["properties"]["record"]
    assert record["type"] == "object" and record["additionalProperties"] is True


def test_the_dns_layout_imports_no_other_family():
    """Its imports are its own family and the common package, never another family."""
    import ast
    from pathlib import Path

    vpn = Path(handlers.__file__).parent
    for stem in ("handlers", "schemas", "registrar", "_v2_records"):
        tree = ast.parse((vpn / f"{stem}.py").read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 2:
                assert (node.module or "").split(".")[0] in ("", "vpn"), (stem, node.module)
            if isinstance(node, ast.ImportFrom) and node.level == 3:
                assert not (node.module or "").startswith("families"), (stem, node.module)
            if isinstance(node, ast.ImportFrom) and node.level == 0:
                module = node.module or ""
                assert not module.startswith("unifi_fabric.families"), (stem, module)


async def test_a_patched_handler_reaches_the_tool(monkeypatch):
    """The registrar calls handlers through the module, so patching one reaches the tool."""
    calls = []

    async def fake(client, registry, host, site):
        calls.append((host, site))
        return {"patched": True}

    monkeypatch.setattr(handlers, "list_doh_servers", fake)
    # The vpn steps are given server._require itself (deps "bound"): it reads these.
    monkeypatch.setattr(server, "_client", object())
    monkeypatch.setattr(server, "_registry", object())
    tools = {t.name: t for t in await server.mcp.list_tools(run_middleware=False)}
    assert await tools["list_doh_servers"].fn(host="h", site="s") == {"patched": True}
    assert calls == [("h", "s")]
