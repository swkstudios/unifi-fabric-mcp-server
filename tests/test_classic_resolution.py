"""Resolver properties over the catalog callers of the shared Classic helpers."""

from __future__ import annotations

import ast
import functools
import importlib.util
import inspect
import textwrap
from collections.abc import Callable
from functools import cache
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import class_axis, tool_batches
from tests.test_cross_tool_invariants import TOOLS, _call
from unifi_fabric.tools import _classic_objects as classic
from unifi_fabric.tools import vpn
from unifi_fabric.tools._classic_objects import listed_record_id

# These tools resolve their ``server_id`` through the Classic remote-user-vpn
# networkconf collection, although their public names do not contain vpn_server.
_REMOTE_USER_VPN_TOOLS = frozenset(
    {
        "create_wireguard_users",
        "delete_wireguard_users",
        "get_openvpn_client_config",
        "list_wireguard_users",
        "update_wireguard_users",
    }
)


@cache
def _resolver_callees(fn: Callable[..., Any]) -> tuple[Callable[..., Any], ...]:
    """Keep direct-call scope, resolving bindings without merging module basenames.

    Registered wrappers may delegate to a module implementation with the same
    name. Follow that explicit binding too; differently named attribute delegates
    (such as post-write advisory checks) were outside the original direct-call
    resolver property and stay outside it.
    """
    fn = inspect.unwrap(fn)
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    except (OSError, TypeError, SyntaxError):
        return ()
    globals_ = getattr(fn, "__globals__", {})
    callees = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        obj = None
        if isinstance(node.func, ast.Name):
            obj = globals_.get(node.func.id)
        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.attr == fn.__name__
        ):
            base = globals_.get(node.func.value.id)
            obj = getattr(base, node.func.attr, None) if base is not None else None
        if callable(obj) and (getattr(obj, "__module__", "") or "").startswith("unifi_fabric"):
            callees.add(inspect.unwrap(obj))
    return tuple(callees)


def _reaches_resolver(fn: Callable[..., Any], seeds: set[Callable[..., Any]]) -> bool:
    """Follow imported aliases and module delegates by callable identity."""
    targets = {inspect.unwrap(seed) for seed in seeds}
    stack = [inspect.unwrap(fn)]
    seen = set()
    while stack:
        current = inspect.unwrap(stack.pop())
        if current in targets:
            return True
        if current in seen:
            continue
        seen.add(current)
        stack.extend(_resolver_callees(current))
    return False


def _catalog_callers(seed: set[Callable[..., Any]]) -> list[str]:
    return sorted(name for name, tool in TOOLS.items() if _reaches_resolver(tool.fn, seed))


def _classic_seed() -> set[Callable[..., Any]]:
    return {
        classic.resolve_networkconf_record,
        classic.resolve_networkconf,
        classic.resolve_device_tag_record,
        classic.resolve_device_tag,
        classic.require_listed_record,
        classic.listed_record_id,
        vpn._select_by_id,
    }


@functools.cache
def _lz_CLASSIC_TOOLS():
    return _catalog_callers(_classic_seed())


@functools.cache
def _is_classic(name: str) -> bool:
    """``_lz_CLASSIC_TOOLS`` membership for one tool, decided at test execution."""
    return _reaches_resolver(TOOLS[name].fn, _classic_seed())


@functools.cache
def _lz_INTEGRATION_SELECTORS():
    return _catalog_callers({vpn._select_by_id})


@functools.cache
def _lz_ALIAS_TOOLS():
    return _catalog_callers(
        {
            classic.resolve_networkconf_record,
            classic.resolve_networkconf,
            classic.resolve_device_tag_record,
            classic.resolve_device_tag,
        }
    )


def _alias_seed() -> set[Callable[..., Any]]:
    return {
        classic.resolve_networkconf_record,
        classic.resolve_networkconf,
        classic.resolve_device_tag_record,
        classic.resolve_device_tag,
    }


@functools.cache
def _is_alias_tool(name: str) -> bool:
    return _reaches_resolver(TOOLS[name].fn, _alias_seed())


@functools.cache
def _is_integration_selector(name: str) -> bool:
    return _reaches_resolver(TOOLS[name].fn, {vpn._select_by_id})


def test_discovery_resolves_import_aliases_without_cross_module_name_collisions(tmp_path):
    def load(name: str, source: str):
        path = tmp_path / f"{name}.py"
        path.write_text(source)
        spec = importlib.util.spec_from_file_location(f"unifi_fabric.tools.{name}", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    imported = load(
        "imported_resolver",
        "from unifi_fabric.tools._classic_objects import listed_record_id as imported_alias\n"
        "def _resolve(record):\n    return imported_alias(record, 'id')\n"
        "resolver_alias = _resolve\n"
        "def catalog_tool(record):\n    return resolver_alias(record)\n",
    )
    unrelated = load(
        "unrelated_resolver",
        "def _resolve(record):\n    return record\n"
        "def catalog_tool(record):\n    return _resolve(record)\n",
    )
    assert imported._resolve.__name__ == unrelated._resolve.__name__
    assert _reaches_resolver(imported.catalog_tool, {classic.listed_record_id})
    assert not _reaches_resolver(unrelated.catalog_tool, {classic.listed_record_id})
    assert not _reaches_resolver(unrelated.catalog_tool, {imported._resolve})
    advisory = load(
        "advisory_resolver",
        "import unifi_fabric.tools._classic_objects as classic\n"
        "def catalog_tool(record):\n"
        "    return classic.listed_record_id(record, 'id')\n",
    )
    assert not _reaches_resolver(advisory.catalog_tool, {classic.listed_record_id})
    assert "alarm_hub_trigger_output" not in _lz_CLASSIC_TOOLS()
    assert "create_network" not in _lz_CLASSIC_TOOLS()


class _Rows(uh.FakeUpstream):
    def __init__(self, name: str, mode: str, native_id: Any = None):
        super().__init__()
        self.name = name
        self.mode = mode
        self.native_id = native_id

    def __call__(self, req: httpx.Request) -> httpx.Response:
        response = super().__call__(req)
        if req.method != "GET" or uh.is_resolution(req.url.path):
            return response
        body = response.json()
        rows = body.get("data") if isinstance(body, dict) else body
        if not isinstance(rows, list):
            return response
        args = tool_args.generated_args(TOOLS[self.name])
        wanted = next((v for k, v in args.items() if k.endswith("_id")), uh.ARG_ID)
        row = {
            "name": uh.ARG_NAME,
            "_id": wanted,
            "id": wanted,
            "external_id": wanted,
            "probe": "selected-record",
        }
        if req.url.path.endswith("/networkconf"):
            row["_id"] = uh.ARG_HEX
            row["purpose"] = (
                "remote-user-vpn"
                if "vpn_server" in self.name or self.name in _REMOTE_USER_VPN_TOOLS
                else "vpn-client"
                if "vpn_client" in self.name
                else "wan"
                if "wan_interface" in self.name
                else "site-vpn"
            )
        if self.mode == "invalid":
            row["_id"] = self.native_id
        rows = [row]
        if self.mode == "malformed":
            rows.append(None)
        if self.mode == "ambiguous":
            rows.append({**row, "_id": "0000000000000000000000bb"})
        if isinstance(body, dict):
            body = {**body, "data": rows}
            if self.mode == "incomplete":
                body.update(incomplete=True, incompleteReason="probe: page cap")
        else:
            body = rows
        return httpx.Response(200, json=body)


def test_catalog_discovery_covers_all_classic_resolver_families():
    assert {
        "update_hotspot_operator",
        "delete_hotspot_operator",
        "update_port_profile",
        "update_traffic_rule",
        "update_vpn_server",
        "delete_vpn_server",
        "update_device_tag",
        "delete_device_tag",
        "get_radius_profile",
    } <= set(_lz_CLASSIC_TOOLS())


def test_catalog_discovery_finds_the_selector_and_alias_families():
    """The integration-selector and alias tool_batches below select their tools from the
    catalog; an empty selection would collect as an empty parameter set, not fail, so
    each family's known members are pinned here, through both selection paths."""
    selectors = {"get_radius_profile", "get_vpn_server"}
    aliases = {
        "update_device_tag",
        "delete_device_tag",
        "update_vpn_server",
        "delete_vpn_server",
        "update_wan_interface",
    }
    assert selectors <= set(_lz_INTEGRATION_SELECTORS())
    assert aliases <= set(_lz_ALIAS_TOOLS())
    assert all(_is_integration_selector(name) for name in selectors)
    assert all(_is_alias_tool(name) for name in aliases)


# Tools whose only Classic list read comes AFTER their write: the networkconf name
# resolution of create_port_profile is a read-after (safe_read_after), so a malformed row
# there must not fail a create the controller already applied; it is reported instead.
READ_AFTER_ONLY = {"create_port_profile"}


@tool_batches("name", lambda: sorted(set(TOOLS) - READ_AFTER_ONLY), member=_is_classic)
async def test_catalog_classic_malformed_rows_fail_as_shape_errors(monkeypatch, name):
    up = _Rows(name, "malformed")
    with pytest.raises(ToolError, match="[Ss]hape"):
        await _call(monkeypatch, name, up)
    assert not up.writes()


@pytest.mark.parametrize("name", sorted(READ_AFTER_ONLY))
async def test_malformed_read_after_rows_are_reported_not_raised(monkeypatch, name):
    assert name in _lz_CLASSIC_TOOLS()
    up = _Rows(name, "malformed")
    result = await _call(monkeypatch, name, up)
    assert len(up.writes()) == 1
    assert "shape" in str(result).lower() and "_readAfterError" in str(result)


@class_axis(
    "name",
    lambda: sorted(TOOLS),
    member=_is_alias_tool,
    native_id=lambda: [None, "", 7, True, [], {}],
)
async def test_catalog_alias_selected_native_id_is_string_before_write(
    monkeypatch, name, native_id
):
    up = _Rows(name, "invalid", native_id)
    args = tool_args.generated_args(TOOLS[name])
    if "tag_id" in args:
        args["tag_id"] = uh.ARG_NAME
    with pytest.raises(ToolError) as exc:
        await _call(monkeypatch, name, up, args)
    assert "_id" in str(exc.value) and "probe-object" in str(exc.value)
    assert not up.writes()


@tool_batches("name", lambda: sorted(TOOLS), member=_is_alias_tool)
async def test_catalog_alias_distinct_native_ids_fail_as_ambiguous(monkeypatch, name):
    up = _Rows(name, "ambiguous")
    args = tool_args.generated_args(TOOLS[name])
    if "tag_id" in args:
        args["tag_id"] = uh.ARG_NAME
    with pytest.raises(ToolError, match="matches|[Aa]mbiguous"):
        await _call(monkeypatch, name, up, args)
    assert not up.writes()


@pytest.mark.parametrize("native_id", [None, "", 7, True, [], {}])
def test_listed_record_native_id_never_coerces_non_strings(native_id):
    with pytest.raises(ValueError, match="probe-object"):
        listed_record_id({"_id": native_id, "name": uh.ARG_NAME}, "record_id")


@tool_batches("name", lambda: sorted(TOOLS), member=_is_integration_selector)
async def test_catalog_selected_integration_record_is_verbatim_when_list_incomplete(
    monkeypatch, name
):
    up = _Rows(name, "incomplete")
    payload = uh.result_payload(await _call(monkeypatch, name, up))
    assert payload["probe"] == "selected-record"
    assert "_incomplete" not in payload
    assert "_incompleteReason" not in payload
