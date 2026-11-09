"""Tool-family classification and a library family-list filter.

The server's exposure settings (``UNIFI_FAMILY_ALLOW`` and the ``family:<id>`` tokens of
``UNIFI_EXCLUDE``) are applied by :func:`unifi_fabric.policy.apply_exposure`, which uses
:func:`build_family_index` from this module. :func:`apply_tool_family_filter` is a
library helper kept for direct callers and the test-suite: it takes plain family-name
lists (commas and/or whitespace, any letter case), not the ``UNIFI_EXCLUDE`` grammar, and
the server does not call it.

The families are the 13 user-facing product areas in :data:`ALL_FAMILIES`. Family
classification is derived *statically from source* (hermetic, no import side effects):

* every ``@mcp.tool()`` is mapped to the ``tools/`` sub-module it delegates to (server.py
  inline tools) or to the registering module (the ``register(mcp, ...)`` modules), and
  :data:`MODULE_FAMILY` maps that module to its family;
* ``firewall`` is then split out BY ROUTE: a tool whose call graph names a firewall route
  (firewall policies and zones, ACL rules, classic firewall rules and groups,
  :data:`FIREWALL_ROUTE_RE`) is in ``firewall`` whatever module defines it. The call graph is
  the one the read/write annotations are derived from
  (:mod:`unifi_fabric._read_only_audit`), resolved here from source; the test-suite checks
  that both resolutions agree for every tool.

This keeps the family index self-maintaining: a new tool added under an existing
delegation is classified automatically, a new firewall tool lands in ``firewall``, and
:func:`build_family_index` covers the whole live roster (asserted by the test-suite).
"""

from __future__ import annotations

import ast
import logging
import re
from functools import cache, lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp import FastMCP

_logger = logging.getLogger(__name__)

#: The names :func:`apply_tool_family_filter` gives its two family lists in errors. The
#: helper's lists are plain family names, not the ``UNIFI_EXCLUDE`` grammar.
TOOL_FAMILIES_ENV = "family allowlist"
DISABLED_TOOL_FAMILIES_ENV = "family exclusion list"

#: The family split out by route (:data:`FIREWALL_ROUTE_RE`) rather than by module.
FIREWALL = "firewall"

# tools/ sub-module -> user-facing family. Python module names are internal; the family
# is what an operator names in UNIFI_FAMILY_ALLOW and family: exclusions. Modules
# registered via a register(mcp, deps_fn) function and modules delegated to by server.py
# inline wrappers are both covered. Firewall tools are moved by route afterwards.
MODULE_FAMILY: dict[str, str] = {
    "site_manager": "site_manager",
    "aggregation": "site_manager",
    "network": "network",
    "network_clients_guests": "network",
    "network_controller_insights": "network",
    "network_nat_qos_traffic": "network",
    "firewall_proxy": "network",
    "network_services_proxy": "network",
    "network_dpi_policy": "network",
    "protect": "protect",
    "protect_private": "protect",
    "protect_camera_recording": "protect",
    "protect_device_lifecycle": "protect",
    "recognition": "protect",
    "carrier_fabric": "carrier",
    "mobility": "mobility",
    "innerspace": "innerspace",
    "innerspace_internal": "innerspace",
    "connector": "connector",
    "device_mgmt": "devices",
    "device_commands": "devices",
    "scheduled_tasks": "devices",
    "device_radios": "devices",
    "clients": "clients",
    "matter": "network",
    "vpn": "vpn",
    "hotspot": "hotspot",
    "statistics": "statistics",
    "placement_snapshot": "innerspace",
    "client_records": "clients",
    "system_log": "statistics",
    "vpn_clients": "vpn",
    "site_admin": "network",
    "network_wifi_radio": "network",
    "network_switching_power": "network",
    "network_controller_admin": "network",
    "network_routing_topology": "network",
    "network_security_diagnostics": "network",
    "network_proav_sandbox": "network",
    "network_mobile_wan": "network",
    "network_device_operations": "network",
    "network_vpn_dns": "vpn",
    "protect_events_cases": "protect",
    "protect_users_assets": "protect",
    "protect_automation_backup": "protect",
    "protect_ptz_doorbell": "protect",
    "protect_recognition_search": "protect",
    "site_config": "network",
    "radius_profiles": "vpn",
}

#: An upstream route of the firewall family, matched against each route literal (a string
#: constant with no whitespace, docstrings excluded) in a tool's call graph: a path segment
#: ``firewall...`` (Integration ``firewall/policies``, ``firewall/zones``; v2
#: ``firewall-policies``, ``firewall/zone``, ``firewall-groups``, ``firewall-app-blocks``),
#: ``acl-rules`` (Integration and v2 ACL rules) or the classic ``firewallrule`` /
#: ``firewallgroup`` collections (both start with ``firewall``).
FIREWALL_ROUTE_RE = re.compile(r"(?:^|/)(?:firewall|acl-rules?)[a-z/-]*(?:\Z|[/?])")

# Families registered through a module-level register(mcp, deps_fn) function whose
# nested @mcp.tool() functions live inside that module (family == module).
_REGISTER_MODULES: tuple[str, ...] = (
    "protect_private",
    "device_mgmt",
    "device_commands",
    "scheduled_tasks",
    "device_radios",
    "network_controller_insights",
    "network_nat_qos_traffic",
    "clients",
    "matter",
    "vpn",
    "hotspot",
    "aggregation",
    "statistics",
    "network_clients_guests",
    "network_dpi_policy",
    "protect_camera_recording",
    "innerspace_internal",
    "protect_device_lifecycle",
    "client_records",
    "system_log",
    "vpn_clients",
    "site_admin",
    "network_wifi_radio",
    "network_switching_power",
    "network_controller_admin",
    "network_routing_topology",
    "network_security_diagnostics",
    "network_proav_sandbox",
    "network_mobile_wan",
    "network_device_operations",
    "network_vpn_dns",
    "protect_events_cases",
    "protect_users_assets",
    "protect_automation_backup",
    "protect_ptz_doorbell",
    "protect_recognition_search",
    "site_config",
    "radius_profiles",
    "connector",
    "carrier_fabric",
    "innerspace",
    "mobility",
    "placement_snapshot",
    "recognition",
    "site_manager",
    "firewall_proxy",
    "network",
    "network_services_proxy",
    "protect",
)

#: The registration functions of a register module: ``register``, plus ``register_2``,
#: ``register_3``, ... where a module registers several runs of wrappers moved from
#: server.py in their original order (scripts/codemod_move_wrappers.py).
_REGISTER_FUNCTION_RE = re.compile(r"register(?:_[0-9]+)?")

#: The 13 user-facing families, sorted: the only names the family variables accept.
ALL_FAMILIES: tuple[str, ...] = tuple(sorted(set(MODULE_FAMILY.values()) | {FIREWALL}))


def _family_items(value: str | None) -> list[str]:
    """The names in a family list: separated by commas and/or whitespace, lower-cased."""
    return (value or "").replace(",", " ").lower().split()


def parse_families_env(value: str | None) -> set[str]:
    """Parse a plain family-name list (the helper lists of :func:`apply_tool_family_filter`).

    Returns an empty set for unset/blank input (the no-op, all-families case). Names are
    separated by commas and/or whitespace and matched in any letter case, so
    ``"Protect, Network"``, ``"protect network"`` and ``"PROTECT,\nnetwork"`` all resolve
    to ``{"protect", "network"}``.
    """
    return set(_family_items(value))


def unknown_families_problem(value: str | None, variable: str = TOOL_FAMILIES_ENV) -> str | None:
    """Why a family-list value names an unknown family, or None.

    The message counts the unknown entries and gives their positions in the list, never
    their text (a value set in the wrong variable may be a credential), and lists the
    valid families.
    """
    parts = _family_items(value)
    positions = [i for i, part in enumerate(parts) if part not in ALL_FAMILIES]
    if not positions:
        return None
    items = "item" if len(positions) == 1 else "items"
    return (
        f"{variable} names unknown families ({items} "
        f"{', '.join(str(i) for i in positions)} of the list, counted from 0, names separated "
        "by commas or whitespace; the value is not shown here); valid families: "
        f"{', '.join(ALL_FAMILIES)}"
    )


def _is_tool_decorator(dec: ast.expr) -> bool:
    """True for a ``@mcp.tool()`` / ``@mcp.tool`` decorator node."""
    func = dec.func if isinstance(dec, ast.Call) else dec
    return (isinstance(func, ast.Attribute) and func.attr == "tool") or (
        isinstance(func, ast.Name) and func.id == "tool"
    )


def _tool_name(node: ast.AsyncFunctionDef | ast.FunctionDef) -> str:
    """The registered tool name: the decorator's ``name=`` keyword, else the function's."""
    for dec in node.decorator_list:
        if _is_tool_decorator(dec) and isinstance(dec, ast.Call):
            for keyword in dec.keywords:
                if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str):
                        return keyword.value.value
    return node.name


def _module_refs(node: ast.AST) -> list[str]:
    """tools/ sub-modules referenced (``<module>.<attr>``) inside a function body."""
    refs: list[str] = []
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Attribute)
            and isinstance(child.value, ast.Name)
            and child.value.id in MODULE_FAMILY
        ):
            refs.append(child.value.id)
    return refs


type _FunctionNode = ast.AsyncFunctionDef | ast.FunctionDef
type _Defs = dict[str, _FunctionNode]
type _Imports = dict[str, tuple[str, str | None]]

_PKG = Path(__file__).parent


@cache
def _module_source(rel: str) -> tuple[ast.Module, _Defs, _Imports]:
    """Parse one package module: its tree, top-level functions and package imports.

    ``defs`` includes module-level aliases of a function (``_impl_x = x``). ``imports`` maps
    a local name to ``(module path, None)`` for an imported package module and to
    ``(module path, function name)`` for an imported package function.
    """
    tree = ast.parse((_PKG / rel).read_text())
    defs: _Defs = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
    }
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Name)
            and node.value.id in defs
        ):
            defs[node.targets[0].id] = defs[node.value.id]
    imports: _Imports = {}
    here = Path(rel).parent
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or not node.level:
            continue
        base = here
        for _ in range(node.level - 1):
            base = base.parent
        parts = node.module.split(".") if node.module else []
        for alias in node.names:
            module = base.joinpath(*parts, alias.name).with_suffix(".py")
            if (_PKG / module).exists():
                imports[alias.asname or alias.name] = (module.as_posix(), None)
                continue
            module = base.joinpath(*parts).with_suffix(".py")
            if parts and (_PKG / module).exists():
                imports[alias.asname or alias.name] = (module.as_posix(), alias.name)
    return tree, defs, imports


def _route_literals(node: ast.AST) -> set[str]:
    """String constants without whitespace in ``node``, docstrings excluded."""
    docstrings: set[int] = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.AsyncFunctionDef, ast.FunctionDef, ast.ClassDef)):
            first = child.body[0] if child.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and id(child) not in docstrings
        and not any(c.isspace() for c in child.value)
    }


def _referenced(rel: str, node: _FunctionNode, scope: _Defs) -> list[tuple[str, _FunctionNode]]:
    """Package functions ``node`` references: by name in its module or scope, or imported."""
    _, defs, imports = _module_source(rel)
    out: list[tuple[str, _FunctionNode]] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            target = scope.get(child.id) or defs.get(child.id)
            if target is not None and target is not node:
                out.append((rel, target))
            elif child.id in imports and imports[child.id][1] is not None:
                module, name = imports[child.id]
                found = _module_source(module)[1].get(str(name))
                if found is not None:
                    out.append((module, found))
        elif (
            isinstance(child, ast.Attribute)
            and isinstance(child.value, ast.Name)
            and child.value.id in imports
            and imports[child.value.id][1] is None
        ):
            module = imports[child.value.id][0]
            found = _module_source(module)[1].get(child.attr)
            if found is not None:
                out.append((module, found))
    return out


def _call_graph(rel: str, node: _FunctionNode, scope: _Defs | None = None) -> list[_FunctionNode]:
    """Every package function reachable from a tool function, the tool itself first."""
    reached: list[_FunctionNode] = []
    seen: set[tuple[str, int]] = set()
    stack: list[tuple[str, _FunctionNode, _Defs]] = [(rel, node, scope or {})]
    while stack:
        module, fn, names = stack.pop()
        key = (module, fn.lineno)
        if key in seen:
            continue
        seen.add(key)
        reached.append(fn)
        stack.extend(
            (m, f, names if m == module else {}) for m, f in _referenced(module, fn, names)
        )
    return reached


def tool_route_literals(rel: str, node: _FunctionNode, scope: _Defs | None = None) -> set[str]:
    """Route literals reachable from a tool function through the package call graph."""
    return set().union(*(_route_literals(fn) for fn in _call_graph(rel, node, scope)))


@lru_cache(maxsize=8)
def tools_referencing(symbol: str) -> frozenset[str]:
    """Tools whose call graph names ``symbol`` (a variable or an attribute), from source.

    ``tools_referencing("CONNECTOR_WRITE_ENV")`` is every tool that checks the connector
    write switch: the relay tools and the typed tools that switch also governs.
    """
    found: set[str] = set()
    for name, rel, node, scope, _module in _tool_nodes():
        for fn in _call_graph(rel, node, scope):
            if any(
                (isinstance(child, ast.Name) and child.id == symbol)
                or (isinstance(child, ast.Attribute) and child.attr == symbol)
                for child in ast.walk(fn)
            ):
                found.add(name)
                break
    return frozenset(found)


def is_firewall_route(literal: str) -> bool:
    """Whether a route literal names a firewall-family route (:data:`FIREWALL_ROUTE_RE`)."""
    return FIREWALL_ROUTE_RE.search(literal) is not None


def _tool_nodes() -> list[tuple[str, str, _FunctionNode, _Defs, str | None]]:
    """``(tool name, source module, node, enclosing scope, delegated tools module)``."""
    out: list[tuple[str, str, _FunctionNode, _Defs, str | None]] = []
    server_tree = _module_source("server.py")[0]
    for node in server_tree.body:
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and any(
            _is_tool_decorator(d) for d in node.decorator_list
        ):
            refs = _module_refs(node)
            out.append((_tool_name(node), "server.py", node, {}, refs[0] if refs else None))
    for mod in _REGISTER_MODULES:
        rel = f"tools/{mod}.py"
        for reg in ast.walk(_module_source(rel)[0]):
            if isinstance(reg, ast.FunctionDef) and _REGISTER_FUNCTION_RE.fullmatch(reg.name):
                nested: _Defs = {
                    sub.name: sub
                    for sub in ast.walk(reg)
                    if isinstance(sub, (ast.AsyncFunctionDef, ast.FunctionDef)) and sub is not reg
                }
                for sub in nested.values():
                    if any(_is_tool_decorator(d) for d in sub.decorator_list):
                        out.append((_tool_name(sub), rel, sub, nested, mod))
    return out


def derive_module_index() -> dict[str, str]:
    """Derive the ``tool_name -> tools module`` map from source (generation time).

    The module a tool is defined in or delegates to. Internal: module names are not
    public family names. The runtime reads the generated table instead
    (:func:`build_module_index`); ``scripts/gen_tool_index.py`` writes it.
    """
    return {name: module for name, _rel, _node, _scope, module in _tool_nodes() if module}


def derive_firewall_route_tools() -> frozenset[str]:
    """Derive the tools whose call graph names a firewall route, from source."""
    return frozenset(
        name
        for name, rel, node, scope, _module in _tool_nodes()
        if any(is_firewall_route(lit) for lit in tool_route_literals(rel, node, scope))
    )


FAMILY_OVERRIDES = {
    "list_vpn_servers": "vpn",
    "list_site_to_site_tunnels": "vpn",
    "list_radius_profiles": "vpn",
    "list_device_tags": "devices",
    "list_scheduled_tasks": "devices",
    "get_scheduled_task": "devices",
}


def derive_family_index() -> dict[str, str]:
    """Derive the ``tool_name -> family`` map from source (generation time).

    Parsed statically from ``server.py`` (inline ``@mcp.tool()`` wrappers, classified by
    the ``tools/`` sub-module they delegate to) and from each ``register(mcp, ...)``
    module (classified by the module itself), through :data:`MODULE_FAMILY`; then every
    tool whose call graph names a firewall route is in ``firewall``. Hermetic: reads
    source only, never imports. The typed catalog records the result per tool.
    """
    firewall = derive_firewall_route_tools()
    index = {
        name: FIREWALL if name in firewall else MODULE_FAMILY[module]
        for name, module in derive_module_index().items()
    }
    index.update(FAMILY_OVERRIDES)
    return index


def build_module_index() -> dict[str, str]:
    """Return the ``tool_name -> tools module`` map (generated table, no source parse).

    The shared table itself, as the cached map was before: callers must not mutate it.
    """
    from ._generated.tool_index import MODULE_INDEX

    return MODULE_INDEX


def firewall_route_tools() -> frozenset[str]:
    """Tools whose call graph names a firewall route (generated table)."""
    from ._generated.tool_index import FIREWALL_ROUTE_TOOLS

    return FIREWALL_ROUTE_TOOLS


def connector_write_tools() -> frozenset[str]:
    """Tools whose call graph checks the connector write switch (generated table).

    The generation-time derivation is ``tools_referencing("CONNECTOR_WRITE_ENV")``.
    """
    from ._generated.tool_index import CONNECTOR_WRITE_TOOLS

    return CONNECTOR_WRITE_TOOLS


def build_family_index() -> dict[str, str]:
    """Return the ``tool_name -> family`` map for the whole registered roster.

    Read from the generated table that mirrors the typed catalog's family per tool
    (src/unifi_fabric/_generated/catalog.json), so it does not depend on which file a
    wrapper lives in. The catalog files ``list_configured_api_keys`` under the reserved
    ``meta`` family; selection keeps its baseline family until the policy selection rule for
    meta tools lands (:data:`_generated.tool_index.SELECTION_FAMILY_OVERRIDES`).
    """
    from ._generated.tool_index import FAMILY_INDEX

    return FAMILY_INDEX


async def apply_tool_family_filter(
    mcp: FastMCP, families_value: str | None, disabled_value: str | None = None
) -> list[str]:
    """De-register tools outside a family allowlist, then the tools of
    every family in a family exclusion list (library helper; the server uses policy).

    No-op when both lists are unset/blank (every family stays registered). Tools that
    cannot be classified are always kept (never silently hidden). Returns the list of
    removed tool names. Raises ``ValueError`` on an unknown family name in either list so a
    typo (or a retired name) fails loud at startup, listing the valid families.
    """
    from .profiles import selection_profile

    allowed = parse_families_env(families_value)
    disabled = parse_families_env(disabled_value)
    # The opt-out list is applied after any allowlist; unknown names fail here.
    profile = selection_profile(
        allowed, disabled, allowed_value=families_value, disabled_value=disabled_value
    )
    if not allowed and not disabled:
        return []
    kept = profile.families

    index = build_family_index()
    removed: list[str] = []
    for tool in await _list_tools(mcp):
        if not profile.includes(index.get(tool.name)):
            _remove_tool(mcp, tool.name)
            removed.append(tool.name)

    _logger.info(
        "tool-family selection active: families=%s disabled=%s kept=%d removed=%d",
        sorted(kept),
        sorted(disabled),
        len(await _list_tools(mcp)),
        len(removed),
    )
    return removed


async def _list_tools(mcp: FastMCP) -> list:
    """Return the registered tool objects, bypassing the tools/list middleware.

    Startup and shutdown read the registered catalog itself; the request-policy middleware
    filters tools/list by the operator's exclusions, so a filtered read would hide the very
    tools the exposure step must de-register (and later restore).
    """
    return list(await mcp.list_tools(run_middleware=False))


def _remove_tool(mcp: FastMCP, name: str) -> None:
    """De-register a tool through the local provider (the FastMCP 4 API)."""
    mcp.local_provider.remove_tool(name)
