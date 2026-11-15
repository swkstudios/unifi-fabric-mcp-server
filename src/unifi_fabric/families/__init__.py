"""Tool-family classification and a library family-list filter.

The server's exposure settings (``UNIFI_FAMILY_ALLOW`` and the ``family:<id>`` /
``module:<module>`` tokens of ``UNIFI_EXCLUDE``) are applied by
:func:`unifi_fabric.policy.apply_exposure`, which uses :func:`build_family_index` and
:func:`build_module_index` from this module. :func:`apply_tool_family_filter` is a library
helper kept for direct callers and the test-suite: it takes plain family-name lists (commas
and/or whitespace, any letter case), not the ``UNIFI_EXCLUDE`` grammar, and the server does
not call it.

The families are the 13 user-facing product areas in :data:`ALL_FAMILIES`: the family
directories of the explicit loader map (:data:`unifi_fabric.catalog.loaders.LOADERS`) plus
``firewall``, which has no directory. Which family each tool belongs to is authored in the
explicit inventory (:mod:`unifi_fabric.catalog.membership`, public #42 steps 6 and 7) and
read from it; nothing here parses source or scans modules. The firewall tools are filed
under ``firewall`` there by route (their call graph names a firewall route), which the
test-suite checks against the call-graph audit (:mod:`unifi_fabric._call_graph`).
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from ..catalog import membership
from ..catalog.loaders import LOADERS, module_key

if TYPE_CHECKING:
    from fastmcp import FastMCP


_logger = logging.getLogger(__name__)

#: The names :func:`apply_tool_family_filter` gives its two family lists in errors. The
#: helper's lists are plain family names, not the ``UNIFI_EXCLUDE`` grammar.
TOOL_FAMILIES_ENV = "family allowlist"
DISABLED_TOOL_FAMILIES_ENV = "family exclusion list"

#: The family filed by route (``_call_graph.FIREWALL_ROUTE_RE``) rather than by directory.
FIREWALL = "firewall"

# Module key -> user-facing family. Python module names are internal; the family is what
# an operator names in UNIFI_FAMILY_ALLOW and family: exclusions. Derived from the family
# directories of the explicit loader map: each step's module (keyed by
# catalog.loaders.module_key: its stem, family-qualified for a layout stem such as
# registrar) belongs to the step's directory. A step's origin is an index key only and is
# not a key here (it may span directories). The private helper modules (``_*.py``)
# register no tools and are not keys. Firewall tools are moved by route afterwards.
MODULE_FAMILY: dict[str, str] = {entry.key: entry.family for entry in LOADERS}


# The modules of the loader map's steps (module keys, in first-step order): their
# nested @mcp.tool() functions are the registered tools.
_REGISTER_MODULES: tuple[str, ...] = tuple(dict.fromkeys(entry.key for entry in LOADERS))

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


def _module_rel(mod: str) -> str:
    """Package-relative source path of a family module, by module key (:data:`MODULE_FAMILY`)."""
    return f"families/{MODULE_FAMILY[mod]}/{mod.rsplit('/', 1)[-1]}.py"


def tool_function_module(fn: object) -> str:
    """The tools module a registered tool function is indexed under (``MODULE_INDEX``).

    The ``origin`` of the loader-map step whose ``register`` function defines it (a moved
    tool keeps its former module), else the key of the module defining it.
    """
    module = str(getattr(fn, "__module__", ""))
    step = f"{module}:{str(getattr(fn, '__qualname__', '')).split('.<locals>', 1)[0]}"
    for entry in LOADERS:
        if entry.ref == step:
            return entry.origin
    return module_key_of(module)


def module_key_of(module_name: str) -> str:
    """The module key of a dotted family module name, e.g. a tool function's ``__module__``.

    ``unifi_fabric.families.vpn.vpn`` -> ``vpn``; a layout module such as
    ``unifi_fabric.families.vpn.registrar`` -> ``vpn/registrar``. Any other module: its stem.
    """
    parts = module_name.split(".")
    if len(parts) >= 2 and parts[-3:-2] == ["families"]:
        return module_key(parts[-2], parts[-1])
    return parts[-1]


def build_module_index() -> dict[str, str]:
    """Return the ``tool_name -> sub-area module`` map, from the explicit inventory.

    The ``origin`` of each tool's loader step (:func:`unifi_fabric.catalog.membership.
    module_index`): the shared table, as before; callers must not mutate it.
    """
    return membership.module_index()


def connector_write_tools() -> frozenset[str]:
    """Tools whose call graph checks the connector write switch (generated table).

    The generation-time derivation is
    ``unifi_fabric._call_graph.tools_referencing("CONNECTOR_WRITE_ENV")``, a policy
    derivation over each registered tool's code, like the read/write verb audit.
    """
    from .._generated.tool_index import CONNECTOR_WRITE_TOOLS

    return CONNECTOR_WRITE_TOOLS


def build_family_index() -> dict[str, str]:
    """Return the ``tool_name -> family`` map for the whole registered roster.

    Read from the explicit inventory (:func:`unifi_fabric.catalog.membership.family_index`),
    so it does not depend on which file a wrapper lives in, and nothing is derived from
    source. ``list_configured_api_keys`` is in the reserved ``meta`` family; selection keeps
    its baseline family until the policy selection rule for meta tools lands
    (:data:`unifi_fabric.catalog.membership.SELECTION_FAMILY_OVERRIDES`). The shared table:
    callers must not mutate it.
    """
    return membership.family_index()


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
    from ..profiles import selection_profile

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
