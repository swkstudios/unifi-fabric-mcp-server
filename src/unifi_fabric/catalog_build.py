"""Build the typed tool catalog from the registered server (generation time only).

``scripts/gen_tool_catalog.py`` writes the result to
``src/unifi_fabric/_generated/catalog.json``; ``tests/test_catalog_contract.py`` rebuilds
it in memory and compares. Importing this module imports the server, so the runtime never
imports it: the runtime reads the committed file through :mod:`unifi_fabric.catalog`.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Mapping
from typing import Any

from .catalog import (
    CATALOG_VERSION,
    DISCOVERY_META_TOOLS,
    INITIAL_TOOL_VERSION,
    META_FAMILY,
    META_TOOL_NAMES,
    Catalog,
    CatalogError,
    ToolSpec,
    api_status_for,
    derived_annotations,
    handler_ref,
    load_catalog,
)

#: The api source of the meta tools that have no row in the baseline source table.
META_SOURCE = "server/local"

#: The frozen behaviour baseline of one family (tests/test_behavior_baseline.py): it pins
#: every full-mode ``tools/list`` entry of the family, its ``outputSchema`` included. A tool
#: with an output schema lists its family's file as its fixture (``missing_fixture``).
BASELINE_FIXTURE = "tests/fixtures/behavior_baseline/{family}.json"

#: The test that validates every self-built result against its advertised output schema.
SELF_BUILT_FIXTURE = "tests/test_output_schemas.py"

#: The ``tools/list`` entry fields the catalog records, as ``(catalog field, entry key)``.
LISTED_FIELDS: tuple[tuple[str, str], ...] = (
    ("description", "description"),
    ("input_schema", "inputSchema"),
    ("output_schema", "outputSchema"),
)


async def registered_tools() -> list[Any]:
    """Every catalog tool object: the full-mode roster plus the discovery meta tools."""
    previous_mode = os.environ.get("UNIFI_TOOL_MODE")
    os.environ["UNIFI_TOOL_MODE"] = "full"
    try:
        from .catalog.deferred import load_all
        from .discovery import apply_tool_mode
        from .server import mcp

        # Every step is loaded first: the derivation reads each tool's ``fn`` (public #41).
        load_all(mcp)

        # Catalog generation is the bootstrap for the policy tables used by the
        # tools/list middleware itself. Enumerate the local provider directly so a
        # newly registered tool does not need to be present in the previous generated
        # catalog before the generator can see it.
        domain = list(await mcp.list_tools(run_middleware=False))
        restore = await apply_tool_mode(mcp, "discovery")
        try:
            meta = [
                tool
                for tool in await mcp.list_tools(run_middleware=False)
                if tool.name in DISCOVERY_META_TOOLS
            ]
        finally:
            restore()
    finally:
        if previous_mode is None:
            os.environ.pop("UNIFI_TOOL_MODE", None)
        else:
            os.environ["UNIFI_TOOL_MODE"] = previous_mode
    if {tool.name for tool in meta} != DISCOVERY_META_TOOLS:
        raise RuntimeError("discovery mode did not register the five discovery meta tools")
    return sorted(domain + meta, key=lambda tool: tool.name)


def classified_sources(names: list[str]) -> dict[str, str]:
    """``name -> primary app/source pair`` from the baseline source table."""
    from .api_sources import primary_pair
    from .generated_api_facts._api_source_table import TOOL_API_SOURCES

    out: dict[str, str] = {}
    for name in names:
        pairs = TOOL_API_SOURCES.get(name)
        if pairs:
            out[name] = primary_pair(pairs)
        elif name in DISCOVERY_META_TOOLS:
            out[name] = META_SOURCE
    return out


def derivation(tools: list[Any], sources: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    """``name -> annotations`` from the single source derivation (for_tool)."""
    from ._read_only_audit import classify_tool_verbs, reaches_upstream
    from .discovery import DISPATCH_TOOLS

    verbs = classify_tool_verbs(tools)
    out: dict[str, dict[str, Any]] = {}
    for tool in tools:
        status = api_status_for(sources[tool.name]) if tool.name in sources else "local"
        if tool.name in DISCOVERY_META_TOOLS:
            # The discovery tools' authority (discovery.py): writes only through
            # call_write_tool; the two dispatch tools reach the upstream.
            tool_verbs: set[str] = {"POST"} if tool.name == "call_write_tool" else set()
            open_world = tool.name in DISPATCH_TOOLS
        else:
            tool_verbs = set(verbs[tool.name])
            open_world = reaches_upstream(tool.fn)
        out[tool.name] = derived_annotations(tool_verbs, open_world, status)
    return out


def client_listing() -> dict[str, dict[str, Any]]:
    """``name -> tools/list entry`` as an MCP client receives it (generation time)."""
    from .catalog.inventory import client_listing as listing

    return {entry["name"]: entry for entry in asyncio.run(listing())}


def output_schema_fixtures(name: str) -> list[str]:
    """The fixtures that pin ``name``'s advertised output schema (``missing_fixture``).

    The family's behaviour-baseline file freezes the full-mode ``tools/list`` entry, its
    ``outputSchema`` included (the baseline groups tools by the selection family index and
    holds no discovery meta tool); :data:`SELF_BUILT_FIXTURE` validates the results the
    server builds itself against their schemas, the discovery meta tools' among them.
    """
    from .families import build_family_index
    from .output_schemas import SELF_BUILT

    family = build_family_index().get(name)
    found = [] if family is None else [BASELINE_FIXTURE.format(family=family)]
    if name in SELF_BUILT:
        found.append(SELF_BUILT_FIXTURE)
    return found


def client_view_drift(catalog: Catalog, listed: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Where ``catalog`` disagrees with the client-visible ``tools/list`` (``listed``).

    Each recorded field is compared as JSON text, so key order counts: a client is sent
    the entry exactly as listed. Empty when the catalog equals the client view.
    """
    problems: list[str] = []
    for spec in catalog.tools:
        entry = listed.get(spec.name)
        if entry is None:
            problems.append(f"{spec.name}: in catalog.json but not in tools/list")
            continue
        data = spec.to_dict()
        for field, key in LISTED_FIELDS:
            if json.dumps(data[field]) != json.dumps(entry.get(key)):
                problems.append(f"{spec.name}: {field} differs from tools/list {key}")
    names = {spec.name for spec in catalog.tools}
    problems.extend(
        f"{name}: in tools/list but not in catalog.json" for name in listed if name not in names
    )
    return problems


def _versions(previous: Catalog | None) -> dict[str, ToolSpec]:
    return {} if previous is None else {spec.id: spec for spec in previous.tools}


def _bump(old: ToolSpec | None, spec: dict[str, Any]) -> str:
    """Keep the committed version while the schema pair is unchanged; else bump minor.

    An automatic bump is minor (additive); an incompatible change needs a major bump set
    by hand in the committed file, which the generator then keeps.
    """
    if old is None:
        return INITIAL_TOOL_VERSION
    same = old.to_dict()["input_schema"] == spec["input_schema"] and (
        old.to_dict()["output_schema"] == spec["output_schema"]
    )
    if same:
        return old.version
    major, minor, _patch = (int(p) for p in old.version.split("."))
    return f"{major}.{minor + 1}.0"


def build_catalog(previous: Catalog | None = None) -> Catalog:
    """Generate the catalog from the live registration.

    ``previous`` (default: the committed catalog, when present) supplies per-tool versions
    and fixture lists, so regeneration is stable and only a schema change moves a version.
    """
    from .catalog.membership import MEMBERS

    if previous is None:
        try:
            previous = load_catalog()
        except FileNotFoundError:
            previous = None
    old = _versions(previous)
    old_by_name = {spec.name: spec for spec in old.values()}
    tools = asyncio.run(registered_tools())
    listed = client_listing()
    names = [tool.name for tool in tools]
    sources = classified_sources(names)
    derived = derivation(tools, sources)
    families = {member.name: member.family for member in MEMBERS}
    specs: list[ToolSpec] = []
    for tool in tools:
        family = META_FAMILY if tool.name in META_TOOL_NAMES else families[tool.name]
        source = sources.get(tool.name)
        if source is None:
            raise CatalogError("unclassified_source", f"{tool.name}: no classified api source")
        status = api_status_for(source)
        data: dict[str, Any] = {
            "id": f"{family}.{tool.name}",
            "family": family,
            "family_id": family,
            "name": tool.name,
            "api_source_id": source,
            "api_status": status,
            "read_only": bool(derived[tool.name]["readOnlyHint"]),
            "annotations": derived[tool.name],
            # The client view: what tools/list sends, key order included.
            "description": listed[tool.name].get("description") or "",
            "input_schema": listed[tool.name].get("inputSchema") or {},
            "output_schema": listed[tool.name].get("outputSchema"),
            "version": INITIAL_TOOL_VERSION,
            "fixtures": [],
            "handler": handler_ref(family, tool.name),
        }
        prior = old.get(data["id"]) or old_by_name.get(tool.name)
        if prior is not None:
            data["fixtures"] = list(prior.fixtures)
        if data["output_schema"] is not None and not data["fixtures"]:
            data["fixtures"] = output_schema_fixtures(tool.name)
            if not data["fixtures"]:
                raise CatalogError(
                    "missing_fixture", f"{tool.name}: an output schema that no fixture pins"
                )
        data["version"] = _bump(prior, data)
        specs.append(ToolSpec.from_dict(data))
    return Catalog(
        version=CATALOG_VERSION,
        tools=tuple(sorted(specs, key=lambda s: s.id)),
        fixtures=tuple(previous.fixtures) if previous is not None else (),
    )
