"""Advertised output schemas for the results this server builds itself.

Most tools return an upstream UniFi body unchanged; those keep no output schema (or the
bare object schema FastMCP derives from ``dict[str, Any]``), because the shape varies by
firmware and a strict schema would reject real responses. The tools here assemble their
top-level result in the server (discovery search and family listing, fleet and site
roll-ups, the InnerSpace summary and the placement snapshot), so their shape is known.
Each is declared as a concrete ``TypedDict`` and advertised as the tool's
``outputSchema``.

Rules every schema here follows:

* every property carries a description (AI clients only see ``tools/list``);
* every object stays open (``additionalProperties: true``), so an extra field never fails
  client-side validation;
* ``required`` names only keys that every code path sets;
* upstream records inside a result (devices, clients, sites, health bodies) are free
  objects, never constrained.

The handlers keep their ``dict[str, Any]`` / ``list`` return annotations, so FastMCP
serializes a result exactly as before (no key reordering or dropped fields). Only the
advertised schema changes. ``tests/test_output_schemas.py`` validates produced results
against these schemas.
"""

from __future__ import annotations

import copy
from typing import Annotated, Any, NotRequired, TypedDict

from pydantic import ConfigDict, Field, TypeAdapter, with_config

_OPEN = ConfigDict(extra="allow")


def _d(text: str) -> Any:
    return Field(description=text)


# --------------------------------------------------------------------------- discovery
@with_config(_OPEN)
class SearchMatch(TypedDict):
    """One search_tools match."""

    name: Annotated[str, _d("Exact tool name; pass it to describe_tool and the call wrappers.")]
    family: Annotated[str, _d("Family slug of the tool, as listed by list_tool_families.")]
    summary: Annotated[str, _d("First line of the tool description.")]
    writes: Annotated[
        bool, _d("True when the tool can change configuration (call it with call_write_tool).")
    ]


@with_config(_OPEN)
class SearchToolsResult(TypedDict):
    """search_tools structured result."""

    result: Annotated[
        list[SearchMatch],
        _d("Matches ranked best first, at most `limit` of them (all of them when limit is null)."),
    ]
    more_available: Annotated[
        bool,
        _d(
            "True when the limit cut the list: more tools match than were returned. Raise "
            "limit, pass limit=null, or refine the query or family instead of assuming the "
            "list is complete."
        ),
    ]
    total_matched: Annotated[
        int, _d("How many enabled tools matched in total, before the limit was applied.")
    ]


@with_config(_OPEN)
class FamilyCount(TypedDict):
    """One list_tool_families entry."""

    family: Annotated[str, _d("Family slug; pass it as the search_tools family filter.")]
    tools: Annotated[int, _d("Number of enabled tools in the family.")]


@with_config(_OPEN)
class ListToolFamiliesResult(TypedDict):
    """list_tool_families structured result."""

    result: Annotated[list[FamilyCount], _d("Enabled families in slug order, with tool counts.")]


@with_config(_OPEN)
class DescribedTool(TypedDict):
    """describe_tool result: the tool's tools/list entry."""

    name: Annotated[str, _d("Tool name.")]
    inputSchema: Annotated[
        dict[str, Any], _d("JSON Schema of the tool arguments, as full mode advertises it.")
    ]
    title: NotRequired[Annotated[str, _d("Display title.")]]
    description: NotRequired[Annotated[str, _d("Full tool description.")]]
    outputSchema: NotRequired[
        Annotated[dict[str, Any], _d("JSON Schema of the result, when the tool declares one.")]
    ]
    annotations: NotRequired[
        Annotated[
            dict[str, Any],
            _d("MCP hints: readOnlyHint, destructiveHint, idempotentHint, openWorldHint, title."),
        ]
    ]


# --------------------------------------------------------------------- shared markers
_INCOMPLETE = "True when a source list stopped short (opt-in page cap, repeated cursor)."
_INCOMPLETE_REASON = "Why the result is incomplete, one reason per source; absent when complete."
_KEY_LABEL = "The key_label argument this call was scoped to, or null for every configured key."
_KEY_LABELS = "Labels of the API keys that answered (multi-key deployments only)."
_ERRORS = "Per-key (or per-site) failures; the other keys' data is still returned."
_WRAPPER = "Server fields whose names collided with an upstream field; upstream keeps the name."


@with_config(_OPEN)
class _Coverage(TypedDict):
    """Markers the server adds to multi-key and paged roll-ups."""

    _key_labels: NotRequired[Annotated[list[str | None], _d(_KEY_LABELS)]]
    errors: NotRequired[Annotated[list[Any], _d(_ERRORS)]]
    incomplete: NotRequired[Annotated[bool, _d(_INCOMPLETE)]]
    incompleteReason: NotRequired[Annotated[str | None, _d(_INCOMPLETE_REASON)]]
    _continuation: NotRequired[
        Annotated[
            str,
            _d("Opaque resume token: pass it back unchanged as page_token or cursor."),
        ]
    ]
    _wrapperFields: NotRequired[Annotated[dict[str, Any], _d(_WRAPPER)]]


# -------------------------------------------------------------------------- fleet views
@with_config(_OPEN)
class DeviceCounts(TypedDict):
    """Device totals and breakdowns."""

    total: Annotated[int, _d("Number of devices counted.")]
    byStatus: Annotated[
        dict[str, int], _d("Device count per status or state value (e.g. online, offline).")
    ]
    byType: Annotated[
        dict[str, int], _d("Device count per productLine or type value (e.g. network, protect).")
    ]


@with_config(_OPEN)
class FleetSummary(_Coverage):
    """get_fleet_summary result."""

    hosts: Annotated[int, _d("Number of consoles (hosts) counted, each once across keys.")]
    sites: Annotated[int, _d("Number of sites counted.")]
    devices: Annotated[DeviceCounts, _d("Device totals with status and type breakdowns.")]
    _key_label: NotRequired[Annotated[str | None, _d(_KEY_LABEL)]]
    _keyTotals: NotRequired[
        Annotated[
            dict[str, Any],
            _d("Per-key share of the totals ({hosts, sites, devices}); they sum to the totals."),
        ]
    ]


@with_config(_OPEN)
class ApiKeyEntry(TypedDict):
    """One configured API key (never its value)."""

    label: Annotated[str | None, _d("Key label from configuration; pass it as key_label.")]
    is_org_key: Annotated[bool, _d("True for an organization (multi-console) key.")]


@with_config(_OPEN)
class ConfiguredApiKeys(TypedDict):
    """list_configured_api_keys result."""

    keys: Annotated[list[ApiKeyEntry], _d("One entry per configured API key, in config order.")]
    count: Annotated[int, _d("Number of configured API keys.")]


@with_config(_OPEN)
class FleetDeviceSearch(_Coverage):
    """search_device_fleet result."""

    data: Annotated[
        list[dict[str, Any]],
        _d("Matching devices, each the upstream record plus _hostId/_hostName context."),
    ]
    _count: Annotated[int, _d("Number of matching devices.")]
    _query: Annotated[str, _d("The query searched (blank matches every device).")]
    _key_label: Annotated[str | None, _d(_KEY_LABEL)]


@with_config(_OPEN)
class FleetDeviceList(_Coverage):
    """list_all_devices result."""

    data: Annotated[
        list[Any], _d("Devices across the fleet, each the upstream record plus console context.")
    ]
    _count: NotRequired[Annotated[int, _d("Number of devices returned (after status_filter).")]]
    _filter: NotRequired[Annotated[str | None, _d("The status_filter applied, or null.")]]
    _key_label: NotRequired[Annotated[str | None, _d(_KEY_LABEL)]]
    byKey: NotRequired[
        Annotated[dict[str, Any], _d("Each key's upstream envelope fields (multi-key only).")]
    ]


@with_config(_OPEN)
class FleetClientList(_Coverage):
    """list_all_clients result."""

    data: Annotated[
        list[Any], _d("Clients across every site, each the upstream record plus site context.")
    ]
    _count: Annotated[int, _d("Number of clients returned.")]
    _sitesQueried: Annotated[int, _d("Number of sites queried.")]
    _sitesSucceeded: Annotated[int, _d("Sites whose client list was read completely.")]
    _sitesFailed: Annotated[int, _d("Sites whose read failed (see errors).")]
    _sitesIncomplete: Annotated[int, _d("Sites whose client list stopped short.")]
    _key_label: Annotated[str | None, _d(_KEY_LABEL)]
    _skipped: NotRequired[Annotated[list[Any], _d("Sites skipped before any request, with why.")]]
    _siteEnvelopes: NotRequired[
        Annotated[dict[str, Any], _d("Each site's upstream envelope fields, keyed by site.")]
    ]


# --------------------------------------------------------------------------- site views
@with_config(_OPEN)
class SitesAggregated(_Coverage):
    """list_all_sites_aggregated result."""

    data: Annotated[list[Any], _d("Site Manager site records, unchanged, across every key.")]
    _count: NotRequired[Annotated[int, _d("Number of sites returned.")]]
    byKey: NotRequired[
        Annotated[dict[str, Any], _d("Each key's upstream envelope fields (multi-key only).")]
    ]


@with_config(_OPEN)
class SiteComparison(_Coverage):
    """compare_site_performance result."""

    _comparison: Annotated[
        list[dict[str, Any]],
        _d(
            "One entry per requested site, in order: its /stat/health body unchanged plus "
            "_siteLabel, or {_siteLabel, error} for a site that failed."
        ),
    ]
    _count: Annotated[int, _d("Number of entries in _comparison.")]


# ------------------------------------------------------------------ innerspace views
@with_config(_OPEN)
class InnerSpaceSummary(TypedDict):
    """get_innerspace_summary result."""

    mode: Annotated[str, _d("Project view summarized: 3D or 2D.")]
    shape_total: Annotated[int, _d("Number of shapes in the project.")]
    shape_counts: Annotated[dict[str, int], _d("Shape count per shape type.")]
    wall_variants: Annotated[dict[str, int], _d("Wall shape count per wall variant.")]
    plan_count: Annotated[int, _d("Number of floor plans.")]
    plans: Annotated[
        list[dict[str, Any]], _d("Per floor plan: ordering, name and that plan's own scale.")
    ]
    # Taken from the upstream project when present, so its shape is not constrained.
    plan_scales: Annotated[
        Any, _d("Scale data per plan id (upstream planScales when present), or null if none.")
    ]
    product_count: Annotated[int, _d("Number of product definitions in the project.")]
    wall_type_count: Annotated[int, _d("Number of wall types in the project.")]
    attenuation_object_type_count: Annotated[
        int | None, _d("Number of attenuation object types, or null when the list is absent.")
    ]
    project: Annotated[
        dict[str, Any], _d("Project metadata: unit, migrated, and id/title/timestamps if present.")
    ]
    multi_floor: Annotated[bool, _d("True when the project has more than one floor plan.")]
    multi_floor_note: NotRequired[
        Annotated[str, _d("Why floors do not share a coordinate origin (multi-floor only).")]
    ]


@with_config(_OPEN)
class PlacementSnapshot(TypedDict):
    """get_unifi_placement_snapshot result (unifi.placement-snapshot/v1)."""

    schema_version: Annotated[str, _d("Snapshot schema id: unifi.placement-snapshot/v1.")]
    generated_at: Annotated[str, _d("When the snapshot was built (ISO 8601 UTC).")]
    freshness: Annotated[
        dict[str, Any], _d("Freshness contract: observed_at, max_age_seconds and cache.")
    ]
    provenance: Annotated[dict[str, Any], _d("Producer, approved read sources and read_only.")]
    floors: Annotated[list[dict[str, Any]], _d("Floor plans with their scale and map.")]
    walls: Annotated[list[dict[str, Any]], _d("Wall segments placed on floors.")]
    placed_devices: Annotated[list[dict[str, Any]], _d("Devices placed on floors, with positions.")]
    topology: Annotated[list[dict[str, Any]], _d("Network and Protect device inventory.")]
    placement_links: Annotated[
        list[dict[str, Any]], _d("Links from placed devices to inventory records by unique name.")
    ]
    incomplete: NotRequired[Annotated[bool, _d(_INCOMPLETE)]]
    incompleteReason: NotRequired[Annotated[str, _d(_INCOMPLETE_REASON)]]
    _unprojected: NotRequired[
        Annotated[dict[str, Any], _d("Count of source records schema v1 cannot represent.")]
    ]
    _unprojected_how_to_obtain: NotRequired[
        Annotated[Any, _d("Which full read tool returns the unprojected records.")]
    ]
    _withheld: NotRequired[
        Annotated[dict[str, Any], _d("Values removed under UNIFI_REDACT_SECRETS, counted.")]
    ]
    _withheld_how_to_obtain: NotRequired[
        Annotated[Any, _d("Which tool returns the withheld values, or how to disable redaction.")]
    ]


# ------------------------------------------------------------------------- rendering
def _inline(node: Any, defs: dict[str, Any]) -> Any:
    """Resolve local ``$ref``s and drop pydantic ``title`` noise."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            target = _inline(copy.deepcopy(defs[ref.split("/")[-1]]), defs)
            # Keep the referring property's own description over the class docstring.
            extra = {k: v for k, v in node.items() if k != "$ref"}
            target.pop("description", None)
            return {**target, **_inline(extra, defs)}
        out = {}
        for key, value in node.items():
            if key in ("$defs", "title"):
                continue
            if key == "properties" and isinstance(value, dict):
                out[key] = {name: _inline(prop, defs) for name, prop in value.items()}
            else:
                out[key] = _inline(value, defs)
        return out
    if isinstance(node, list):
        return [_inline(item, defs) for item in node]
    return node


def schema_of(declared: Any, *, wrap: bool = False) -> dict[str, Any]:
    """The advertised JSON Schema of a ``TypedDict``, ``$ref``-free.

    ``wrap`` marks a list result FastMCP serves as ``{"result": [...]}`` (the
    ``x-fastmcp-wrap-result`` convention), so FastMCP clients unwrap ``.data`` to the list.
    """
    raw = TypeAdapter(declared).json_schema()
    schema = _inline(raw, raw.get("$defs", {}))
    schema.pop("description", None)
    if wrap:
        schema["x-fastmcp-wrap-result"] = True
    return schema


SEARCH_TOOLS = schema_of(SearchToolsResult, wrap=True)
LIST_TOOL_FAMILIES = schema_of(ListToolFamiliesResult, wrap=True)
DESCRIBE_TOOL = schema_of(DescribedTool)
FLEET_SUMMARY = schema_of(FleetSummary)
CONFIGURED_API_KEYS = schema_of(ConfiguredApiKeys)
FLEET_DEVICE_SEARCH = schema_of(FleetDeviceSearch)
FLEET_DEVICE_LIST = schema_of(FleetDeviceList)
FLEET_CLIENT_LIST = schema_of(FleetClientList)
SITES_AGGREGATED = schema_of(SitesAggregated)
SITE_COMPARISON = schema_of(SiteComparison)
INNERSPACE_SUMMARY = schema_of(InnerSpaceSummary)
PLACEMENT_SNAPSHOT = schema_of(PlacementSnapshot)

#: Tool name -> advertised output schema, for every self-built result.
SELF_BUILT: dict[str, dict[str, Any]] = {
    "search_tools": SEARCH_TOOLS,
    "list_tool_families": LIST_TOOL_FAMILIES,
    "describe_tool": DESCRIBE_TOOL,
    "get_fleet_summary": FLEET_SUMMARY,
    "list_configured_api_keys": CONFIGURED_API_KEYS,
    "search_device_fleet": FLEET_DEVICE_SEARCH,
    "list_all_devices": FLEET_DEVICE_LIST,
    "list_all_clients": FLEET_CLIENT_LIST,
    "list_all_sites_aggregated": SITES_AGGREGATED,
    "compare_site_performance": SITE_COMPARISON,
    "get_innerspace_summary": INNERSPACE_SUMMARY,
    "get_unifi_placement_snapshot": PLACEMENT_SNAPSHOT,
}
#: The discovery meta-tools among them (registered at lifespan start, not in the catalog).
META_TOOL_SCHEMAS = frozenset({"search_tools", "list_tool_families", "describe_tool"})
