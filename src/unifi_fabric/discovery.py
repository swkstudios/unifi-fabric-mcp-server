"""Compact discovery catalog; execution uses the original registered tools."""

from __future__ import annotations

import inspect
import math
import re
from collections import Counter
from collections.abc import Callable
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as FrameworkValidationError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import Tool, ToolResult

from ._read_only_audit import derive_write_tools
from .argument_errors import argument_validation_error, format_argument_error
from .families import build_family_index, build_module_index
from .read_only import read_only_message
from .read_only_tools import hidden_area_write_refusal, is_write_tool_call
from .switches import READ_ONLY_ENV
from .tool_annotations import for_tool

META_TOOLS = frozenset(
    {"search_tools", "describe_tool", "call_read_tool", "call_write_tool", "list_tool_families"}
)
DISPATCH_TOOLS = frozenset({"call_read_tool", "call_write_tool"})
# Search vocabulary of each product sub-area: the BM25 "area" field of a tool. It adds
# domain words without turning a camera search into an unrelated network search. Names and
# parameter descriptions still dominate ties. A sub-area is keyed by the tools module
# (families.build_module_index), so a sub-area inside a broader family (fleet health inside
# site_manager, face recognition inside protect) keeps its own words. Families are the
# filter and the label; these keys are internal and never shown.
SUBAREA_TERMS = {
    "protect": "protect camera nvr doorbell video recording liveview sensor alarm",
    "recognition": "recognition face person license plate recognition detection",
    "network": "network vlan wifi ssid wlan wireless network switch routing",
    "firewall": "firewall firewall acl traffic policy zone security access control",
    "services": "network services dns dhcp radius routing service",
    "site_manager": "site manager console host site organization inventory",
    "devices": "device mgmt device switch access point port firmware adoption",
    "clients": "clients client station connected user mac",
    "vpn": "vpn vpn wireguard openvpn tunnel remote access",
    "hotspot": "hotspot guest hotspot voucher captive portal operator",
    "statistics": "statistics statistics stats metric performance traffic usage history",
    "fleet": "aggregation health summary compare aggregate overview",
    "innerspace": "innerspace floor plan map placement location building",
    "placement": "placement snapshot floor plan map placement snapshot",
    "carrier": "carrier fabric carrier isp subscriber billing plan internet provider",
    "mobility": "mobility mobility cellular sim modem mobile lte 5g",
    "connector": "connector connector relay proxy request integration",
}
#: tools module -> sub-area of :data:`SUBAREA_TERMS` (default: the module's family).
MODULE_SUBAREA = {
    "aggregation": "fleet",
    "recognition": "recognition",
    "placement_snapshot": "placement",
    "firewall_proxy": "firewall",
    "network_services_proxy": "services",
    "network_dpi_policy": "services",
    "site_config": "services",
}


def subarea_terms(name: str, families: dict[str, str]) -> str:
    """The search vocabulary of tool ``name``: its sub-area's words, else its family's."""
    module = build_module_index().get(name, "")
    family = families.get(name, "other")
    return SUBAREA_TERMS.get(MODULE_SUBAREA.get(module, ""), SUBAREA_TERMS.get(family, family))


QUERY_SYNONYMS = {
    "read": "get",
    "fetch": "get",
    "retrieve": "get",
    "browse": "list",
    "enumerate": "list",
    "remove": "delete",
    "reorder": "ordering set",
    "rearrange": "ordering set",
    # "ordered rules" / "evaluation order" / "sequence of policies" name the ordering
    # tools (get_*_ordering, set_*_ordering); the stemmer never maps them to "ordering".
    "ordered": "ordering",
    "order": "ordering",
    "sequence": "ordering",
    "change": "update",
    "modify": "update",
    "add": "create",
    "recording": "video",
}
_STOPWORDS = frozenset(
    "a an the of to for and or with on in my me please show can i how do is are".split()
)


def _terms(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9]+", text.lower().replace("_", " "))
    return [
        word[:-1] if len(word) > 3 and word.endswith("s") else word
        for word in words
        if word not in _STOPWORDS
    ]


def _schema_text(value: Any) -> str:
    """Index all nested property names and descriptions, including body schemas."""
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            if key == "description" and isinstance(item, str):
                parts.append(item)
            elif key == "properties" and isinstance(item, dict):
                parts.extend(item)
            if isinstance(item, (dict, list)):
                parts.append(_schema_text(item))
        return " ".join(parts)
    if isinstance(value, list):
        return " ".join(_schema_text(item) for item in value)
    return ""


class SearchIndex:
    """Weighted BM25 fields with family-local synonym expansion."""

    def __init__(self, catalog: dict[str, Tool], families: dict[str, str]) -> None:
        self.catalog = catalog
        self.families = families
        self.fields: dict[str, list[Counter[str]]] = {}
        frequency: Counter[str] = Counter()
        for name, tool in catalog.items():
            fields = [
                Counter(_terms(name)),
                Counter(_terms(subarea_terms(name, families))),
                Counter(_terms(tool.description or "")),
                Counter(_terms(_schema_text(tool.parameters))),
            ]
            self.fields[name] = fields
            frequency.update(set().union(*(field.keys() for field in fields)))
        count = len(catalog)
        self.idf = {
            word: math.log(1 + (count - freq + 0.5) / (freq + 0.5))
            for word, freq in frequency.items()
        }
        self.averages = [
            sum(sum(fields[i].values()) for fields in self.fields.values()) / max(count, 1)
            for i in range(4)
        ]

    def search(
        self,
        query: str,
        family: str | None,
        writes: bool | None,
        write_names: set[str],
        limit: int | None,
    ) -> list[dict[str, Any]]:
        available = sorted({self.families.get(name, "other") for name in self.catalog})
        if family is not None and family not in available:
            raise ToolError(
                f"Unknown or unavailable family {family!r}; valid families: {available}"
            )
        if limit is not None and limit < 1:
            raise ToolError(
                "limit must be a positive integer, or null to return every match; "
                "there is no maximum"
            )
        terms = set(_terms(query))
        if query.strip() and not terms:
            raise ToolError(
                "Your query has no searchable terms. Try a tool name or product topic, "
                "or use query=\x27\x27 to browse enabled tools."
            )
        terms.update(word for term in tuple(terms) for word in _terms(QUERY_SYNONYMS.get(term, "")))
        ranked = []
        for name, tool in self.catalog.items():
            slug = self.families.get(name, "other")
            mutates = name in write_names
            if family is not None and slug != family:
                continue
            if writes is not None and mutates != writes:
                continue
            score = 0.0
            for field, weight, average in zip(
                self.fields[name], (6.0, 3.0, 1.0, 2.0), self.averages, strict=True
            ):
                norm = 1.2 * (0.25 + 0.75 * sum(field.values()) / max(average, 1))
                for term in sorted(terms):
                    freq = field.get(term, 0)
                    if freq:
                        score += weight * self.idf[term] * freq * 2.2 / (freq + norm)
            if terms and score == 0:
                continue
            if query.strip().lower() == name.lower():
                score += 100.0
            description = tool.description or name
            ranked.append(
                (
                    score,
                    {
                        "name": name,
                        "family": slug,
                        "summary": " ".join(description.splitlines()[0].split()),
                        "writes": mutates,
                    },
                )
            )
        ranked.sort(key=lambda item: (-item[0], item[1]["name"]))
        results = [result for _, result in ranked]
        if query.strip() and not results:
            raise ToolError(
                f"No enabled tools match {query!r}. Try a broader query, select a different "
                "family, or use query=\x27\x27 to browse enabled tools."
            )
        return results if limit is None else results[:limit]


class DiscoveryMiddleware(Middleware):
    """List a stable surface and validate dispatch envelopes before target guards.

    The envelope's registered body re-enters the public dispatch API. Target
    authentication, argument validation and all middleware run on the original
    registered tool, with secret scrubbing also outside the envelope validation.
    """

    def __init__(self, app: FastMCP) -> None:
        self.app = app

    async def on_list_tools(self, context: MiddlewareContext, call_next: CallNext) -> list[Tool]:
        return [tool for tool in await call_next(context) if tool.name in META_TOOLS]

    async def on_call_tool(self, context: MiddlewareContext, call_next: CallNext) -> Any:
        name = context.message.name
        if name in DISPATCH_TOOLS:
            envelope = await self.app.get_tool(name)
            if envelope is None:
                # A startup-hidden dispatcher still reaches the audited read-only backstop.
                return await call_next(context)
            try:
                return await envelope.run(context.message.arguments or {})
            except FrameworkValidationError as exc:
                error = argument_validation_error(exc, getattr(envelope, "fn", None))
                if error is None:
                    raise
                raise ToolError(format_argument_error(name, envelope, error)) from None
        return await call_next(context)


async def apply_tool_mode(
    app: FastMCP,
    mode: str,
    *,
    read_only: bool = False,
    hidden_write_names: set[str] | None = None,
    hidden_area_writes: dict[str, str] | None = None,
    audit: Callable[[str, str], None] | None = None,
) -> Callable[[], None]:
    """Apply mode after family selection; return lifecycle cleanup.

    ``hidden_write_names`` (``UNIFI_READ_ONLY``) and ``hidden_area_writes`` (per-area write
    opt-outs, name -> variable) were removed before this runs, so search, describe and the
    family counts cover only callable tools; naming one still gets its refusal.
    ``audit(tool, reason)`` records a refusal by ``call_read_tool`` of a write it hides
    (read-only mode, a per-area opt-out) or a write route under read-only mode
    (``outcome=refused``), as the read-only and area opt-out middleware do for a direct call.
    """
    if mode not in {"full", "discovery"}:
        raise ValueError("UNIFI_TOOL_MODE must be one of discovery, full")
    catalog = {tool.name: tool for tool in await app.list_tools()}
    if META_TOOLS & catalog.keys():
        raise ValueError("Discovery meta-tool names collide with registered tools")
    if mode == "full":
        return lambda: None
    families = build_family_index()
    write_names = derive_write_tools(list(catalog.values()))
    index: SearchIndex | None = SearchIndex(catalog, families)
    counts = Counter(families.get(name, "other") for name in catalog)
    family_catalog = "; ".join(f"{slug}: {count}" for slug, count in sorted(counts.items()))

    area_hidden = dict(hidden_area_writes or {})

    def require_tool(name: str) -> Tool:
        if read_only and name in (hidden_write_names or ()):
            raise ToolError(read_only_message(name, tool=True))
        if name in area_hidden:
            raise ToolError(hidden_area_write_refusal(name, area_hidden[name]))
        if name not in catalog:
            raise ToolError(
                f"Unknown or unavailable tool {name!r}. "
                "Use search_tools(query='', limit=null) to list enabled tools; "
                "UNIFI_TOOL_FAMILIES and UNIFI_DISABLED_TOOL_FAMILIES select the available "
                "families."
            )
        return catalog[name]

    async def search_tools(
        query: str, family: str | None = None, writes: bool | None = None, limit: int | None = 10
    ) -> list[dict[str, Any]]:
        """Find enabled tools by intent, ranked over names, descriptions and parameter schemas.

        Default returns ten matches. Choose any positive limit, or null for every
        match; no tool or search result is hard-capped. Empty query browses tools.
        Use describe_tool for the exact schema, then call_read_tool or call_write_tool.

        Args:
            query: Natural language intent, for example "camera recordings";
                empty browses all tools.
            family: Optional exact family slug from list_tool_families, for example "protect".
            writes: Optional filter: true for mutations, false for reads, null for both.
            limit: Number of results (default 10); any positive integer or null for every match.
        """
        if index is None:
            raise ToolError("Discovery lifecycle has ended")
        return index.search(query, family, writes, write_names, limit)

    async def describe_tool(name: str) -> dict[str, Any]:
        """Return the complete enabled tool schema, identical to its full-mode tools/list entry.

        Args:
            name: Exact enabled tool name from search_tools, for example "get_acl_rule_ordering".
        """
        return require_tool(name).to_mcp_tool().model_dump(by_alias=True, exclude_none=True)

    async def call_read_tool(name: str, arguments: dict[str, Any]) -> ToolResult:
        """Execute a read tool with its original validation, guards, audit and result format.

        Refuses write calls, including state-changing routes of the mixed GET relay.
        Describe the target first; its schema and permissions apply. Read-only mode
        and secret scrubbing are preserved.

        Args:
            name: Exact enabled read tool name, for example "get_acl_rule_ordering".
            arguments: Target schema arguments, for example {"host": "console", "site": "default"}.
        """
        if audit is not None:
            # A hidden write is refused by require_tool (read-only mode first, then a per-area
            # opt-out); the call is audited with that switch, like a direct one.
            if read_only and name in (hidden_write_names or ()):
                audit(name, READ_ONLY_ENV)
            elif name in area_hidden:
                audit(name, area_hidden[name])
        tool = require_tool(name)
        if (name in write_names and name != "fabric_connector_get") or is_write_tool_call(
            tool, name, arguments
        ):
            if read_only:
                # call_write_tool is not listed in read-only mode: name the switch that
                # refuses the call instead of a dispatcher the caller cannot see.
                if audit is not None:
                    audit(name, READ_ONLY_ENV)
                raise ToolError(
                    read_only_message(name, tool=True)
                    + " call_write_tool is not listed while read-only mode is on."
                )
            if audit is not None and name == "fabric_connector_get":
                # A state-changing relay route that a write opt-out refuses: audited with
                # that switch, as the direct call is.
                from .tools import connector

                gate = connector.relay_get_opt_out_env(
                    arguments.get("path"), arguments.get("scope")
                )
                if gate is not None:
                    audit(name, gate)
            raise ToolError(
                f"{name!r} is a write tool. "
                f"Use call_write_tool(name={name!r}, arguments=...) instead; "
                "the target's write permissions, dry-run and read-only policy still apply."
            )
        return await app.call_tool(name, arguments)

    async def call_write_tool(name: str, arguments: dict[str, Any]) -> ToolResult:
        """Execute a tool that may mutate live configuration through registered dispatch.

        Describe the target first. Target validation, per-area opt-outs, UNIFI_READ_ONLY,
        OAuth permissions, dry-run, audit and secret scrubbing match a direct call.

        Args:
            name: Exact enabled tool name, for example "set_firewall_policy_ordering".
            arguments: Target schema arguments from describe_tool; for example
                {"host": "console", "site": "default"} plus the target's required fields.
        """
        if name not in area_hidden:
            require_tool(name)
        # An opted-out area's hidden write is refused, with its reason, and audited by the
        # area opt-out middleware on the registered call path, exactly as a direct call.
        return await app.call_tool(name, arguments)

    async def list_tool_families() -> list[dict[str, Any]]:
        """List enabled families and counts; use their slugs as search_tools family filters."""
        return [{"family": slug, "tools": count} for slug, count in sorted(counts.items())]

    original_instructions = app.instructions
    dispatch_guidance = (
        "Execute via call_read_tool. "
        if read_only
        else "Execute via call_read_tool or call_write_tool. "
    )
    app.instructions = (
        (original_instructions or "") + "\nDiscovery mode: search_tools finds enabled tools; "
        "describe_tool gives exact schemas. "
        + dispatch_guidance
        + "Enabled families (counts): "
        + family_catalog
        + "."
    )
    functions: list[Callable[..., Any]] = [
        search_tools,
        describe_tool,
        call_read_tool,
        call_write_tool,
        list_tool_families,
    ]
    for fn in functions:
        description = inspect.cleandoc(fn.__doc__ or "")
        if read_only:
            description = description.replace("call_read_tool or call_write_tool", "call_read_tool")
        if fn is search_tools:
            description += "\nEnabled families (tool counts): " + family_catalog + "."
        app.add_tool(
            Tool.from_function(
                fn,
                description=description,
                # Writes only through call_write_tool. Search, describe and family listing
                # read the local catalog; the two dispatch tools run domain tools upstream.
                annotations=for_tool(
                    writes=fn is call_write_tool,
                    open_world=fn.__name__ in DISPATCH_TOOLS,
                ),
            )
        )
    middleware = DiscoveryMiddleware(app)
    position = next(
        (
            i + 1
            for i, mw in enumerate(app.middleware)
            if type(mw).__name__ == "SecretScrubMiddleware"
        ),
        0,
    )
    app.middleware.insert(position, middleware)

    def restore() -> None:
        nonlocal index
        # Framework function/type-adapter caches may retain the meta-tool
        # closures after removal. Release this lifespan's catalog-sized state
        # rather than retaining another search index for every client session.
        index = None
        catalog.clear()
        write_names.clear()
        counts.clear()
        if middleware in app.middleware:
            app.middleware.remove(middleware)
        for name in META_TOOLS:
            try:
                app.local_provider.remove_tool(name)
            except KeyError:
                # Startup read-only selection may already have removed a meta-tool.
                pass
        app.instructions = original_instructions

    return restore
