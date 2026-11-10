"""Compact discovery catalog; execution uses the original registered tools."""

from __future__ import annotations

import inspect
import logging
import math
import re
from collections import Counter
from collections.abc import Callable, Sequence
from contextvars import ContextVar
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as FrameworkValidationError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.server.middleware.dereference import DereferenceRefsMiddleware
from fastmcp.tools import Tool, ToolResult
from fastmcp.utilities.types import NotSet
from mcp.types import ListToolsRequest, TextContent

from . import code_mode, output_schemas
from ._read_only_audit import derive_write_tools
from .argument_errors import argument_validation_error, format_argument_error
from .families import build_family_index, build_module_index
from .list_results import to_structured_list_result
from .read_only import read_only_message
from .read_only_tools import (
    TOOL_NOT_EXPOSED,
    WRITE_DENIED,
    hidden_area_write_refusal,
    is_write_tool_call,
    not_exposed,
    refusal,
)
from .removed_tools import removed_tool_error
from .switches import READ_ONLY_ENV
from .tool_annotations import for_tool

META_TOOLS = frozenset(
    {"search_tools", "describe_tool", "call_read_tool", "call_write_tool", "list_tool_families"}
)
DISPATCH_TOOLS = frozenset({"call_read_tool", "call_write_tool"})
#: UNIFI_TOOL_MODE values and the startup error naming them.
TOOL_MODES = ("discovery", "full", "codemode")
TOOL_MODE_ERROR = "UNIFI_TOOL_MODE must be one of discovery, full, codemode"
#: Set while the Code Mode read broker dispatches a script's call_tool, so that call (and
#: only that call) may reach a registered tool that Code Mode does not list.
_BROKER_CALL: ContextVar[bool] = ContextVar("unifi_code_mode_broker_call", default=False)
logger = logging.getLogger(__name__)
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


def search_result(found: list[dict[str, Any]], limit: int | None) -> ToolResult:
    """search_tools result: the ranked list plus the truncation marker.

    Backward compatible by construction: the first text block and
    ``structuredContent.result`` are the same JSON list as before, flagged for FastMCP
    clients to unwrap. ``more_available`` and ``total_matched`` are added beside
    ``result``. When the limit cut the list, a second text block says so in words, so a
    client that shows the model only text still learns the list is partial.
    """
    shown = found if limit is None else found[:limit]
    result = to_structured_list_result(shown)
    more = len(shown) < len(found)
    result.structured_content = {
        **(result.structured_content or {}),
        "more_available": more,
        "total_matched": len(found),
    }
    if more:
        result.content.append(
            TextContent(
                type="text",
                text=(
                    f"more_available: true. Showing {len(shown)} of {len(found)} matching "
                    "tools. Raise limit, pass limit=null for every match, or refine the "
                    "query or family."
                ),
            )
        )
    return result


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
        # Request framing is not resource vocabulary. Strip it only from the query,
        # retaining words such as "help" and "need" in the indexed tool descriptions.
        query = re.sub(r"^(?:I\s+need\s+to|Help\s+me)\s+(?=\S)", "", query.strip(), flags=re.I)
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
            if query.strip().lower().replace(" ", "_") == name.lower():
                score += 100.0
            if (
                query.strip().lower().split()
                and query.strip().lower().split()[0] == name.split("_")[0]
            ):
                score += 5.0
                if set(_terms(query)) <= set(_terms(name)):
                    score += 20.0
            # Asking for resource IDs is a request to enumerate matching resources.
            query_terms = set(_terms(query))
            if query_terms & {"id", "ids"} and name.startswith("list_"):
                resource_terms = query_terms - {"id", "ids"}
                if resource_terms and resource_terms <= set(_terms(name)):
                    score += 25.0
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

    def __init__(
        self, app: FastMCP, listed: frozenset[str] = META_TOOLS, *, code_mode: bool = False
    ) -> None:
        self.app = app
        self.listed = listed
        self.code_mode = code_mode

    async def on_list_tools(self, context: MiddlewareContext, call_next: CallNext) -> list[Tool]:
        return [tool for tool in await call_next(context) if tool.name in self.listed]

    async def on_call_tool(self, context: MiddlewareContext, call_next: CallNext) -> Any:
        name = context.message.name
        if self.code_mode:
            # Code Mode exposes exactly its three tools. Every other registered tool is
            # reachable only as a script's call_tool through the read broker.
            if name not in self.listed and not _BROKER_CALL.get():
                raise refusal(
                    name,
                    TOOL_NOT_EXPOSED,
                    f"{name!r} is not exposed in Code Mode (UNIFI_TOOL_MODE=codemode): only "
                    "search_tools, describe_tool and execute are callable. Call read tools "
                    "with call_tool inside an execute script. No request was sent.",
                )
            return await call_next(context)
        if name in DISPATCH_TOOLS:
            envelope = await self.app.get_tool(name)
            if envelope is None:
                # A startup-hidden dispatcher still reaches the audited read-only backstop.
                return await call_next(context)
            try:
                # This dispatcher bypasses the remaining middleware for its own
                # envelope; establish its parent context before the target re-enters
                # AuditContextMiddleware through the public dispatch API.
                from .audit import audit_call

                with audit_call(name):
                    return await envelope.run(context.message.arguments or {})
            except FrameworkValidationError as exc:
                error = argument_validation_error(exc, getattr(envelope, "fn", None))
                if error is None:
                    raise
                raise ToolError(format_argument_error(name, envelope, error)) from None
        return await call_next(context)


def _request_write_refusal(
    app: FastMCP, name: str, arguments: dict[str, Any]
) -> tuple[str, str] | None:
    """The request policy's coded refusal of write ``name``, or None (no request policy)."""
    from .request_policy import RequestPolicyMiddleware

    for middleware in app.middleware:
        if isinstance(middleware, RequestPolicyMiddleware):
            return middleware.write_refusal(name, arguments)
    return None


async def listed_entry(app: FastMCP, tool: Tool) -> dict[str, Any]:
    """The tool's entry exactly as the app's ``tools/list`` serves it to a client.

    The discovery catalog comes from ``list_tools(run_middleware=False)``, which skips
    the framework's ``$ref`` dereferencing (``FastMCP(dereference_schemas=True)``, on by
    default). Every schema the meta-tools hand out goes through the app's own
    dereferencing middleware here, so it is the full-mode entry and never carries
    ``$ref``/``$defs`` that full mode inlines. The other list middleware only filters.
    """

    def given(tools: Sequence[Tool]) -> CallNext[ListToolsRequest, Sequence[Tool]]:
        async def call_next(context: MiddlewareContext[ListToolsRequest]) -> Sequence[Tool]:
            return tools

        return call_next

    listed: Sequence[Tool] = [tool]
    list_context = MiddlewareContext(message=ListToolsRequest(), method="tools/list")
    for middleware in app.middleware:
        if isinstance(middleware, DereferenceRefsMiddleware):
            listed = list(await middleware.on_list_tools(list_context, given(listed)))
    (entry,) = listed
    return entry.to_mcp_tool().model_dump(by_alias=True, exclude_none=True)


async def apply_tool_mode(
    app: FastMCP,
    mode: str,
    *,
    read_only: bool = False,
    hidden_write_names: set[str] | None = None,
    hidden_area_writes: dict[str, str] | None = None,
    audit: Callable[[str, str], None] | None = None,
    audit_hmac_key: bytes | None = None,
) -> Callable[[], None]:
    """Apply mode after family selection; return lifecycle cleanup.

    ``codemode`` (experimental, read-only) lists only search_tools and describe_tool over
    the read tools plus ``execute(code)``, whose scripts read through the same broker as
    ``call_read_tool`` (:mod:`unifi_fabric.code_mode`); it never dispatches a write.

    ``hidden_write_names`` (``UNIFI_WRITE_POLICY=deny``) and ``hidden_area_writes`` (per-area write
    opt-outs, name -> variable) were removed before this runs, so search, describe and the
    family counts cover only callable tools; naming one still gets its refusal.
    ``audit(tool, reason)`` records a refusal by ``call_read_tool`` of a write it hides
    (read-only mode, a per-area opt-out) or a write route under read-only mode
    (``outcome=refused``), as the read-only and area opt-out middleware do for a direct call.
    """
    if mode not in TOOL_MODES:
        raise ValueError(TOOL_MODE_ERROR)
    codemode = mode == "codemode"
    if codemode and (audit_hmac_key is None or len(audit_hmac_key) != 32):
        raise ValueError("UNIFI_AUDIT_HMAC_KEY must provide 32 decoded bytes in Code Mode")
    listed = code_mode.CODE_MODE_TOOLS if codemode else META_TOOLS
    catalog = {tool.name: tool for tool in await app.list_tools(run_middleware=False)}
    if listed & catalog.keys():
        raise ValueError("Discovery meta-tool names collide with registered tools")
    if mode == "full":
        return lambda: None
    families = build_family_index()
    write_names = derive_write_tools(list(catalog.values()))
    # Code Mode searches and describes read tools only; the mixed GET relay stays (its
    # state-changing routes are refused per call by the broker).
    searchable = (
        {
            name: tool
            for name, tool in catalog.items()
            if name == "fabric_connector_get"
            or (name not in write_names and not is_write_tool_call(tool, name, {}))
        }
        if codemode
        else catalog
    )
    index: SearchIndex | None = SearchIndex(searchable, families)
    if codemode:
        logger.warning("UNIFI_TOOL_MODE=codemode: %s", code_mode.EXPERIMENTAL_NOTICE)
    counts = Counter(families.get(name, "other") for name in catalog)
    family_catalog = "; ".join(f"{slug}: {count}" for slug, count in sorted(counts.items()))

    area_hidden = dict(hidden_area_writes or {})

    def require_tool(name: str) -> Tool:
        from . import policy

        if name in policy.excluded_names():
            raise not_exposed(name)
        if read_only and name in (hidden_write_names or ()):
            raise refusal(name, WRITE_DENIED, read_only_message(name, tool=True))
        if name in area_hidden:
            raise refusal(name, WRITE_DENIED, hidden_area_write_refusal(name, area_hidden[name]))
        if name not in catalog:
            removed = removed_tool_error(name)
            if removed is not None:
                raise removed
            raise ToolError(
                f"Unknown or unavailable tool {name!r}. "
                "Use search_tools(query='', limit=null) to list enabled tools; "
                "UNIFI_FAMILY_ALLOW and UNIFI_EXCLUDE select the available "
                "families."
            )
        return catalog[name]

    async def search_tools(
        query: str, family: str | None = None, writes: bool | None = None, limit: int | None = 10
    ) -> ToolResult:
        """Find enabled tools by intent, ranked over names, descriptions and parameter schemas.

        Default returns ten matches. Choose any positive limit, or null for every
        match; no tool or search result is hard-capped. more_available is true when
        the limit cut the list (total_matched gives the full count): raise the limit
        or refine. Empty query browses tools.
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
        if limit is not None and limit < 1:
            index.search(query, family, writes, write_names, limit)
            raise AssertionError("limit < 1 is refused by SearchIndex.search")
        # Request policy headers (X-UniFi-Family-Allow / X-UniFi-Exclude) narrow the
        # searchable set to the tools this request may call.
        from .request_policy import visible_to_request

        found = [
            item
            for item in index.search(query, family, writes, write_names, None)
            if visible_to_request(item["name"])
        ]
        return search_result(found, limit)

    async def describe_tool(name: str) -> dict[str, Any]:
        """Return the complete enabled tool schema, identical to its full-mode tools/list entry.

        Args:
            name: Exact enabled tool name from search_tools, for example "list_devices".
        """
        return await listed_entry(app, require_tool(name))

    async def dispatch_read(
        name: str, arguments: dict[str, Any], *, script: bool = False
    ) -> ToolResult:
        """The one read broker: call_read_tool's body and every Code Mode call_tool.

        ``script`` (a Code Mode call) refuses every write, whatever the write switches,
        dry-run or read-only mode say, and is the only path to an unlisted tool there.
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
            if script:
                if audit is not None:
                    audit(name, READ_ONLY_ENV if read_only else "UNIFI_TOOL_MODE")
                raise refusal(
                    name,
                    WRITE_DENIED,
                    f"{name!r} writes (or this call uses a state-changing route); Code Mode "
                    "is read-only and never dispatches a write. No request was sent.",
                )
            if read_only:
                # call_write_tool is not listed in read-only mode: name the switch that
                # refuses the call instead of a dispatcher the caller cannot see.
                if audit is not None:
                    audit(name, READ_ONLY_ENV)
                raise refusal(
                    name,
                    WRITE_DENIED,
                    read_only_message(name, tool=True)
                    + " call_write_tool is not listed while read-only mode is on.",
                )
            denial = _request_write_refusal(app, name, arguments)
            if denial is not None:
                # The request's own policy (headers, exceptions) denies this write: refuse
                # with the coded refusal, as the direct call does, and audit it.
                code, message = denial
                if audit is not None:
                    from .refusal_audit import denial_reason

                    audit(name, denial_reason(name, arguments) if code == WRITE_DENIED else code)
                raise refusal(name, code, message)
            if audit is not None and name == "fabric_connector_get":
                # A state-changing relay route that a write opt-out refuses: audited with
                # that switch, as the direct call is.
                from .families.connector import connector

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
        if not script:
            return await app.call_tool(name, arguments)
        token = _BROKER_CALL.set(True)
        try:
            return await app.call_tool(name, arguments)
        finally:
            _BROKER_CALL.reset(token)

    async def call_read_tool(name: str, arguments: dict[str, Any]) -> ToolResult:
        """Execute a read tool with its original validation, guards, audit and result format.

        Refuses write calls, including state-changing routes of the mixed GET relay.
        Describe the target first; its schema and permissions apply. Read-only mode
        and secret scrubbing are preserved.

        Args:
            name: Exact enabled read tool name, for example "list_devices".
            arguments: Target schema arguments, for example {"host": "console", "site": "default"}.
        """
        return await dispatch_read(name, arguments)

    async def call_write_tool(name: str, arguments: dict[str, Any]) -> ToolResult:
        """Execute a tool that may mutate live configuration through registered dispatch.

        Describe the target first. Target validation, per-area opt-outs, UNIFI_WRITE_POLICY=deny,
        OAuth permissions, dry-run, audit and secret scrubbing match a direct call.

        Args:
            name: Exact enabled tool name, for example "update_wlan_config".
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

    async def broker(name: str, arguments: dict[str, Any]) -> ToolResult:
        return await dispatch_read(name, arguments, script=True)

    async def code_search_tools(
        query: str, family: str | None = None, limit: int | None = 10
    ) -> ToolResult:
        """Find enabled read tools by intent, ranked over names, descriptions and parameter schemas.

        Code Mode is read-only: only read tools are searched. Default returns ten matches;
        choose any positive limit, or null for every match. more_available is true when
        the limit cut the list (total_matched gives the full count). Empty query browses
        tools. Use describe_tool for the exact schema, then call the tool inside an execute
        script.

        Args:
            query: Natural language intent, for example "camera recordings";
                empty browses all read tools.
            family: Optional exact family slug, for example "protect".
            limit: Number of results (default 10); any positive integer or null for every match.
        """
        if index is None:
            raise ToolError("Discovery lifecycle has ended")
        if limit is not None and limit < 1:
            index.search(query, family, None, set(), limit)
            raise AssertionError("limit < 1 is refused by SearchIndex.search")
        from .request_policy import visible_to_request

        found = [
            item
            for item in index.search(query, family, None, set(), None)
            if visible_to_request(item["name"])
        ]
        return search_result(found, limit)

    async def code_describe_tool(name: str) -> dict[str, Any]:
        """Return the complete schema of an enabled read tool, as call_tool inside execute takes it.

        Args:
            name: Exact read tool name from search_tools, for example "list_hosts".
        """
        tool = require_tool(name)
        if name != "fabric_connector_get" and (
            name in write_names or is_write_tool_call(tool, name, {})
        ):
            raise refusal(
                name,
                WRITE_DENIED,
                f"{name!r} is a write tool; Code Mode is read-only and does not describe or "
                "call writes. No request was sent.",
            )
        return await listed_entry(app, tool)

    async def execute(code: str) -> str:
        """Run a Python script that reads UniFi data through read tools; returns its output.

        Experimental: no compatibility promise for this schema or the output shape.
        Inside the script, `result = await call_tool(name, arguments)` calls one read tool
        (names and schemas from search_tools/describe_tool) and returns
        {"ok": true, "result": ...} or {"ok": false, "error": {"code", "message"}}.
        Writes are always refused. The output is everything the script prints followed
        by its final expression (strings verbatim, other values as JSON). No imports of
        network, file or environment access exist in the sandbox.
        Limits: code 32,768 UTF-8 bytes; 32 tool calls (refusals count); each response
        262,144 bytes and 2,097,152 bytes in total (larger pages: use continuation);
        memory 64 MiB; recursion 64; 30 s of interpreter time (waits on UniFi are not
        counted); output 65,536 bytes, longer output ends with "...[truncated]"; one
        script at a time per server (code_mode_busy otherwise).

        Args:
            code: Python source, for example
                'hosts = await call_tool("list_hosts", {})\nhosts["result"]'.
        """
        from .header_credentials import current_request_id

        try:
            return await code_mode.run_script(
                code,
                dispatch=broker,
                known=searchable.__contains__,
                request_id=current_request_id(),
                audit=code_mode.log_run,
                audit_hmac_key=audit_hmac_key,
            )
        except code_mode.CodeModeError as exc:
            if exc.code in {code_mode.INVALID_SOURCE, code_mode.BUSY}:
                # Pre-dispatch refusals: their policy.refusal record, zero upstream calls.
                raise refusal(code_mode.EXECUTE_TOOL, exc.code, exc.message) from None
            raise exc.tool_error() from None

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
        + ". list_tool_families lists the families again."
    )
    functions: list[Callable[..., Any]] = (
        []
        if codemode
        else [
            search_tools,
            describe_tool,
            call_read_tool,
            call_write_tool,
            list_tool_families,
        ]
    )
    for fn in functions:
        description = inspect.cleandoc(fn.__doc__ or "").split("\n\nArgs:", 1)[0]
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
                # Results the server builds itself advertise their concrete shape; the
                # two dispatch tools return the target tool's own result.
                output_schema=output_schemas.SELF_BUILT.get(fn.__name__, NotSet),
            )
        )
    if codemode:
        app.instructions = (
            (original_instructions or "")
            + "\nCode Mode (experimental, read-only): search_tools finds enabled read tools; "
            "describe_tool gives exact schemas; execute(code) runs a Python script that "
            "calls them with await call_tool(name, arguments). Enabled families (counts): "
            + family_catalog
            + ". "
            + code_mode.EXPERIMENTAL_NOTICE
        )
        for fn, tool_name in (
            (code_search_tools, "search_tools"),
            (code_describe_tool, "describe_tool"),
            (execute, code_mode.EXECUTE_TOOL),
        ):
            description = inspect.cleandoc(fn.__doc__ or "").split("\n\nArgs:", 1)[0]
            if fn is code_search_tools:
                description += "\nEnabled families (tool counts): " + family_catalog + "."
            app.add_tool(
                Tool.from_function(
                    fn,
                    name=tool_name,
                    description=description,
                    # All three are reads; execute reaches UniFi through its scripts.
                    annotations=for_tool(writes=False, open_world=fn is execute),
                    # execute returns its output once, as text: no structuredContent copy,
                    # so the 65,536-byte output limit bounds the whole response.
                    output_schema=(None if fn is execute else output_schemas.SELF_BUILT[tool_name]),
                )
            )
    middleware = DiscoveryMiddleware(app, listed, code_mode=codemode)
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
        for name in listed:
            try:
                app.local_provider.remove_tool(name)
            except KeyError:
                # Startup read-only selection may already have removed a meta-tool.
                pass
        app.instructions = original_instructions

    return restore
