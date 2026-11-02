"""Explicit, structured tool results for list-shaped responses.

Many tools return the upstream ``data`` array (Classic REST ``{"meta": ..., "data": [...]}``
envelopes, v2 list endpoints, projected selections). FastMCP converts a tool's
return value into MCP content blocks, and it treats a returned list as a list of
content blocks: an EMPTY list is (vacuously) "all content blocks", so it becomes
``content: []`` with no ``structuredContent``. A client then receives nothing at all
and cannot tell "the upstream returned zero items" from "the tool produced no output".
A non-empty list fared better (one JSON text block) but still carried no
``structuredContent``, unlike dict-shaped results.

:func:`install_structured_list_results` closes that gap at one shared point, using
FastMCP's public server-level transform API (``FastMCP.add_transform``). The
transform hands out each tool with its handler wrapped so a list-shaped result is
returned as:

* ``content``: one text block holding the JSON array — byte-identical to the text a
  non-empty list already produced, and ``"[]"`` for an empty one; and
* ``structuredContent``: ``{"result": [...]}`` — FastMCP's own convention for
  non-object results (the MCP spec requires ``structuredContent`` to be an object),
  flagged with ``_meta.fastmcp.wrap_result`` so FastMCP clients unwrap it back to the
  list.

A tool is wrapped only when its advertised ``outputSchema`` admits that payload (no
schema, or an open object schema). A tool that advertises a narrower schema — e.g.
``{"result": string}`` — is left exactly as FastMCP serves it, so the wrapper can never
emit a payload that violates a tool's own advertised schema.

The same gap swallows a ``None`` result: a write whose upstream answered 200/204 with no
body (``restart_device``, ``update_network`` ...) and a read passed through verbatim
both returned ``content: []``. A ``None`` result is served as an explicit ``"null"``
text block plus ``structuredContent: {"result": null}`` (same ``wrap_result`` flag), so
an empty-body success is never an empty MCP result.

The list itself is not altered — every item is passed through unchanged (see the
pass-through invariant in ``CLAUDE.md``). Dict, scalar, and content-block results are
returned untouched. The opt-in redaction wrapper replaces handlers at registration, so
it always runs inside this one and still sees the raw list.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Sequence
from typing import Any

from fastmcp.server.transforms import GetToolNext, Transform
from fastmcp.tools.base import Tool, ToolResult, default_serializer
from fastmcp.utilities.types import Audio, File, Image
from mcp.types import ContentBlock, TextContent
from pydantic_core import to_jsonable_python

_WRAPPED_FLAG = "_unifi_structured_list_wrapped"


def _is_plain_list(value: Any) -> bool:
    """True for a list/tuple result that is data, not MCP content blocks."""
    if not isinstance(value, list | tuple):
        return False
    return not any(isinstance(item, ContentBlock | Image | Audio | File) for item in value)


def to_structured_list_result(value: list[Any] | tuple[Any, ...]) -> ToolResult:
    """Build the explicit text + structured result for a list-shaped tool return."""
    items = to_jsonable_python(list(value), fallback=str)
    return ToolResult(
        content=[TextContent(type="text", text=default_serializer(items))],
        structured_content={"result": items},
        meta={"fastmcp": {"wrap_result": True}},
    )


def to_structured_null_result() -> ToolResult:
    """Build the explicit text + structured result for a ``None`` tool return."""
    return ToolResult(
        content=[TextContent(type="text", text="null")],
        structured_content={"result": None},
        meta={"fastmcp": {"wrap_result": True}},
    )


def _schema_admits_type(schema: Any, json_type: str) -> bool:
    """True if a JSON-schema fragment accepts a value of JSON type ``json_type``."""
    if not isinstance(schema, dict):
        return False
    if not schema:  # {} accepts anything
        return True
    if any(
        _schema_admits_type(s, json_type) for key in ("anyOf", "oneOf") for s in schema.get(key, [])
    ):
        return True
    declared = schema.get("type")
    if declared is None:
        return not any(k in schema for k in ("anyOf", "oneOf", "allOf", "const", "enum", "$ref"))
    return declared == json_type or (isinstance(declared, list) and json_type in declared)


def _schema_admits_array(schema: Any) -> bool:
    """True if a JSON-schema fragment accepts a JSON array."""
    return _schema_admits_type(schema, "array")


def _output_schema_admits_result(schema: dict[str, Any] | None, json_type: str) -> bool:
    if schema is None:
        return True
    if schema.get("type", "object") != "object":
        return False
    props = schema.get("properties") or {}
    if "result" in props:
        return _schema_admits_type(props["result"], json_type)
    required = set(schema.get("required") or [])
    return schema.get("additionalProperties", True) is not False and required <= {"result"}


def output_schema_admits_list_payload(schema: dict[str, Any] | None) -> bool:
    """True if ``{"result": [...]}`` is valid under a tool's advertised output schema."""
    return _output_schema_admits_result(schema, "array")


def output_schema_admits_null_payload(schema: dict[str, Any] | None) -> bool:
    """True if ``{"result": null}`` is valid under a tool's advertised output schema."""
    return _output_schema_admits_result(schema, "null")


def _make_structured_fn(
    fn: Callable[..., Any], *, lists: bool = True, nulls: bool = True
) -> Callable[..., Any]:
    """Wrap a tool handler so list (``lists``) and ``None`` (``nulls``) results become
    explicit text + structured content."""

    def convert(result: Any) -> Any:
        if lists and _is_plain_list(result):
            return to_structured_list_result(result)
        if nulls and result is None:
            return to_structured_null_result()
        return result

    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            return convert(await fn(*args, **kwargs))

        setattr(async_wrapper, _WRAPPED_FLAG, True)
        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        return convert(fn(*args, **kwargs))

    setattr(sync_wrapper, _WRAPPED_FLAG, True)
    return sync_wrapper


def is_wrapped(tool: Tool) -> bool:
    """True if ``tool`` is served with the structured-list wrapper."""
    return bool(getattr(getattr(tool, "fn", None), _WRAPPED_FLAG, False))


class StructuredListResults(Transform):
    """Server-level transform serving each eligible tool with the list wrapper.

    Eligible = a function tool whose advertised output schema admits
    ``{"result": [...]}`` or ``{"result": null}`` (each conversion applies only where
    the schema admits its payload). The wrapped copy is cached per registered tool object, so
    the per-call cost is a dict lookup; re-registering a tool yields a fresh copy.
    """

    def __init__(self) -> None:
        self._cache: dict[str, tuple[Tool, Tool]] = {}

    def wrap(self, tool: Tool) -> Tool:
        fn = getattr(tool, "fn", None)
        if fn is None or not callable(fn) or getattr(fn, _WRAPPED_FLAG, False):
            return tool
        lists = output_schema_admits_list_payload(tool.output_schema)
        nulls = output_schema_admits_null_payload(tool.output_schema)
        if not (lists or nulls):
            return tool
        cached = self._cache.get(tool.key)
        if cached is not None and cached[0] is tool:
            return cached[1]
        structured = _make_structured_fn(fn, lists=lists, nulls=nulls)
        wrapped = tool.model_copy(update={"fn": structured})
        self._cache[tool.key] = (tool, wrapped)
        return wrapped

    async def list_tools(self, tools: Sequence[Tool]) -> Sequence[Tool]:
        return [self.wrap(tool) for tool in tools]

    async def get_tool(
        self, name: str, call_next: GetToolNext, *, version: Any = None
    ) -> Tool | None:
        tool = await call_next(name, version=version)
        return self.wrap(tool) if tool is not None else None


def install_structured_list_results(mcp: Any) -> StructuredListResults:
    """Register the structured-list transform on ``mcp`` (public ``add_transform`` API).

    Idempotent. Raises ``RuntimeError`` at startup if the FastMCP instance has no
    ``add_transform`` — a FastMCP API change must fail loudly, never silently drop the
    explicit-empty-result guarantee.
    """
    add_transform = getattr(mcp, "add_transform", None)
    if not callable(add_transform):
        raise RuntimeError(
            "install_structured_list_results: this FastMCP instance has no public "
            "add_transform(); explicit structured list results cannot be installed. "
            "FastMCP's transform API changed — update unifi_fabric.list_results."
        )
    for existing in getattr(mcp, "transforms", None) or []:
        if isinstance(existing, StructuredListResults):
            return existing
    transform = StructuredListResults()
    add_transform(transform)
    return transform
