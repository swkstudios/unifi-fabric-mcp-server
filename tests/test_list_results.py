"""Explicit, structured list results (list_results.install_structured_list_results).

FastMCP turns an empty list return into ``content: []`` with no structuredContent, so a
client could not tell "zero items" from "no output" (seen live on list_firewall_rules,
list_traffic_routes, list_hotspot_packages, list_routing_entries and
get_historical_stats). Every list-shaped result must now carry a JSON text block and
``structuredContent: {"result": [...]}`` with the items unchanged. Classic REST tools now
return the controller's ``{"meta", "data"}`` envelope verbatim (an object), so an empty
Classic answer is the envelope itself — explicit and structured — never ``content: []``.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import jsonschema
import pytest
from fastmcp import Client, FastMCP
from fastmcp.utilities.types import Image
from mcp.types import TextContent

from unifi_fabric import server
from unifi_fabric.config import Settings
from unifi_fabric.list_results import (
    StructuredListResults,
    _is_plain_list,
    _make_structured_fn,
    _schema_admits_array,
    install_structured_list_results,
    is_wrapped,
    output_schema_admits_list_payload,
    to_structured_list_result,
)
from unifi_fabric.redaction import REDACTION_MASK

_EMPTY_CLASSIC = {"meta": {"rc": "ok"}, "data": []}

# The tools the live sweep saw return ``content: []``; each one's upstream answer here is
# the real empty shape that route returns (Classic envelope, or a bare v2 array).
EMPTY_CASES: list[tuple[str, dict[str, Any], str, Any]] = [
    ("list_firewall_rules", {"host": "h", "site": "s"}, "get", _EMPTY_CLASSIC),
    ("list_traffic_routes", {"host": "h", "site": "s"}, "get", []),
    ("list_traffic_rules", {"host": "h", "site": "s"}, "get", []),
    ("list_hotspot_packages", {"host": "h", "site": "s"}, "get", _EMPTY_CLASSIC),
    ("list_routing_entries", {"host": "h", "site": "s"}, "get", _EMPTY_CLASSIC),
    (
        "get_historical_stats",
        {
            "host": "h",
            "site": "s",
            "interval": "hourly",
            "scope": "site",
            "start": 1_700_000_000,
            "end": 1_700_086_400,
        },
        "post",
        _EMPTY_CLASSIC,
    ),
    ("get_channel_plan", {"host": "h", "site": "s"}, "get", _EMPTY_CLASSIC),
    ("list_wlan_groups", {"host": "h", "site": "s"}, "get", _EMPTY_CLASSIC),
]


@pytest.fixture
def upstream(monkeypatch):
    """Install a fake client/registry behind every tool (both _require call styles)."""
    client = MagicMock()
    client.get = AsyncMock()
    client.post = AsyncMock()
    registry = MagicMock()
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="host-001")
    registry.resolve_site_slug = AsyncMock(return_value="default")
    registry.resolve_site_id = AsyncMock(return_value="3fa85f64-5717-4562-b3fc-2c963f66afa6")
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    monkeypatch.setattr(server, "_settings", Settings())
    return client


_LIST_PAYLOADS = ({"result": []}, {"result": [{"a": 1}, "x", 3, None]})


async def test_every_tool_is_wrapped_exactly_when_its_output_schema_admits_the_payload():
    """Class coverage over all registered tools: a tool is served with the wrapper iff its
    advertised outputSchema accepts {"result": [...]}, checked independently with
    jsonschema — so the wrapper can never emit a schema-violating payload, and no tool
    that could carry it is left emitting a bare ``content: []``."""
    tools = await server.mcp.list_tools()
    assert len(tools) >= 250
    skipped = []
    for tool in tools:
        schema = tool.output_schema
        valid = schema is None or all(
            jsonschema.Draft202012Validator(schema).is_valid(p) for p in _LIST_PAYLOADS
        )
        assert output_schema_admits_list_payload(schema) is valid, tool.name
        assert is_wrapped(tool) is valid, tool.name
        # the call path (get_tool) serves the same decision as tools/list
        assert is_wrapped(await server.mcp.get_tool(tool.name)) is valid, tool.name
        if not valid:
            skipped.append(tool.name)
    # Every tool returns an object or list (delete tools return a deletion result
    # carrying the upstream body). Only the tools whose result the server assembles
    # itself declare a concrete object schema (output_schemas.SELF_BUILT); they always
    # return an object, so their schema rejects the list payload and they are served
    # unwrapped. No other tool may advertise a schema that rejects it.
    from unifi_fabric.output_schemas import META_TOOL_SCHEMAS, SELF_BUILT

    assert set(skipped) == set(SELF_BUILT) - META_TOOL_SCHEMAS
    for name in skipped:
        props = (await server.mcp.get_tool(name)).output_schema["properties"]
        assert "result" not in props or not _schema_admits_array(props["result"]), name


def test_install_is_idempotent():
    before = list(server.mcp.transforms)
    again = install_structured_list_results(server.mcp)
    assert isinstance(again, StructuredListResults)
    assert list(server.mcp.transforms) == before
    assert sum(isinstance(t, StructuredListResults) for t in server.mcp.transforms) == 1


def test_install_fails_loudly_without_public_transform_api():
    class NoTransforms:
        pass

    with pytest.raises(RuntimeError, match="add_transform"):
        install_structured_list_results(NoTransforms())


@pytest.mark.parametrize(
    "schema,admits",
    [
        (None, True),
        ({"type": "object", "additionalProperties": True}, True),
        ({"type": "object"}, True),
        ({"type": "object", "additionalProperties": False}, False),
        ({"type": "object", "required": ["other"]}, False),
        ({"type": "array"}, False),
        ({"type": "object", "properties": {"result": {"type": "string"}}}, False),
        ({"type": "object", "properties": {"result": {"type": "array"}}}, True),
        ({"type": "object", "properties": {"result": {"type": ["string", "array"]}}}, True),
        ({"type": "object", "properties": {"result": {}}}, True),
        (
            {
                "type": "object",
                "properties": {"result": {"anyOf": [{"type": "object"}, {"type": "string"}]}},
            },
            False,
        ),
        (
            {"type": "object", "properties": {"result": {"anyOf": [{"type": "array"}]}}},
            True,
        ),
        ({"type": "object", "properties": {"result": {"enum": [1]}}}, False),
    ],
)
def test_output_schema_admission_matches_jsonschema(schema, admits):
    assert output_schema_admits_list_payload(schema) is admits
    if schema is not None:
        valid = all(jsonschema.Draft202012Validator(schema).is_valid(p) for p in _LIST_PAYLOADS)
        assert valid is admits


async def test_narrow_schema_tool_is_served_unchanged():
    scratch = FastMCP("scratch")

    @scratch.tool
    async def text_only() -> str:
        return "ok"

    install_structured_list_results(scratch)
    tool = await scratch.get_tool("text_only")
    assert not is_wrapped(tool)
    result = await scratch.call_tool("text_only", {})
    assert result.structured_content == {"result": "ok"}


async def test_transform_caches_wrapped_copy_per_registered_tool():
    first = await server.mcp.get_tool("list_firewall_rules")
    second = await server.mcp.get_tool("list_firewall_rules")
    assert first is second
    assert is_wrapped(first)


def _wire(result: Any) -> tuple[list[Any], Any]:
    """(content blocks, structuredContent) of the MCP wire result, whatever form FastMCP
    serializes it to (a CallToolResult when meta is set, else a (content, structured)
    tuple)."""
    wire = result.to_mcp_result()
    if isinstance(wire, tuple):
        return list(wire[0]), wire[1]
    return list(wire.content), wire.structured_content


def _expected_empty(body: Any) -> tuple[str, Any]:
    """(text block, structuredContent) for an empty upstream answer: a bare list is wrapped
    as {"result": []}; a Classic envelope is relayed verbatim as the object it is."""
    if isinstance(body, list):
        return "[]", {"result": []}
    return json.dumps(body, separators=(",", ":")), body


@pytest.mark.parametrize("name,args,method,body", EMPTY_CASES)
async def test_empty_upstream_result_is_explicit_and_structured(upstream, name, args, method, body):
    getattr(upstream, method).return_value = body
    tool = await server.mcp.get_tool(name)
    result = await tool.run(args)
    text, structured = _expected_empty(body)
    assert [json.loads(c.text) for c in result.content] == [json.loads(text)]
    assert result.structured_content == structured


@pytest.mark.parametrize("name,args,method,body", EMPTY_CASES)
async def test_empty_result_through_server_pipeline(upstream, name, args, method, body):
    """Full server dispatch (middleware included) and the MCP wire result."""
    getattr(upstream, method).return_value = body
    result = await server.mcp.call_tool(name, args)
    content, sc = _wire(result)
    text, structured = _expected_empty(body)
    assert [json.loads(c.text) for c in content] == [json.loads(text)]
    assert sc == structured
    assert not result.is_error


async def test_fastmcp_client_unwraps_structured_list():
    """A FastMCP client sees the list itself in ``.data`` (wrap_result meta honoured)."""
    scratch = FastMCP("scratch")

    @scratch.tool
    async def rows(empty: bool) -> Any:
        return [] if empty else [{"id": "a"}]

    install_structured_list_results(scratch)
    async with Client(scratch) as mcp_client:
        empty = await mcp_client.call_tool("rows", {"empty": True})
        full = await mcp_client.call_tool("rows", {"empty": False})
    assert [c.text for c in empty.content] == ["[]"]
    assert empty.structured_content == {"result": []}
    assert empty.data == []
    assert full.structured_content == {"result": [{"id": "a"}]}
    assert full.data == [{"id": "a"}]


_MULTI_ROWS = [
    {"_id": "r1", "name": "rule-1", "future_field": {"nested": [1, 2]}},
    {"_id": "r2", "name": "rule-2", "enabled": False, "ruleset": "WAN_IN"},
    {"_id": "r3", "name": "rule-3", "src_address": "", "tags": []},
]


@pytest.mark.parametrize("rows", [_MULTI_ROWS[:1], _MULTI_ROWS, _MULTI_ROWS * 40])
async def test_multi_item_list_structured_equals_full_text_list(upstream, rows):
    """structuredContent carries every item, identical to the text block: a truncated,
    reordered or altered structured list fails here (v2 bare-array route)."""
    upstream.get.return_value = json.loads(json.dumps(rows))
    result = await server.mcp.call_tool("list_traffic_routes", {"host": "h", "site": "s"})
    assert len(result.content) == 1
    text_list = json.loads(result.content[0].text)
    assert text_list == rows
    assert result.structured_content == {"result": text_list}
    assert len(result.structured_content["result"]) == len(rows)
    wire = result.to_mcp_result()
    assert wire.structured_content["result"] == json.loads(wire.content[0].text)


@pytest.mark.parametrize("rows", [_MULTI_ROWS[:1], _MULTI_ROWS, _MULTI_ROWS * 40])
async def test_multi_item_classic_envelope_structured_equals_full_text(upstream, rows):
    """A Classic envelope comes back whole — meta and every data item — in both the
    structured content and the text block."""
    body = {"meta": {"rc": "ok"}, "data": json.loads(json.dumps(rows))}
    upstream.get.return_value = body
    result = await server.mcp.call_tool("list_firewall_rules", {"host": "h", "site": "s"})
    assert len(result.content) == 1
    assert json.loads(result.content[0].text) == body
    assert result.structured_content == body
    content, sc = _wire(result)
    assert sc == json.loads(content[0].text)


async def test_dict_result_untouched(upstream):
    upstream.get.return_value = {"meta": {"rc": "ok"}, "data": []}
    tool = await server.mcp.get_tool("list_hotspot_operators")
    result = await tool.run({"host": "h", "site": "s"})
    assert isinstance(result.structured_content, dict)
    assert "result" not in result.structured_content
    assert result.meta is None


async def test_redaction_still_applies_to_list_results(upstream, monkeypatch):
    """The structured wrapper runs after redaction, so redaction still sees the raw list."""
    upstream.get.return_value = {
        "meta": {"rc": "ok"},
        "data": [{"name": "ssid", "x_passphrase": "example-pass-value"}],
    }
    monkeypatch.setattr(server, "_settings", Settings(redact_secrets=True))
    tool = await server.mcp.get_tool("list_wlan_configs")
    result = await tool.run({"host": "h", "site": "s"})
    blob = json.dumps(result.structured_content) + result.content[0].text
    assert "example-pass-value" not in blob
    assert REDACTION_MASK in blob


def test_is_plain_list():
    assert _is_plain_list([])
    assert _is_plain_list(())
    assert _is_plain_list([{"a": 1}, "x", 3])
    assert not _is_plain_list({"data": []})
    assert not _is_plain_list("[]")
    assert not _is_plain_list(None)
    assert not _is_plain_list([TextContent(type="text", text="t")])
    assert not _is_plain_list([Image(data=b"\x89PNG", format="png")])


def test_to_structured_list_result_tuple():
    result = to_structured_list_result(({"a": 1},))
    assert result.structured_content == {"result": [{"a": 1}]}
    assert result.content[0].text == '[{"a":1}]'


async def test_wrapper_async_and_sync_paths():
    async def async_handler() -> Any:
        return []

    def sync_handler() -> Any:
        return {"k": "v"}

    a = _make_structured_fn(async_handler)
    s = _make_structured_fn(sync_handler)
    assert (await a()).structured_content == {"result": []}
    assert s() == {"k": "v"}
    assert getattr(a, "_unifi_structured_list_wrapped", False)
    assert getattr(s, "_unifi_structured_list_wrapped", False)

    def sync_list() -> Any:
        return [1]

    assert _make_structured_fn(sync_list)().structured_content == {"result": [1]}
