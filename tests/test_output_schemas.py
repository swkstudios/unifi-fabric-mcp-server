"""Output schemas of self-built results and the search_tools truncation marker.

The server builds some results itself (discovery search and family listing, fleet and
site roll-ups, the InnerSpace summary, the placement snapshot). Those advertise a
concrete ``outputSchema`` in which every property is described, and what they return
validates against it. Pass-through tools keep no schema. ``search_tools`` reports when
its limit cut the list, without changing the list clients already read.
"""

from __future__ import annotations

import json
from typing import Any

import jsonschema
import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric import output_schemas, server
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.discovery import apply_tool_mode

DOMAIN_SELF_BUILT = sorted(set(output_schemas.SELF_BUILT) - output_schemas.META_TOOL_SCHEMAS)
BARE_OBJECT = {"type": "object", "additionalProperties": True}


async def _discovery_app(mode: str = "discovery", **kwargs: Any) -> tuple[FastMCP, Any]:
    app = FastMCP("output-schema-test")
    for tool in await server.mcp.list_tools(run_middleware=False):
        app.add_tool(tool)
    app.middleware = list(server.mcp.middleware)
    restore = await apply_tool_mode(app, mode, **kwargs)
    return app, restore


def _undescribed(schema: Any, path: str = "$") -> list[str]:
    """JSON pointers of properties (at any depth) that carry no description."""
    missing: list[str] = []
    if isinstance(schema, dict):
        for name, prop in (schema.get("properties") or {}).items():
            if not (isinstance(prop, dict) and str(prop.get("description") or "").strip()):
                missing.append(f"{path}.{name}")
            missing += _undescribed(prop, f"{path}.{name}")
        for key in ("items", "additionalProperties"):
            if isinstance(schema.get(key), dict):
                missing += _undescribed(schema[key], f"{path}[{key}]")
        for key in ("anyOf", "oneOf", "allOf"):
            for i, sub in enumerate(schema.get(key) or []):
                missing += _undescribed(sub, f"{path}.{key}[{i}]")
    return missing


def _descriptions(schema: Any) -> list[str]:
    out: list[str] = []
    if isinstance(schema, dict):
        if isinstance(schema.get("description"), str):
            out.append(schema["description"])
        for value in schema.values():
            out += _descriptions(value)
    elif isinstance(schema, list):
        for value in schema:
            out += _descriptions(value)
    return out


# ------------------------------------------------------------------ search marker
@pytest.mark.asyncio
async def test_search_tools_default_limit_reports_truncation():
    app, restore = await _discovery_app()
    try:
        total = len(await server.mcp.list_tools(run_middleware=False))
        async with Client(app) as client:
            result = await client.call_tool("search_tools", {"query": ""})
        structured = result.structured_content
        rows = structured["result"]
        assert len(rows) == len(result.data) == 10  # FastMCP clients still unwrap the list
        assert [row.name for row in result.data] == [row["name"] for row in rows]
        assert structured["more_available"] is True
        assert structured["total_matched"] == total
        # Text block 0 is the list as before; block 1 tells a text-only reader.
        assert json.loads(result.content[0].text) == rows
        assert len(result.content) == 2
        note = result.content[1].text
        assert note.startswith("more_available: true.")
        assert f"Showing 10 of {total}" in note
        assert "limit=null" in note
    finally:
        restore()


@pytest.mark.asyncio
async def test_search_tools_unlimited_is_complete_and_text_unchanged():
    app, restore = await _discovery_app()
    try:
        total = len(await server.mcp.list_tools(run_middleware=False))
        async with Client(app) as client:
            result = await client.call_tool("search_tools", {"query": "", "limit": None})
            exact = await client.call_tool("search_tools", {"query": "", "limit": total})
        assert result.structured_content["more_available"] is False
        rows = result.structured_content["result"]
        assert result.structured_content["total_matched"] == total == len(rows)
        # One text block holding exactly the JSON list: byte-compatible with 0.7.1.
        assert len(result.content) == 1
        assert json.loads(result.content[0].text) == rows
        assert result.meta["fastmcp"] == {"wrap_result": True}
        # A limit equal to the match count cuts nothing.
        assert exact.structured_content["more_available"] is False
        assert len(exact.content) == 1
    finally:
        restore()


@pytest.mark.asyncio
async def test_search_tools_marker_counts_filtered_matches():
    app, restore = await _discovery_app()
    try:
        async with Client(app) as client:
            everything = await client.call_tool(
                "search_tools", {"query": "camera", "family": "protect", "limit": None}
            )
            two = await client.call_tool(
                "search_tools", {"query": "camera", "family": "protect", "limit": 2}
            )
        every = everything.structured_content["result"]
        matched = len(every)
        assert matched > 2
        assert two.structured_content["result"] == every[:2]
        assert two.structured_content["total_matched"] == matched
        assert two.structured_content["more_available"] is True
    finally:
        restore()


@pytest.mark.asyncio
async def test_code_mode_search_tools_reports_truncation():
    app, restore = await _discovery_app("codemode", audit_hmac_key=bytes(32))
    try:
        async with Client(app) as client:
            listed = {t.name: t for t in await client.list_tools()}
            result = await client.call_tool("search_tools", {"query": "", "limit": 3})
        assert listed["search_tools"].output_schema == output_schemas.SEARCH_TOOLS
        assert listed["describe_tool"].output_schema == output_schemas.DESCRIBE_TOOL
        assert result.structured_content["more_available"] is True
        assert result.structured_content["total_matched"] > 3
        jsonschema.validate(result.structured_content, output_schemas.SEARCH_TOOLS)
    finally:
        restore()


# ------------------------------------------------------------ advertised schemas
def test_every_self_built_schema_property_is_described():
    for name, schema in output_schemas.SELF_BUILT.items():
        assert schema != BARE_OBJECT, name
        assert schema.get("properties"), name
        assert _undescribed(schema) == [], name
        assert "$ref" not in json.dumps(schema), name
        # Client-visible description limit (nested descriptions included).
        assert all(len(text) <= 2048 for text in _descriptions(schema)), name
        jsonschema.Draft202012Validator.check_schema(schema)


@pytest.mark.asyncio
async def test_meta_tools_advertise_their_output_schema():
    app, restore = await _discovery_app()
    try:
        async with Client(app) as client:
            listed = {t.name: t for t in await client.list_tools()}
            families = await client.call_tool("list_tool_families", {})
            described = await client.call_tool("describe_tool", {"name": "list_hosts"})
            search = await client.call_tool("search_tools", {"query": "camera"})
        for name in output_schemas.META_TOOL_SCHEMAS:
            assert listed[name].output_schema == output_schemas.SELF_BUILT[name], name
        # The dispatch wrappers return the target tool's own result: no schema of theirs.
        assert listed["call_read_tool"].output_schema is None
        assert listed["call_write_tool"].output_schema is None
        jsonschema.validate(families.structured_content, output_schemas.LIST_TOOL_FAMILIES)
        rows = families.structured_content["result"]
        assert rows and all(set(row) == {"family", "tools"} for row in rows)
        jsonschema.validate(described.structured_content, output_schemas.DESCRIBE_TOOL)
        jsonschema.validate(search.structured_content, output_schemas.SEARCH_TOOLS)
    finally:
        restore()


@pytest.mark.asyncio
@pytest.mark.parametrize("name", DOMAIN_SELF_BUILT)
async def test_self_built_domain_tool_advertises_its_schema(name):
    tool = await server.mcp.get_tool(name)
    assert tool is not None, name
    assert tool.output_schema == output_schemas.SELF_BUILT[name]
    # Served through the list middleware ($ref dereferencing included), as full mode lists it.
    listed = {t.name: t for t in await server.mcp.list_tools()}
    assert listed[name].output_schema == output_schemas.SELF_BUILT[name]


# ------------------------------------------------- produced results match the schema
def _keys() -> list[APIKeyConfig]:
    # Synthetic labels; key values are built at runtime, never stored as literals.
    return [
        APIKeyConfig(key="-".join(("synthetic", label)), label=label, is_org_key=org)
        for label, org in (("alpha", False), ("beta", True))
    ]


async def _produce(monkeypatch, name: str, *, multi: bool, env: dict[str, str] | None = None):
    for key, value in {**tool_args.TOOL_ENV.get(name, {}), **(env or {})}.items():
        monkeypatch.setenv(key, value)
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up, keys=_keys() if multi else None)
    tool_args.prepare_upstream(name, up)
    tool = await server.mcp.get_tool(name)
    return await server.mcp.call_tool(name, tool_args.generated_args(tool))


@pytest.mark.asyncio
@pytest.mark.parametrize("multi", [False, True], ids=["single-key", "multi-key"])
@pytest.mark.parametrize("name", DOMAIN_SELF_BUILT)
async def test_self_built_result_matches_declared_shape(monkeypatch, name, multi):
    result = await _produce(monkeypatch, name, multi=multi)
    assert result.structured_content is not None, name
    jsonschema.validate(result.structured_content, output_schemas.SELF_BUILT[name])
    # The text block is the same object (no result was reshaped for the schema).
    assert json.loads(result.content[0].text) == result.structured_content


@pytest.mark.asyncio
@pytest.mark.parametrize("name", DOMAIN_SELF_BUILT)
async def test_self_built_capped_result_matches_declared_shape(monkeypatch, name):
    try:
        result = await _produce(
            monkeypatch, name, multi=True, env={"UNIFI_PAGINATE_MAX_PAGES": "1"}
        )
    except ToolError as exc:
        # A capped list may make a name ambiguous: a refusal, not a shape.
        assert "UNIFI_PAGINATE_MAX_PAGES" in str(exc), (name, str(exc))
        return
    jsonschema.validate(result.structured_content, output_schemas.SELF_BUILT[name])


def test_pass_through_tools_declare_no_concrete_schema():
    """Tools not in SELF_BUILT keep FastMCP's derived schema (none, a bare object or the
    list wrapper): a strict schema over a firmware-dependent upstream body is the defect
    the decision rules out."""
    import asyncio

    tools = asyncio.run(server.mcp.list_tools(run_middleware=False))
    for tool in tools:
        if tool.name in output_schemas.SELF_BUILT:
            continue
        schema = tool.output_schema
        assert (
            schema is None
            or schema == BARE_OBJECT
            or schema.get("x-fastmcp-wrap-result")
            or not schema.get("required")
        ), tool.name
