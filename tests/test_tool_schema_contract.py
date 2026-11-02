"""Tool schema contract: parameter descriptions, schema stability, and annotations.

Agents choose arguments from each tool's JSON schema. These gates keep that schema
useful and stable:

* every property of every tool carries a ``description`` (lifted from the docstring's
  Google-style ``Args:`` section by FastMCP at registration), and so does every nested
  property at any depth (generated body shapes and typed models alike);
* the docstring layout cannot silently truncate the tool description (FastMCP keeps
  only the text before the first structured section);
* adding descriptions changed nothing else: with description keys stripped, every
  input schema equals the committed baseline captured before the change;
* every tool advertises all four MCP annotation hints from the source derivation,
  and docs/TOOLS.md lists them.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from griffe import Docstring, DocstringSectionKind

from unifi_fabric import server
from unifi_fabric._read_only_audit import (
    classify_tool_verbs,
    derive_write_tools,
    reaches_upstream,
)
from unifi_fabric.argument_errors import _example_from_description

BASELINE = Path(__file__).parent / "fixtures" / "tool_input_schemas_baseline.json"
ROOT = Path(__file__).resolve().parents[1]
BASELINE_GENERATOR = ROOT / "scripts" / "gen_tool_input_schemas.py"


def _tools() -> list[Any]:
    result = server.mcp.list_tools()
    if inspect.isawaitable(result):
        result = asyncio.run(result)
    return list(result)


def _catalog_count() -> int:
    return len(server.mcp._local_provider._components)  # noqa: SLF001 - registered catalog


def _strip_descriptions(schema: Any) -> Any:
    """Drop JSON-schema ``description`` keywords, keeping property *names* intact."""
    if isinstance(schema, dict):
        out: dict[str, Any] = {}
        for key, value in schema.items():
            if key == "properties" and isinstance(value, dict):
                out[key] = {name: _strip_descriptions(sub) for name, sub in value.items()}
            elif key == "description" and isinstance(value, str):
                continue
            else:
                out[key] = _strip_descriptions(value)
        return out
    if isinstance(schema, list):
        return [_strip_descriptions(item) for item in schema]
    return schema


def _missing_property_descriptions(schema: Any, path: str = "") -> list[str]:
    """Return every undocumented property below a JSON-schema node.

    The traversal is intentionally schema-generic: advisory shapes use ``anyOf`` and
    nested arrays today, and future schemas may use other JSON Schema containers.
    """
    if isinstance(schema, list):
        return [
            missing
            for index, child in enumerate(schema)
            for missing in _missing_property_descriptions(child, f"{path}[{index}]")
        ]
    if not isinstance(schema, dict):
        return []
    missing: list[str] = []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for name, child in properties.items():
            child_path = f"{path}.{name}" if path else str(name)
            if not isinstance(child, dict) or not str(child.get("description") or "").strip():
                missing.append(child_path)
            missing.extend(_missing_property_descriptions(child, child_path))
    for key, child in schema.items():
        if key != "properties":
            child_path = f"{path}.{key}" if path else key
            missing.extend(_missing_property_descriptions(child, child_path))
    return missing


# Keywords whose values are subschemas (one, a list, or a name -> schema map). A nested
# property is reached through any of them, so the description check follows them all.
_SUBSCHEMA_ONE = ("items", "additionalProperties", "not")
_SUBSCHEMA_LIST = ("anyOf", "oneOf", "allOf", "prefixItems")
_SUBSCHEMA_MAP = ("$defs", "definitions")


def _undescribed(schema: Any, path: str) -> list[str]:
    """Every property under ``schema``, at any depth, without a nonempty description."""
    if not isinstance(schema, dict):
        return []
    out: list[str] = []
    for name, sub in (schema.get("properties") or {}).items():
        if not isinstance(sub, dict) or not str(sub.get("description") or "").strip():
            out.append(f"{path}.{name}")
        out += _undescribed(sub, f"{path}.{name}")
    for key in _SUBSCHEMA_ONE:
        out += _undescribed(schema.get(key), f"{path}/{key}")
    for key in _SUBSCHEMA_LIST:
        for i, sub in enumerate(schema.get(key) or []):
            out += _undescribed(sub, f"{path}/{key}[{i}]")
    for key in _SUBSCHEMA_MAP:
        for name, sub in (schema.get(key) or {}).items():
            out += _undescribed(sub, f"{path}/{key}/{name}")
    return out


def test_every_parameter_has_a_description() -> None:
    tools = _tools()
    assert len(tools) == _catalog_count()
    missing = [path for tool in tools for path in _undescribed(tool.parameters, tool.name)]
    assert missing == [], (
        f"{len(missing)} schema properties without a description (top level: add a "
        "`name: text` entry to the tool docstring's Args: section; generated body "
        "shapes: tests/tool_shapes_gen.py FIELD_NOTES; typed models: a Field "
        f"description): {missing}"
    )
    generic_missing = [
        f"{tool.name}.{path}"
        for tool in tools
        for path in _missing_property_descriptions(tool.parameters)
    ]
    assert generic_missing == [], f"Schema properties without a description: {generic_missing}"


def test_description_contract_recurses_into_unions_and_items() -> None:
    schema = {
        "properties": {
            "outer": {
                "description": "Outer object.",
                "anyOf": [{"items": {"properties": {"inner": {}}}}],
            }
        }
    }
    assert _missing_property_descriptions(schema) == ["outer.anyOf[0].items.inner"]


def test_description_check_reaches_every_nesting_keyword() -> None:
    leaf = {"properties": {"bare": {"type": "string"}}}
    described = {"description": "x", **leaf}
    schema = {
        "properties": {
            "a": described,
            "b": {"description": "x", "items": leaf},
            "c": {"description": "x", "anyOf": [leaf, {}]},
            "d": {"description": "x", "oneOf": [leaf]},
            "e": {"description": "x", "allOf": [leaf]},
            "f": {"description": "x", "additionalProperties": leaf},
            "g": {"type": "string"},
            "h": {"description": "  "},
        },
        "$defs": {"Model": leaf},
    }
    assert sorted(_undescribed(schema, "t")) == sorted(
        [
            "t.a.bare",
            "t.b/items.bare",
            "t.c/anyOf[0].bare",
            "t.d/oneOf[0].bare",
            "t.e/allOf[0].bare",
            "t.f/additionalProperties.bare",
            "t.g",
            "t.h",
            "t/$defs/Model.bare",
        ]
    )


def test_docstring_layout_keeps_full_tool_description() -> None:
    # FastMCP uses only the text before the first structured docstring section as the
    # tool description. A stray "Word: ..." line followed by an indented block would be
    # parsed as a section and silently cut everything after it, so each docstring must
    # parse as exactly [text, Args] (or [text] for a tool with no parameters).
    bad = []
    for tool in _tools():
        doc = inspect.getdoc(inspect.unwrap(tool.fn)) or ""
        kinds = [s.kind for s in Docstring(doc, lineno=1, parser="google").parse()]
        expected = [DocstringSectionKind.text]
        if tool.parameters.get("properties"):
            expected.append(DocstringSectionKind.parameters)
        if kinds != expected:
            bad.append(f"{tool.name}: {[k.value for k in kinds]}")
        prose = doc.split("\n\nArgs:\n")[0].strip()
        if (tool.description or "").strip() != prose:
            bad.append(f"{tool.name}: description differs from the docstring prose")
    assert bad == []


def test_args_section_documents_exactly_the_signature() -> None:
    bad = []
    for tool in _tools():
        doc = inspect.getdoc(inspect.unwrap(tool.fn)) or ""
        documented: list[str] = []
        for section in Docstring(doc, lineno=1, parser="google").parse():
            if section.kind == DocstringSectionKind.parameters:
                documented = [p.name for p in section.value]
        if documented != list(tool.parameters.get("properties") or {}):
            bad.append(tool.name)
    assert bad == []


def test_input_schemas_unchanged_apart_from_descriptions() -> None:
    baseline = json.loads(BASELINE.read_text())
    schemas = baseline["schemas"]
    assert len(schemas) == baseline["tool_count"] == _catalog_count()
    current = {tool.name: tool.parameters for tool in _tools()}
    assert sorted(current) == sorted(schemas)
    drift = [
        name
        for name, schema in current.items()
        if _strip_descriptions(schema) != _strip_descriptions(schemas[name])
    ]
    assert drift == [], f"input schema changed beyond descriptions: {drift}"


def test_input_schema_baseline_is_regenerated_and_counts_live_catalog() -> None:
    baseline = json.loads(BASELINE.read_text())
    assert baseline["tool_count"] == len(baseline["schemas"]) == _catalog_count()
    result = subprocess.run(  # noqa: S603 -- fixed local generator path and interpreter
        [sys.executable, str(BASELINE_GENERATOR), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,  # noqa: S603 -- fixed local generator path and interpreter
    )
    assert result.returncode == 0, result.stderr or result.stdout


def _hint(annotations: Any, camel: str, snake: str) -> Any:
    """Read a hint under either MCP SDK naming (v1 camelCase, v2 snake_case)."""
    if snake in type(annotations).model_fields:
        return getattr(annotations, snake)
    return getattr(annotations, camel)


def _read_only(a: Any) -> Any:
    return _hint(a, "readOnlyHint", "read_only_hint")


def _destructive(a: Any) -> Any:
    return _hint(a, "destructiveHint", "destructive_hint")


def _idempotent(a: Any) -> Any:
    return _hint(a, "idempotentHint", "idempotent_hint")


def _open_world(a: Any) -> Any:
    return _hint(a, "openWorldHint", "open_world_hint")


def _expected_hints(verbs: set[str], open_world: bool) -> dict[str, bool]:
    """The derivation, written out independently of tool_annotations.for_tool."""
    write = bool(verbs)
    return {
        "readOnlyHint": not write,
        "destructiveHint": write,
        "idempotentHint": not write or verbs == {"PUT"} or verbs == {"DELETE"},
        "openWorldHint": open_world,
    }


def _hints(annotations: Any) -> dict[str, Any]:
    return {
        "readOnlyHint": _read_only(annotations),
        "destructiveHint": _destructive(annotations),
        "idempotentHint": _idempotent(annotations),
        "openWorldHint": _open_world(annotations),
    }


def test_every_tool_advertises_all_four_hints_from_the_derivation() -> None:
    tools = _tools()
    verbs = classify_tool_verbs(tools)
    wrong = []
    for tool in tools:
        assert tool.annotations is not None, f"{tool.name} has no annotations"
        expected = _expected_hints(verbs[tool.name], reaches_upstream(tool.fn))
        if _hints(tool.annotations) != expected:
            wrong.append(f"{tool.name}: {_hints(tool.annotations)} != {expected}")
    assert wrong == []
    read_only = [t.name for t in tools if _read_only(t.annotations)]
    # The expected read-only set is derived from the registry, never a literal count:
    # every registered tool minus the write set classified from source.
    write_tools = derive_write_tools(tools)
    assert 0 < len(write_tools) < len(tools)
    assert set(read_only) == {t.name for t in tools} - write_tools
    assert "get_firewall_policy_ordering" in read_only
    assert "set_firewall_policy_ordering" not in read_only


def test_every_connector_annotation_accounts_for_all_reachable_routes() -> None:
    """Even the GET relay can reach Protect actions, so every generic relay writes."""
    connectors = [tool for tool in _tools() if tool.name.startswith("fabric_connector_")]
    assert {tool.name for tool in connectors} == {
        f"fabric_connector_{verb}" for verb in ("get", "post", "put", "patch", "delete")
    }
    derived_writes = derive_write_tools(connectors)
    for tool in connectors:
        assert tool.name in derived_writes, tool.name
        assert _read_only(tool.annotations) is False, tool.name
        assert _destructive(tool.annotations) is True, tool.name
        assert _idempotent(tool.annotations) is False, tool.name
    # Typed Protect reads share the relay implementation, but expose no action route.
    tools = {tool.name: tool for tool in _tools()}
    for name in ("get_camera_private", "get_nvr_private", "list_ptz_presets", "list_ptz_patrols"):
        assert _read_only(tools[name].annotations) is True, name


def test_open_world_is_false_exactly_for_the_local_tools() -> None:
    """The call-graph answer agrees with the API source table's local-only tools."""
    from unifi_fabric._api_source_table import TOOL_API_SOURCES

    tools = _tools()
    local = {t.name for t in tools if not reaches_upstream(t.fn)}
    assert local == {
        name for name, sources in TOOL_API_SOURCES.items() if sources == ("server/local",)
    }
    assert local == {"list_configured_api_keys"}


def test_install_annotates_every_registered_tool_and_fails_closed() -> None:
    from unifi_fabric.tool_annotations import install_tool_annotations

    assert install_tool_annotations(server.mcp) == _catalog_count() == len(_tools())
    with pytest.raises(RuntimeError, match="registered tool catalog"):
        install_tool_annotations(object())


# Synthetic tools for the mutation tests: module-level so the source audit can read them.
async def _synthetic_get(client: Any) -> Any:
    return await client.get("/proxy/network/integration/v1/sites")


async def _synthetic_put(client: Any) -> Any:
    return await client.put("/proxy/network/integration/v1/sites/s/things/t", json={})


async def _synthetic_delete(client: Any) -> Any:
    return await client.delete("/proxy/network/integration/v1/sites/s/things/t")


async def _synthetic_post(client: Any) -> Any:
    return await client.post("/proxy/network/integration/v1/sites/s/things", json={})


async def _synthetic_patch(client: Any) -> Any:
    return await client.patch("/proxy/network/integration/v1/sites/s/things/t", json={})


async def _synthetic_put_and_delete(client: Any, remove: bool) -> Any:
    if remove:
        return await client.delete("/proxy/network/integration/v1/sites/s/things/t")
    return await client.put("/proxy/network/integration/v1/sites/s/things/t", json={})


def _synthetic_state_changing_get_impl(client: Any) -> Any:
    return client.get("/proxy/protect/api/cameras/c/enable-control")


def _synthetic_local() -> list[str]:
    return ["local-only"]


def _synthetic_hints(name: str, fn: Any) -> dict[str, Any]:
    from types import SimpleNamespace

    from unifi_fabric.tool_annotations import for_tool

    tool = SimpleNamespace(name=name, fn=fn)
    return _hints(
        for_tool(verbs=classify_tool_verbs([tool])[name], open_world=reaches_upstream(fn))
    )


def test_mutation_get_is_a_read() -> None:
    assert _synthetic_hints("get_thing", _synthetic_get) == {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }


def test_mutation_put_and_delete_alone_are_idempotent_destructive_writes() -> None:
    for name, fn in (("update_thing", _synthetic_put), ("delete_thing", _synthetic_delete)):
        assert _synthetic_hints(name, fn) == {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
            "openWorldHint": True,
        }, name


def test_mutation_post_patch_and_several_verbs_are_not_idempotent() -> None:
    for name, fn in (
        ("post_thing", _synthetic_post),
        ("patch_thing", _synthetic_patch),
        ("set_thing", _synthetic_put_and_delete),
    ):
        hints = _synthetic_hints(name, fn)
        assert hints["readOnlyHint"] is False and hints["destructiveHint"] is True, name
        assert hints["idempotentHint"] is False, name


def test_mutation_state_changing_get_is_a_non_idempotent_write() -> None:
    from unifi_fabric._read_only_audit import state_changing_get

    fn = state_changing_get(_synthetic_state_changing_get_impl)
    assert _synthetic_hints("enable_thing_control", fn) == {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    }


def test_mutation_create_prefix_changes_nothing() -> None:
    assert _synthetic_hints("create_thing", _synthetic_post) == _synthetic_hints(
        "post_thing", _synthetic_post
    )
    assert _synthetic_hints("create_thing", _synthetic_post)["destructiveHint"] is True


def test_mutation_local_function_is_not_open_world() -> None:
    assert _synthetic_hints("list_local_things", _synthetic_local)["openWorldHint"] is False


def _advertised(mode: str) -> dict[str, Any]:
    from fastmcp import Client

    async def _list() -> dict[str, Any]:
        async with Client(server.mcp) as client:
            listed = await client.list_tools()
        return {t.name: t.annotations for t in listed}

    original = server._settings
    server._settings = server.Settings(api_key="test-key-not-used", tool_mode=mode)
    try:
        return asyncio.run(_list())
    finally:
        server._settings = original


def test_annotations_advertised_on_the_wire_in_full_mode() -> None:
    advertised = _advertised("full")
    expected = {
        # a read
        "get_firewall_policy_ordering": (True, False, True, True),
        # a single PUT (ordering replace)
        "set_firewall_policy_ordering": (False, True, True, True),
        # a single DELETE
        "delete_firewall_policy": (False, True, True, True),
        # a PATCH
        "patch_firewall_policy": (False, True, False, True),
        # a create (POST) stays destructive
        "create_network": (False, True, False, True),
        # a Classic delete command POST
        "forget_device": (False, True, False, True),
        # local configuration only
        "list_configured_api_keys": (True, False, True, False),
    }
    for name, (read_only, destructive, idempotent, open_world) in expected.items():
        assert _hints(advertised[name]) == {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": open_world,
        }, name


def test_annotations_advertised_on_the_wire_in_discovery_mode() -> None:
    advertised = _advertised("discovery")
    assert set(advertised) == {
        "search_tools",
        "describe_tool",
        "call_read_tool",
        "call_write_tool",
        "list_tool_families",
    }
    local_read = (True, False, True, False)
    expected = {
        "search_tools": local_read,
        "describe_tool": local_read,
        "list_tool_families": local_read,
        "call_read_tool": (True, False, True, True),
        "call_write_tool": (False, True, False, True),
    }
    for name, (read_only, destructive, idempotent, open_world) in expected.items():
        assert _hints(advertised[name]) == {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": open_world,
        }, name


def test_annotation_constants_are_derived_from_one_classification() -> None:
    from unifi_fabric import tool_annotations

    assert tool_annotations.for_tool(verbs=set()) == tool_annotations.READ_ONLY
    assert tool_annotations.for_tool(verbs={"POST"}) == tool_annotations.WRITE
    assert tool_annotations.for_tool(writes=False) == tool_annotations.READ_ONLY
    assert tool_annotations.for_tool(writes=True) == tool_annotations.WRITE
    assert tool_annotations.READ_ONLY != tool_annotations.WRITE
    # No second, identical write constant that could drift from the derivation.
    constants = [
        name
        for name, value in vars(tool_annotations).items()
        if isinstance(value, type(tool_annotations.WRITE))
    ]
    assert sorted(constants) == ["READ_ONLY", "WRITE"]


def test_tools_reference_lists_the_advertised_annotations() -> None:
    """docs/TOOLS.md carries each tool's four hints, current with the runtime."""
    doc = (ROOT / "docs" / "TOOLS.md").read_text()
    sections = re.split(r"^### `([a-z0-9_]+)`$", doc, flags=re.M)
    listed = {}
    for name, body in zip(sections[1::2], sections[2::2], strict=True):
        match = re.search(
            r"^\| readOnly \| destructive \| idempotent \| openWorld \|\n"
            r"\| --- \| --- \| --- \| --- \|\n"
            r"\| (true|false) \| (true|false) \| (true|false) \| (true|false) \|$",
            body,
            flags=re.M,
        )
        assert match, f"docs/TOOLS.md: {name} has no annotation row"
        listed[name] = [value == "true" for value in match.groups()]
    tools = {t.name: t for t in _tools()}
    assert set(listed) == set(tools)
    for name, tool in tools.items():
        assert listed[name] == list(_hints(tool.annotations).values()), name


def test_no_tool_description_paragraph_is_a_fragment() -> None:
    # A paragraph that starts lower-case or with "(" is the tail of a sentence whose
    # beginning moved into the Args: section — a dangling fragment in the description.
    fragments = []
    for tool in _tools():
        for para in re.split(r"\n\s*\n", tool.description or ""):
            text = para.lstrip()
            if text and (text[0].islower() or text[0] == "("):
                fragments.append(f"{tool.name}: {text[:60]!r}")
    assert fragments == []


def _schema_types(schema: dict[str, Any]) -> set[str]:
    if "type" in schema:
        return {schema["type"]}
    return {v.get("type") for v in schema.get("anyOf", []) if isinstance(v, dict)}


def _placeholders(value: Any, path: str, out: list[str]) -> None:
    if isinstance(value, dict):
        for key, sub in value.items():
            if isinstance(sub, str) and (sub == key or sub.startswith("<")):
                out.append(f"{path}.{key}={sub!r}")
            _placeholders(sub, f"{path}.{key}", out)
    elif isinstance(value, list):
        for idx, sub in enumerate(value):
            _placeholders(sub, f"{path}[{idx}]", out)


def test_example_calls_use_real_values_of_the_right_type() -> None:
    bad: list[str] = []
    with_examples = 0
    for tool in _tools():
        description = tool.description or ""
        if "docs/TOOL-USAGE.md#" in description:
            reference = (Path(__file__).resolve().parents[1] / "docs/TOOL-USAGE.md").read_text()
            section = reference.split(f"## {tool.name}\n", 1)[1].split("\n## ", 1)[0]
            description += "\n" + section
        example = _example_from_description(description)
        if "Example call (" in description and example is None:
            bad.append(f"{tool.name}: example call is not valid JSON")
            continue
        if example is None:
            continue
        with_examples += 1
        args = json.loads(example)
        props = tool.parameters.get("properties") or {}
        for name, value in args.items():
            if name not in props:
                bad.append(f"{tool.name}.{name}: not a parameter")
                continue
            types = _schema_types(props[name])
            if "object" in types and not isinstance(value, dict):
                bad.append(f"{tool.name}.{name}: object parameter given {type(value).__name__}")
            if types == {"array"} and not isinstance(value, list):
                bad.append(f"{tool.name}.{name}: array parameter given {type(value).__name__}")
        _placeholders(args, tool.name, bad)
    assert bad == []
    assert with_examples >= 188


# Gateways that ingest this catalog reject descriptions that look like HTML, so a
# placeholder such as ``array<object>`` or ``<client MAC>`` makes the whole tool
# unregistrable there. Any ``<`` that starts a tag-like token (a letter, ``/``, ``!``
# or ``?`` after optional whitespace) is rejected; comparisons such as ``< 5`` are not.
_TAG_LIKE = re.compile(r"<\s*[A-Za-z/!?]")


def _schema_descriptions(schema: Any, path: str, out: list[tuple[str, str]]) -> None:
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key == "description" and isinstance(value, str):
                out.append((path, value))
            elif key == "properties" and isinstance(value, dict):
                for name, sub in value.items():
                    _schema_descriptions(sub, f"{path}.{name}", out)
            else:
                _schema_descriptions(value, path, out)
    elif isinstance(schema, list):
        for item in schema:
            _schema_descriptions(item, path, out)


def test_no_description_contains_markup() -> None:
    tools = _tools()
    assert len(tools) == _catalog_count()
    bad = []
    for tool in tools:
        texts: list[tuple[str, str]] = [(tool.name, tool.description or "")]
        _schema_descriptions(tool.parameters, tool.name, texts)
        for where, text in texts:
            for match in _TAG_LIKE.finditer(text):
                bad.append(f"{where}: {text[match.start() : match.start() + 40]!r}")
    assert bad == [], (
        "Tool or parameter descriptions contain angle-bracket markup; write "
        f"placeholders as OBJECT, 'array of string' or {{...}} instead: {bad}"
    )


def test_server_instructions_contain_no_markup() -> None:
    assert _TAG_LIKE.findall(server.INSTRUCTIONS) == []


def test_markup_pattern_catches_placeholders() -> None:
    for sample in ("array<object>", "</b>", "< string>", "<client\nMAC>", "<!-- x -->"):
        assert _TAG_LIKE.search(sample), sample
    for sample in ("a < 5", "x <= y", "array of object", "{...}", "a -> b"):
        assert not _TAG_LIKE.search(sample), sample


# Rule 17(a): a node that admits an object or array value but whose structure JSON Schema
# leaves open must have its shape stated in prose. "Open" means an object without
# ``properties``, an array without ``items``, or a union (``anyOf``/``oneOf``) with an object
# or array branch, since clients read a union's branches poorly. Such a node is covered by
# the nearest description at or above it (its own, else its enclosing property's) when that
# description carries a ``Shape:`` clause (a TypeScript-like outline, the form the generated
# body shapes use) or says the value is free-form.
_SHAPE_STATED = re.compile(r"Shape:|free-form", re.IGNORECASE)
_STRUCTURED = {"object", "array"}


def _own_kinds(node: dict[str, Any]) -> set[str]:
    kind = node.get("type")
    if isinstance(kind, list):
        return {str(k) for k in kind}
    return {str(kind)} if kind else set()


def _union_kinds(node: dict[str, Any]) -> set[str]:
    kinds = _own_kinds(node)
    for key in ("anyOf", "oneOf"):
        for branch in node.get(key) or []:
            if isinstance(branch, dict):
                kinds |= _union_kinds(branch)
    return kinds


def _structure_is_open(node: dict[str, Any]) -> bool:
    kinds = _own_kinds(node)
    if "object" in kinds and not node.get("properties"):
        return True
    if "array" in kinds and not isinstance(node.get("items"), dict):
        return True
    union = [b for key in ("anyOf", "oneOf") for b in node.get(key) or [] if isinstance(b, dict)]
    return any(_union_kinds(branch) & _STRUCTURED for branch in union)


def _unstated_shapes(schema: Any, path: str, description: str = "") -> list[str]:
    """Paths of open object/array nodes whose nearest description states no shape."""
    if not isinstance(schema, dict):
        return []
    own = schema.get("description")
    description = own if isinstance(own, str) and own.strip() else description
    out = []
    if _structure_is_open(schema) and not _SHAPE_STATED.search(description):
        out.append(path)
    for name, sub in (schema.get("properties") or {}).items():
        # A property starts a new scope: only its own description can state its shape.
        out += _unstated_shapes(sub, f"{path}.{name}")
    for key in _SUBSCHEMA_ONE:
        out += _unstated_shapes(schema.get(key), f"{path}/{key}", description)
    for key in _SUBSCHEMA_LIST:
        for i, sub in enumerate(schema.get(key) or []):
            out += _unstated_shapes(sub, f"{path}/{key}[{i}]", description)
    return out


def test_every_open_object_or_array_parameter_states_its_shape() -> None:
    tools = _tools()
    assert len(tools) == _catalog_count()
    missing = [
        path
        for tool in tools
        for name, prop in (tool.parameters.get("properties") or {}).items()
        for path in _unstated_shapes(prop, f"{tool.name}.{name}")
    ]
    assert missing == [], (
        f"{len(missing)} object/array schema nodes without properties/items (or behind a "
        "union) whose description states no shape: add a `Shape:` clause (for example "
        "`Shape: {mac:string}[]`, derived from the pinned spec or the keys the code reads) "
        f"or say the value is free-form: {missing}"
    )


def test_shape_statement_check_reaches_nested_and_union_nodes() -> None:
    bare_obj = {"type": "object"}
    schema = {
        "properties": {
            "typed": {"type": "array", "items": {"type": "string"}},
            "typed_obj": {"type": "object", "properties": {"a": {"type": "string"}}},
            "nullable": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {}]},
            "stated": {"description": "x. Shape: string|string[]", "anyOf": [{"type": "string"}]},
            "union": {"description": "x", "anyOf": [{"type": "string"}, {"type": "array"}]},
            "free": {"description": "Free-form body.", "type": "object"},
            "dict_items": {"description": "x", "type": "array", "items": bare_obj},
            "nested": {
                "description": "x. Shape: {inner:string[]}",
                "type": "object",
                "properties": {"inner": {"description": "y", "anyOf": [{"type": "array"}]}},
            },
            "scalar": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        }
    }
    found = [
        path
        for name, prop in schema["properties"].items()
        for path in _unstated_shapes(prop, f"t.{name}")
    ]
    assert found == [
        "t.nullable",
        "t.union",
        "t.union/anyOf[1]",
        "t.dict_items/items",
        "t.nested.inner",
        "t.nested.inner/anyOf[0]",
    ]
