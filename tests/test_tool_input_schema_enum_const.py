"""No registered tool input schema has an enum/const value that disagrees with its type.

FastMCP 4.1.6 validates ``enum`` and ``const`` by JSON equality, not Python ``==``. Python
conflates ``True`` with ``1`` and ``False`` with ``0``; JSON Schema keeps them distinct. A
schema whose enum/const values do not match the node's declared ``type`` (or whose enum lists
two members that Python equates but JSON does not) would change which arguments are accepted
when the validator stops conflating them.

The walk covers every registered tool's input schema, including ``$defs`` and every
sub-schema, and the test pins that it visited the whole catalog.
"""

from __future__ import annotations

from typing import Any

from tests import _tool_catalog as cti
from tests.runtime_catalog import runtime_tool_count


def _json_type_ok(value: Any, declared: str) -> bool:
    if declared == "null":
        return value is None
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (
            isinstance(value, float) and value.is_integer()
        )
    if declared == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if declared == "string":
        return isinstance(value, str)
    if declared == "array":
        return isinstance(value, list)
    if declared == "object":
        return isinstance(value, dict)
    return True


def _json_kind(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return "number"
    return type(value).__name__


def _nodes(node: Any, path: str) -> Any:
    if isinstance(node, dict):
        yield path, node
        for key, child in node.items():
            yield from _nodes(child, f"{path}/{key}")
    elif isinstance(node, list):
        for i, child in enumerate(node):
            yield from _nodes(child, f"{path}/{i}")


def _mismatches(schema: Any) -> list[str]:
    found: list[str] = []
    for path, node in _nodes(schema, ""):
        values: list[Any] = []
        if "enum" in node and isinstance(node["enum"], list):
            values.extend(node["enum"])
            kinds: dict[tuple[str, Any], str] = {}
            for v in node["enum"]:
                if isinstance(v, (bool, int, float)) or v is None:
                    key = (_json_kind(v), v)
                    other = [k for k in kinds if k != key and k[1] == v]
                    if other:
                        found.append(f"{path}/enum: {v!r} equal to {other[0][1]!r} in Python only")
                    kinds[key] = _json_kind(v)
        if "const" in node:
            values.append(node["const"])
        declared = node.get("type")
        if declared is None or not values:
            continue
        types = declared if isinstance(declared, list) else [declared]
        for v in values:
            if not any(_json_type_ok(v, t) for t in types):
                found.append(f"{path}: value {v!r} is not of declared type {declared!r}")
    return found


def test_walker_detects_a_mismatch() -> None:
    assert _mismatches({"type": "boolean", "enum": [0, 1]})
    assert _mismatches({"type": "integer", "const": True})
    assert _mismatches({"enum": [1, True]})
    assert not _mismatches(
        {"type": "string", "enum": ["a"], "properties": {"n": {"type": "integer", "const": 1}}}
    )


def test_no_enum_or_const_type_mismatch_in_any_registered_tool_input_schema(
    record_property,
) -> None:
    tools = cti.tools()
    bad = {t.name: m for t in tools if (m := _mismatches(t.parameters))}
    checked_enum_const = sum(
        1 for t in tools for _, n in _nodes(t.parameters, "") if "enum" in n or "const" in n
    )
    record_property("input_schemas_checked", len(tools))
    record_property("enum_const_nodes_checked", checked_enum_const)
    assert len(tools) == runtime_tool_count() > 0, (
        f"schemas checked={len(tools)} runtime_tools={runtime_tool_count()} "
        f"enum_const_nodes={checked_enum_const}"
    )
    assert checked_enum_const > 0, f"enum_const_nodes={checked_enum_const}"
    assert not bad, bad
