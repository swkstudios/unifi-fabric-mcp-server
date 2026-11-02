"""Protect request-body descriptions agree with the pinned Protect 7.3.70 spec.

Every Protect tool whose description carries a "Request body (Protect 7.3.70, METHOD
path; ...)" block lists the body keys as ``- key: <type ...>``. For each listed key the
spec documents:

* the stated type matches the spec type (``update_camera`` ``micVolume`` is a number
  1-100, not an object);
* a nested object (or array of objects) names every key the spec gives it, so a caller
  can build ``osdSettings`` / ``ringSettings`` / ``slots`` / ... without the spec;
* every ``minimum`` / ``maximum`` of a nested key is stated as a range next to that key.
"""

from __future__ import annotations

import asyncio
import functools
import json
import re
from pathlib import Path
from typing import Any

from tests._tool_catalog import lazy_parametrize
from unifi_fabric import server

SPEC = json.loads(
    (Path(__file__).parent / "fixtures" / "openapi" / "protect-7.3.70.json").read_text()
)
_BLOCK_RE = re.compile(r"Request body \(Protect 7\.3\.70, (\w+) (\S+?);")


def _resolve(node: Any) -> Any:
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 20:
        target: Any = SPEC
        for part in node["$ref"][2:].split("/"):
            target = target[part]
        node = {**target, **{k: v for k, v in node.items() if k != "$ref"}}
        seen += 1
    if isinstance(node, dict) and "allOf" in node:
        merged: dict[str, Any] = {k: v for k, v in node.items() if k != "allOf"}
        props: dict[str, Any] = {}
        for part in node["allOf"]:
            part = _resolve(part)
            props.update(part.get("properties", {}))
            for k, v in part.items():
                if k != "properties":
                    merged.setdefault(k, v)
        if props:
            merged["properties"] = props
        node = merged
    return node


def _tools() -> dict[str, Any]:
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def _documented_bodies() -> list[tuple[str, dict[str, Any], dict[str, str]]]:
    """(tool, spec body properties, {key: documented text}) for every Protect body block."""
    out = []
    from tests.test_spec_conformance import usage_section

    for name, tool in sorted(_tools().items()):
        text = tool.description or ""
        if f"docs/TOOL-USAGE.md#{name}" in text:
            # A body block moved out of a shortened description is checked where it lives.
            text += "\n" + usage_section(name)
        match = _BLOCK_RE.search(text)
        if not match:
            continue
        method, path = match.group(1).lower(), match.group(2)
        op = SPEC["paths"].get(path, {}).get(method)
        if op is None or "requestBody" not in op:
            continue
        body = _resolve(op["requestBody"]["content"]["application/json"]["schema"])
        documented: dict[str, str] = {}
        current: str | None = None
        for line in text[match.start() :].splitlines()[1:]:
            item = re.match(r"^- (\w+): (.*)\Z", line)
            if item:
                current = item.group(1)
                documented[current] = item.group(2)
            elif current and line.startswith("  ") and not line.startswith("    "):
                documented[current] += " " + line.strip()
            elif not line.strip() and documented:
                break
        out.append((name, body.get("properties", {}), documented))
    return out


@functools.cache
def _bodies() -> list[tuple[str, dict[str, Any], dict[str, str]]]:
    return _documented_bodies()


def _spec_kind(schema: Any) -> str:
    schema = _resolve(schema)
    if "enum" in schema or "const" in schema:
        return "enum"
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)
    if kind:
        return str(kind)
    if "oneOf" in schema or "anyOf" in schema:
        return "alternatives"
    return "?"


def _nested_object(schema: Any) -> dict[str, Any] | None:
    schema = _resolve(schema)
    if schema.get("type") == "array":
        schema = _resolve(schema.get("items", {}))
    return schema if schema.get("properties") else None


def test_the_protect_body_blocks_are_found():
    names = {name for name, _props, _doc in _bodies()}
    assert {"update_camera", "update_sensor", "update_light", "update_chime"} <= names
    assert len(_bodies()) >= 20


@lazy_parametrize("tool", lambda: [name for name, _p, _d in _bodies()])
def test_documented_body_keys_match_the_spec(tool):
    _name, props, documented = next(b for b in _bodies() if b[0] == tool)
    problems: list[str] = []
    for key, text in documented.items():
        if key not in props:
            continue
        kind = _spec_kind(props[key])
        first = text.split(" ", 1)[0]
        if kind in {"number", "integer"} and not first.startswith(("number", "integer", "one")):
            problems.append(f"{key}: documented {first!r}, spec {kind}")
        if kind == "object" and not first.startswith("object"):
            problems.append(f"{key}: documented {first!r}, spec object")
        nested = _nested_object(props[key])
        if nested is not None:
            for sub, sub_schema in nested["properties"].items():
                if not re.search(rf"\b{re.escape(sub)}\b", text):
                    problems.append(f"{key}.{sub}: not documented")
                    continue
                sub_schema = _resolve(sub_schema)
                low, high = sub_schema.get("minimum"), sub_schema.get("maximum")
                if low is not None and high is not None:
                    if f"{low}-{high}" not in text:
                        problems.append(f"{key}.{sub}: range {low}-{high} not documented")
                elif low is not None and f">= {low}" not in text:
                    problems.append(f"{key}.{sub}: minimum {low} not documented")
        own = _resolve(props[key])
        low, high = own.get("minimum"), own.get("maximum")
        if low is not None and high is not None and f"{low}-{high}" not in text:
            problems.append(f"{key}: range {low}-{high} not documented")
    assert problems == []


def test_ptz_patrol_start_names_the_patrol_slot():
    description = _tools()["ptz_patrol_start"].description or ""
    first_line = description.splitlines()[0]
    assert "patrol slot 0-4" in first_line
    assert "on a preset slot" not in description
