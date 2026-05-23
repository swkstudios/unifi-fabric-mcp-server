#!/usr/bin/env python3
"""Generate docs/TOOLS.md from FastMCP runtime tool metadata."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DOCS_PATH = ROOT / "docs" / "TOOLS.md"


def _tool_name(tool: Any) -> str:
    return str(getattr(tool, "name", ""))


def _tool_description(tool: Any) -> str:
    return str(getattr(tool, "description", "") or "").strip()


def _type_label(schema: dict[str, Any] | None) -> str:
    if not schema:
        return "unknown"
    if "type" in schema:
        return str(schema["type"])
    if "const" in schema:
        return "constant"
    if "enum" in schema:
        return "enum"
    for union_key in ("anyOf", "oneOf"):
        variants = schema.get(union_key)
        if isinstance(variants, list):
            return " | ".join(_type_label(item) for item in variants if isinstance(item, dict))
    if "$ref" in schema:
        return str(schema["$ref"]).rsplit("/", maxsplit=1)[-1]
    return "object"


def _escape_table_cell(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")


def _default_label(value: Any) -> str:
    if isinstance(value, str):
        if value == "":
            return '`""`'
        return f"`{_escape_table_cell(value)}`"
    if value is None:
        return "`null`"
    return f"`{_escape_table_cell(json.dumps(value, sort_keys=True))}`"


def _parameter_descriptions(description: str, parameter_names: set[str]) -> dict[str, str]:
    """Extract simple ``name: description`` lines from tool docstrings."""

    descriptions: dict[str, str] = {}
    last_name: str | None = None
    for line in description.splitlines():
        stripped = line.strip()
        pattern = r"(?:^|\s)([a-zA-Z_][a-zA-Z0-9_]*):\s*"
        matches = [
            match
            for match in re.finditer(pattern, stripped)
            if match.group(1) in parameter_names
        ]
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(stripped)
            descriptions[match.group(1)] = stripped[match.end() : end].strip()
            last_name = match.group(1)
        if (
            not matches
            and last_name is not None
            and descriptions[last_name].count("(") > descriptions[last_name].count(")")
        ):
            descriptions[last_name] = f"{descriptions[last_name]} {stripped}".strip()
    return descriptions


def _parameter_table(tool: Any) -> list[str]:
    parameters = getattr(tool, "parameters", None) or {}
    properties = parameters.get("properties") or {}
    if not properties:
        return ["No parameters."]

    required = set(parameters.get("required") or [])
    doc_descriptions = _parameter_descriptions(_tool_description(tool), set(properties))
    lines = [
        "| Name | Type | Required | Default | Description |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, schema in properties.items():
        if not isinstance(schema, dict):
            schema = {}
        default = _default_label(schema["default"]) if "default" in schema else ""
        description = str(schema.get("description") or doc_descriptions.get(name) or "").strip()
        lines.append(
            f"| `{name}` | `{_type_label(schema)}` | "
            f"{'yes' if name in required else 'no'} | {default} | "
            f"{_escape_table_cell(description)} |"
        )
    return lines


def _return_type(tool: Any) -> str:
    return_type = getattr(tool, "return_type", None)
    if return_type is not None:
        if isinstance(return_type, type):
            return return_type.__name__
        return str(return_type).replace("typing.", "")
    output_schema = getattr(tool, "output_schema", None) or {}
    return _type_label(output_schema)


def _category(tool_name: str) -> str:
    if tool_name.startswith("list_"):
        return "Listing & Discovery"
    if tool_name.startswith(("get_", "download_")):
        return "Reading & Inspection"
    if tool_name.startswith(("create_", "upload_")):
        return "Create"
    if tool_name.startswith(("update_", "patch_")):
        return "Update"
    if tool_name.startswith("delete_"):
        return "Delete"
    if tool_name.startswith(("execute_", "trigger_", "start_", "disable_")):
        return "Execute & Actions"
    if tool_name.startswith("search_"):
        return "Search"
    if tool_name.startswith(("block_", "unblock_", "reconnect_")):
        return "Client Management"
    if tool_name.startswith(("adopt_", "unadopt_", "restart_", "upgrade_")):
        return "Device Management"
    if tool_name.startswith(("ptz_", "locate_")):
        return "Device Control"
    if tool_name.startswith("set_"):
        return "Configuration"
    return "Other"


async def _runtime_tools() -> list[Any]:
    sys.path.insert(0, str(SRC))
    from unifi_fabric.server import mcp

    return sorted(await mcp.list_tools(), key=_tool_name)


def _anchor(text: str) -> str:
    return re.sub(r"[^a-z0-9 -]", "", text.lower()).replace(" ", "-")


def render_markdown(tools: list[Any]) -> str:
    categories: dict[str, list[Any]] = {}
    for tool in tools:
        categories.setdefault(_category(_tool_name(tool)), []).append(tool)

    lines = [
        "# UniFi Fabric MCP Server - Tools Reference",
        "",
        "<!-- This file is generated by scripts/gen_tools_doc.py. Do not edit by hand. -->",
        "",
        "Reference manual for every tool registered with the FastMCP runtime.",
        "",
        f"Total tools: {len(tools)}",
        "",
        "## Tool Categories",
        "",
    ]
    for category in sorted(categories):
        lines.append(f"- [{category}](#{_anchor(category)}) ({len(categories[category])})")

    for category in sorted(categories):
        category_tools = categories[category]
        lines.extend(["", "---", "", f"## {category}", "", f"**{len(category_tools)} tools**", ""])
        for tool in category_tools:
            description = _tool_description(tool) or "No description provided."
            lines.extend(
                [
                    f"### `{_tool_name(tool)}`",
                    "",
                    description,
                    "",
                    "**Parameters**",
                    "",
                    *_parameter_table(tool),
                    "",
                    "**Return type**",
                    "",
                    f"`{_return_type(tool)}`",
                    "",
                ]
            )

    lines.extend(
        [
            "---",
            "",
            "## Usage Notes",
            "",
            "- Tool metadata is read from `await mcp.list_tools()` in "
            "`src/unifi_fabric/server.py`.",
            "- Parameter types and defaults come from FastMCP's runtime schema.",
            "- Descriptions come from tool docstrings exposed through FastMCP metadata.",
            "- Run `python3 scripts/gen_tools_doc.py --check` to verify this file has no drift.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


async def generate() -> str:
    tools = await _runtime_tools()
    if not tools:
        raise RuntimeError("No FastMCP tools were registered")
    return render_markdown(tools)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail when docs/TOOLS.md is stale")
    parser.add_argument("--output", type=Path, default=DOCS_PATH)
    args = parser.parse_args()

    content = asyncio.run(generate())
    if args.check:
        existing = args.output.read_text() if args.output.exists() else ""
        if existing != content:
            print(
                f"{args.output} is out of date; run python3 scripts/gen_tools_doc.py",
                file=sys.stderr,
            )
            return 1
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content)
    print(f"Generated {args.output} from FastMCP metadata", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
