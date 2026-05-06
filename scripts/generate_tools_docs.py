#!/usr/bin/env python3
"""Generate docs/TOOLS.md from @mcp.tool() definitions in server.py."""

import ast
import inspect
import re
import sys
from pathlib import Path
from typing import NamedTuple

# Add src to path so we can import unifi_fabric
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class ToolInfo(NamedTuple):
    """Extracted tool information."""

    name: str
    description: str
    module: str
    params: str | None = None


def extract_tools_from_source() -> list[ToolInfo]:
    """Parse server.py source to extract @mcp.tool() decorated functions."""
    server_path = Path(__file__).parent.parent / "src" / "unifi_fabric" / "server.py"

    with open(server_path) as f:
        content = f.read()

    tools = []

    # Find all @mcp.tool() patterns followed by function definitions
    # Pattern: @mcp.tool()\nasync def function_name(...):
    pattern = r'@mcp\.tool\(\)\s+async\s+def\s+(\w+)\([^)]*\)\s*->\s*[^:]+:\s+"""([^"]*?)"""'

    matches = re.finditer(pattern, content, re.DOTALL)
    for match in matches:
        name, docstring = match.groups()
        # Extract first line or full docstring
        description = docstring.strip().split("\n")[0] if docstring.strip() else "(No description)"
        tools.append(ToolInfo(name=name, description=description, module="server"))

    # If we didn't find any, try AST fallback
    if not tools:
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Check for @mcp.tool() decorator
                    has_mcp_tool = any(
                        (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and
                         dec.func.attr == "tool")
                        for dec in node.decorator_list
                    )

                    if has_mcp_tool:
                        docstring = ast.get_docstring(node) or ""
                        description = docstring.split("\n")[0] if docstring else "(No description)"
                        tools.append(ToolInfo(name=node.name, description=description, module="server"))
        except SyntaxError:
            pass

    return sorted(tools, key=lambda t: t.name)


def categorize_tools(tools: list[ToolInfo]) -> dict[str, list[ToolInfo]]:
    """Group tools by category based on naming convention."""
    categories = {}

    for tool in tools:
        # Determine category from tool name prefix
        if tool.name.startswith("list_"):
            category = "Listing & Discovery"
        elif tool.name.startswith("get_"):
            category = "Reading & Inspection"
        elif tool.name.startswith("create_"):
            category = "Create"
        elif tool.name.startswith("update_"):
            category = "Update"
        elif tool.name.startswith("delete_"):
            category = "Delete"
        elif tool.name.startswith("execute_"):
            category = "Execute & Actions"
        elif tool.name.startswith("search_"):
            category = "Search"
        elif any(tool.name.startswith(prefix) for prefix in ["block_", "unblock_", "reconnect_"]):
            category = "Client Management"
        elif any(tool.name.startswith(prefix) for prefix in ["adopt_", "unadopt_", "restart_"]):
            category = "Device Management"
        elif any(tool.name.startswith(prefix) for prefix in ["ptz_", "locate_"]):
            category = "Device Control"
        elif any(tool.name.startswith(prefix) for prefix in ["set_", "patch_"]):
            category = "Configuration"
        else:
            category = "Other"

        if category not in categories:
            categories[category] = []
        categories[category].append(tool)

    return dict(sorted(categories.items()))


def generate_markdown(tools: list[ToolInfo]) -> str:
    """Generate markdown documentation for tools."""
    categories = categorize_tools(tools)

    md = """# UniFi Fabric MCP Server — Tools Reference

**Auto-generated reference manual for all `@mcp.tool()` exports.**

This document lists all available tools organized by category. Each tool represents
a discrete operation or query you can perform against UniFi consoles via the MCP protocol.

## Tool Categories

"""

    # Table of contents
    for category in categories:
        md += f"- [{category}](#{category.lower().replace(' & ', '-').replace(' ', '-')})\n"

    md += "\n---\n\n"

    # Detailed sections
    for category, category_tools in categories.items():
        md += f"## {category}\n\n"
        md += f"**{len(category_tools)} tools**\n\n"

        for tool in category_tools:
            md += f"### `{tool.name}`\n\n"
            if tool.description and tool.description != "(No description)":
                md += f"{tool.description}\n\n"
            else:
                md += "*No description provided.*\n\n"

    md += """---

## Usage Notes

- All tools are registered in `src/unifi_fabric/server.py` via `@mcp.tool()` decorators.
- Tool parameters accept human-readable names (hosts, sites, SSIDs) or IDs where applicable.
- Refer to the [README](../README.md) for setup, authentication, and configuration details.
- For detailed parameter descriptions and return values, inspect tool docstrings in
  the source code or ask your MCP client for help (e.g., Claude Code's built-in help).

---

*Generated from `src/unifi_fabric/server.py` on 2026-05-03.*
"""

    return md


def main() -> None:
    """Main entry point."""
    try:
        tools = extract_tools_from_source()

        if not tools:
            print("Error: No @mcp.tool() definitions found!", file=sys.stderr)
            sys.exit(1)

        markdown = generate_markdown(tools)

        # Write to docs/TOOLS.md
        output_path = Path(__file__).parent.parent / "docs" / "TOOLS.md"
        output_path.write_text(markdown)

        print(f"Generated {output_path} with {len(tools)} tools", file=sys.stderr)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
