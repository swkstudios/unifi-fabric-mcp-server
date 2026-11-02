"""Mode-aware, transport-independent MCP discovery navigation (no credentials)."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

META_TOOLS = frozenset(
    {"search_tools", "describe_tool", "call_read_tool", "call_write_tool", "list_tool_families"}
)


def decode(status: int, body: Any) -> dict[str, Any]:
    """Preserve the wire envelope alongside the historical live-runner fields."""
    if not isinstance(body, dict) or "error" in body or not isinstance(body.get("result"), dict):
        return {
            "http": status,
            "err": True,
            "text": json.dumps(body),
            "data": None,
            "envelope": body,
        }
    result = body["result"]
    content = result.get("content", [])
    text = "".join(c.get("text", "") for c in content if c.get("type") == "text")
    data = result.get("structuredContent")
    if isinstance(data, dict) and set(data) == {"result"}:
        data = data["result"]
    if data is None:
        try:
            data = json.loads(text)
        except ValueError:
            pass
    failed = isinstance(data, dict) and (bool(data.get("error")) or data.get("success") is False)
    return {
        "http": status,
        "err": not 200 <= status < 300 or bool(result.get("isError")) or failed,
        "text": text,
        "data": data,
        "content_blocks": len(content),
        "content": content,
        "structuredContent": result.get("structuredContent"),
        "envelope": body,
    }


def discovery_mode(tools: list[dict[str, Any]]) -> bool:
    names = [tool["name"] for tool in tools]
    if META_TOOLS.intersection(names):
        if len(names) != 5 or set(names) != META_TOOLS:
            raise ValueError("discovery advertisement must contain exactly the five meta-tools")
        return True
    return False


def checked(result: dict[str, Any], operation: str) -> Any:
    if result["err"]:
        raise ValueError(f"{operation} failed (HTTP {result['http']}): {result['text']}")
    return result["data"]


def domain_catalog(tools: list[dict[str, Any]], call) -> tuple[bool, list[dict[str, Any]]]:
    """Validate advertisement separately, then recover every exact hidden schema."""
    discovery = discovery_mode(tools)
    if not discovery:
        return False, tools
    matches = checked(call("search_tools", {"query": "", "limit": None}), "search_tools")
    if not isinstance(matches, list) or not matches:
        raise ValueError("search_tools returned an invalid catalog")
    names = [match.get("name") for match in matches if isinstance(match, dict)]
    if len(names) != len(matches) or not all(isinstance(n, str) and n for n in names):
        raise ValueError("search_tools returned invalid names")
    if len(set(names)) != len(names) or META_TOOLS.intersection(names):
        raise ValueError("search_tools returned duplicate or meta-tool names")
    catalog = []
    for name in names:
        tool = checked(call("describe_tool", {"name": name}), "describe_tool")
        if (
            not isinstance(tool, dict)
            or tool.get("name") != name
            or not isinstance(tool.get("inputSchema"), dict)
        ):
            raise ValueError("describe_tool returned a mismatched or invalid schema")
        catalog.append(tool)
    return True, catalog


def probe_hosts(tools: list[dict[str, Any]], call) -> dict[str, Any]:
    """Smoke only the selected read target; a tool error is never a PASS."""
    if discovery_mode(tools):
        matches = checked(call("search_tools", {"query": "", "limit": None}), "search_tools")
        if not isinstance(matches, list) or not any(t.get("name") == "list_hosts" for t in matches):
            raise ValueError("list_hosts missing from discovered catalog")
        target = checked(call("describe_tool", {"name": "list_hosts"}), "describe_tool")
        if not isinstance(target, dict) or target.get("name") != "list_hosts":
            raise ValueError("list_hosts description mismatch")
        return call("call_read_tool", {"name": "list_hosts", "arguments": {}})
    if not any(t["name"] == "list_hosts" for t in tools):
        raise ValueError("list_hosts missing from advertised catalog")
    return call("list_hosts", {})


def full_mode_catalog(source: str) -> list[dict[str, Any]]:
    """Fresh full-mode registry independent of an already initialized discovery app."""
    program = (
        "import asyncio, json, os, sys; "
        f"sys.path.insert(0, {source!r}); "
        "os.environ['UNIFI_TOOL_MODE'] = 'full'; "
        "from unifi_fabric.server import mcp; "
        "tools = asyncio.run(mcp.list_tools()); "
        "print(json.dumps([t.to_mcp_tool().model_dump(by_alias=True, exclude_none=True) "
        "for t in tools]))"
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed Python program, repo-local path
            [sys.executable, "-c", program], check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError as exc:
        raise ImportError("full-mode registry could not be imported") from exc
    return json.loads(completed.stdout)
