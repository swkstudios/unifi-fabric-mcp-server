"""Mode-aware, transport-independent MCP discovery navigation (no credentials)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_tools_doc import catalog_environ  # noqa: E402

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
    meta = result.get("_meta")
    fastmcp_meta = meta.get("fastmcp") if isinstance(meta, dict) else None
    wrapped = isinstance(fastmcp_meta, dict) and fastmcp_meta.get("wrap_result") is True
    # A wrapped result keeps its value under "result"; additive siblings (search_tools'
    # more_available and total_matched) do not change what the caller receives.
    if isinstance(data, dict) and "result" in data and (wrapped or set(data) == {"result"}):
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
    catalog = []
    for name in inventory_names(matches):
        tool = checked(call("describe_tool", {"name": name}), "describe_tool")
        catalog.append(described(tool, name))
    return True, catalog


def inventory_names(matches: Any) -> list[str]:
    """The hidden inventory names from ``search_tools({"query":"","limit":null})``."""
    if not isinstance(matches, list) or not matches:
        raise ValueError("search_tools returned an invalid catalog")
    names = [match.get("name") for match in matches if isinstance(match, dict)]
    if len(names) != len(matches) or not all(isinstance(n, str) and n for n in names):
        raise ValueError("search_tools returned invalid names")
    if len(set(names)) != len(names) or META_TOOLS.intersection(names):
        raise ValueError("search_tools returned duplicate or meta-tool names")
    return names


def described(tool: Any, name: str) -> dict[str, Any]:
    """One ``describe_tool`` result, held to the name asked for and an exact schema."""
    if (
        not isinstance(tool, dict)
        or tool.get("name") != name
        or not isinstance(tool.get("inputSchema"), dict)
    ):
        raise ValueError("describe_tool returned a mismatched or invalid schema")
    return tool


PARITY_KEYS = ("inputSchema", "outputSchema", "annotations")


def require_catalog_parity(catalog: list[dict[str, Any]], expected: list[dict[str, Any]]) -> None:
    """A five-tool advertisement cannot replace complete hidden inventory evidence.

    ``catalog`` (the hidden discovery inventory) must hold exactly the tools of ``expected``
    (a full-mode catalog), each with the same input schema, output schema and annotations.
    """
    actual = {tool["name"]: {key: tool.get(key) for key in PARITY_KEYS} for tool in catalog}
    baseline = {tool["name"]: {key: tool.get(key) for key in PARITY_KEYS} for tool in expected}
    if len(actual) != len(catalog) or set(actual) != set(baseline):
        missing = sorted(set(baseline) - set(actual))[:5]
        extra = sorted(set(actual) - set(baseline))[:5]
        raise ValueError(
            "hidden catalog names differ from full-mode baseline "
            f"({len(catalog)} hidden, {len(baseline)} full; missing {missing}, extra {extra})"
        )
    mismatches = sorted(name for name in actual if actual[name] != baseline[name])
    if mismatches:
        raise ValueError(f"hidden catalog schemas differ from full-mode baseline: {mismatches}")


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
            [sys.executable, "-c", program],
            check=True,
            capture_output=True,
            text=True,
            env=catalog_environ(os.environ),
        )
    except subprocess.CalledProcessError as exc:
        raise ImportError("full-mode registry could not be imported") from exc
    return json.loads(completed.stdout)
