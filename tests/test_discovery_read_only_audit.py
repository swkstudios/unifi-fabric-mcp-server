"""A refusal by discovery call_read_tool of a hidden write is audited exactly once.

With ``UNIFI_AUDIT_LOG`` on, a write named through ``call_read_tool`` writes one
``outcome=refused`` record naming the switch that refused it, and the same refusal reached
by a direct call writes one as well:
- ``UNIFI_WRITE_POLICY``: a hidden write tool, or the mixed GET relay on a state-changing route
  (ReadOnlyToolMiddleware, fabric_connector_get);
- a per-area write opt-out (``family:connector=deny``): a write it hides
  (AreaOptOutMiddleware).
Without an audit helper (apply_tool_mode's default) the refusals are unchanged. No request
reaches the upstream.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp import Client, FastMCP

from unifi_fabric import server, switches
from unifi_fabric._read_only_audit import derive_write_tools
from unifi_fabric.config import Settings
from unifi_fabric.discovery import apply_tool_mode
from unifi_fabric.read_only import read_only_message
from unifi_fabric.read_only_tools import (
    AreaOptOutMiddleware,
    ReadOnlyToolMiddleware,
    apply_area_opt_out_tool_filter,
    apply_read_only_tool_filter,
)
from unifi_fabric.refusal_audit import RefusedWriteAuditMiddleware

#: A state-changing route of the mixed GET relay (refused under read-only mode).
WRITE_GET = "/proxy/protect/api/cameras/camera/enable-control"


async def _app() -> FastMCP:
    app = FastMCP("discovery-read-only-audit")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool)
    app.add_middleware(server.SecretScrubMiddleware())
    app.add_middleware(RefusedWriteAuditMiddleware(app, lambda: True, server._audit_refusal))
    app.add_middleware(ReadOnlyToolMiddleware(app, audit=server._audit_refusal))
    return app


@pytest.fixture()
def audit_file(monkeypatch, tmp_path) -> Path:
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    monkeypatch.setattr(
        server,
        "_settings",
        Settings(
            api_key="synthetic-key",
            write_policy="deny",
            tool_mode="discovery",
            audit_log=str(path),
            audit_log_format="json",
        ),
    )

    async def no_upstream(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a read-only refusal must not contact upstream")

    monkeypatch.setattr(httpx.AsyncClient, "send", no_upstream)
    return path


def _records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        r
        for r in (json.loads(line) for line in path.read_text().splitlines())
        if r.get("event", "audit") == "audit"
    ]


async def _hidden_write() -> str:
    tools = await server.mcp.list_tools()
    return sorted(derive_write_tools(list(tools)) - {"fabric_connector_get"})[0]


async def test_hidden_write_through_call_read_tool_and_direct_each_audit_once(audit_file):
    name = await _hidden_write()
    app = await _app()
    async with server.lifespan(app), Client(app) as client:
        with pytest.raises(Exception, match="UNIFI_WRITE_POLICY") as error:
            await client.call_tool("call_read_tool", {"name": name, "arguments": {}})
        assert read_only_message(name, tool=True) in str(error.value)
        discovery = _records(audit_file)
        assert [(r["tool"], r["outcome"], r["reason"]) for r in discovery] == [
            (name, "refused", "UNIFI_WRITE_POLICY")
        ]

        # describe_tool names the same switch but is not a call: no record.
        with pytest.raises(Exception, match="UNIFI_WRITE_POLICY"):
            await client.call_tool("describe_tool", {"name": name})
        assert len(_records(audit_file)) == 1

        with pytest.raises(Exception, match="UNIFI_WRITE_POLICY"):
            await client.call_tool(name, {})
        direct = _records(audit_file)[1:]
        assert [(r["tool"], r["outcome"], r["reason"]) for r in direct] == [
            (name, "refused", "UNIFI_WRITE_POLICY")
        ]


async def test_mixed_get_write_route_through_call_read_tool_and_direct_each_audit_once(
    audit_file,
):
    args = {"host": "console", "path": WRITE_GET}
    app = await _app()
    async with server.lifespan(app), Client(app) as client:
        with pytest.raises(Exception, match="UNIFI_WRITE_POLICY") as error:
            await client.call_tool(
                "call_read_tool", {"name": "fabric_connector_get", "arguments": args}
            )
        assert read_only_message("fabric_connector_get", tool=True) in str(error.value)
        discovery = _records(audit_file)
        assert len(discovery) == 1
        assert discovery[0]["outcome"] == "refused"
        assert discovery[0]["reason"] == "UNIFI_WRITE_POLICY"

        with pytest.raises(Exception, match="UNIFI_WRITE_POLICY"):
            await client.call_tool("fabric_connector_get", args)
        direct = _records(audit_file)[1:]
        assert len(direct) == 1
        assert direct[0]["outcome"] == "refused"
        assert direct[0]["reason"] == "UNIFI_WRITE_POLICY"


@pytest.fixture()
def area_audit_file(monkeypatch, tmp_path) -> Path:
    path = tmp_path / "audit.jsonl"
    monkeypatch.delenv("UNIFI_WRITE_POLICY", raising=False)
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:connector=deny")
    monkeypatch.setattr(
        server,
        "_settings",
        Settings(
            api_key="synthetic-key",
            tool_mode="discovery",
            audit_log=str(path),
            audit_log_format="json",
        ),
    )

    async def no_upstream(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("an area opt-out refusal must not contact upstream")

    monkeypatch.setattr(httpx.AsyncClient, "send", no_upstream)
    return path


async def test_area_opted_out_write_through_call_read_tool_and_direct_each_audit_once(
    area_audit_file,
):
    app = await _app()
    app.add_middleware(
        AreaOptOutMiddleware(app, switches.connector_writes_enabled, audit=server._audit_refusal)
    )
    name = "fabric_connector_put"
    args = {"host": "console", "path": "/proxy/network/api/s/default/rest/user/x"}
    async with server.lifespan(app), Client(app) as client:
        with pytest.raises(Exception, match="family:connector=deny"):
            await client.call_tool("call_read_tool", {"name": name, "arguments": args})
        discovery = _records(area_audit_file)
        assert [(r["tool"], r["outcome"], r["reason"]) for r in discovery] == [
            (name, "refused", "family:connector=deny")
        ]

        with pytest.raises(Exception, match="family:connector=deny"):
            await client.call_tool(name, args)
        direct = _records(area_audit_file)[1:]
        assert [(r["tool"], r["outcome"], r["reason"]) for r in direct] == [
            (name, "refused", "family:connector=deny")
        ]


async def test_without_an_audit_helper_the_call_read_tool_refusals_are_unchanged(monkeypatch):
    # apply_tool_mode's default (audit=None): each refusal still raises its own message.
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:connector=deny")
    app = FastMCP("discovery-no-audit")
    for tool in await server.mcp.list_tools():
        app.add_tool(tool)
    hidden = await apply_read_only_tool_filter(app, True)
    area = await apply_area_opt_out_tool_filter(app, False)
    restore = await apply_tool_mode(
        app, "discovery", read_only=True, hidden_write_names=hidden, hidden_area_writes=area
    )
    try:
        name = sorted(hidden - {"fabric_connector_get"})[0]
        async with Client(app) as client:
            with pytest.raises(Exception, match="UNIFI_WRITE_POLICY") as error:
                await client.call_tool("call_read_tool", {"name": name, "arguments": {}})
            assert read_only_message(name, tool=True) in str(error.value)
            with pytest.raises(Exception, match="UNIFI_WRITE_POLICY"):
                await client.call_tool(
                    "call_read_tool",
                    {
                        "name": "fabric_connector_get",
                        "arguments": {"host": "console", "path": WRITE_GET},
                    },
                )
    finally:
        restore()
