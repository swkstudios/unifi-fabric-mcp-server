"""Regressions for the v0.7.2 review findings."""

from __future__ import annotations

import contextvars
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from unifi_fabric import request_policy as rp
from unifi_fabric import server
from unifi_fabric.config import Settings
from unifi_fabric.refusal_audit import RefusedWriteAuditMiddleware


@pytest.mark.asyncio
async def test_exclude_tool_target_starts_the_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """UNIFI_EXCLUDE=tool:<name> validates against the whole catalog, not the filtered list."""
    monkeypatch.setenv("UNIFI_EXCLUDE", "tool:list_sites")
    effective = await server.startup_policy(server.mcp)
    assert "tool:list_sites" in effective.exclusions


@pytest.mark.parametrize("entry", [True, False, 1.0, "1"])
async def test_remove_ports_rejects_non_integer_entries_at_the_boundary(entry: object) -> None:
    """A bool (an int in Python), float or string is refused, never coerced to a port number."""
    args = {"host": "h", "site": "s", "device": "d", "remove_ports": [entry]}
    with pytest.raises(ToolError, match="Invalid arguments"):
        await server.mcp.call_tool("update_switch_port_overrides", args)


async def test_door_lock_schema_offers_only_the_served_actions() -> None:
    """set_door_lock_state advertises unlock/open; lock/close are not enum values."""
    tools = await server.mcp.list_tools(run_middleware=False)
    tool = next(t for t in tools if t.name == "set_door_lock_state")
    assert tool.parameters["properties"]["action"]["enum"] == ["unlock", "open"]


# --------------------------------------------------------------- MR-8 (call_read_tool refusal)

HEADER_DENY = (("X-UniFi-Write-Policy", "deny"),)


async def _discovery_chain() -> FastMCP:
    app = FastMCP("mr8-discovery")
    for tool in await server.mcp.list_tools(run_middleware=False):
        app.add_tool(tool)
    app.add_middleware(server.SecretScrubMiddleware())
    app.add_middleware(RefusedWriteAuditMiddleware(app, lambda: True, server._audit_refusal))
    evaluator = rp.RequestPolicy(lambda: rp.local_tools(app), headers=_header_source)
    app.add_middleware(rp.RequestPolicyMiddleware(evaluator))
    return app


_HEADERS: contextvars.ContextVar[tuple[tuple[str, str], ...]] = contextvars.ContextVar(
    "mr8h", default=()
)


def _header_source(name: str) -> list[str] | None:
    found = [v for k, v in _HEADERS.get() if k.lower() == name.lower()]
    return found or None


@pytest.mark.parametrize("name", ["update_switch_port_overrides", "fabric_connector_get"])
async def test_call_read_tool_header_deny_is_coded_and_audited(
    name: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A write named through call_read_tool under a request deny: coded, recorded, audited."""
    audit_file = tmp_path / "audit.jsonl"
    monkeypatch.delenv("UNIFI_WRITE_POLICY", raising=False)
    monkeypatch.setattr(
        server,
        "_settings",
        Settings(
            api_key="synthetic-key",
            tool_mode="discovery",
            audit_log=str(audit_file),
            audit_log_format="json",
        ),
    )

    async def no_upstream(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a refusal must not contact upstream")

    monkeypatch.setattr(httpx.AsyncClient, "send", no_upstream)
    arguments = (
        {"host": "h", "path": "/proxy/protect/api/cameras/c/enable-control"}
        if name == "fabric_connector_get"
        else {"host": "h", "site": "s", "device": "d", "remove_ports": [1]}
    )
    app = await _discovery_chain()
    token = _HEADERS.set(HEADER_DENY)
    try:
        async with server.lifespan(app), Client(app) as client:
            with pytest.raises(Exception) as error:  # noqa: B017 - the code is asserted below
                await client.call_tool("call_read_tool", {"name": name, "arguments": arguments})
    finally:
        _HEADERS.reset(token)
    assert '"code": "write_denied"' in str(error.value)
    lines = (
        [json.loads(x) for x in audit_file.read_text().splitlines()] if audit_file.exists() else []
    )
    refused = [
        r for r in lines if r.get("event", "audit") == "audit" and r.get("outcome") == "refused"
    ]
    assert len(refused) == 1


# ------------------------------------------------ MR-2 / MR-3 (pending changelog fragments)
# The entry-style check of pending fragments lives in tests/test_changelog_fragment_lint.py.


def test_no_fragment_links_a_public_issue_that_does_not_exist() -> None:
    """The event-buffer entry linked public issue 831, which the public repository lacks."""
    root = Path(__file__).resolve().parents[1]
    for fragment in (root / "changelog.d").glob("*.md"):
        assert "/issues/831" not in fragment.read_text(), fragment.name
