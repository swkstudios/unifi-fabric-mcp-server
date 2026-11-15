"""A server session that hides tools leaves the registry in registration order.

The lifespan de-registers the tools the exposure settings, a deny write policy and the
area write exceptions hide, and puts them back when it ends. They go back where they
were registered, so a later session in the same process lists the same tools in the same
order (tools/list order is caller-visible).
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys

import pytest
from fastmcp import Client

from unifi_fabric import server


def _names() -> list[str]:
    return [t.name for t in asyncio.run(server.mcp.list_tools(run_middleware=False))]


@pytest.mark.parametrize(
    "env",
    [
        {"UNIFI_FAMILY_ALLOW": "protect"},
        {"UNIFI_EXCLUDE": "family:network"},
        {"UNIFI_WRITE_POLICY": "deny"},
        {"UNIFI_TOOL_MODE": "discovery", "UNIFI_FAMILY_ALLOW": "site_manager,vpn"},
    ],
    ids=["family-allow", "exclude-family", "write-deny", "discovery-narrowed"],
)
def test_a_narrowed_session_restores_the_registration_order(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str]
) -> None:
    before = _names()
    monkeypatch.setenv("UNIFI_KEY_MODE", "header")
    monkeypatch.setenv("UNIFI_TOOL_MODE", "full")
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(server, "_settings", None)

    async def session() -> int:
        async with Client(server.mcp) as client:
            return len(await client.list_tools())

    listed = asyncio.run(session())
    assert 0 < listed < len(before) or env.get("UNIFI_TOOL_MODE") == "discovery"
    assert _names() == before


def test_the_restored_order_equals_a_fresh_registration(monkeypatch: pytest.MonkeyPatch) -> None:
    """After an excluded session, the order equals a fresh interpreter's, whatever the hash
    seed (the hidden set used to come back in set order, which varies by seed)."""
    probe = (
        "import asyncio, json\n"
        "from unifi_fabric import server\n"
        "tools = asyncio.run(server.mcp.list_tools(run_middleware=False))\n"
        "print(json.dumps([t.name for t in tools]))"
    )
    fresh = subprocess.run(  # noqa: S603 - this interpreter, a fixed import probe
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    monkeypatch.setenv("UNIFI_KEY_MODE", "header")
    monkeypatch.setenv("UNIFI_TOOL_MODE", "full")
    monkeypatch.setenv("UNIFI_EXCLUDE", "family:protect,family:network")
    monkeypatch.setattr(server, "_settings", None)

    async def session() -> None:
        async with Client(server.mcp) as client:
            await client.list_tools()

    asyncio.run(session())
    assert _names() == json.loads(fresh.stdout.splitlines()[-1])
