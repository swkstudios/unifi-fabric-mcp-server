"""Header-credential contract fixtures (tests/fixtures/contracts/h/v1) run against the server.

Every envelope runs end to end through ``fastmcp.Client(server.mcp)``: the real lifespan
(settings, tool mode), the middleware chain (credential ingress, request policy, guards,
credential lease) and the real ``UniFiClient``, on the fixture's ``input.upstream``
(tests/contract_upstream.py). ``input.env`` is the process environment,
``input.headers`` the wire header values the ingress and the policy read, and
``input.transport`` the startup key-mode check (``check_startup``, as ``server.main``
runs it). A reject fixture must refuse with its code before any upstream call; an accept
fixture must succeed and match every expected key. tests/test_contract_c0.py checks the
same files against the envelope schema.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client

from tests import contract_upstream as cu
from unifi_fabric import header_credentials as hc
from unifi_fabric import server

FIXTURES = Path(__file__).parent / "fixtures" / "contracts" / "h" / "v1"
#: The accept keys this runner observes; a fixture expecting any other key fails.
ACCEPT_KEYS = frozenset({"listed_tools", "selected_labels", "upstream_calls", "upstream_mutations"})
HANDSHAKE_ROUTES = frozenset({"initialize", "ping"})


def _fixture_files() -> list[Path]:
    return sorted(FIXTURES.glob("*.json"))


def _wire(pairs: Sequence[tuple[str, str]]) -> hc.HeaderSource:
    """Every wire value of a header, matched case-insensitively, in wire order."""

    def values(name: str) -> list[str]:
        return [v for k, v in pairs if k.lower() == name.lower()]

    return values


def _error_code(text: str) -> str | None:
    try:
        return json.loads(text)["error"]["code"]
    except (ValueError, KeyError, TypeError):
        return None


async def _run(fx: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    inp = fx["input"]
    for name, value in inp.get("env", {}).items():
        monkeypatch.setenv(name, value)
    upstream = cu.install(monkeypatch, inp.get("upstream"))
    transport = inp.get("transport", "http")
    out: dict[str, Any] = {}
    try:
        mode = hc.check_startup(transport)
    except hc.StartupRefusal as refusal:
        out["code"] = refusal.token
        out["upstream_calls"] = len(upstream.calls)
        return out
    # stdio carries no request headers.
    headers = [] if transport == "stdio" else [tuple(p) for p in inp.get("headers", [])]
    monkeypatch.setattr(hc, "_raw_header_values", _wire(headers))
    hc.set_process_key_mode(mode)
    route = inp["route"]
    # initialize and ping are handshake-era methods (MCP 2024-11-05 .. 2025-11-25): the
    # 2026-07-28 protocol the client negotiates by default has neither, so these routes
    # connect in legacy mode, which sends a real initialize and answers ping.
    mode_kw = {"mode": "legacy"} if route in HANDSHAKE_ROUTES else {}
    try:
        async with Client(server.mcp, **mode_kw) as client:
            if route == "initialize":
                assert client.initialize_result is not None
            elif route == "ping":
                assert await client.ping()
            elif route == "tools/list":
                try:
                    listed = await client.list_tools()
                except Exception as exc:  # noqa: BLE001 - an MCP error carries the code
                    data = getattr(getattr(exc, "error", None), "data", None) or {}
                    out["code"] = (data.get("error") or {}).get("code")
                    out["tool_error"] = type(exc).__name__
                else:
                    out["listed"] = sorted(t.name for t in listed)
            else:
                result = await client.call_tool(
                    route, copy.deepcopy(inp.get("arguments", {})), raise_on_error=False
                )
                if result.is_error:
                    text = "".join(getattr(c, "text", "") for c in result.content)
                    code = _error_code(text)
                    if code is not None:
                        out["code"] = code
                    else:
                        out["tool_error"] = text[:300]
    finally:
        hc.set_process_key_mode(None)
    out["upstream_calls"] = len(upstream.calls)
    out["upstream_mutations"] = len(upstream.mutations())
    out["selected_labels"] = upstream.labels()
    return out


def test_h_fixtures_present() -> None:
    assert len(_fixture_files()) >= 35


@pytest.mark.parametrize("path", _fixture_files(), ids=lambda p: p.stem)
async def test_fixture(path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fx = json.loads(path.read_text(encoding="utf-8"))
    assert fx["contract"] == "h" and fx["name"] == path.stem
    result = await _run(fx, monkeypatch)
    expected = fx["expected"]
    if fx["kind"] == "reject":
        assert result.get("code") == expected["code"], result
        assert result["upstream_calls"] == expected["upstream_calls"] == 0, result
        return
    assert fx["kind"] == "accept"
    # An accept fixture passes only when the call succeeds: a refusal or a tool error
    # (an unresolvable host, a missing argument) is never an accept.
    assert "code" not in result and "tool_error" not in result, result
    assert set(expected) <= ACCEPT_KEYS, sorted(set(expected) - ACCEPT_KEYS)
    for key in ("selected_labels", "upstream_calls", "upstream_mutations"):
        if key in expected:
            assert result[key] == expected[key], (key, result)
    if "listed_tools" in expected:
        assert result.get("listed") == expected["listed_tools"], result
