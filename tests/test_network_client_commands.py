"""Network client commands: block / unblock / reconnect send a MAC straight to the Classic
``stamgr`` command (no connected-client lookup, so a blocked or offline client is
addressable), a client id that is not connected fails asking for the MAC, the tools that
need the Integration id say the client must be connected, and no tool description carries
a doubled brace."""

from __future__ import annotations

from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import upstream_harness as uh
from tests.test_network_mac_resolution_and_shapes import OTHER_ID, _call, _Upstream
from unifi_fabric import server

BLOCKED_MAC = "02:00:5e:00:00:cc"  # in no list: a blocked client is offline
OFFLINE_ID = "00000000-0000-4000-8000-0000000000cc"
_STAMGR = {
    "block_client": "block-sta",
    "unblock_client": "unblock-sta",
    "reconnect_client": "kick-sta",
}


def _non_resolution_gets(up: uh.FakeUpstream) -> list[str]:
    return [s.path for s in up.served if s.method == "GET" and not s.resolution]


async def test_unblock_a_mac_absent_from_list_clients(monkeypatch):
    up = _Upstream()
    up.clients = [{"id": OTHER_ID, "name": "laptop", "macAddress": "02:00:5e:00:00:bb"}]
    await _call(monkeypatch, up, "unblock_client", client_id="02-00-5E-00-00-CC")
    writes = up.writes()
    assert len(writes) == 1 and writes[0].method == "POST"
    assert writes[0].path.endswith("/cmd/stamgr")
    assert writes[0].sent_json == {"cmd": "unblock-sta", "mac": BLOCKED_MAC}
    assert _non_resolution_gets(up) == []  # 0 list GETs (no /clients read at all)


async def test_pre_block_an_offline_mac(monkeypatch):
    up = _Upstream()
    up.clients = []  # nothing connected
    await _call(monkeypatch, up, "block_client", client_id="02005E0000CC")
    assert [(w.path.endswith("/cmd/stamgr"), w.sent_json) for w in up.writes()] == [
        (True, {"cmd": "block-sta", "mac": BLOCKED_MAC})
    ]
    assert _non_resolution_gets(up) == []


@pytest.mark.parametrize("tool", sorted(_STAMGR))
@pytest.mark.parametrize(
    "form", [BLOCKED_MAC.upper(), BLOCKED_MAC.replace(":", "-"), "02005e0000cc"]
)
async def test_stamgr_mac_is_normalized_and_sent_directly(monkeypatch, tool, form):
    up = _Upstream()
    await _call(monkeypatch, up, tool, client_id=form)
    assert [w.sent_json for w in up.writes()] == [{"cmd": _STAMGR[tool], "mac": BLOCKED_MAC}]
    assert _non_resolution_gets(up) == []


class _Offline(_Upstream):
    """The Integration client GET answers 404: the client is not connected."""

    def __call__(self, req):  # type: ignore[no-untyped-def]
        import httpx

        if req.method == "GET" and req.url.path.endswith(f"/clients/{OFFLINE_ID}"):
            body = {"code": "api.err.NotFound", "message": "probe: client not connected"}
            self._record(req, 404, body, False)
            return httpx.Response(404, json=body)
        return super().__call__(req)


@pytest.mark.parametrize("tool", sorted(_STAMGR))
async def test_uuid_of_an_offline_client_fails_asking_for_the_mac(monkeypatch, tool):
    up = _Offline()
    with pytest.raises(ToolError) as err:
        await _call(monkeypatch, up, tool, client_id=OFFLINE_ID)
    msg = str(err.value)
    assert "HTTP 404 from" in msg and "probe: client not connected" in msg  # upstream verbatim
    assert "Pass the client's MAC instead" in msg and "list_known_clients" in msg
    assert up.writes() == []


@pytest.mark.parametrize("tool", ["get_client", "execute_client_action"])
async def test_id_needing_tools_say_the_client_must_be_connected(monkeypatch, tool):
    up = _Upstream()
    up.clients = []
    extra: dict[str, Any] = (
        {"action": {"action": "UNAUTHORIZE_GUEST_ACCESS"}} if tool.startswith("exec") else {}
    )
    with pytest.raises(ToolError) as err:
        await _call(monkeypatch, up, tool, client_id=BLOCKED_MAC, **extra)
    assert "exists only while the client is connected" in str(err.value)
    assert up.writes() == []


async def _tool_descriptions(monkeypatch) -> dict[str, dict[str, Any]]:
    from fastmcp import Client

    uh.install(monkeypatch, uh.FakeUpstream(), tool_mode="full")
    async with Client(server.mcp) as mcp_client:
        return {
            t.name: {"description": t.description, "inputSchema": t.input_schema}
            for t in await mcp_client.list_tools()
        }


async def test_client_id_descriptions_state_the_connection_requirement(monkeypatch):
    tools = await _tool_descriptions(monkeypatch)
    for name in _STAMGR:
        desc = " ".join(
            tools[name]["inputSchema"]["properties"]["client_id"]["description"].split()
        )
        assert "any client the controller knows, connected or not" in desc, name
        assert "list_known_clients" in desc, name
    for name in ("block_client", "unblock_client"):
        assert "connected or not" in " ".join((tools[name]["description"] or "").split()), name
    for name in ("get_client", "execute_client_action"):
        desc = " ".join(
            tools[name]["inputSchema"]["properties"]["client_id"]["description"].split()
        )
        assert "the client must be connected" in desc, name


def _escaped_brace(text: str) -> str | None:
    """Where ``text`` shows a str.format brace escape left in a plain docstring: any ``{{``,
    or a ``}}`` that does not close two braces opened before it. A ``}}`` ending a nested
    object (``{a: {b}}``) is legitimate and is not reported."""
    if "{{" in text:
        at = text.index("{{")
        return text[max(0, at - 40) : at + 40]
    depth = 0
    for i, ch in enumerate(text):
        if ch == "{":
            depth += 1
        elif ch == "}":
            if text.startswith("}}", i) and depth < 2:
                return text[max(0, i - 40) : i + 40]
            depth -= 1
    return None


@pytest.mark.parametrize(
    "text", ["{{meta: {{rc}}, data: [...]}}", "{a}}", "x}} y", "{{dryRun, message, preview}}"]
)
def test_escaped_brace_detector_flags_the_defect(text):
    assert _escaped_brace(text) is not None


def test_escaped_brace_detector_accepts_nested_objects():
    assert _escaped_brace("{status, changed: {field: {from, to}}, verified}") is None


async def test_no_tool_description_in_tools_list_has_a_doubled_brace(monkeypatch):
    tools = await _tool_descriptions(monkeypatch)
    bad = {}
    for name, tool in tools.items():
        texts = [tool.get("description") or ""]
        for prop in ((tool.get("inputSchema") or {}).get("properties") or {}).values():
            texts.append(str(prop.get("description") or ""))
        hits = [h for t in texts if (h := _escaped_brace(t)) is not None]
        if hits:
            bad[name] = hits
    assert bad == {}, f"literal doubled braces: {bad}"
