"""Contract tests for the 0.7.1 source-core follow-ups (official-only client split,
read-POST guidance, purpose-only update refusal, lane vocabulary in shipped source).

Hermetic: no request reaches an upstream, no credential is read.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp import Client, FastMCP

from unifi_fabric import policy, request_policy, server
from unifi_fabric.config import Settings
from unifi_fabric.read_only_tools import ReadOnlyToolMiddleware, apply_read_only_tool_filter
from unifi_fabric.refusal_audit import RefusedWriteAuditMiddleware
from unifi_fabric.write_body import TOOL_IDENTITY_FIELDS, identity_fields, update_problem

ROOT = Path(__file__).resolve().parents[1]

#: The one sentence every write tool that declares no consequence carries: the guidance an
#: AI client needs to call a read sent as a POST that the exact-route classifier
#: (read_post_routes.READ_POST_ROUTES) does not list.
READ_POST_GUIDANCE = (
    "Write class: its POST is not read-POST allowlisted, so UNIFI_WRITE_POLICY=deny hides "
    "the whole tool and discovery mode runs it through call_write_tool."
)

#: Independent expected members, so the derived class can never pass empty.
KNOWN_NO_CONSEQUENCE_WRITES = frozenset(
    {
        "export_traffic_flows",
        "get_inactive_sim_slot",
        "get_lte_subscription_status",
        "get_multicast_insights",
        "get_rolling_upgrade_plan",
        "get_sites_overview",
        "get_system_log",
        "list_guests",
        "list_ips_events",
        "list_network_events",
        "query_app_traffic_rates",
        "query_port_system_logs",
        "query_power_supervisor_logs",
        "query_switch_mac_tables",
        "query_teleport_invitations",
    }
)


def _flat(text: str | None) -> str:
    return " ".join((text or "").split())


async def _tools() -> dict[str, Any]:
    return {tool.name: tool for tool in await server.mcp.list_tools()}


def _no_consequence_writes(tools: dict[str, Any]) -> set[str]:
    return {
        name
        for name, tool in tools.items()
        if not tool.annotations.read_only_hint
        and re.search(r"Consequence:\s*none", tool.description or "")
    }


# --------------------------------------------------------------- read-POST guidance


async def test_no_consequence_write_tools_state_the_read_post_guidance():
    tools = await _tools()
    derived = _no_consequence_writes(tools)
    assert KNOWN_NO_CONSEQUENCE_WRITES <= derived
    want = _flat(READ_POST_GUIDANCE)
    missing = sorted(n for n in derived if want not in _flat(tools[n].description))
    assert missing == [], f"tools without the read-POST guidance sentence: {missing}"
    for name in derived:
        assert len(tools[name].description) <= 2048, name


async def test_read_post_guidance_matches_annotations_and_deny_filter():
    tools = await _tools()
    derived = _no_consequence_writes(tools)
    assert KNOWN_NO_CONSEQUENCE_WRITES <= derived
    for name in derived:
        ann = tools[name].annotations
        assert ann.read_only_hint is False and ann.destructive_hint is True, name
    app = FastMCP("read-post-guidance")
    for tool in tools.values():
        app.add_tool(tool)
    assert derived <= await apply_read_only_tool_filter(app, True)


async def test_read_post_guidance_matches_discovery_dispatch(monkeypatch, tmp_path):
    monkeypatch.delenv("UNIFI_WRITE_POLICY", raising=False)
    monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS", raising=False)
    monkeypatch.setattr(
        server, "_settings", Settings(api_key="synthetic-key", tool_mode="discovery")
    )

    async def no_upstream(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a dispatcher refusal must not contact upstream")

    monkeypatch.setattr(httpx.AsyncClient, "send", no_upstream)
    tools = await _tools()
    derived = _no_consequence_writes(tools)
    app = FastMCP("read-post-guidance-discovery")
    for tool in tools.values():
        app.add_tool(tool)
    app.add_middleware(server.SecretScrubMiddleware())
    app.add_middleware(RefusedWriteAuditMiddleware(app, lambda: True, server._audit_refusal))
    app.add_middleware(ReadOnlyToolMiddleware(app, audit=server._audit_refusal))
    async with server.lifespan(app), Client(app) as client:
        for name in sorted(derived):
            with pytest.raises(Exception) as error:
                await client.call_tool("call_read_tool", {"name": name, "arguments": {}})
            assert f"Use call_write_tool(name={name!r}" in str(error.value), name


# ------------------------------------------------------- purpose-only update refusal


#: The update tools that pin ``purpose`` (the Classic networkconf record kind).
PURPOSE_PINNED = sorted(t for t, keys in TOOL_IDENTITY_FIELDS.items() if "purpose" in keys)


@pytest.mark.parametrize("tool", PURPOSE_PINNED)
@pytest.mark.parametrize("purpose", ["pinned-kind", "corporate"])
def test_purpose_only_body_is_refused_with_accurate_reason(tool, purpose):
    assert len(PURPOSE_PINNED) >= 4
    _clean, _dropped, reason = update_problem(
        {"purpose": purpose}, "fields", identity=identity_fields(tool)
    )
    assert reason is not None
    # The id argument addresses the record; purpose is the record kind the tool pins, so
    # no argument names it. The reason must not claim one does.
    assert "id argument already names" not in reason
    assert "purpose, the record kind the tool pins" in reason
    assert "No request was sent." in reason


def test_key_named_by_an_argument_keeps_the_id_argument_reason():
    for body, tool in (({"_id": "x"}, "update_vpn_server"), ({"key": "mgmt"}, "update_setting")):
        _clean, _dropped, reason = update_problem(body, "fields", identity=identity_fields(tool))
        assert reason is not None and "id argument already names" in reason, tool
        assert "the tool pins" not in reason, tool


def test_purpose_with_a_real_field_is_not_refused():
    for tool in PURPOSE_PINNED:
        _clean, _dropped, reason = update_problem(
            {"purpose": "corporate", "enabled": False}, "fields", identity=identity_fields(tool)
        )
        assert reason is None, tool


async def test_purpose_pinned_tool_descriptions_state_the_refusal():
    tools = await _tools()
    for tool in PURPOSE_PINNED:
        text = _flat(f"{tools[tool].description} {tools[tool].parameters}")
        assert "purpose-only update is refused" in text, tool


# ----------------------------------------------- official-only client split (FA-06)


@pytest.mark.parametrize(
    ("exclude", "official_exposed", "private_exposed"),
    [
        ("unofficial", True, False),
        ("source:network/private", True, False),
        ("source:network/private.v2", True, False),
        ("source:network/official", False, True),
        ("tool:list_active_clients", True, False),
    ],
)
async def test_client_split_through_production_exposure(exclude, official_exposed, private_exposed):
    tools = await _tools()
    catalog = request_policy.catalog_from_tools(tools.values())
    effective = policy.operator_policy({"UNIFI_EXCLUDE": exclude}, catalog)
    assert policy.is_exposed(effective, catalog.tools["list_clients"]) is official_exposed
    assert policy.is_exposed(effective, catalog.tools["list_active_clients"]) is private_exposed


# ---------------------------------------------- lane vocabulary in shipped source


_TWO_LETTER_LANE = re.compile(r"\b[Ll]anes? [A-Z]{2,3}[0-9]?\b")


def test_shipped_source_carries_no_multi_letter_lane_id():
    hits = [
        f"{path.relative_to(ROOT)}:{n}"
        for path in sorted((ROOT / "src").rglob("*.py"))
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _TWO_LETTER_LANE.search(line)
    ]
    assert hits == []
