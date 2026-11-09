"""Guidance an AI client needs survives on the advertised surface itself.

Descriptions were shortened to fit Claude Code's 2,048-character limit; these checks
pin the parts that must stay on the wire rather than only in docs/TOOL-USAGE.md: the
connector relay's return and refusal contract, a consequence line on every delete and
physical-action tool, and the firewall / tool-family / ordering / Mobility guidance.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from unifi_fabric import server
from unifi_fabric._read_only_audit import classify_tool_verbs, is_destructive


def _tools() -> dict[str, Any]:
    return {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}


def _flat(text: str | None) -> str:
    """Description text with line wrapping undone, so a phrase may span a wrap."""
    return " ".join((text or "").split())


RELAY_COMMON = (
    "status",
    "contentType",
    "bodyBase64",
    "sizeBytes",
    "dry_run",
    "family:connector=deny",
    "UNIFI_WRITE_POLICY",
    "family:protect=deny",
    "unclassified",
    "never auto-retried on 429",
)
RELAY_TWIN = ("readBefore", "readAfter", "noOp", "changed", "readAfterError")


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_relay_write_descriptions_state_return_and_refusal_contract(method: str) -> None:
    raw = _tools()[f"fabric_connector_{method}"].description or ""
    description = _flat(raw)
    missing = [term for term in RELAY_COMMON if term not in description]
    if method == "post":
        assert "no read-before/after" in description
        assert not [term for term in RELAY_TWIN if term in description]
    else:
        missing += [term for term in RELAY_TWIN if term not in description]
    assert missing == []
    assert len(raw) <= 2048


def _consequence_tools(tools: dict[str, Any]) -> set[str]:
    """Every tool that can remove upstream state, plus every POST command/action tool."""
    verbs = classify_tool_verbs(list(tools.values()))
    out = set()
    for name, tool in tools.items():
        if not verbs[name]:
            continue
        if is_destructive(tool.fn):
            out.add(name)
        elif verbs[name] == {"POST"} and not name.startswith("create_"):
            out.add(name)
    return out


def test_every_delete_and_physical_action_states_its_consequence() -> None:
    tools = _tools()
    swept = _consequence_tools(tools)
    assert {"delete_network", "unadopt_device", "forget_device", "restart_device"} <= swept
    assert {"siren_play", "execute_port_action", "fabric_connector_delete"} <= swept
    assert len(swept) > 50
    missing = sorted(n for n in swept if "Consequence:" not in _flat(tools[n].description))
    assert missing == []
    assert "disconnects all clients on that network" in _flat(tools["delete_network"].description)
    unadopt = _flat(tools["unadopt_device"].description)
    assert "removes the device's association" in unadopt
    assert "must be re-adopted" in unadopt


def test_acl_rules_say_what_they_are_and_when_to_use_them() -> None:
    tools = _tools()
    for name in ("list_acl_rules", "create_acl_rule"):
        description = _flat(tools[name].description)
        assert "network-layer" in description, name
        assert "only when the user asks for ACL rules" in description, name
        assert "create_firewall_policy" in description, name
    assert "unless the user asks for ACL" in _flat(server.INSTRUCTIONS)


def test_instructions_name_the_tool_family_allowlist() -> None:
    assert "UNIFI_FAMILY_ALLOW" in server.INSTRUCTIONS
    assert len(server.INSTRUCTIONS) <= 2048


def test_firewall_ordering_guidance_is_on_the_wire() -> None:
    description = _flat(_tools()["set_firewall_policy_ordering"].description)
    assert "Use [] for an empty side" in description
    assert "read back with get_firewall_policy_ordering" in description
    assert "HTTP 400" in description


def test_mobility_network_update_says_explicit_null_is_forwarded() -> None:
    description = _flat(_tools()["update_mobility_device_network"].description)
    assert "explicit null is forwarded" in description


def test_tool_usage_explains_annotation_semantics() -> None:
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "docs/TOOL-USAGE.md").read_text()
    section = text.split("## Tool annotations\n", 1)[1].split("\n## ", 1)[0]
    for term in ("readOnlyHint: true", "destructiveHint: false", "destructiveHint: true"):
        assert term in section
