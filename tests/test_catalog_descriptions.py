"""Shared selector text and the required-arguments line applied at registration."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastmcp import Client

from unifi_fabric import server
from unifi_fabric.catalog_descriptions import (
    _ORIGINAL_HOST,
    HOST_DESCRIPTION,
    _host_description,
    install_compact_selector_descriptions,
)
from unifi_fabric.config import Settings


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (_ORIGINAL_HOST, HOST_DESCRIPTION),
        (
            'Console name or id from list_hosts, e.g. "my-console".',
            "Console name, MAC or id from list_hosts: reportedState.hostname/name "
            '(e.g. "my-console") or data[].id.',
        ),
        (
            'Protect console name or composite id from list_hosts; for example "Home NVR".',
            "Protect console name, MAC or id from list_hosts: reportedState.hostname/name "
            '(for example "Home NVR") or data[].id.',
        ),
        (
            "Console name or id from list_hosts.",
            "Console name, MAC or id from list_hosts: reportedState.hostname/name or data[].id.",
        ),
        (
            'Required console selector from list_hosts, for example "Home NVR".',
            "Console name, MAC or id from list_hosts: reportedState.hostname/name "
            '(for example "Home NVR") or data[].id.',
        ),
        (
            'Console name or id from list_hosts, e.g. "my-console"; resolved to its owning '
            "Fabric API key.",
            "Console name, MAC or id from list_hosts: reportedState.hostname/name "
            '(e.g. "my-console") or data[].id. Resolved to its owning Fabric API key.',
        ),
    ],
)
def test_generic_host_hints_gain_both_console_forms(given: str, expected: str) -> None:
    assert _host_description(given) == expected
    assert "reportedState.hostname" in expected and "data[].id" in expected


@pytest.mark.parametrize(
    "kept",
    [
        HOST_DESCRIPTION,
        "Optional filter. Console name or id: the short name from list_hosts "
        "(data[].reportedState.hostname or reportedState.name) or the long data[].id.",
        "Console that owns the camera; must match the camera's NVR.",
    ],
)
def test_specific_or_complete_host_hints_are_kept(kept: str) -> None:
    assert _host_description(kept) is None


def _app(**tools: dict[str, Any]) -> SimpleNamespace:
    components = {
        name: SimpleNamespace(description=spec["description"], parameters=spec["parameters"])
        for name, spec in tools.items()
    }
    return SimpleNamespace(_local_provider=SimpleNamespace(_components=components))


def test_unnamed_required_parameter_gets_the_required_arguments_line() -> None:
    app = _app(
        restart={
            "description": "Restart an adopted device.",
            "parameters": {
                "properties": {"host": {}, "site": {}, "device_id": {}},
                "required": ["host", "site", "device_id"],
            },
        },
        named={
            "description": "Read one host's site summary.",
            "parameters": {"properties": {"host": {}, "site": {}}, "required": ["host", "site"]},
        },
    )
    install_compact_selector_descriptions(app)
    components = app._local_provider._components
    assert components["restart"].description == (
        "Restart an adopted device.\n\nRequired arguments: host, site, device_id."
    )
    assert components["named"].description == "Read one host's site summary."


@pytest.fixture
def full_catalog(_reset_server_singletons, monkeypatch):
    monkeypatch.setattr(
        server, "_settings", server.Settings(api_key="n06-unit-test-key", tool_mode="full")
    )


async def test_tool_surface_notes_reach_tools_list(full_catalog) -> None:
    """_proxy suffix, dry-run switch, UUID zone ids and filter families are described."""
    async with Client(server.mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    for name in tools:
        if name.endswith("_proxy"):
            assert "_proxy suffix" in tools[name].description, name
    for name in ("get_firewall_policy_ordering", "set_firewall_policy_ordering"):
        source = tools[name].input_schema["properties"]["source_zone_id"]["description"]
        assert "UUID" in source and "8-4-4-4-12" in source and "rejected" in source
    dry = [t for t in tools.values() if "dry-run policy" in t.description.lower()]
    assert dry
    for tool in dry:
        read_only = bool(tool.annotations and tool.annotations.read_only_hint)
        assert ("UNIFI_WRITE_POLICY=dry-run" in tool.description) is not read_only, tool.name
    # the named settings exist under those names in Settings
    assert {"write_policy", "write_exceptions"} <= set(Settings.model_fields)
    for name, key in (
        ("list_firewall_policies", "Filter family: zone-to-zone"),
        ("list_acl_rules", "Filter family: L3/MAC"),
        ("list_traffic_rules", "Filter family: QoS"),
        ("list_content_filters", "Filter family: category-based"),
    ):
        assert key in tools[name].description, name


async def test_proxy_suffix_sentence_names_no_tool_that_does_not_exist(full_catalog) -> None:
    """The ``_proxy suffix:`` sentence once said "same resource as the unsuffixed tool", but
    no unsuffixed zone tool exists. Nothing served says it, and every tool the sentence names
    is in the catalog."""
    import re

    async with Client(server.mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    proxies = sorted(name for name in tools if name.endswith("_proxy"))
    assert len(proxies) >= 5
    assert not [n for n, t in tools.items() if "unsuffixed tool" in (t.description or "")]
    sentence = re.compile(r"_proxy suffix:[^\n]*?\.(?=\s|$)")
    name = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")
    for proxy in proxies:
        found = sentence.search(" ".join((tools[proxy].description or "").split()))
        assert found, proxy
        text = found.group(0)
        assert "calls the Network Integration API through the connector proxy" in text, proxy
        assert [n for n in name.findall(text[len("_proxy suffix:") :]) if n not in tools] == []


async def test_advertised_text_keeps_its_promises(full_catalog) -> None:
    """U4-U8: the notes and claims in the tool text match what the tool does."""
    async with Client(server.mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    flat = {name: " ".join((tool.description or "").split()) for name, tool in tools.items()}
    # U4: the dry-run switch is a write note; a read-only tool never carries it.
    carriers = [
        name
        for name, tool in tools.items()
        if tool.annotations
        and tool.annotations.read_only_hint
        and "UNIFI_WRITE_POLICY=dry-run" in flat[name]
    ]
    assert carriers == []
    # U5: no promise of validation the tool does not do.
    assert "both arrays required" not in flat["set_firewall_policy_ordering"]
    assert "does not check them" in " ".join(
        tools["set_firewall_policy_ordering"]
        .input_schema["properties"]["ordering"]["description"]
        .split()
    )
    # U6: the preview POST says it is a write class hidden under deny.
    assert "Write class:" in flat["preview_policy_engine_rule"]
    assert "UNIFI_WRITE_POLICY=deny hides it" in flat["preview_policy_engine_rule"]
    # U8: integrationArmProfiles is null when the mode is undetermined.
    assert "or null when mode is null" in flat["get_protect_alarm_manager_mode"]
