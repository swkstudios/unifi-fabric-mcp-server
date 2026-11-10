"""The relay tools' ``path`` descriptions state how a GET is treated, as the relay does it.

An ordinary GET relays even while an area write opt-out is active; a GET of a
state-changing route (``read_only.STATE_CHANGING_GET_ROUTES``) is a write and follows the
write switches. Each description must name every such route, and only such routes, and
the relay must behave as described.
"""

from __future__ import annotations

import re
from unittest.mock import AsyncMock

import pytest
import respx

from tests._tool_catalog import lazy_parametrize, tools_by_name
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.connector import connector
from unifi_fabric.read_only import STATE_CHANGING_GET_ROUTES, state_changing_get_route

HOST = "console-relay-doc"
BASE = "https://api.ui.com"
PREFIX = f"/v1/connector/consoles/{HOST}/proxy/"
SAMPLE_ID = "65d4f1e2a1b2c3d4e5f60718"
_NAMED_ROUTE = re.compile(r"(?:[a-z][\w.-]*/)+\{id\}/[\w-]+")


def _relay_tools() -> list[str]:
    return sorted(
        name
        for name, tool in tools_by_name().items()
        if name.startswith("fabric_connector_")
        and "path" in (tool.parameters.get("properties") or {})
    )


def _path_description(name: str) -> str:
    prop = tools_by_name()[name].parameters["properties"]["path"]
    return " ".join(str(prop.get("description", "")).split())


@lazy_parametrize("name", _relay_tools)
def test_the_path_description_qualifies_the_get_relay_rule(name):
    description = _path_description(name)
    # A GET relays during an opt-out only when it is an ordinary one (not state-changing).
    assert "GET always relays" not in description, name
    assert re.search(r"\b[Oo]rdinary GET", description), name
    named = _NAMED_ROUTE.findall(description)
    for route in named:
        assert state_changing_get_route(route.replace("{id}", SAMPLE_ID)), (name, route)
    for pattern in STATE_CHANGING_GET_ROUTES if named else ():
        assert any(pattern.fullmatch(r.replace("{id}", SAMPLE_ID)) for r in named), (
            name,
            pattern.pattern,
        )


@pytest.fixture
def registry():
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = HOST
    return registry


@pytest.mark.parametrize("env", ["family:protect=deny", connector.CONNECTOR_WRITE_ENV])
async def test_a_state_changing_get_follows_the_write_switches(monkeypatch, registry, env):
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", env)
    client = UniFiClient(Settings(api_key="synthetic-relay-doc"))
    path = f"protect/api/cameras/{SAMPLE_ID}/enable-control"
    with respx.mock(assert_all_called=False) as router:
        route = router.get(BASE + PREFIX + path).respond(200, json={})
        with pytest.raises(ValueError, match=env):
            await connector.connector_get(client, registry, HOST, path)
        assert route.call_count == 0
    await client.close()


async def test_an_ordinary_get_relays_while_an_area_opt_out_is_active(monkeypatch, registry):
    monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", "family:protect=deny")
    client = UniFiClient(Settings(api_key="synthetic-relay-doc"))
    path = f"protect/api/cameras/{SAMPLE_ID}"
    with respx.mock as router:
        route = router.get(BASE + PREFIX + path).respond(200, json={"id": SAMPLE_ID})
        result = await connector.connector_get(client, registry, HOST, path)
        assert result["status"] == 200
        assert route.call_count == 1
    await client.close()
