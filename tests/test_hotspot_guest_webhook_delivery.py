"""get_hotspot_guest_webhook_delivery: route, the recorded 204, derived read hint."""

from __future__ import annotations

from unittest.mock import AsyncMock

from fastmcp import FastMCP

from unifi_fabric.families.network import network_clients_guests as guests
from unifi_fabric.families.network import registrar as network_registrar

V2 = "/v1/connector/consoles/host-1/proxy/network/v2/api/site/default"


def _deps(body):
    client = AsyncMock()
    client.get = AsyncMock(return_value=body)
    registry = AsyncMock()
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="host-1")
    registry.resolve_site_slug = AsyncMock(return_value="default")
    return client, registry


async def test_reads_the_last_delivery_route_and_returns_null_for_the_recorded_204() -> None:
    # Recorded read-only on the development console (Network 11.1.47): HTTP 204, no body.
    client, registry = _deps(None)
    result = await guests.get_hotspot_guest_webhook_delivery(client, registry, "h", "Default")
    client.get.assert_called_once_with(f"{V2}/hotspot/guest-data-webhook/last-delivery", key=None)
    assert result is None


async def test_returns_a_delivery_record_verbatim() -> None:
    # The field names the 11.1.47 web application reads from this route.
    body = {"attemptedAtSeconds": 1794300000, "delivered": False, "error": "TimedOut", "extra": 1}
    client, registry = _deps(body)
    assert await guests.get_hotspot_guest_webhook_delivery(client, registry, "h", "s") == body


async def test_tool_is_a_derived_read_with_described_arguments() -> None:
    mcp = FastMCP("webhook")
    network_registrar.register_4(mcp, lambda: (AsyncMock(), AsyncMock()))
    tool = next(t for t in await mcp.list_tools() if t.name == "get_hotspot_guest_webhook_delivery")
    assert tool.annotations.readOnlyHint is True
    assert set(tool.parameters["properties"]) == {"host", "site"}
    assert all(p.get("description") for p in tool.parameters["properties"].values())
