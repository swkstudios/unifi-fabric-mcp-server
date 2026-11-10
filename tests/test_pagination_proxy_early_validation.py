"""Proxy list arguments are validated before any registry or client request."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.families.network import firewall_proxy as firewall
from unifi_fabric.families.network import network_services_proxy as services
from unifi_fabric.registry import Registry

ListTool = Callable[..., Awaitable[dict[str, Any]]]
PROXY_LISTS = [
    (firewall.list_firewall_policies, True),
    (firewall.list_firewall_zones, True),
    (firewall.list_acl_rules, True),
    (services.list_dns_policies, True),
    (services.list_traffic_matching_lists, True),
    (services.list_vpn_servers, True),
    (services.list_site_to_site_tunnels, True),
    (services.list_radius_profiles, True),
    (services.list_hotspot_vouchers, True),
    (services.list_countries, False),
    (services.list_dpi_categories, False),
    (services.list_dpi_applications, False),
]
TOOLS = pytest.mark.parametrize(
    ("tool", "site_scoped"), PROXY_LISTS, ids=[tool.__name__ for tool, _ in PROXY_LISTS]
)


@TOOLS
@pytest.mark.parametrize(
    ("arguments", "message"),
    # PAGING-VALIDATION-A1 rule 3: the refusal names the caller's argument, limit.
    [
        ({"limit": 0}, "^limit must be a positive integer"),
        ({"limit": -1}, "^limit must be a positive integer"),
        ({"limit": True}, "^limit must be a positive integer"),
        ({"limit": "1"}, "^limit must be a positive integer"),
        ({"offset": -1}, "offset must be 0 or more"),
        ({"offset": True}, "offset must be 0 or more"),
        ({"offset": "0"}, "offset must be 0 or more"),
    ],
)
async def test_invalid_proxy_pagination_performs_no_resolution_or_upstream_request(
    tool: ListTool, site_scoped: bool, arguments: dict[str, Any], message: str
) -> None:
    client = MagicMock(spec=UniFiClient)
    registry = MagicMock(spec=Registry)
    scope = {"host": "synthetic-host", **({"site": "synthetic-site"} if site_scoped else {})}
    with pytest.raises(ValueError, match=message):
        await tool(client, registry, **scope, **arguments)
    assert registry.mock_calls == []
    assert client.mock_calls == []


@TOOLS
@pytest.mark.parametrize(("offset", "limit"), [(0, 1), (0, 10**30), (10**30, 1)])
async def test_valid_proxy_pagination_reaches_upstream_unchanged(
    tool: ListTool, site_scoped: bool, offset: int, limit: int
) -> None:
    client = MagicMock(spec=UniFiClient)
    response = {
        "data": [{"id": "synthetic-row", "unchanged": {"value": "original"}}],
        "offset": offset,
        "limit": limit,
        "totalCount": offset + 1,
    }
    client.get = AsyncMock(return_value=response)
    registry = MagicMock(spec=Registry)
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="synthetic-host")
    registry.resolve_site_id = AsyncMock(return_value="11111111-1111-4111-8111-111111111111")
    scope = {"host": "synthetic-host", **({"site": "synthetic-site"} if site_scoped else {})}
    result = await tool(client, registry, **scope, offset=offset, limit=limit)
    registry.resolve_key_for_host.assert_awaited_once_with("synthetic-host")
    registry.resolve_host_id.assert_awaited_once_with("synthetic-host", key=None)
    if site_scoped:
        registry.resolve_site_id.assert_awaited_once_with(
            "synthetic-site", "synthetic-host", key=None
        )
    else:
        registry.resolve_site_id.assert_not_awaited()
    client.get.assert_awaited_once()
    assert client.get.call_args.kwargs["params"] == {"offset": offset, "limit": limit}
    assert result["data"] == response["data"]
    assert result["totalCount"] == response["totalCount"]
