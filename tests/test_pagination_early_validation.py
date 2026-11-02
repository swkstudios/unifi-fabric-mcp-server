"""Pagination arguments are checked before host and site resolution."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.tools import (
    clients,
    device_mgmt,
    network,
    network_controller_insights,
    network_vpn_dns,
    protect,
    protect_recognition_search,
    site_manager,
)

_HOST = "synthetic-console"
_SITE = "synthetic-site"
_UUID = "00000000-0000-4000-8000-000000000001"
_CASES = [
    pytest.param(
        clients._list_clients, {"host": _HOST, "site": _SITE}, "limit", True, id="clients"
    ),
    pytest.param(
        device_mgmt._list_site_devices,
        {"host": _HOST, "site": _SITE},
        "limit",
        True,
        id="site-devices",
    ),
    pytest.param(
        device_mgmt._list_pending_devices, {"host": _HOST}, "limit", True, id="pending-devices"
    ),
    pytest.param(network.list_local_sites, {"host": _HOST}, "limit", True, id="local-sites"),
    pytest.param(
        network.list_networks, {"host": _HOST, "site": _SITE}, "limit", True, id="networks"
    ),
    pytest.param(
        network.list_wifi_broadcasts, {"host": _HOST, "site": _SITE}, "limit", True, id="wifi"
    ),
    pytest.param(
        network.list_wan_interfaces, {"host": _HOST, "site": _SITE}, "limit", True, id="wan"
    ),
    pytest.param(
        network._list_switching_resources,
        {"host": _HOST, "site": _SITE, "resource": "lags", "filter": None, "offset": None},
        "limit",
        True,
        id="switching",
    ),
    pytest.param(
        protect.list_protect_events,
        {"host": _HOST, "start": 1700000000, "end": 1700000100},
        "limit",
        True,
        id="events",
    ),
    pytest.param(
        protect_recognition_search._search_detections,
        {"host": _HOST, "search_text": "person"},
        "limit",
        True,
        id="detections",
    ),
    pytest.param(site_manager.list_devices, {"host": _HOST}, "page_size", False, id="host-devices"),
    pytest.param(
        network_controller_insights.get_sites_overview,
        {"host": _HOST},
        "page_size",
        False,
        id="overview",
    ),
    pytest.param(
        network_vpn_dns.query_teleport_invitations,
        {"host": _HOST, "site": _SITE},
        "page_size",
        False,
        id="teleport",
    ),
]


@pytest.mark.parametrize("entry,arguments,count_name,has_offset", _CASES)
@pytest.mark.parametrize("value", [0, -1, False, True, 1.5, "1"])
async def test_invalid_requested_count_makes_no_calls(
    entry, arguments, count_name, has_offset, value
):
    client, registry = AsyncMock(), AsyncMock()
    with pytest.raises(ValueError) as error:
        await entry(client, registry, **{**arguments, count_name: value})
    # PAGING-VALIDATION-A1 rule 3: the message names the argument the caller passed.
    assert str(error.value) == (
        f"{count_name} must be a positive integer (1 or more); got {value}. "
        f"Omit {count_name} to read the whole collection."
    )
    assert client.mock_calls == []
    assert registry.mock_calls == []


@pytest.mark.parametrize(
    "entry,arguments,count_name,has_offset", [case for case in _CASES if case.values[3]]
)
@pytest.mark.parametrize("value", [-1, False, True, 1.5, "1"])
async def test_invalid_offset_makes_no_calls(entry, arguments, count_name, has_offset, value):
    client, registry = AsyncMock(), AsyncMock()
    with pytest.raises(ValueError) as error:
        await entry(client, registry, **{**arguments, count_name: 1, "offset": value})
    assert str(error.value) == f"offset must be 0 or more; got {value}."
    assert client.mock_calls == []
    assert registry.mock_calls == []


def _upstream():
    body = {
        "data": [],
        "totalCount": 0,
        "total_page_count": 0,
        "total_element_count": 0,
        "page_number": 0,
        "meta": {"rc": "ok"},
    }
    client = UniFiClient(Settings(api_key="synthetic-early-pagination"))
    client.get = AsyncMock(return_value=body)
    client.post = AsyncMock(return_value=body)
    registry = SimpleNamespace(
        resolve_key_for_host=AsyncMock(return_value=None),
        resolve_host_id=AsyncMock(return_value=_UUID),
        resolve_site_id=AsyncMock(return_value=_UUID),
        resolve_site_slug=AsyncMock(return_value="default"),
    )
    return client, registry


@pytest.mark.parametrize("entry,arguments,count_name,has_offset", _CASES)
@pytest.mark.parametrize("value", [1, 275, 10**30])
async def test_valid_requested_count_reaches_upstream(
    entry, arguments, count_name, has_offset, value
):
    client, registry = _upstream()
    kwargs = {**arguments, count_name: value}
    if has_offset:
        kwargs["offset"] = 0
    await entry(client, registry, **kwargs)
    assert registry.resolve_key_for_host.await_count == 1
    assert registry.resolve_host_id.await_count == 1
    assert client.get.await_count + client.post.await_count >= 1


@pytest.mark.parametrize(
    "entry,arguments",
    [
        pytest.param(
            network_controller_insights.get_sites_overview,
            {"host": _HOST, "page": 0},
            id="overview",
        ),
        pytest.param(
            network_vpn_dns.query_teleport_invitations,
            {"host": _HOST, "site": _SITE, "page_number": 0},
            id="teleport",
        ),
    ],
)
async def test_native_zero_based_page_still_reaches_upstream(entry, arguments):
    client, registry = _upstream()
    await entry(client, registry, **arguments)
    client.post.assert_awaited_once()
    assert client.post.call_args.kwargs["json"] == {"pageNumber": 0}
