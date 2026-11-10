"""Legacy query compatibility and exact upstream-error propagation, with no network."""

from unittest.mock import AsyncMock

import pytest
from fastmcp import FastMCP

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.families.network import (
    network_clients_guests as clients,
)
from unifi_fabric.families.network import (
    network_controller_insights as controller,
)
from unifi_fabric.families.network import (
    network_nat_qos_traffic as traffic,
)
from unifi_fabric.families.network import (
    network_wifi_radio as wifi,
)
from unifi_fabric.families.protect import (
    protect_device_lifecycle as lifecycle,
)
from unifi_fabric.families.protect import (
    protect_recognition_search as recognition,
)

CASES = [
    (controller, "get_controller_stats", controller.get_controller_stats, {"host": "h"}, None),
    (
        controller,
        "get_controller_stats",
        controller.get_controller_stats,
        {"host": "h", "schema": "s", "period": "DAY", "start": 1},
        {"schema": "s", "period": "DAY", "start": 1000},
    ),
    *[
        (
            clients,
            "get_client_observability",
            clients.get_client_observability,
            {"host": "h", "site": "s", "client": "00:00:5e:00:53:01", "view": view, **window},
            {k: v * 1000 for k, v in window.items()} or None,
        )
        for view in ("logs-all", "timeline", "timestamps")
        for window in ({}, {"start": 1}, {"end": 2})
    ],
    *[
        (
            traffic,
            "get_traffic_stats",
            traffic.get_traffic_stats,
            {"host": "h", "site": "s", "params": p},
            p,
        )
        for p in (
            None,
            {},
            {"start": [1], "end": {"x": 2}, "includeUnidentified": "future", "private": True},
        )
    ],
    *[
        (traffic, "get_poe_info", traffic.get_poe_info, {"host": "h", "site": "s", "params": p}, p)
        for p in (None, {}, {"mac": ["future"], "private": True})
    ],
    *[
        (
            traffic,
            "get_latest_traffic_flow_stats",
            traffic.get_latest_traffic_flow_stats,
            {"host": "h", "site": "s", "period": p},
            {"period": p} if p is not None else None,
        )
        for p in ("day", "future", None)
    ],
    *[
        (
            wifi,
            "get_wifi_quick_scan_status",
            wifi.get_wifi_quick_scan_status,
            {"host": "h", "site": "s", "radio_band": p},
            {"band": p} if p else None,
        )
        for p in (None, "", "future")
    ],
    (
        lifecycle,
        "get_sensor_readings",
        lifecycle.get_sensor_readings,
        {"host": "h", "sensor_id": "abc"},
        None,
    ),
    *[
        (
            recognition,
            "get_detection_statistics",
            recognition._get_detection_statistics,
            {"host": "h", "period": p},
            {"period": p} if p is not None else None,
        )
        for p in (None, "day", "900")
    ],
]


@pytest.mark.parametrize("module,name,helper,arguments,expected", CASES)
@pytest.mark.parametrize("registered", [False, True])
async def test_legacy_inputs_reach_upstream_once_and_preserve_error(
    module, name, helper, arguments, expected, registered
):
    cause = RuntimeError("synthetic upstream cause")
    error = UniFiConnectionError("synthetic upstream 400", status=400)
    error.__cause__ = cause
    client = AsyncMock()
    client.get.side_effect = error
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "h-id"
    registry.resolve_site_slug.return_value = "site-id"
    if registered:
        mcp = FastMCP("compat")
        module.register(mcp, lambda: (client, registry))
        tool = {t.name: t for t in await mcp.list_tools()}[name]
        call = tool.fn(**arguments)
    else:
        direct_args = dict(arguments)
        if module is clients:
            direct_args["client_ref"] = direct_args.pop("client")
        call = helper(client, registry, **direct_args)
    with pytest.raises(UniFiConnectionError) as info:
        await call
    assert info.value is error
    assert info.value.status == 400
    assert info.value.__cause__ is cause
    client.get.assert_awaited_once()
    assert client.get.await_args.kwargs.get("params") == expected


@pytest.mark.parametrize(
    "module,name,helper,arguments,expected",
    [
        (
            controller,
            "get_controller_stats",
            controller.get_controller_stats,
            {"host": "h", "schema": "s", "period": "DAY", "start": 1},
            {"schema": "s", "period": "DAY", "start": 1000},
        ),
        (
            lifecycle,
            "get_sensor_readings",
            lifecycle.get_sensor_readings,
            {"host": "h", "sensor_id": "abc"},
            None,
        ),
        (
            recognition,
            "get_detection_statistics",
            recognition._get_detection_statistics,
            {"host": "h", "period": "day"},
            {"period": "day"},
        ),
        (
            recognition,
            "get_detection_statistics",
            recognition._get_detection_statistics,
            {"host": "h"},
            None,
        ),
        (
            clients,
            "get_client_observability",
            clients.get_client_observability,
            {"host": "h", "site": "s", "client": "00:00:5e:00:53:01", "view": "logs-all"},
            None,
        ),
    ],
)
@pytest.mark.parametrize("registered", [False, True])
async def test_legacy_success_preserves_body_and_query(
    module, name, helper, arguments, expected, registered
):
    body = {"data": [], "total_page_count": 1}
    client = AsyncMock()
    client.get.return_value = body
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "h-id"
    registry.resolve_site_slug.return_value = "site-id"
    if registered:
        mcp = FastMCP("compat-success")
        module.register(mcp, lambda: (client, registry))
        result = await {t.name: t for t in await mcp.list_tools()}[name].fn(**arguments)
    else:
        direct_args = dict(arguments)
        if module is clients:
            direct_args["client_ref"] = direct_args.pop("client")
        result = await helper(client, registry, **direct_args)
    assert result == body
    client.get.assert_awaited_once()
    assert client.get.await_args.kwargs.get("params") == expected
