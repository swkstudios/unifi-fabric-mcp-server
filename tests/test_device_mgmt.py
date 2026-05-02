"""Tests for device management tools via connector proxy."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.device_mgmt import (
    _adopt_device as adopt_device,
)
from unifi_fabric.tools.device_mgmt import (
    _approve_pending_device as approve_pending_device,
)
from unifi_fabric.tools.device_mgmt import (
    _create_device_tag as create_device_tag,
)
from unifi_fabric.tools.device_mgmt import (
    _delete_device_tag as delete_device_tag,
)
from unifi_fabric.tools.device_mgmt import (
    _execute_device_action as execute_device_action,
)
from unifi_fabric.tools.device_mgmt import (
    _execute_port_action as execute_port_action,
)
from unifi_fabric.tools.device_mgmt import (
    _get_device as get_device,
)
from unifi_fabric.tools.device_mgmt import (
    _get_device_statistics as get_device_statistics,
)
from unifi_fabric.tools.device_mgmt import (
    _list_pending_devices as list_pending_devices,
)
from unifi_fabric.tools.device_mgmt import (
    _list_site_devices as list_site_devices,
)
from unifi_fabric.tools.device_mgmt import (
    _locate_device as locate_device,
)
from unifi_fabric.tools.device_mgmt import _mac_uuid_cache
from unifi_fabric.tools.device_mgmt import (
    _reject_pending_device as reject_pending_device,
)
from unifi_fabric.tools.device_mgmt import (
    _restart_device as restart_device,
)
from unifi_fabric.tools.device_mgmt import (
    _unadopt_device as unadopt_device,
)
from unifi_fabric.tools.device_mgmt import (
    _update_device_tag as update_device_tag,
)
from unifi_fabric.tools.device_mgmt import (
    _upgrade_device as upgrade_device,
)
from unifi_fabric.tools.network import PROXY_BASE

HOST_ID = "host-001"
SITE_ID = "11111111-0000-0000-0000-000000000001"
BASE = PROXY_BASE.format(host_id=HOST_ID)


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    return r


class TestListSiteDevices:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"id": "dev-1", "model": "USW-24"}]
        result = await list_site_devices(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/devices")
        assert result == [{"id": "dev-1", "model": "USW-24"}]


class TestAdoptDevice:
    async def test_basic(self, client, registry):
        payload = {"mac": "aa:bb:cc:dd:ee:ff"}
        client.post.return_value = {"id": "dev-2", **payload}
        result = await adopt_device(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/devices", json=payload)
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"


class TestGetDevice:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "dev-1", "model": "USW-24"}
        result = await get_device(client, registry, "h", "s", "dev-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/devices/dev-1")
        assert result["id"] == "dev-1"

    async def test_mac_bare_resolves_to_uuid(self, client, registry):
        """Uppercase bare 12-hex MAC matches device returned with macAddress field."""
        _mac_uuid_cache.clear()
        uuid = "aaaaaaaa-0000-0000-0000-000000000001"
        device_list = [{"id": uuid, "macAddress": "de:ad:be:ef:c5:01", "model": "U6-Pro"}]
        device_detail = {"id": uuid, "model": "U6-Pro"}
        client.get.side_effect = [device_list, device_detail]

        result = await get_device(client, registry, "h", "s", "DEADBEEFC501")
        assert result["id"] == uuid
        calls = client.get.call_args_list
        assert calls[0][0][0] == f"{BASE}/sites/{SITE_ID}/devices"
        assert calls[1][0][0] == f"{BASE}/sites/{SITE_ID}/devices/{uuid}"

    async def test_mac_colon_resolves_to_uuid(self, client, registry):
        """Lowercase colon-separated MAC matches device returned with macAddress field."""
        _mac_uuid_cache.clear()
        uuid = "bbbbbbbb-0000-0000-0000-000000000002"
        device_list = [{"id": uuid, "macAddress": "de:ad:be:ef:c5:01", "model": "U6-Pro"}]
        device_detail = {"id": uuid, "model": "U6-Pro"}
        client.get.side_effect = [device_list, device_detail]

        result = await get_device(client, registry, "h", "s", "de:ad:be:ef:c5:01")
        assert result["id"] == uuid

    async def test_mac_dashes_mixed_case_resolves_to_uuid(self, client, registry):
        """Mixed-case dash-separated MAC matches device returned with macAddress field."""
        _mac_uuid_cache.clear()
        uuid = "eeeeeeee-0000-0000-0000-000000000005"
        device_list = [{"id": uuid, "macAddress": "de:ad:be:ef:c5:01", "model": "U6-Pro"}]
        device_detail = {"id": uuid, "model": "U6-Pro"}
        client.get.side_effect = [device_list, device_detail]

        result = await get_device(client, registry, "h", "s", "DE-AD-BE-EF-C5-01")
        assert result["id"] == uuid

    async def test_mac_cached(self, client, registry):
        """Second call with the same MAC skips the device list fetch."""
        _mac_uuid_cache.clear()
        uuid = "cccccccc-0000-0000-0000-000000000003"
        device_list = [{"id": uuid, "macAddress": "de:ad:be:ef:00:01"}]
        device_detail = {"id": uuid}
        client.get.side_effect = [device_list, device_detail, device_detail]

        await get_device(client, registry, "h", "s", "DEADBEEF0001")
        client.get.reset_mock()
        client.get.return_value = device_detail

        result = await get_device(client, registry, "h", "s", "DEADBEEF0001")
        assert result["id"] == uuid
        # Only one call (the device detail) — device list was skipped via cache
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/devices/{uuid}")


class TestUnadoptDevice:
    async def test_basic(self, client, registry):
        await unadopt_device(client, registry, "h", "s", "dev-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/devices/dev-1")


class TestExecuteDeviceAction:
    async def test_restart(self, client, registry):
        action = {"action": "restart"}
        client.post.return_value = {"status": "ok"}
        result = await execute_device_action(client, registry, "h", "s", "dev-1", action)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/actions", json=action
        )
        assert result["status"] == "ok"


class TestGetDeviceStatistics:
    async def test_basic(self, client, registry):
        client.get.return_value = {"cpu": 12, "mem": 45}
        result = await get_device_statistics(client, registry, "h", "s", "dev-1")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/statistics/latest"
        )
        assert result["cpu"] == 12

    async def test_mac_resolves_to_uuid(self, client, registry):
        """A bare MAC passed to get_device_statistics is resolved via device list."""
        _mac_uuid_cache.clear()
        uuid = "dddddddd-0000-0000-0000-000000000004"
        device_list = [{"id": uuid, "macAddress": "aa:bb:cc:dd:ee:ff"}]
        stats = {"cpu": 5, "mem": 20}
        client.get.side_effect = [device_list, stats]

        result = await get_device_statistics(client, registry, "h", "s", "AABBCCDDEEFF")
        assert result["cpu"] == 5
        calls = client.get.call_args_list
        assert calls[0][0][0] == f"{BASE}/sites/{SITE_ID}/devices"
        assert calls[1][0][0] == f"{BASE}/sites/{SITE_ID}/devices/{uuid}/statistics/latest"


class TestExecutePortAction:
    async def test_basic(self, client, registry):
        action = {"action": "power_cycle"}
        client.post.return_value = {"status": "ok"}
        result = await execute_port_action(client, registry, "h", "s", "dev-1", 3, action)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/interfaces/ports/3/actions",
            json=action,
        )
        assert result["status"] == "ok"


class TestRestartDevice:
    async def test_basic(self, client, registry):
        client.post.return_value = {"status": "ok"}
        result = await restart_device(client, registry, "h", "s", "dev-1")
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/actions", json={"action": "restart"}
        )
        assert result["status"] == "ok"


class TestLocateDevice:
    async def test_enable(self, client, registry):
        client.post.return_value = {"status": "ok"}
        result = await locate_device(client, registry, "h", "s", "dev-1")
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/actions",
            json={"action": "locate", "enabled": True},
        )
        assert result["status"] == "ok"

    async def test_disable(self, client, registry):
        client.post.return_value = {"status": "ok"}
        await locate_device(client, registry, "h", "s", "dev-1", enabled=False)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/actions",
            json={"action": "locate", "enabled": False},
        )


class TestUpgradeDevice:
    async def test_basic(self, client, registry):
        client.post.return_value = {"status": "ok"}
        result = await upgrade_device(client, registry, "h", "s", "dev-1")
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/actions", json={"action": "upgrade"}
        )
        assert result["status"] == "ok"


class TestListPendingDevices:
    async def test_basic(self, client, registry):
        client.get.return_value = [{"mac": "aa:bb:cc:dd:ee:ff"}]
        result = await list_pending_devices(client, registry, "h")
        client.get.assert_called_once_with(f"{BASE}/pending-devices")
        assert len(result) == 1


class TestCreateDeviceTag:
    async def test_basic(self, client, registry):
        tag = {"name": "AP-Floor1", "color": "blue"}
        client.post.return_value = {"id": "tag-1", **tag}
        result = await create_device_tag(client, registry, "h", "s", tag)
        client.post.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/device-tags", json=tag)
        assert result["name"] == "AP-Floor1"


class TestUpdateDeviceTag:
    async def test_basic(self, client, registry):
        tag = {"name": "AP-Floor2"}
        client.put.return_value = {"id": "tag-1", **tag}
        result = await update_device_tag(client, registry, "h", "s", "tag-1", tag)
        client.put.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/device-tags/tag-1", json=tag)
        assert result["name"] == "AP-Floor2"


class TestDeleteDeviceTag:
    async def test_basic(self, client, registry):
        client.delete.return_value = None
        result = await delete_device_tag(client, registry, "h", "s", "tag-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/device-tags/tag-1")
        assert result == {"deleted": True, "tagId": "tag-1"}


class TestApprovePendingDevice:
    async def test_basic(self, client, registry):
        client.post.return_value = {"status": "ok"}
        result = await approve_pending_device(client, registry, "h", "s", "dev-1")
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/actions", json={"action": "approve"}
        )
        assert result["status"] == "ok"


class TestRejectPendingDevice:
    async def test_basic(self, client, registry):
        client.post.return_value = {"status": "ok"}
        result = await reject_pending_device(client, registry, "h", "s", "dev-1")
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/actions", json={"action": "reject"}
        )
        assert result["status"] == "ok"
