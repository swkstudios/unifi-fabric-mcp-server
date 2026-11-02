"""Tests for device management tools via connector proxy."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
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
    _forget_device as forget_device,
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
    c.paginate_max_pages = None
    c.post = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    r.resolve_site_slug = AsyncMock(return_value="default")
    return r


class TestListSiteDevices:
    async def test_drains_all_by_default(self, client, registry):
        rows = [{"id": "dev-1", "model": "USW-24"}, {"id": "dev-2"}]
        client.get.side_effect = [rows, []]
        result = await list_site_devices(client, registry, "h", "s")
        assert all(
            request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            for request in client.get.call_args_list
        )
        assert client.get.call_count == 2
        assert result == {
            "data": [{"id": "dev-1", "model": "USW-24"}, {"id": "dev-2"}],
            "totalCount": None,  # upstream sent no totalCount: never invented
        }

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 2]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result

    async def test_explicit_offset_and_limit_single_page(self, client, registry):
        rows = [{"id": "dev-9"}] + [{"id": f"dev-{index}"} for index in range(10, 19)]
        client.get.return_value = {"data": rows, "totalCount": 30}
        result = await list_site_devices(client, registry, "h", "s", offset=10, limit=10)
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices", key=None, params={"offset": 10, "limit": 10}
        )
        client.paginate_offset.assert_not_called()
        assert result == {
            "data": rows,
            "totalCount": 30,
            "_pageSize": {"requested": 10, "sent": [10], "effective": 10, "returned": 10},
        }

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        rows = [{"id": "dev-1"}] + [
            dict({"id": "dev-1"}, id=f"extra-{index}") for index in range(1, 3)
        ]
        client.paginate_max_pages = 3
        client.get.side_effect = [{"data": [row], "limit": 1} for row in rows]
        result = await list_site_devices(client, registry, "h", "s")
        assert result["incomplete"] is True
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == list(
            range(3)
        )

    async def test_filter_drains_with_exact_param(self, client, registry):
        client.get.return_value = []
        await list_site_devices(client, registry, "h", "s", filter="state.eq('ONLINE')")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices",
            key=None,
            params={"filter": "state.eq('ONLINE')", "offset": 0, "limit": 200},
        )

    async def test_filter_manual_page_exact_param(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 0}
        await list_site_devices(
            client, registry, "h", "s", offset=10, limit=10, filter="model.eq('U7PG2')"
        )
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices",
            key=None,
            params={"filter": "model.eq('U7PG2')", "offset": 10, "limit": 10},
        )
        client.paginate_offset.assert_not_called()

    async def test_filter_none_omits_param_not_string(self, client, registry):
        client.get.return_value = []
        await list_site_devices(client, registry, "h", "s", filter=None)
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices", key=None, params={"offset": 0, "limit": 200}
        )

    async def test_filter_threads_owning_key(self, client, registry):
        sentinel = object()
        registry.resolve_key_for_host.return_value = sentinel
        client.get.return_value = []
        await list_site_devices(client, registry, "h", "s", filter="state.eq('ONLINE')")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices",
            key=sentinel,
            params={"filter": "state.eq('ONLINE')", "offset": 0, "limit": 200},
        )


class TestAdoptDevice:
    async def test_basic(self, client, registry):
        payload = {"mac": "aa:bb:cc:dd:ee:ff"}
        client.post.return_value = {"id": "dev-2", **payload}
        result = await adopt_device(client, registry, "h", "s", payload)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices", json=payload, key=None
        )
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"


class TestGetDevice:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "dev-1", "model": "USW-24"}
        result = await get_device(client, registry, "h", "s", "dev-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/devices/dev-1", key=None)
        assert result["id"] == "dev-1"

    async def test_mac_bare_resolves_to_uuid(self, client, registry):
        """Uppercase bare 12-hex MAC matches device returned with macAddress field."""
        _mac_uuid_cache.clear()
        uuid = "aaaaaaaa-0000-0000-0000-000000000001"
        device_list = [{"id": uuid, "macAddress": "de:ad:be:ef:c5:01", "model": "U6-Pro"}]
        device_detail = {"id": uuid, "model": "U6-Pro"}
        client.get.side_effect = [device_list, [], device_detail]

        result = await get_device(client, registry, "h", "s", "DEADBEEFC501")
        assert result["id"] == uuid
        calls = client.get.call_args_list
        assert calls[0].args[0] == f"{BASE}/sites/{SITE_ID}/devices"
        assert calls[0].kwargs == {"key": None, "params": {"offset": 0, "limit": 200}}
        assert calls[2][0][0] == f"{BASE}/sites/{SITE_ID}/devices/{uuid}"

        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_mac_colon_resolves_to_uuid(self, client, registry):
        """Lowercase colon-separated MAC matches device returned with macAddress field."""
        _mac_uuid_cache.clear()
        uuid = "bbbbbbbb-0000-0000-0000-000000000002"
        device_list = [{"id": uuid, "macAddress": "de:ad:be:ef:c5:01", "model": "U6-Pro"}]
        device_detail = {"id": uuid, "model": "U6-Pro"}
        client.get.side_effect = [device_list, [], device_detail]

        result = await get_device(client, registry, "h", "s", "de:ad:be:ef:c5:01")
        assert result["id"] == uuid

        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_mac_dashes_mixed_case_resolves_to_uuid(self, client, registry):
        """Mixed-case dash-separated MAC matches device returned with macAddress field."""
        _mac_uuid_cache.clear()
        uuid = "eeeeeeee-0000-0000-0000-000000000005"
        device_list = [{"id": uuid, "macAddress": "de:ad:be:ef:c5:01", "model": "U6-Pro"}]
        device_detail = {"id": uuid, "model": "U6-Pro"}
        client.get.side_effect = [device_list, [], device_detail]

        result = await get_device(client, registry, "h", "s", "DE-AD-BE-EF-C5-01")
        assert result["id"] == uuid

        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_mac_cached(self, client, registry):
        """Second call with the same MAC skips the device list fetch."""
        _mac_uuid_cache.clear()
        uuid = "cccccccc-0000-0000-0000-000000000003"
        device_list = [{"id": uuid, "macAddress": "de:ad:be:ef:00:01"}]
        device_detail = {"id": uuid}
        client.get.side_effect = [device_list, [], device_detail, device_detail]

        await get_device(client, registry, "h", "s", "DEADBEEF0001")
        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        client.get.reset_mock()
        client.get.return_value = device_detail

        result = await get_device(client, registry, "h", "s", "DEADBEEF0001")
        assert result["id"] == uuid
        # Only one call (the device detail) — device list was skipped via cache
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/devices/{uuid}", key=None)


class TestResolveDeviceIdErrors:
    """A MAC that matches no device lists every valid device; a partial drain fails
    with its reason instead of a false "not found"."""

    async def test_unknown_mac_lists_every_device(self, client, registry):
        _mac_uuid_cache.clear()
        rows = [
            {"id": "uuid-1", "name": "AP-1", "macAddress": "aa:bb:cc:00:00:01"},
            {"id": "uuid-2", "name": "SW-1", "macAddress": "aa:bb:cc:00:00:02"},
        ]
        client.get.side_effect = [rows, []]
        with pytest.raises(ValueError) as exc:
            await get_device(client, registry, "h", "s", "aa:bb:cc:00:00:ff")
        msg = str(exc.value)
        assert "not found" in msg
        assert "AP-1 (mac=aa:bb:cc:00:00:01, id=uuid-1)" in msg
        assert "SW-1 (mac=aa:bb:cc:00:00:02, id=uuid-2)" in msg
        assert all(
            request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            for request in client.get.call_args_list
        )

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 2]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_partial_drain_reports_incomplete_not_not_found(self, client, registry):
        _mac_uuid_cache.clear()
        rows = [{"id": "uuid-1", "name": "AP-1", "macAddress": "aa:bb:cc:00:00:01"}] + [
            dict(
                {"id": "uuid-1", "name": "AP-1", "macAddress": "aa:bb:cc:00:00:01"},
                id=f"extra-{index}",
            )
            for index in range(1, 3)
        ]
        client.paginate_max_pages = 3
        client.get.side_effect = [{"data": [row], "limit": 1} for row in rows]
        with pytest.raises(ValueError) as exc:
            await get_device(client, registry, "h", "s", "aa:bb:cc:00:00:ff")
        msg = str(exc.value)
        assert "incomplete" in msg and "page cap of 3 reached" in msg
        assert "not found" not in msg
        assert "AP-1" in msg
        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == list(
            range(3)
        )


class TestMacCacheInvalidation:
    """The MAC -> id cache never addresses a device by an id it no longer has.

    Unadopt, forget and adopt drop the cached entry (a re-adopted device gets a new id);
    a cached id answering HTTP 404 is re-resolved once from the device list. A read is
    then repeated at the fresh id; a write is never re-sent.
    """

    MAC = "de:ad:be:ef:00:0a"
    OLD = "aaaaaaaa-0000-4000-8000-00000000000a"
    NEW = "bbbbbbbb-0000-4000-8000-00000000000b"

    def _cache_old_id(self, client):
        _mac_uuid_cache.clear()
        client.get.return_value = [{"id": self.OLD, "macAddress": self.MAC}]

    async def _prime(self, client, registry):
        self._cache_old_id(client)
        client.get.side_effect = [client.get.return_value, [], {"id": self.OLD}]
        await get_device(client, registry, "h", "s", self.MAC)
        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert _mac_uuid_cache[client]  # the old id is cached
        # the device is re-adopted: the list now carries the new id
        new_list = [{"id": self.NEW, "macAddress": self.MAC}]
        client.get.side_effect = [new_list, []]
        client.get.reset_mock()

    def _action_path(self, uuid):
        return f"{BASE}/sites/{SITE_ID}/devices/{uuid}/actions"

    async def test_unadopt_drops_the_cached_id(self, client, registry):
        await self._prime(client, registry)
        await unadopt_device(client, registry, "h", "s", self.MAC)
        client.delete.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/{self.OLD}", key=None
        )
        await execute_device_action(client, registry, "h", "s", self.MAC, {"action": "RESTART"})
        assert client.post.call_args.args[0] == self._action_path(self.NEW)

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_unadopt_by_uuid_drops_the_cached_id(self, client, registry):
        await self._prime(client, registry)
        await unadopt_device(client, registry, "h", "s", self.OLD)
        await execute_device_action(client, registry, "h", "s", self.MAC, {"action": "RESTART"})
        assert client.post.call_args.args[0] == self._action_path(self.NEW)

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_forget_drops_the_cached_id(self, client, registry):
        await self._prime(client, registry)
        client.post.return_value = {"meta": {"rc": "ok"}, "data": []}
        await forget_device(client, registry, "h", "s", self.MAC.upper())
        client.post.reset_mock()
        await execute_device_action(client, registry, "h", "s", self.MAC, {"action": "RESTART"})
        assert client.post.call_args.args[0] == self._action_path(self.NEW)

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_failed_forget_still_drops_the_cached_id(self, client, registry):
        """A 429 does not prove the controller did not act: the entry goes either way."""
        await self._prime(client, registry)
        client.post.side_effect = UniFiConnectionError("HTTP 500 from POST sitemgr: {}")
        with pytest.raises(UniFiConnectionError):
            await forget_device(client, registry, "h", "s", self.MAC)
        assert not _mac_uuid_cache[client]

    async def test_approve_pending_drops_the_cached_id(self, client, registry):
        await self._prime(client, registry)
        await approve_pending_device(client, registry, "h", "s", self.MAC, False)
        client.post.reset_mock()
        await execute_device_action(client, registry, "h", "s", self.MAC, {"action": "RESTART"})
        assert client.post.call_args.args[0] == self._action_path(self.NEW)

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_adopt_drops_the_cached_id(self, client, registry):
        await self._prime(client, registry)
        await adopt_device(client, registry, "h", "s", {"macAddress": self.MAC.upper()})
        assert not _mac_uuid_cache[client]

    async def test_cached_id_404_on_a_read_re_resolves_once(self, client, registry):
        await self._prime(client, registry)
        gone = UniFiConnectionError(f"HTTP 404 from GET devices/{self.OLD}: not found")
        client.get.reset_mock()
        client.get.side_effect = [
            gone,
            [{"id": self.NEW, "macAddress": self.MAC}],
            [],
            {"id": self.NEW},
        ]
        result = await get_device(client, registry, "h", "s", self.MAC)
        assert result == {"id": self.NEW}
        assert [c.args[0] for c in client.get.call_args_list] == [
            f"{BASE}/sites/{SITE_ID}/devices/{self.OLD}",
            f"{BASE}/sites/{SITE_ID}/devices",
            f"{BASE}/sites/{SITE_ID}/devices",
            f"{BASE}/sites/{SITE_ID}/devices/{self.NEW}",
        ]
        assert client.get.call_args_list[1].kwargs == {
            "key": None,
            "params": {"offset": 0, "limit": 200},
        }  # first page of the collection refresh

        assert client.get.call_count == 4
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[1:3]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[1:3]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_cached_id_404_on_a_write_is_never_re_sent(self, client, registry):
        await self._prime(client, registry)
        client.post.side_effect = UniFiConnectionError(
            f"HTTP 404 from POST devices/{self.OLD}/actions: not found"
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await execute_device_action(client, registry, "h", "s", self.MAC, {"action": "RESTART"})
        client.post.assert_called_once()  # the write was sent once, at the cached id
        assert client.post.call_args.args[0] == self._action_path(self.OLD)
        msg = str(exc.value)
        assert self.OLD in msg and self.NEW in msg and "not re-sent" in msg
        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        # the cache now holds the fresh id: the caller's retry acts on the current device
        client.post.side_effect = None
        client.post.reset_mock()
        await execute_device_action(client, registry, "h", "s", self.MAC, {"action": "RESTART"})
        assert client.post.call_args.args[0] == self._action_path(self.NEW)

        client.post.assert_called_once_with(
            self._action_path(self.NEW), json={"action": "RESTART"}, key=None
        )
        assert client.get.call_count == 2

    async def test_404_on_an_uncached_id_is_raised_unchanged(self, client, registry):
        _mac_uuid_cache.clear()
        client.get.side_effect = UniFiConnectionError("HTTP 404 from GET devices/dev-9: gone")
        with pytest.raises(UniFiConnectionError, match="HTTP 404 from GET devices/dev-9"):
            await get_device(client, registry, "h", "s", "dev-9")
        client.get.assert_called_once()


class TestUnadoptDevice:
    async def test_basic(self, client, registry):
        await unadopt_device(client, registry, "h", "s", "dev-1")
        client.delete.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/devices/dev-1", key=None)


class TestExecuteDeviceAction:
    async def test_restart(self, client, registry):
        action = {"action": "restart"}
        client.post.return_value = {"status": "ok"}
        result = await execute_device_action(client, registry, "h", "s", "dev-1", action)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/actions", json=action, key=None
        )
        assert result["status"] == "ok"


class TestGetDeviceStatistics:
    async def test_basic(self, client, registry):
        client.get.return_value = {"cpu": 12, "mem": 45}
        result = await get_device_statistics(client, registry, "h", "s", "dev-1")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/statistics/latest", key=None
        )
        assert result["cpu"] == 12

    async def test_mac_resolves_to_uuid(self, client, registry):
        """A bare MAC passed to get_device_statistics is resolved via device list."""
        _mac_uuid_cache.clear()
        uuid = "dddddddd-0000-0000-0000-000000000004"
        device_list = [{"id": uuid, "macAddress": "aa:bb:cc:dd:ee:ff"}]
        stats = {"cpu": 5, "mem": 20}
        client.get.side_effect = [device_list, [], stats]

        result = await get_device_statistics(client, registry, "h", "s", "AABBCCDDEEFF")
        assert result["cpu"] == 5
        calls = client.get.call_args_list
        assert calls[0].args[0] == f"{BASE}/sites/{SITE_ID}/devices"
        assert calls[0].kwargs == {"key": None, "params": {"offset": 0, "limit": 200}}
        assert calls[2][0][0] == f"{BASE}/sites/{SITE_ID}/devices/{uuid}/statistics/latest"

        assert client.get.call_count == 3
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list[0:2]] == [
            0,
            1,
        ]
        for request in client.get.call_args_list[0:2]:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }


class TestExecutePortAction:
    async def test_basic(self, client, registry):
        action = {"action": "power_cycle"}
        client.post.return_value = {"status": "ok"}
        result = await execute_port_action(client, registry, "h", "s", "dev-1", 3, action)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/interfaces/ports/3/actions",
            json=action,
            key=None,
        )
        assert result["status"] == "ok"


class TestRestartDevice:
    async def test_basic(self, client, registry):
        """The spec's (and the controller's) only device action value is RESTART."""
        client.post.return_value = {"status": "ok"}
        result = await restart_device(client, registry, "h", "s", "dev-1")
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices/dev-1/actions",
            json={"action": "RESTART"},
            key=None,
        )
        assert result["status"] == "ok"


# Classic device manager (locate / upgrade are not in the Integration action schema).
DEVMGR = f"/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/default/cmd/devmgr"
DEVMGR_OK = {"meta": {"rc": "ok"}, "data": []}  # recorded live answer to set-locate


@pytest.fixture()
def slug_registry(registry):
    registry.resolve_site_slug = AsyncMock(return_value="default")
    return registry


class TestLocateDevice:
    async def test_enable_resolves_uuid_to_mac_and_uses_classic_devmgr(self, client, slug_registry):
        client.get.return_value = {"id": "dev-1", "macAddress": "AA:BB:CC:DD:EE:01"}
        client.post.return_value = DEVMGR_OK
        result = await locate_device(client, slug_registry, "h", "s", "dev-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/devices/dev-1", key=None)
        client.post.assert_called_once_with(
            DEVMGR, key=None, json={"cmd": "set-locate", "mac": "aa:bb:cc:dd:ee:01"}
        )
        assert result == DEVMGR_OK  # Classic envelope verbatim

    async def test_disable_with_mac_checks_the_site_device_list(self, client, slug_registry):
        """A MAC is checked against the adopted devices first (no device GET by id)."""
        _mac_uuid_cache.clear()
        rows = [{"id": "dev-1", "macAddress": "AA:BB:CC:DD:EE:01"}]
        client.get.side_effect = [rows, []]
        client.post.return_value = DEVMGR_OK
        await locate_device(client, slug_registry, "h", "s", "AABBCCDDEE01", enabled=False)
        assert all(
            request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            for request in client.get.call_args_list
        )
        client.post.assert_called_once_with(
            DEVMGR,
            key=None,
            json={"cmd": "unset-locate", "mac": "aa:bb:cc:dd:ee:01"},
        )

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_unknown_mac_lists_the_devices_and_sends_nothing(self, client, slug_registry):
        _mac_uuid_cache.clear()
        rows = [{"id": "dev-1", "macAddress": "aa:bb:cc:dd:ee:01"}]
        client.get.side_effect = [rows, []]
        with pytest.raises(ValueError, match="aa:bb:cc:dd:ee:01"):
            await locate_device(client, slug_registry, "h", "s", "aa:bb:cc:dd:ee:99")
        client.post.assert_not_called()

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/sites/{SITE_ID}/devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }

    async def test_device_without_mac_raises_with_shape(self, client, slug_registry):
        client.get.return_value = {"id": "dev-1"}
        with pytest.raises(UniFiConnectionError, match="macAddress"):
            await locate_device(client, slug_registry, "h", "s", "dev-1")
        client.post.assert_not_called()


class TestUpgradeDevice:
    async def test_basic(self, client, slug_registry):
        client.get.return_value = {"id": "dev-1", "macAddress": "aa:bb:cc:dd:ee:02"}
        client.post.return_value = DEVMGR_OK
        result = await upgrade_device(client, slug_registry, "h", "s", "dev-1")
        client.post.assert_called_once_with(
            DEVMGR, key=None, json={"cmd": "upgrade", "mac": "aa:bb:cc:dd:ee:02"}
        )
        assert result == DEVMGR_OK


class TestListPendingDevices:
    async def test_basic(self, client, registry):
        rows = [{"mac": "aa:bb:cc:dd:ee:ff"}]
        client.get.side_effect = [rows, []]
        result = await list_pending_devices(client, registry, "h")
        assert client.get.call_args.args[0] == f"{BASE}/pending-devices"
        assert result == {"data": [{"mac": "aa:bb:cc:dd:ee:ff"}], "totalCount": None}

        assert client.get.call_count == 2
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == [0, 1]
        for request in client.get.call_args_list:
            assert request.args == (f"{BASE}/pending-devices",)
            assert request.kwargs == {
                "key": None,
                "params": {"offset": request.kwargs["params"]["offset"], "limit": 200},
            }
        assert result["data"] == rows
        assert result["totalCount"] is None
        assert "incomplete" not in result
        assert "_incomplete" not in result


# Device tags are v2 records (the Integration device-tags collection is GET-only and, on
# Network 11.0.81, a different, empty collection). v2 list/create/update are site-scoped;
# the delete has no site segment.
V2 = f"/v1/connector/consoles/{HOST_ID}/proxy/network/v2/api"
V2_TAGS = [
    {"_id": "t-1", "name": "Cameras", "member_device_macs": ["aa:bb:cc:dd:ee:01"]},
    {"_id": "t-2", "name": "Uplinks", "member_device_macs": []},
    {"_id": "t-3", "name": "Dup", "member_device_macs": []},
    {"_id": "t-4", "name": "Dup", "member_device_macs": []},
]


class TestCreateDeviceTag:
    async def test_basic(self, client, registry):
        tag = {"name": "AP-Floor1", "member_device_macs": []}
        body = {"_id": "t-9", **tag}
        client.post.return_value = body
        result = await create_device_tag(client, registry, "h", "s", tag)
        client.post.assert_called_once_with(f"{V2}/site/default/device-tags", key=None, json=tag)
        assert result is body
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key=None)


class TestUpdateDeviceTag:
    async def test_by_id(self, client, registry):
        client.get.return_value = V2_TAGS
        tag = {"name": "AP-Floor2", "device_mac_additions": [], "device_mac_removals": []}
        client.put.return_value = {"_id": "t-2", "name": "AP-Floor2"}
        result = await update_device_tag(client, registry, "h", "s", "t-2", tag)
        client.get.assert_called_once_with(f"{V2}/site/default/device-tags", key=None)
        client.put.assert_called_once_with(f"{V2}/site/default/device-tags/t-2", key=None, json=tag)
        assert result == {"_id": "t-2", "name": "AP-Floor2"}

    async def test_by_exact_name(self, client, registry):
        client.get.return_value = V2_TAGS
        client.put.return_value = {}
        tag = {"device_mac_additions": ["aa:bb:cc:dd:ee:02"], "device_mac_removals": []}
        await update_device_tag(client, registry, "h", "s", "Cameras", tag)
        assert client.put.call_args[0][0] == f"{V2}/site/default/device-tags/t-1"

    async def test_unknown_tag_lists_every_tag(self, client, registry):
        client.get.return_value = V2_TAGS
        tag = {"device_mac_additions": [], "device_mac_removals": []}
        with pytest.raises(ValueError) as exc:
            await update_device_tag(client, registry, "h", "s", "nope", tag)
        assert "'Cameras' (_id=t-1)" in str(exc.value)
        client.put.assert_not_called()

    async def test_ambiguous_name_fails(self, client, registry):
        client.get.return_value = V2_TAGS
        tag = {"device_mac_additions": [], "device_mac_removals": []}
        with pytest.raises(ValueError, match="matches 2 tags"):
            await update_device_tag(client, registry, "h", "s", "Dup", tag)
        client.put.assert_not_called()

    async def test_edited_list_entry_becomes_the_native_body(self, client, registry):
        """A list_device_tags entry fed back (renamed, members edited) is translated: the
        v2 PUT rejects _id and member_device_macs with HTTP 400 "Unrecognized field"."""
        client.get.return_value = [
            {
                "_id": "t-1",
                "name": "Cameras",
                "member_device_macs": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
            }
        ]
        client.put.return_value = {"_id": "t-1"}
        entry = {
            "_id": "t-1",
            "name": "Outdoor",
            "member_device_macs": ["AA:BB:CC:DD:EE:02", "aa:bb:cc:dd:ee:03"],
        }
        await update_device_tag(client, registry, "h", "s", "t-1", entry)
        client.put.assert_called_once_with(
            f"{V2}/site/default/device-tags/t-1",
            key=None,
            json={
                "name": "Outdoor",
                "device_mac_additions": ["aa:bb:cc:dd:ee:03"],
                "device_mac_removals": ["aa:bb:cc:dd:ee:01"],
            },
        )

    @pytest.mark.parametrize(
        "spelled",
        [
            ["AA-BB-CC-DD-EE-01", "aa-bb-cc-dd-ee-03"],
            ["AABBCCDDEE01", "aabbccddee03"],
            ["aa:bb:cc:dd:ee:01", "AA:BB:CC:DD:EE:03"],
        ],
        ids=["hyphenated", "bare-hex", "colon"],
    )
    async def test_desired_macs_are_normalised_to_colon_form(self, client, registry, spelled):
        """Hyphenated or bare-hex members compare equal to the stored colon form: an
        unchanged member is neither re-added nor removed, and additions are sent in the
        controller's lowercase colon form."""
        client.get.return_value = [
            {
                "_id": "t-1",
                "name": "Cameras",
                "member_device_macs": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
            }
        ]
        client.put.return_value = {}
        entry = {"name": "Cameras", "member_device_macs": spelled}
        await update_device_tag(client, registry, "h", "s", "t-1", entry)
        assert client.put.call_args.kwargs["json"] == {
            "name": "Cameras",
            "device_mac_additions": ["aa:bb:cc:dd:ee:03"],
            "device_mac_removals": ["aa:bb:cc:dd:ee:02"],
        }

    async def test_unchanged_entry_sends_empty_deltas(self, client, registry):
        current = {"_id": "t-1", "name": "Cameras", "member_device_macs": ["aa:bb:cc:dd:ee:01"]}
        client.get.return_value = [current]
        client.put.return_value = {}
        await update_device_tag(client, registry, "h", "s", "Cameras", dict(current))
        assert client.put.call_args.kwargs["json"] == {
            "name": "Cameras",
            "device_mac_additions": [],
            "device_mac_removals": [],
        }

    async def test_unexpected_list_shape_raises(self, client, registry):
        client.get.return_value = {"data": V2_TAGS}
        tag = {"device_mac_additions": [], "device_mac_removals": []}
        with pytest.raises(UniFiConnectionError, match="expected a JSON array"):
            await update_device_tag(client, registry, "h", "s", "t-1", tag)


class TestDeleteDeviceTag:
    async def test_basic_uses_siteless_delete(self, client, registry):
        client.get.return_value = V2_TAGS
        client.delete.return_value = None
        result = await delete_device_tag(client, registry, "h", "s", "t-1")
        client.delete.assert_called_once_with(f"{V2}/device-tags/t-1", key=None)
        assert result == {"deleted": True, "message": "Device tag t-1 deleted.", "response": None}

    async def test_unknown_tag_is_never_reported_deleted(self, client, registry):
        # Live: the controller answers DELETE on an unknown id with HTTP 200.
        client.get.return_value = V2_TAGS
        with pytest.raises(ValueError, match="not found"):
            await delete_device_tag(client, registry, "h", "s", "missing")
        client.delete.assert_not_called()


class TestApprovePendingDevice:
    async def test_basic_uses_spec_adopt_route(self, client, registry):
        """Approve = the spec's adoptDevice (POST /sites/{id}/devices) with both
        required keys; pending devices are addressed by MAC (their schema has no id)."""
        client.post.return_value = {"id": "dev-9", "state": "ADOPTING"}
        result = await approve_pending_device(
            client, registry, "h", "s", "02-00-5E-00-00-A1", False
        )
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/devices",
            key=None,
            json={"macAddress": "02:00:5e:00:00:a1", "ignoreDeviceLimit": False},
        )
        assert result == {"id": "dev-9", "state": "ADOPTING"}

    async def test_ignore_device_limit_is_forwarded(self, client, registry):
        client.post.return_value = {}
        await approve_pending_device(
            client, registry, "h", "s", "02:00:5e:00:00:a1", ignore_device_limit=True
        )
        assert client.post.call_args.kwargs["json"]["ignoreDeviceLimit"] is True

    async def test_non_mac_id_fails_with_the_right_identifier(self, client, registry):
        with pytest.raises(ValueError, match="macAddress"):
            await approve_pending_device(client, registry, "h", "s", "dev-1", False)
        client.post.assert_not_called()


# Classic site manager: the controller UI's "Forget device" (sitemgr delete-device by MAC).
SITEMGR = f"/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/default/cmd/sitemgr"
UNKNOWN_DEVICE = '{"meta":{"rc":"error","msg":"api.err.UnknownDevice"},"data":[]}'


class TestForgetDevice:
    async def test_single_mac_sends_mac_and_returns_envelope_verbatim(self, client, slug_registry):
        client.post.return_value = DEVMGR_OK
        result = await forget_device(client, slug_registry, "h", "s", "AABBCCDDEE01")
        client.get.assert_not_called()  # pending devices have no id: MAC only, no lookup
        client.post.assert_called_once_with(
            SITEMGR,
            key=None,
            json={"cmd": "delete-device", "mac": "aa:bb:cc:dd:ee:01"},
        )
        assert result == DEVMGR_OK

    async def test_list_of_macs_sends_one_request_per_mac(self, client, slug_registry):
        """No live evidence the controller reads a multi-MAC ``macs`` body (2026-10-10 probe:
        two absent MACs answered exactly like the single form), so each MAC is its own
        proven single-MAC request; results are aggregated per MAC."""
        client.post.return_value = DEVMGR_OK
        result = await forget_device(
            client, slug_registry, "h", "s", ["AA:BB:CC:DD:EE:01", "aa-bb-cc-dd-ee-02"]
        )
        assert [c.kwargs["json"] for c in client.post.call_args_list] == [
            {"cmd": "delete-device", "mac": "aa:bb:cc:dd:ee:01"},
            {"cmd": "delete-device", "mac": "aa:bb:cc:dd:ee:02"},
        ]
        assert all(c.args == (SITEMGR,) for c in client.post.call_args_list)
        assert result == {
            "byMac": {"aa:bb:cc:dd:ee:01": DEVMGR_OK, "aa:bb:cc:dd:ee:02": DEVMGR_OK},
            "forgotten": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"],
            "errors": [],
        }
        assert all("macs" not in c.kwargs["json"] for c in client.post.call_args_list)

    async def test_duplicate_spellings_of_one_mac_send_one_request(self, client, slug_registry):
        client.post.return_value = DEVMGR_OK
        result = await forget_device(
            client, slug_registry, "h", "s", ["AA:BB:CC:DD:EE:01", "aabbccddee01"]
        )
        client.post.assert_called_once_with(
            SITEMGR,
            key=None,
            json={"cmd": "delete-device", "mac": "aa:bb:cc:dd:ee:01"},
        )
        # A list always returns the per-MAC shape, even when duplicates collapse to one.
        assert result == {
            "byMac": {"aa:bb:cc:dd:ee:01": DEVMGR_OK},
            "forgotten": ["aa:bb:cc:dd:ee:01"],
            "errors": [],
        }

    async def test_partial_failure_keeps_per_mac_errors(self, client, slug_registry):
        err = UniFiConnectionError(f"HTTP 400 from POST {SITEMGR}: {UNKNOWN_DEVICE}")
        client.post.side_effect = [DEVMGR_OK, err]
        result = await forget_device(
            client, slug_registry, "h", "s", ["aa:bb:cc:dd:ee:01", "02:de:ad:be:ef:02"]
        )
        assert result["byMac"] == {"aa:bb:cc:dd:ee:01": DEVMGR_OK}
        assert result["forgotten"] == ["aa:bb:cc:dd:ee:01"]
        assert result["errors"] == [{"mac": "02:de:ad:be:ef:02", "error": str(err)}]
        assert UNKNOWN_DEVICE in result["errors"][0]["error"]

    async def test_every_mac_failing_raises_with_each_error(self, client, slug_registry):
        client.post.side_effect = [
            UniFiConnectionError(f"HTTP 400 from POST {SITEMGR}: {UNKNOWN_DEVICE}"),
            UniFiConnectionError(f"HTTP 400 from POST {SITEMGR}: {UNKNOWN_DEVICE}"),
        ]
        with pytest.raises(UniFiConnectionError, match="every MAC failed") as exc:
            await forget_device(
                client, slug_registry, "h", "s", ["02:de:ad:be:ef:01", "02:de:ad:be:ef:02"]
            )
        msg = str(exc.value)
        assert "02:de:ad:be:ef:01" in msg and "02:de:ad:be:ef:02" in msg
        assert msg.count("api.err.UnknownDevice") == 2

    async def test_one_item_list_sends_mac(self, client, slug_registry):
        client.post.return_value = DEVMGR_OK
        await forget_device(client, slug_registry, "h", "s", ["aa:bb:cc:dd:ee:01"])
        assert client.post.call_args.kwargs["json"] == {
            "cmd": "delete-device",
            "mac": "aa:bb:cc:dd:ee:01",
        }

    async def test_threads_the_owning_key(self, client, slug_registry):
        owner = object()
        slug_registry.resolve_key_for_host = AsyncMock(return_value=owner)
        client.post.return_value = DEVMGR_OK
        await forget_device(client, slug_registry, "h", "s", "aa:bb:cc:dd:ee:01")
        assert client.post.call_args.kwargs["key"] is owner
        slug_registry.resolve_site_slug.assert_awaited_once_with("s", HOST_ID, key=owner)

    @pytest.mark.parametrize("bad", ["dev-1", ["aa:bb:cc:dd:ee:01", "not-a-mac"], []])
    async def test_non_mac_or_empty_fails_before_any_call(self, client, slug_registry, bad):
        with pytest.raises(ValueError, match="list_pending_devices"):
            await forget_device(client, slug_registry, "h", "s", bad)
        client.post.assert_not_called()
        slug_registry.resolve_host_id.assert_not_called()

    async def test_unknown_mac_surfaces_the_upstream_reason(self, client, slug_registry):
        client.post.side_effect = UniFiConnectionError(
            f"HTTP 400 from POST {SITEMGR}: {UNKNOWN_DEVICE}"
        )
        with pytest.raises(UniFiConnectionError, match="api.err.UnknownDevice") as exc:
            await forget_device(client, slug_registry, "h", "s", "02:de:ad:be:ef:01")
        assert UNKNOWN_DEVICE in str(exc.value)


@pytest.mark.parametrize("url", ["ftp://example.com/fw", "https:///fw", "relative.bin"])
async def test_upgrade_rejects_non_http_firmware_url_before_requests(client, slug_registry, url):
    with pytest.raises(ValueError, match="http"):
        await upgrade_device(client, slug_registry, "h", "s", "dev-1", url)
    client.get.assert_not_called()
    client.post.assert_not_called()


async def test_empty_firmware_url_uses_standard_upgrade(client, slug_registry):
    client.get.return_value = {"id": "dev-1", "macAddress": "aa:bb:cc:dd:ee:02"}
    client.post.return_value = DEVMGR_OK
    await upgrade_device(client, slug_registry, "h", "s", "dev-1", "")
    client.post.assert_called_once_with(
        DEVMGR, key=None, json={"cmd": "upgrade", "mac": "aa:bb:cc:dd:ee:02"}
    )


@pytest.mark.parametrize("url", ["http://example.com/fw.bin", "https://example.com/fw.bin"])
async def test_external_upgrade_preserves_valid_url(client, slug_registry, url):
    client.get.return_value = {"id": "dev-1", "macAddress": "aa:bb:cc:dd:ee:02"}
    client.post.return_value = DEVMGR_OK
    await upgrade_device(client, slug_registry, "h", "s", "dev-1", url)
    client.post.assert_called_once_with(
        DEVMGR + "/upgrade-external",
        key=None,
        json={"url": url, "macs": ["aa:bb:cc:dd:ee:02"]},
    )
