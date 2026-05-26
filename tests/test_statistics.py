"""Tests for statistics — read-only stat endpoints via Classic REST."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.statistics import (
    _CLASSIC_STAT_BASE,
    _get_site_statistics,
    _get_system_info,
    _list_active_clients_stats,
    _list_device_stats,
)

HOST_ID = "host-001"
SITE_SLUG = "default"
STAT_BASE = _CLASSIC_STAT_BASE.format(host_id=HOST_ID, site_slug=SITE_SLUG)


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


# --- get_site_statistics ---


class TestGetSiteStatistics:
    async def test_uses_stat_health_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"subsystem": "wlan"}]}
        result = await _get_site_statistics(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/health")
        assert result == [{"subsystem": "wlan"}]

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        await _get_site_statistics(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID)

    async def test_extracts_data_list(self, client, registry):
        items = [{"subsystem": "wan"}, {"subsystem": "lan"}]
        client.get.return_value = {"meta": {"rc": "ok"}, "data": items}
        result = await _get_site_statistics(client, registry, "h", "s")
        assert result == items


# --- get_system_info ---


class TestGetSystemInfo:
    async def test_uses_stat_sysinfo_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"version": "8.0.0"}]}
        result = await _get_system_info(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/sysinfo")
        assert result == [{"version": "8.0.0"}]

    async def test_extracts_data(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"uptime": 123456}]}
        result = await _get_system_info(client, registry, "h", "s")
        assert result[0]["uptime"] == 123456


# --- list_active_clients_stats ---


class TestListActiveClientsStats:
    async def test_uses_stat_sta_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"mac": "aa:bb:cc:dd:ee:ff"}]}
        result = await _list_active_clients_stats(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/sta")
        assert result == [{"mac": "aa:bb:cc:dd:ee:ff"}]

    async def test_extracts_data(self, client, registry):
        items = [{"mac": "aa:bb:cc:dd:ee:ff", "signal": -65}]
        client.get.return_value = {"meta": {"rc": "ok"}, "data": items}
        result = await _list_active_clients_stats(client, registry, "h", "s")
        assert result == items


# --- list_device_stats ---


class TestListDeviceStats:
    async def test_uses_stat_device_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"mac": "11:22:33:44:55:66"}]}
        result = await _list_device_stats(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/device")
        assert result == [{"mac": "11:22:33:44:55:66"}]

    async def test_extracts_data(self, client, registry):
        items = [{"mac": "11:22:33:44:55:66", "uptime": 9999}]
        client.get.return_value = {"meta": {"rc": "ok"}, "data": items}
        result = await _list_device_stats(client, registry, "h", "s")
        assert result == items

    async def test_passthrough_when_no_data_key(self, client, registry):
        raw = [{"mac": "11:22:33:44:55:66"}]
        client.get.return_value = raw
        result = await _list_device_stats(client, registry, "h", "s")
        assert result == raw
