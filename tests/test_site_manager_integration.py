"""Integration tests for Site Manager tools against the live test console.

Requires UNIFI_API_KEY (and optionally UNIFI_API_BASE_URL) to be set.
Skip all tests automatically when the env var is absent.

Run:
    UNIFI_API_KEY=<key> pytest tests/test_site_manager_integration.py -v
"""

from __future__ import annotations

import os

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.site_manager import (
    get_host,
    get_isp_metrics,
    get_sdwan_config,
    get_sdwan_config_status,
    list_devices,
    list_hosts,
    list_sdwan_configs,
    list_sites,
    query_isp_metrics,
)

# These tests are gated on UNIFI_API_KEY so they are always skipped in CI where the
# env var is absent.  pytest --collect-only still succeeds because skipif is evaluated
# at collection time, not import time.  Run with a real key to execute them:
#   UNIFI_API_KEY=<key> pytest tests/test_site_manager_integration.py -v
pytestmark = pytest.mark.skipif(
    not os.environ.get("UNIFI_API_KEY"),
    reason="UNIFI_API_KEY not set — skipping live integration tests",
)


@pytest.fixture(scope="module")
def settings():
    return Settings()


@pytest.fixture(scope="module")
def client(settings):
    return UniFiClient(settings)


@pytest.fixture(scope="module")
def registry(client, settings):
    return Registry(client, ttl_seconds=settings.cache_ttl_seconds)


# ---------------------------------------------------------------------------
# list_hosts
# ---------------------------------------------------------------------------


class TestListHostsIntegration:
    @pytest.mark.asyncio
    async def test_returns_at_least_one_host(self, client, registry):
        result = await list_hosts(client, registry)
        assert "hosts" in result
        assert "count" in result
        assert result["count"] >= 1, "Expected at least one host on test console"

    @pytest.mark.asyncio
    async def test_host_has_required_fields(self, client, registry):
        result = await list_hosts(client, registry)
        host = result["hosts"][0]
        assert "id" in host, "Host must have an id field"

    @pytest.mark.asyncio
    async def test_gps_stripped_by_default(self, client, registry):
        result = await list_hosts(client, registry, include_gps=False)
        for host in result["hosts"]:
            reported = host.get("reportedState", {})
            assert "latitude" not in reported, "latitude should be stripped"
            assert "longitude" not in reported, "longitude should be stripped"
            assert "geoInfo" not in reported, "geoInfo should be stripped"

    @pytest.mark.asyncio
    async def test_count_matches_hosts_length(self, client, registry):
        result = await list_hosts(client, registry)
        assert result["count"] == len(result["hosts"])

    @pytest.mark.asyncio
    async def test_populates_registry_cache(self, client, registry):
        registry.invalidate()
        await list_hosts(client, registry)
        assert len(registry._hosts) >= 1, "Registry should be populated after list_hosts"


# ---------------------------------------------------------------------------
# get_host
# ---------------------------------------------------------------------------


class TestGetHostIntegration:
    @pytest.mark.asyncio
    async def test_get_host_by_id(self, client, registry):
        hosts_result = await list_hosts(client, registry)
        first_id = hosts_result["hosts"][0]["id"]

        host = await get_host(client, registry, first_id)
        assert host.get("id") == first_id

    @pytest.mark.asyncio
    async def test_get_host_gps_stripped(self, client, registry):
        hosts_result = await list_hosts(client, registry)
        first_id = hosts_result["hosts"][0]["id"]

        host = await get_host(client, registry, first_id, include_gps=False)
        reported = host.get("reportedState", {})
        assert "latitude" not in reported
        assert "longitude" not in reported

    @pytest.mark.asyncio
    async def test_get_host_by_hostname(self, client, registry):
        hosts_result = await list_hosts(client, registry)
        hostname = hosts_result["hosts"][0].get("reportedState", {}).get("hostname")
        if not hostname:
            pytest.skip("First host has no reportedState.hostname — cannot test name resolution")

        host = await get_host(client, registry, hostname)
        assert "id" in host


# ---------------------------------------------------------------------------
# list_sites
# ---------------------------------------------------------------------------


class TestListSitesIntegration:
    @pytest.mark.asyncio
    async def test_returns_sites(self, client, registry):
        result = await list_sites(client, registry)
        assert "sites" in result
        assert "count" in result
        assert result["count"] >= 1, "Expected at least one site on test console"

    @pytest.mark.asyncio
    async def test_site_has_required_fields(self, client, registry):
        result = await list_sites(client, registry)
        site = result["sites"][0]
        assert "siteId" in site or "id" in site, "Site must have siteId or id"

    @pytest.mark.asyncio
    async def test_count_matches_sites_length(self, client, registry):
        result = await list_sites(client, registry)
        assert result["count"] == len(result["sites"])

    @pytest.mark.asyncio
    async def test_populates_registry_cache(self, client, registry):
        registry.invalidate()
        await list_sites(client, registry)
        assert len(registry._sites) >= 1, "Registry should be populated after list_sites"


# ---------------------------------------------------------------------------
# list_devices
# ---------------------------------------------------------------------------


class TestListDevicesIntegration:
    @pytest.mark.asyncio
    async def test_returns_devices(self, client, registry):
        result = await list_devices(client, registry)
        assert "devices" in result
        assert "count" in result

    @pytest.mark.asyncio
    async def test_count_matches_devices_length(self, client, registry):
        result = await list_devices(client, registry)
        assert result["count"] == len(result["devices"])

    @pytest.mark.asyncio
    async def test_device_has_id(self, client, registry):
        result = await list_devices(client, registry)
        if result["count"] == 0:
            pytest.skip("No devices returned — skipping field check")
        device = result["devices"][0]
        assert "id" in device or "deviceId" in device, "Device must have an id field"

    @pytest.mark.asyncio
    async def test_filter_by_host(self, client, registry):
        hosts_result = await list_hosts(client, registry)
        first_host_id = hosts_result["hosts"][0]["id"]

        result = await list_devices(client, registry, host=first_host_id)
        assert "devices" in result
        # All returned devices should belong to the specified host
        for device in result["devices"]:
            host_id_field = device.get("hostId") or device.get("host_id")
            if host_id_field:
                assert host_id_field == first_host_id


# ---------------------------------------------------------------------------
# get_isp_metrics
# ---------------------------------------------------------------------------


class TestGetISPMetricsIntegration:
    @pytest.mark.asyncio
    async def test_get_5m_metrics(self, client):
        result = await get_isp_metrics(client, "5m")
        assert isinstance(result, dict), "ISP metrics must return a dict"

    @pytest.mark.asyncio
    async def test_get_1h_metrics(self, client):
        result = await get_isp_metrics(client, "1h")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_invalid_interval_rejected(self, client):
        with pytest.raises(ValueError, match="interval must be"):
            await get_isp_metrics(client, "wan")


# ---------------------------------------------------------------------------
# query_isp_metrics
# ---------------------------------------------------------------------------


class TestQueryISPMetricsIntegration:
    @pytest.mark.asyncio
    async def test_query_5m_no_filters(self, client):
        result = await query_isp_metrics(client, "5m")
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_query_1h_with_time_range(self, client):
        result = await query_isp_metrics(
            client,
            "1h",
            start_time="2026-03-01T00:00:00Z",
            end_time="2026-04-01T00:00:00Z",
        )
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_query_with_sites(self, client, registry):
        sites_result = await list_sites(client, registry)
        if sites_result["count"] == 0:
            pytest.skip("No sites available to filter by")
        site = sites_result["sites"][0]
        host_id = site.get("hostId", "")
        site_id = site.get("siteId") or site.get("id", "")
        if not host_id or not site_id:
            pytest.skip("Site missing hostId or siteId")

        result = await query_isp_metrics(
            client, "5m", sites=[{"hostId": host_id, "siteId": site_id}]
        )
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# list_sdwan_configs
# ---------------------------------------------------------------------------


class TestListSDWANConfigsIntegration:
    @pytest.mark.asyncio
    async def test_returns_configs(self, client):
        result = await list_sdwan_configs(client)
        assert "configs" in result
        assert "count" in result

    @pytest.mark.asyncio
    async def test_count_matches_configs_length(self, client):
        result = await list_sdwan_configs(client)
        assert result["count"] == len(result["configs"])


# ---------------------------------------------------------------------------
# get_sdwan_config
# ---------------------------------------------------------------------------


class TestGetSDWANConfigIntegration:
    @pytest.mark.asyncio
    async def test_get_config_by_id(self, client):
        configs_result = await list_sdwan_configs(client)
        if configs_result["count"] == 0:
            pytest.skip("No SD-WAN configs available on test console")

        config_id = configs_result["configs"][0]["id"]
        config = await get_sdwan_config(client, config_id)
        assert config.get("id") == config_id


# ---------------------------------------------------------------------------
# get_sdwan_config_status
# ---------------------------------------------------------------------------


class TestGetSDWANConfigStatusIntegration:
    @pytest.mark.asyncio
    async def test_get_config_status(self, client):
        configs_result = await list_sdwan_configs(client)
        if configs_result["count"] == 0:
            pytest.skip("No SD-WAN configs available on test console")

        config_id = configs_result["configs"][0]["id"]
        status = await get_sdwan_config_status(client, config_id)
        assert isinstance(status, dict), "SD-WAN status must be a dict"
