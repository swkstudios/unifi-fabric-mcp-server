"""Integration tests for Site Manager tools against the live test console.

Requires UNIFI_API_KEY (and optionally UNIFI_API_BASE_URL) to be set.
Skip all tests automatically when the env var is absent.

Run:
    UNIFI_API_KEY=<key> pytest tests/test_site_manager_integration.py -v
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

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
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("UNIFI_API_KEY"),
        reason="UNIFI_API_KEY not set — skipping live integration tests",
    ),
    # Share ONE event loop across every test in the module so the module-scoped client
    # (and its lazily-created httpx.AsyncClient) stays valid for all tests. Without this,
    # pytest-asyncio's default function-scoped loop closes after the first test and every
    # subsequent test dies in httpx teardown with "Event loop is closed".
    #
    # NOTE: with asyncio_mode = "auto" (pyproject) this module-scoped marker is the ONLY
    # asyncio marker the tests carry. Do NOT re-add a bare per-method @pytest.mark.asyncio:
    # a function-scoped per-method marker OVERRIDES this module pytestmark back to function
    # scope, which reintroduces the "Event loop is closed" failures on every test after the
    # first. The other three integration modules follow the same pattern.
    pytest.mark.asyncio(loop_scope="module"),
]


@pytest.fixture(scope="module")
def settings():
    return Settings()


@pytest_asyncio.fixture(loop_scope="module", scope="module")
async def client(settings):
    c = UniFiClient(settings)
    yield c
    await c.close()


@pytest.fixture(scope="module")
def registry(client, settings):
    return Registry(client, ttl_seconds=settings.cache_ttl_seconds)


# ---------------------------------------------------------------------------
# list_hosts
# ---------------------------------------------------------------------------


class TestListHostsIntegration:
    async def test_returns_at_least_one_host(self, client, registry):
        result = await list_hosts(client, registry)
        assert "hosts" in result
        assert "count" in result
        assert result["count"] >= 1, "Expected at least one host on test console"

    async def test_host_has_required_fields(self, client, registry):
        result = await list_hosts(client, registry)
        host = result["hosts"][0]
        assert "id" in host, "Host must have an id field"

    async def test_gps_passed_through(self, client, registry):
        # Faithful pass-through: host records are returned verbatim. Any GPS
        # coordinates the controller reports survive rather than being stripped.
        result = await list_hosts(client, registry)
        for host in result["hosts"]:
            reported = host.get("reportedState", {})
            if "latitude" in reported:
                assert isinstance(reported["latitude"], (int, float))

    async def test_count_matches_hosts_length(self, client, registry):
        result = await list_hosts(client, registry)
        assert result["count"] == len(result["hosts"])

    async def test_populates_registry_cache(self, client, registry):
        registry.invalidate()
        await list_hosts(client, registry)
        assert len(registry._hosts) >= 1, "Registry should be populated after list_hosts"


# ---------------------------------------------------------------------------
# get_host
# ---------------------------------------------------------------------------


class TestGetHostIntegration:
    async def test_get_host_by_id(self, client, registry):
        hosts_result = await list_hosts(client, registry)
        first_id = hosts_result["hosts"][0]["id"]

        host = await get_host(client, registry, first_id)
        assert host.get("id") == first_id

    async def test_get_host_gps_passed_through(self, client, registry):
        hosts_result = await list_hosts(client, registry)
        first_id = hosts_result["hosts"][0]["id"]

        host = await get_host(client, registry, first_id)
        reported = host.get("reportedState", {})
        if "latitude" in reported:
            assert isinstance(reported["latitude"], (int, float))

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
    async def test_returns_sites(self, client, registry):
        result = await list_sites(client, registry)
        assert "sites" in result
        assert "count" in result
        assert result["count"] >= 1, "Expected at least one site on test console"

    async def test_site_has_required_fields(self, client, registry):
        result = await list_sites(client, registry)
        site = result["sites"][0]
        assert "siteId" in site or "id" in site, "Site must have siteId or id"

    async def test_count_matches_sites_length(self, client, registry):
        result = await list_sites(client, registry)
        assert result["count"] == len(result["sites"])

    async def test_populates_registry_cache(self, client, registry):
        registry.invalidate()
        await list_sites(client, registry)
        # list_sites drains the MSP /ea/sites list and primes the EA-sites cache
        # (Registry.set_ea_sites -> _ea_sites, keyed by API-key label). The separate
        # _sites cache is the per-console PROXY site list (keyed by (label, host_id))
        # and is only populated by the per-host proxy path, not by list_sites.
        assert len(registry._ea_sites) >= 1, "EA-sites cache should be populated after list_sites"


# ---------------------------------------------------------------------------
# list_devices
# ---------------------------------------------------------------------------


class TestListDevicesIntegration:
    async def test_returns_devices(self, client, registry):
        result = await list_devices(client, registry)
        assert "devices" in result
        assert "count" in result

    async def test_count_matches_devices_length(self, client, registry):
        result = await list_devices(client, registry)
        assert result["count"] == len(result["devices"])

    async def test_device_has_id(self, client, registry):
        result = await list_devices(client, registry)
        if result["count"] == 0:
            pytest.skip("No device host-wrappers returned — skipping field check")
        # /ea/devices returns HOST-WRAPPER objects: {hostId, hostName, devices[], updatedAt}.
        # The actual device items are nested one level deeper at wrapper["devices"][*] and
        # carry the "id" field — the wrapper itself does not. Assert at the correct depth.
        wrapper = result["devices"][0]
        assert "devices" in wrapper, (
            "Expected a host-wrapper with a nested devices[] list; "
            f"got keys {sorted(wrapper.keys())}"
        )
        nested = wrapper["devices"]
        if not nested:
            pytest.skip("Host wrapper has no nested devices — skipping field check")
        device = nested[0]
        assert "id" in device or "deviceId" in device, "Nested device must have an id field"

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
    async def test_get_5m_metrics(self, client):
        result = await get_isp_metrics(client, "5m")
        assert isinstance(result, dict), "ISP metrics must return a dict"

    async def test_get_1h_metrics(self, client):
        result = await get_isp_metrics(client, "1h")
        assert isinstance(result, dict)

    async def test_invalid_interval_rejected(self, client):
        with pytest.raises(ValueError, match="interval must be"):
            await get_isp_metrics(client, "wan")


# ---------------------------------------------------------------------------
# query_isp_metrics
# ---------------------------------------------------------------------------


class TestQueryISPMetricsIntegration:
    async def test_query_no_sites_rejected(self, client):
        # The UniFi Site Manager API requires at least one site filter on
        # POST /ea/isp-metrics/{interval}/query; an empty body returns an opaque
        # HTTP 400 "error while parsing request" (verified live). The tool rejects
        # a no-sites call up front with a clear ValueError rather than forwarding
        # the empty POST.
        with pytest.raises(ValueError, match="at least one site"):
            await query_isp_metrics(client, "5m")

    async def test_query_1h_with_time_range(self, client, registry):
        sites_result = await list_sites(client, registry)
        if sites_result["count"] == 0:
            pytest.skip("No sites available to filter by")
        site = sites_result["sites"][0]
        host_id = site.get("hostId", "")
        site_id = site.get("siteId") or site.get("id", "")
        if not host_id or not site_id:
            pytest.skip("Site missing hostId or siteId")

        # Relative window computed at runtime. The Site Manager API enforces a
        # ~30-day rolling validation window and rejects stale absolute ranges, so a
        # hardcoded date rots into an HTTP 400 on a delay rather than on a defect.
        # Anchor to a whole hour because the 1h interval requires hour-aligned bounds.
        end = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
        start = end - timedelta(hours=6)
        result = await query_isp_metrics(
            client,
            "1h",
            sites=[{"hostId": host_id, "siteId": site_id}],
            start_time=start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            end_time=end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        assert isinstance(result, dict)

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
    async def test_returns_configs(self, client):
        result = await list_sdwan_configs(client)
        assert "configs" in result
        assert "count" in result

    async def test_count_matches_configs_length(self, client):
        result = await list_sdwan_configs(client)
        assert result["count"] == len(result["configs"])


# ---------------------------------------------------------------------------
# get_sdwan_config
# ---------------------------------------------------------------------------


class TestGetSDWANConfigIntegration:
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
    async def test_get_config_status(self, client):
        configs_result = await list_sdwan_configs(client)
        if configs_result["count"] == 0:
            pytest.skip("No SD-WAN configs available on test console")

        config_id = configs_result["configs"][0]["id"]
        status = await get_sdwan_config_status(client, config_id)
        assert isinstance(status, dict), "SD-WAN status must be a dict"
