"""Tests for Site Manager tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.site_manager import (
    _filter_gps,
    _resolve_ea_host_site,
    compare_site_performance,
    get_host,
    get_isp_metrics,
    get_sdwan_config,
    get_sdwan_config_status,
    get_site_health_summary,
    get_site_inventory,
    list_all_sites_aggregated,
    list_devices,
    list_hosts,
    list_sdwan_configs,
    list_sites,
    query_isp_metrics,
    search_across_sites,
)


@pytest.fixture
def settings():
    return Settings(api_key="test-key")


@pytest.fixture
def client(settings):
    return UniFiClient(settings)


@pytest.fixture
def registry(client):
    return Registry(client, ttl_seconds=900)


class TestGPSFiltering:
    def test_gps_filtered_by_default(self):
        host = {
            "id": "h1",
            "reportedState": {
                "hostname": "console-1",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "geoInfo": {"city": "NYC"},
                "firmware": "4.0.6",
            },
        }
        result = _filter_gps(host, include_gps=False)
        assert "latitude" not in result["reportedState"]
        assert "longitude" not in result["reportedState"]
        assert "geoInfo" not in result["reportedState"]
        assert result["reportedState"]["firmware"] == "4.0.6"

    def test_gps_included_when_requested(self):
        host = {
            "id": "h1",
            "reportedState": {
                "latitude": 40.7128,
                "longitude": -74.0060,
            },
        }
        result = _filter_gps(host, include_gps=True)
        assert result["reportedState"]["latitude"] == 40.7128

    def test_no_reported_state(self):
        host = {"id": "h1"}
        result = _filter_gps(host, include_gps=False)
        assert result == {"id": "h1"}


class TestListHosts:
    @pytest.mark.asyncio
    async def test_list_hosts_basic(self, client, registry):
        mock_data = {
            "data": [
                {
                    "id": "h1",
                    "reportedState": {
                        "hostname": "console-1",
                        "latitude": 40.0,
                        "longitude": -74.0,
                    },
                }
            ]
        }
        client.get = AsyncMock(return_value=mock_data)

        result = await list_hosts(client, registry)
        assert result["count"] == 1
        assert "latitude" not in result["hosts"][0]["reportedState"]

    @pytest.mark.asyncio
    async def test_list_hosts_with_gps(self, client, registry):
        mock_data = {
            "data": [
                {
                    "id": "h1",
                    "reportedState": {"latitude": 40.0, "longitude": -74.0},
                }
            ]
        }
        client.get = AsyncMock(return_value=mock_data)

        result = await list_hosts(client, registry, include_gps=True)
        assert result["hosts"][0]["reportedState"]["latitude"] == 40.0

    @pytest.mark.asyncio
    async def test_list_hosts_pagination(self, client, registry):
        mock_data = {
            "data": [{"id": "h1"}],
            "nextToken": "abc123",
        }
        client.get = AsyncMock(return_value=mock_data)

        result = await list_hosts(client, registry)
        assert result["nextToken"] == "abc123"

    @pytest.mark.asyncio
    async def test_list_hosts_sends_limit_param(self, client, registry):
        client.get = AsyncMock(return_value={"data": []})

        await list_hosts(client, registry, page_size=50)

        _, kwargs = client.get.call_args
        assert kwargs["params"]["limit"] == 50

    @pytest.mark.asyncio
    async def test_list_hosts_sends_page_token(self, client, registry):
        client.get = AsyncMock(return_value={"data": []})

        await list_hosts(client, registry, page_token="tok1")

        _, kwargs = client.get.call_args
        assert kwargs["params"]["nextToken"] == "tok1"


class TestGetHost:
    @pytest.mark.asyncio
    async def test_get_host_by_id(self, client, registry):
        registry.resolve_host_id = AsyncMock(return_value="host-id-1")
        client.get = AsyncMock(
            return_value={"data": {"id": "host-id-1", "reportedState": {"hostname": "c1"}}}
        )

        result = await get_host(client, registry, "host-id-1")
        assert result["id"] == "host-id-1"


class TestListSites:
    @pytest.mark.asyncio
    async def test_list_sites(self, client, registry):
        mock_data = {
            "data": [{"siteId": "s1", "siteName": "Main Office"}],
        }
        client.get = AsyncMock(return_value=mock_data)

        result = await list_sites(client, registry)
        assert result["count"] == 1
        assert result["sites"][0]["siteName"] == "Main Office"


class TestListDevices:
    @pytest.mark.asyncio
    async def test_list_devices(self, client, registry):
        mock_data = {
            "data": [{"id": "d1", "model": "U6-Pro", "status": "online"}],
        }
        client.get = AsyncMock(return_value=mock_data)

        result = await list_devices(client, registry)
        assert result["count"] == 1
        assert result["devices"][0]["model"] == "U6-Pro"


class TestISPMetrics:
    @pytest.mark.asyncio
    async def test_get_isp_metrics_list_response(self, client):
        client.get = AsyncMock(return_value={"data": [{"speed": 100}]})

        result = await get_isp_metrics(client, "5m")
        assert result["periods"][0]["speed"] == 100

    @pytest.mark.asyncio
    async def test_get_isp_metrics_invalid_interval(self, client):
        with pytest.raises(ValueError, match="interval must be"):
            await get_isp_metrics(client, "wan")

    @pytest.mark.asyncio
    async def test_query_isp_metrics(self, client):
        client.post = AsyncMock(return_value={"data": [{"latency": 5}]})

        result = await query_isp_metrics(
            client,
            "5m",
            sites=[{"hostId": "h1", "siteId": "s1"}],
            start_time="2026-01-01T00:00:00Z",
        )
        assert result["periods"][0]["latency"] == 5

    @pytest.mark.asyncio
    async def test_query_isp_metrics_body_shape(self, client):
        client.post = AsyncMock(return_value={"data": []})

        await query_isp_metrics(
            client,
            "1h",
            sites=[{"hostId": "h1", "siteId": "s1"}],
            start_time="2026-01-01T00:00:00Z",
            end_time="2026-01-02T00:00:00Z",
        )
        _, kwargs = client.post.call_args
        body = kwargs["json"]
        assert body["sites"] == [{"hostId": "h1", "siteId": "s1"}]
        assert "beginTimestamp" in body
        assert "endTimestamp" in body
        assert "siteIds" not in body

    @pytest.mark.asyncio
    async def test_query_isp_metrics_invalid_interval(self, client):
        with pytest.raises(ValueError, match="interval must be"):
            await query_isp_metrics(client, "packetloss")


class TestSDWAN:
    @pytest.mark.asyncio
    async def test_list_sdwan_configs(self, client):
        client.get = AsyncMock(return_value={"data": [{"id": "cfg1", "name": "Mesh VPN"}]})

        result = await list_sdwan_configs(client)
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_get_sdwan_config(self, client):
        client.get = AsyncMock(return_value={"data": {"id": "cfg1"}})

        result = await get_sdwan_config(client, "cfg1")
        assert result["id"] == "cfg1"

    @pytest.mark.asyncio
    async def test_get_sdwan_config_status(self, client):
        client.get = AsyncMock(return_value={"data": {"status": "active"}})

        result = await get_sdwan_config_status(client, "cfg1")
        assert result["status"] == "active"


class TestListAllSitesAggregated:
    @pytest.mark.asyncio
    async def test_basic(self, client, registry):
        client.get = AsyncMock(
            return_value={
                "data": [
                    {"siteId": "s1", "siteName": "HQ", "deviceCount": 10, "alerts": 0},
                    {"siteId": "s2", "siteName": "Branch", "deviceCount": 5, "alerts": 2},
                ]
            }
        )

        result = await list_all_sites_aggregated(client, registry)
        assert result["count"] == 2
        assert result["sites"][0]["siteName"] == "HQ"

    @pytest.mark.asyncio
    async def test_empty_response(self, client, registry):
        client.get = AsyncMock(return_value={"data": []})

        result = await list_all_sites_aggregated(client, registry)
        assert result["count"] == 0
        assert result["sites"] == []

    @pytest.mark.asyncio
    async def test_list_response_without_data_wrapper(self, client, registry):
        client.get = AsyncMock(return_value=[{"siteId": "s1", "siteName": "HQ"}])

        result = await list_all_sites_aggregated(client, registry)
        assert result["count"] == 1


class TestResolveEaHostSite:
    @pytest.mark.asyncio
    async def test_resolves_by_site_id(self, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[
                {"hostId": "host-abc", "siteId": "site-xyz", "siteName": "HQ"},
            ]
        )
        host_id, site_id = await _resolve_ea_host_site(registry, "site-xyz")
        assert host_id == "host-abc"
        assert site_id == "site-xyz"

    @pytest.mark.asyncio
    async def test_resolves_by_site_name(self, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[
                {"hostId": "host-abc", "siteId": "site-xyz", "siteName": "Main Office"},
            ]
        )
        host_id, site_id = await _resolve_ea_host_site(registry, "main office")
        assert host_id == "host-abc"

    @pytest.mark.asyncio
    async def test_resolves_by_name_field(self, registry):
        """Sites from /v1/sites data use 'name' field instead of 'siteName'."""
        registry.get_ea_sites = AsyncMock(
            return_value=[
                {"hostId": "host-abc", "id": "uuid-site-1", "name": "Default"},
            ]
        )
        host_id, site_id = await _resolve_ea_host_site(registry, "Default")
        assert host_id == "host-abc"
        assert site_id == "uuid-site-1"

    @pytest.mark.asyncio
    async def test_resolves_by_meta_desc(self, registry):
        """/v1/sites data may nest the site name under meta.desc."""
        registry.get_ea_sites = AsyncMock(
            return_value=[
                {"hostId": "host-abc", "id": "uuid-site-2", "meta": {"desc": "Branch Office"}},
            ]
        )
        host_id, site_id = await _resolve_ea_host_site(registry, "Branch Office")
        assert host_id == "host-abc"
        assert site_id == "uuid-site-2"

    @pytest.mark.asyncio
    async def test_resolves_by_meta_name(self, registry):
        """/v1/sites data may nest the site name under meta.name."""
        registry.get_ea_sites = AsyncMock(
            return_value=[
                {"hostId": "host-abc", "id": "uuid-site-3", "meta": {"name": "Warehouse"}},
            ]
        )
        host_id, site_id = await _resolve_ea_host_site(registry, "warehouse")
        assert host_id == "host-abc"
        assert site_id == "uuid-site-3"

    @pytest.mark.asyncio
    async def test_raises_if_not_found(self, registry):
        registry.get_ea_sites = AsyncMock(return_value=[])
        with pytest.raises(ValueError, match="not found"):
            await _resolve_ea_host_site(registry, "ghost-site")

    @pytest.mark.asyncio
    async def test_raises_on_malformed_host_id(self, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[
                {"hostId": "../bad", "siteId": "site-xyz", "siteName": "HQ"},
            ]
        )
        with pytest.raises(ValueError):
            await _resolve_ea_host_site(registry, "site-xyz")


_UUID_SITE = "aaaaaaaa-0000-4000-8000-000000000001"


class TestGetSiteHealthSummary:
    @pytest.mark.asyncio
    async def test_by_site_name(self, client, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h2", "siteId": "objectid-abc", "siteName": "My Site"}]
        )
        registry.resolve_site_slug = AsyncMock(return_value="default")
        client.get = AsyncMock(return_value={"data": [{"subsystem": "wlan", "alerts": 3}]})

        result = await get_site_health_summary(client, registry, "My Site")
        # Bare list from /stat/health is wrapped
        assert result["count"] == 1
        assert result["health"][0]["alerts"] == 3
        # URL routes through Classic REST stat/health, not /v1/sites/{uuid}
        call_path = client.get.call_args[0][0]
        assert "/stat/health" in call_path
        assert "objectid-abc" not in call_path

    @pytest.mark.asyncio
    async def test_routes_through_classic_stat_health(self, client, registry):
        """Routes through Classic REST /stat/health using site_slug, not /v1/sites/{uuid}."""
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h1", "siteId": "objectid-123", "siteName": "Default"}]
        )
        registry.resolve_site_slug = AsyncMock(return_value="default")
        client.get = AsyncMock(return_value={"data": {"numSta": 5}})

        result = await get_site_health_summary(client, registry, "Default")
        assert result["numSta"] == 5
        registry.resolve_site_slug.assert_called_once_with("Default", "host-h1")
        call_path = client.get.call_args[0][0]
        assert "/stat/health" in call_path
        assert "host-h1" in call_path
        assert "default" in call_path

    @pytest.mark.asyncio
    async def test_list_response_wrapped(self, client, registry):
        """Bare list from /stat/health is normalized to {health: [...], count: N}."""
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h3", "siteId": "s3", "siteName": "Branch"}]
        )
        registry.resolve_site_slug = AsyncMock(return_value="branch")
        health_list = [{"subsystem": "wan", "status": "ok"}, {"subsystem": "wlan", "status": "ok"}]
        client.get = AsyncMock(return_value={"data": health_list})

        result = await get_site_health_summary(client, registry, "Branch")
        assert result["count"] == 2
        assert result["health"] == health_list


class TestCompareSitePerformance:
    @pytest.mark.asyncio
    async def test_compare_two_sites(self, client, registry):
        health_a = {"health": [{"subsystem": "wan", "status": "ok"}], "count": 1}
        health_b = {"health": [{"subsystem": "wlan", "status": "ok"}], "count": 1}

        with patch(
            "unifi_fabric.tools.site_manager.get_site_health_summary",
            new_callable=AsyncMock,
            side_effect=[health_a, health_b],
        ):
            result = await compare_site_performance(client, registry, ["Site A", "Site B"])

        assert result["count"] == 2
        assert result["comparison"][0]["_siteLabel"] == "Site A"
        assert result["comparison"][1]["_siteLabel"] == "Site B"
        # verify each result includes the health data
        assert result["comparison"][0]["health"] == health_a["health"]

    @pytest.mark.asyncio
    async def test_error_handled_per_site(self, client, registry):
        health_a = {"health": [{"subsystem": "wan", "status": "ok"}], "count": 1}

        with patch(
            "unifi_fabric.tools.site_manager.get_site_health_summary",
            new_callable=AsyncMock,
            side_effect=[health_a, Exception("connection refused")],
        ):
            result = await compare_site_performance(client, registry, ["Site A", "Site B"])

        assert result["count"] == 2
        assert "error" in result["comparison"][1]
        assert result["comparison"][1]["_siteLabel"] == "Site B"

    @pytest.mark.asyncio
    async def test_uses_stat_health_not_v1_sites(self, client, registry):
        """Verify compare_site_performance routes through stat/health, not /v1/sites."""
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h1", "siteId": "s1", "siteName": "Site A"}]
        )
        registry.resolve_site_slug = AsyncMock(return_value="default")
        client.get = AsyncMock(return_value={"data": [{"subsystem": "wan", "status": "ok"}]})

        result = await compare_site_performance(client, registry, ["Site A"])
        assert result["count"] == 1
        call_path = client.get.call_args[0][0]
        assert "/stat/health" in call_path
        assert "/v1/sites/" not in call_path

    @pytest.mark.asyncio
    async def test_empty_sites_list(self, client, registry):
        result = await compare_site_performance(client, registry, [])
        assert result["count"] == 0
        assert result["comparison"] == []


class TestSearchAcrossSites:
    @pytest.mark.asyncio
    async def test_finds_matching_device(self, client, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h1", "siteId": "s1", "siteName": "HQ"}]
        )
        registry.resolve_site_id = AsyncMock(return_value=_UUID_SITE)
        client.get = AsyncMock(
            side_effect=[
                {
                    "data": [
                        {
                            "name": "AP-Living-Room",
                            "mac": "aa:bb:cc:dd:ee:ff",
                            "ip": "192.168.1.10",
                            "model": "U6-Pro",
                        }
                    ]
                },
                {"data": []},
            ]
        )

        result = await search_across_sites(client, registry, "AP-Living")
        assert result["count"] == 1
        assert result["matches"][0]["name"] == "AP-Living-Room"
        assert result["matches"][0]["_type"] == "device"
        assert result["sitesSearched"] == 1

    @pytest.mark.asyncio
    async def test_finds_matching_client(self, client, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h1", "siteId": "s1", "siteName": "HQ"}]
        )
        registry.resolve_site_id = AsyncMock(return_value=_UUID_SITE)
        client.get = AsyncMock(
            side_effect=[
                {"data": []},
                {
                    "data": [
                        {
                            "hostname": "my-laptop",
                            "mac": "11:22:33:44:55:66",
                            "ip": "10.0.0.5",
                            "name": "",
                        }
                    ]
                },
            ]
        )

        result = await search_across_sites(client, registry, "my-laptop")
        assert result["count"] == 1
        assert result["matches"][0]["_type"] == "client"

    @pytest.mark.asyncio
    async def test_no_matches(self, client, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h1", "siteId": "s1", "siteName": "HQ"}]
        )
        registry.resolve_site_id = AsyncMock(return_value=_UUID_SITE)
        client.get = AsyncMock(
            side_effect=[
                {
                    "data": [
                        {
                            "name": "Switch-1",
                            "mac": "aa:bb:cc:00:00:01",
                            "ip": "10.0.0.1",
                            "model": "USW-8",
                        }
                    ]
                },
                {"data": []},
            ]
        )

        result = await search_across_sites(client, registry, "nonexistent-xyz")
        assert result["count"] == 0

    @pytest.mark.asyncio
    async def test_site_error_skipped(self, client, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[
                {"hostId": "host-h1", "siteId": "s1", "siteName": "Good"},
                {"hostId": "host-h2", "siteId": "s2", "siteName": "Bad"},
            ]
        )
        registry.resolve_site_id = AsyncMock(return_value=_UUID_SITE)
        client.get = AsyncMock(
            side_effect=[
                {
                    "data": [
                        {
                            "name": "Router-A",
                            "mac": "aa:00:00:00:00:01",
                            "ip": "10.0.0.1",
                            "model": "UDM",
                        }
                    ]
                },
                {"data": []},
                UniFiConnectionError("site unreachable"),
                UniFiConnectionError("site unreachable"),
            ]
        )

        result = await search_across_sites(client, registry, "router")
        assert result["sitesSearched"] == 2
        assert result["count"] == 1


class TestGetSiteInventory:
    @pytest.mark.asyncio
    async def test_returns_devices_and_clients(self, client, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h1", "siteId": "objectid-abc", "siteName": "HQ"}]
        )
        registry.resolve_site_id = AsyncMock(return_value=_UUID_SITE)
        client.get = AsyncMock(
            side_effect=[
                {"data": [{"id": "d1", "model": "U6-Pro"}, {"id": "d2", "model": "USW-8"}]},
                {"data": [{"mac": "aa:bb:cc:dd:ee:01"}, {"mac": "aa:bb:cc:dd:ee:02"}]},
            ]
        )

        result = await get_site_inventory(client, registry, "HQ")
        assert result["siteId"] == _UUID_SITE
        assert result["deviceCount"] == 2
        assert result["clientCount"] == 2
        assert result["devices"][0]["model"] == "U6-Pro"

    @pytest.mark.asyncio
    async def test_proxy_url_uses_uuid(self, client, registry):
        """Proxy URLs must use UUID from resolve_site_id, not ObjectId from EA sites."""
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h1", "siteId": "objectid-123", "siteName": "Default"}]
        )
        registry.resolve_site_id = AsyncMock(return_value=_UUID_SITE)
        client.get = AsyncMock(side_effect=[{"data": []}, {"data": []}])

        await get_site_inventory(client, registry, "Default")

        registry.resolve_site_id.assert_called_once_with("Default", "host-h1")
        # Both proxy calls should use the UUID
        for call in client.get.call_args_list:
            assert _UUID_SITE in call[0][0]
            assert "objectid-123" not in call[0][0]

    @pytest.mark.asyncio
    async def test_empty_inventory(self, client, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h1", "siteId": "objectid-empty", "siteName": "Empty"}]
        )
        registry.resolve_site_id = AsyncMock(return_value=_UUID_SITE)
        client.get = AsyncMock(
            side_effect=[
                {"data": []},
                {"data": []},
            ]
        )

        result = await get_site_inventory(client, registry, "Empty")
        assert result["deviceCount"] == 0
        assert result["clientCount"] == 0

    @pytest.mark.asyncio
    async def test_non_list_response_handled(self, client, registry):
        registry.get_ea_sites = AsyncMock(
            return_value=[{"hostId": "host-h1", "siteId": "objectid-x", "siteName": "X"}]
        )
        registry.resolve_site_id = AsyncMock(return_value=_UUID_SITE)
        client.get = AsyncMock(
            side_effect=[
                {"error": "not found"},
                {"error": "not found"},
            ]
        )

        result = await get_site_inventory(client, registry, "X")
        assert result["devices"] == []
        assert result["clients"] == []
