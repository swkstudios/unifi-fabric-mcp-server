"""Tests for Site Manager tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.site_manager import (
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


class TestGPSSurvival:
    """The server is a faithful pass-through: host records — including
    reportedState GPS coordinates — reach the caller unchanged. A deployment
    that wants coordinates hidden layers that policy on top of the response.
    """

    @pytest.mark.asyncio
    async def test_gps_survives_by_default(self, client, registry):
        mock_data = {
            "data": [
                {
                    "id": "h1",
                    "reportedState": {
                        "hostname": "console-1",
                        "latitude": 40.7128,
                        "longitude": -74.0060,
                        "geoInfo": {"city": "NYC"},
                        "firmware": "4.0.6",
                    },
                }
            ]
        }
        client.get = AsyncMock(return_value=mock_data)
        result = await list_hosts(client, registry)
        reported = result["hosts"][0]["reportedState"]
        assert reported["latitude"] == 40.7128
        assert reported["longitude"] == -74.0060
        assert reported["geoInfo"] == {"city": "NYC"}
        assert reported["firmware"] == "4.0.6"

    @pytest.mark.asyncio
    async def test_get_host_gps_survives(self, client, registry):
        client.get = AsyncMock(
            return_value={"data": {"id": "h1", "reportedState": {"latitude": 40.7128}}}
        )
        registry.resolve_host_id = AsyncMock(return_value="h1")
        result = await get_host(client, registry, "h1")
        assert result["reportedState"]["latitude"] == 40.7128


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
        # Host records pass through verbatim, coordinates included.
        assert result["hosts"][0]["reportedState"]["latitude"] == 40.0

    @pytest.mark.asyncio
    async def test_list_hosts_drains_all_pages(self, client, registry):
        # Default (no page_token): drain every page and return the complete set.
        client.get = AsyncMock(
            side_effect=[
                {"data": [{"id": "h1"}], "nextToken": "t1"},
                {"data": [{"id": "h2"}]},
            ]
        )
        result = await list_hosts(client, registry)
        assert client.get.call_count == 2
        assert result["count"] == 2
        assert [h["id"] for h in result["hosts"]] == ["h1", "h2"]
        # A complete drain surfaces no continuation cursor and no incomplete marker.
        assert "nextToken" not in result
        assert "incomplete" not in result
        # Page 2 carried page 1's cursor.
        assert client.get.call_args_list[1].kwargs["params"]["nextToken"] == "t1"

    @pytest.mark.asyncio
    async def test_list_hosts_sends_limit_param(self, client, registry):
        client.get = AsyncMock(return_value={"data": []})

        await list_hosts(client, registry, page_size=50)

        _, kwargs = client.get.call_args
        assert kwargs["params"]["limit"] == 50

    @pytest.mark.asyncio
    async def test_list_hosts_page_token_returns_single_page(self, client, registry):
        # Explicit paging: one page only, continuation cursor surfaced for manual paging.
        client.get = AsyncMock(return_value={"data": [{"id": "h1"}], "nextToken": "n2"})

        result = await list_hosts(client, registry, page_token="tok1")

        assert client.get.call_count == 1
        _, kwargs = client.get.call_args
        assert kwargs["params"]["nextToken"] == "tok1"
        assert result["nextToken"] == "n2"
        assert "incomplete" not in result

    @pytest.mark.asyncio
    async def test_list_hosts_cap_exceeded_marked_incomplete(self):
        # A drain that hits the page cap returns the pages gathered so far, flagged.
        capped = UniFiClient(Settings(api_key="test-key", paginate_max_pages=2))
        capped.get = AsyncMock(
            side_effect=[
                {"data": [{"id": "h1"}], "nextToken": "t1"},
                {"data": [{"id": "h2"}], "nextToken": "t2"},
            ]
        )
        registry = Registry(capped, ttl_seconds=900)

        result = await list_hosts(capped, registry)

        assert result["incomplete"] is True
        assert "page cap of 2" in result["incompleteReason"]
        assert result["count"] == 2
        assert [h["id"] for h in result["hosts"]] == ["h1", "h2"]
        assert "nextToken" not in result


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

    @pytest.mark.asyncio
    async def test_list_sites_drains_all_pages(self, client, registry):
        client.get = AsyncMock(
            side_effect=[
                {"data": [{"siteId": "s1"}], "nextToken": "t1"},
                {"data": [{"siteId": "s2"}]},
            ]
        )
        result = await list_sites(client, registry)
        assert client.get.call_count == 2
        assert result["count"] == 2
        assert "nextToken" not in result
        assert "incomplete" not in result

    @pytest.mark.asyncio
    async def test_list_sites_page_token_returns_single_page(self, client, registry):
        client.get = AsyncMock(return_value={"data": [{"siteId": "s1"}], "nextToken": "n2"})
        result = await list_sites(client, registry, page_token="p1")
        assert client.get.call_count == 1
        assert result["nextToken"] == "n2"

    @pytest.mark.asyncio
    async def test_list_sites_cap_exceeded_marked_incomplete(self):
        capped = UniFiClient(Settings(api_key="test-key", paginate_max_pages=1))
        capped.get = AsyncMock(return_value={"data": [{"siteId": "s1"}], "nextToken": "t1"})
        registry = Registry(capped, ttl_seconds=900)
        result = await list_sites(capped, registry)
        assert result["incomplete"] is True
        assert "page cap of 1" in result["incompleteReason"]
        assert result["count"] == 1


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

    @pytest.mark.asyncio
    async def test_list_devices_drains_all_pages(self, client, registry):
        client.get = AsyncMock(
            side_effect=[
                {"data": [{"id": "d1"}], "nextToken": "t1"},
                {"data": [{"id": "d2"}]},
            ]
        )
        result = await list_devices(client, registry)
        assert client.get.call_count == 2
        assert result["count"] == 2
        assert "incomplete" not in result

    @pytest.mark.asyncio
    async def test_list_devices_page_token_returns_single_page(self, client, registry):
        client.get = AsyncMock(return_value={"data": [{"id": "d1"}], "nextToken": "n2"})
        result = await list_devices(client, registry, page_token="p1")
        assert client.get.call_count == 1
        assert result["nextToken"] == "n2"

    @pytest.mark.asyncio
    async def test_list_devices_cap_exceeded_marked_incomplete(self):
        capped = UniFiClient(Settings(api_key="test-key", paginate_max_pages=1))
        capped.get = AsyncMock(return_value={"data": [{"id": "d1"}], "nextToken": "t1"})
        registry = Registry(capped, ttl_seconds=900)
        result = await list_devices(capped, registry)
        assert result["incomplete"] is True
        assert result["count"] == 1


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
        # The UniFi Site Manager API reads the time window from per-site
        # beginTimestamp/endTimestamp nested INSIDE each sites[] entry; a
        # top-level timestamp is silently ignored (verified live). The tool
        # must place the window inside each site entry, not at the top level.
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
        # Timestamps are nested per-site, NOT top-level.
        assert body["sites"] == [
            {
                "hostId": "h1",
                "siteId": "s1",
                "beginTimestamp": "2026-01-01T00:00:00Z",
                "endTimestamp": "2026-01-02T00:00:00Z",
            }
        ]
        assert "beginTimestamp" not in body
        assert "endTimestamp" not in body
        assert "siteIds" not in body

    @pytest.mark.asyncio
    async def test_query_isp_metrics_window_applied_to_every_site(self, client):
        # The window must be injected into every site entry (that is where the
        # API filters), and the caller's original list must not be mutated.
        client.post = AsyncMock(return_value={"data": []})
        sites_arg = [
            {"hostId": "h1", "siteId": "s1"},
            {"hostId": "h2", "siteId": "s2"},
        ]
        await query_isp_metrics(
            client,
            "5m",
            sites=sites_arg,
            start_time="2026-01-01T00:00:00Z",
            end_time="2026-01-02T00:00:00Z",
        )
        _, kwargs = client.post.call_args
        for entry in kwargs["json"]["sites"]:
            assert entry["beginTimestamp"] == "2026-01-01T00:00:00Z"
            assert entry["endTimestamp"] == "2026-01-02T00:00:00Z"
        # Caller's list was copied, not mutated in place.
        assert sites_arg == [
            {"hostId": "h1", "siteId": "s1"},
            {"hostId": "h2", "siteId": "s2"},
        ]

    @pytest.mark.asyncio
    async def test_query_isp_metrics_explicit_per_site_window_wins(self, client):
        # A caller may pin a per-entry window directly; the convenience params
        # must not override an explicit per-site value.
        client.post = AsyncMock(return_value={"data": []})
        await query_isp_metrics(
            client,
            "1h",
            sites=[
                {
                    "hostId": "h1",
                    "siteId": "s1",
                    "beginTimestamp": "2025-06-01T00:00:00Z",
                }
            ],
            start_time="2026-01-01T00:00:00Z",
            end_time="2026-01-02T00:00:00Z",
        )
        _, kwargs = client.post.call_args
        entry = kwargs["json"]["sites"][0]
        assert entry["beginTimestamp"] == "2025-06-01T00:00:00Z"  # explicit wins
        assert entry["endTimestamp"] == "2026-01-02T00:00:00Z"  # filled from param

    @pytest.mark.asyncio
    async def test_query_isp_metrics_no_window_leaves_sites_bare(self, client):
        # With no start/end, site entries carry no timestamp keys.
        client.post = AsyncMock(return_value={"data": []})
        await query_isp_metrics(client, "5m", sites=[{"hostId": "h1", "siteId": "s1"}])
        _, kwargs = client.post.call_args
        assert kwargs["json"]["sites"] == [{"hostId": "h1", "siteId": "s1"}]

    @pytest.mark.asyncio
    async def test_query_isp_metrics_invalid_interval(self, client):
        with pytest.raises(ValueError, match="interval must be"):
            await query_isp_metrics(client, "packetloss")

    @pytest.mark.asyncio
    async def test_query_isp_metrics_requires_sites(self, client):
        # The UniFi API rejects an unscoped query body with an opaque HTTP 400.
        # The tool guards against that by requiring at least one site filter and
        # never issues the request when none is supplied.
        client.post = AsyncMock()
        with pytest.raises(ValueError, match="at least one site"):
            await query_isp_metrics(client, "5m")
        client.post.assert_not_awaited()


class TestSDWAN:
    @pytest.mark.asyncio
    async def test_list_sdwan_configs(self, client):
        client.get = AsyncMock(return_value={"data": [{"id": "cfg1", "name": "Mesh VPN"}]})

        result = await list_sdwan_configs(client)
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_list_sdwan_configs_drains_all_pages(self, client):
        client.get = AsyncMock(
            side_effect=[
                {"data": [{"id": "cfg1"}], "nextToken": "t1"},
                {"data": [{"id": "cfg2"}]},
            ]
        )
        result = await list_sdwan_configs(client)
        assert client.get.call_count == 2
        assert result["count"] == 2
        assert "incomplete" not in result

    @pytest.mark.asyncio
    async def test_list_sdwan_configs_page_token_returns_single_page(self, client):
        client.get = AsyncMock(return_value={"data": [{"id": "cfg1"}], "nextToken": "n2"})
        result = await list_sdwan_configs(client, page_token="p1")
        assert client.get.call_count == 1
        assert result["nextToken"] == "n2"

    @pytest.mark.asyncio
    async def test_list_sdwan_configs_cap_exceeded_marked_incomplete(self):
        capped = UniFiClient(Settings(api_key="test-key", paginate_max_pages=1))
        capped.get = AsyncMock(return_value={"data": [{"id": "cfg1"}], "nextToken": "t1"})
        result = await list_sdwan_configs(capped)
        assert result["incomplete"] is True
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


# --- MSP multi-key aggregation for the list tools (issue #19) ---
# The ``multikey_client`` / ``multikey_registry`` fixtures live in tests/conftest.py so
# every test module shares one multi-key substrate (two keys, disjoint host ownership).


class TestListHostsMultiKey:
    @pytest.mark.asyncio
    async def test_aggregates_hosts_across_all_keys(self, multikey_client, multikey_registry):
        async def _paginate(path, *, key=None):
            return {
                "alpha": [{"id": "h-a", "reportedState": {"hostname": "a"}}],
                "beta": [{"id": "h-b", "reportedState": {"hostname": "b"}}],
            }[key.label]

        multikey_client.paginate = AsyncMock(side_effect=_paginate)

        result = await list_hosts(multikey_client, multikey_registry)
        assert result["count"] == 2
        assert result["key_labels"] == ["alpha", "beta"]
        ids = {h["id"]: h["_keyLabel"] for h in result["hosts"]}
        assert ids == {"h-a": "alpha", "h-b": "beta"}
        assert "errors" not in result

    @pytest.mark.asyncio
    async def test_partial_failure_returns_healthy_key_and_errors(
        self, multikey_client, multikey_registry
    ):
        async def _paginate(path, *, key=None):
            if key.label == "beta":
                raise UniFiConnectionError("HTTP 401 from GET /ea/hosts")
            return [{"id": "h-a", "reportedState": {"hostname": "a"}}]

        multikey_client.paginate = AsyncMock(side_effect=_paginate)

        result = await list_hosts(multikey_client, multikey_registry)
        assert result["count"] == 1
        assert result["hosts"][0]["_keyLabel"] == "alpha"
        assert "errors" in result
        assert any("beta" in e for e in result["errors"])

    @pytest.mark.asyncio
    async def test_all_keys_fail_raises(self, multikey_client, multikey_registry):
        multikey_client.paginate = AsyncMock(
            side_effect=UniFiConnectionError("HTTP 401 from GET /ea/hosts")
        )
        with pytest.raises(RuntimeError, match="All 2 API key"):
            await list_hosts(multikey_client, multikey_registry)

    @pytest.mark.asyncio
    async def test_gps_survives_in_multikey_mode(self, multikey_client, multikey_registry):
        async def _paginate(path, *, key=None):
            return [{"id": f"h-{key.label}", "reportedState": {"hostname": "x", "latitude": 1.0}}]

        multikey_client.paginate = AsyncMock(side_effect=_paginate)

        # Data-survival: aggregated host records carry coordinates through unchanged.
        result = await list_hosts(multikey_client, multikey_registry)
        assert all(h["reportedState"]["latitude"] == 1.0 for h in result["hosts"])


class TestListSitesMultiKey:
    @pytest.mark.asyncio
    async def test_aggregates_sites_across_all_keys(self, multikey_client, multikey_registry):
        async def _paginate(path, *, key=None):
            return {
                "alpha": [{"siteId": "s-a", "siteName": "Alpha HQ"}],
                "beta": [{"siteId": "s-b", "siteName": "Beta HQ"}],
            }[key.label]

        multikey_client.paginate = AsyncMock(side_effect=_paginate)

        result = await list_sites(multikey_client, multikey_registry)
        assert result["count"] == 2
        assert result["key_labels"] == ["alpha", "beta"]
        labels = {s["siteId"]: s["_keyLabel"] for s in result["sites"]}
        assert labels == {"s-a": "alpha", "s-b": "beta"}


class TestListAllSitesAggregatedMultiKey:
    @pytest.mark.asyncio
    async def test_aggregates_across_all_keys(self, multikey_client, multikey_registry):
        async def _get(path, *, key=None, params=None):
            return {
                "alpha": {"data": [{"id": "s-a", "name": "Alpha"}]},
                "beta": {"data": [{"id": "s-b", "name": "Beta"}]},
            }[key.label]

        multikey_client.get = AsyncMock(side_effect=_get)

        result = await list_all_sites_aggregated(multikey_client, multikey_registry)
        assert result["count"] == 2
        assert result["key_labels"] == ["alpha", "beta"]
        labels = {s["id"]: s["_keyLabel"] for s in result["sites"]}
        assert labels == {"s-a": "alpha", "s-b": "beta"}

    @pytest.mark.asyncio
    async def test_partial_failure_surfaces_errors(self, multikey_client, multikey_registry):
        async def _get(path, *, key=None, params=None):
            if key.label == "alpha":
                raise UniFiConnectionError("HTTP 500")
            return {"data": [{"id": "s-b", "name": "Beta"}]}

        multikey_client.get = AsyncMock(side_effect=_get)

        result = await list_all_sites_aggregated(multikey_client, multikey_registry)
        assert result["count"] == 1
        assert result["sites"][0]["_keyLabel"] == "beta"
        assert "errors" in result
