"""Tests for cross-site aggregation tools."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastmcp import FastMCP

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.aggregation import (
    _fleet_summary,
    _get_all_host_site_pairs,
    _list_all_clients_fleet,
    _list_all_devices_fleet,
    _list_api_keys,
    _search_device,
    _unwrap_ea_devices,
    register,
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


_UUID_S1 = "11111111-0000-4000-8000-000000000001"
_UUID_S2 = "22222222-0000-4000-8000-000000000002"


class TestGetAllHostSitePairs:
    async def test_valid_pairs_included(self, registry):
        ea_sites = [
            {"hostId": "host-abc123", "hostname": "c1"},
            {"hostId": "aabbccdd:12345", "hostname": "c2"},
        ]
        registry.get_ea_sites = AsyncMock(return_value=ea_sites)

        async def mock_get_sites(host_id, **kwargs):
            if host_id == "host-abc123":
                return [{"id": _UUID_S1, "description": "Site 1"}]
            return [{"id": _UUID_S2, "description": "Site 2"}]

        registry.get_sites = AsyncMock(side_effect=mock_get_sites)

        pairs = await _get_all_host_site_pairs(registry)
        assert len(pairs) == 2

    async def test_malformed_host_id_skipped(self, registry):
        ea_sites = [
            {"hostId": "valid-host", "hostname": "c1"},
            {"hostId": "../bad", "hostname": "c2"},
        ]
        registry.get_ea_sites = AsyncMock(return_value=ea_sites)
        registry.get_sites = AsyncMock(return_value=[{"id": _UUID_S1, "description": "Site 1"}])

        pairs = await _get_all_host_site_pairs(registry)
        assert len(pairs) == 1
        assert pairs[0]["hostId"] == "valid-host"

    async def test_non_uuid_site_id_skipped(self, registry):
        """Proxy sites with non-UUID IDs (e.g. Fabric ObjectIds) are skipped."""
        ea_sites = [
            {"hostId": "h1", "hostname": "c1"},
            {"hostId": "h2", "hostname": "c2"},
        ]
        registry.get_ea_sites = AsyncMock(return_value=ea_sites)

        async def mock_get_sites(host_id, **kwargs):
            if host_id == "h1":
                # ObjectId — not a valid UUID for proxy URLs
                return [{"id": "5d21296497ba433a10af6cbd", "description": "Bad"}]
            return [{"id": _UUID_S2, "description": "Good"}]

        registry.get_sites = AsyncMock(side_effect=mock_get_sites)

        pairs = await _get_all_host_site_pairs(registry)
        assert len(pairs) == 1
        assert pairs[0]["siteId"] == _UUID_S2

    async def test_get_sites_failure_skips_host(self, registry):
        """If proxy /sites fetch fails for a host, that host is skipped gracefully."""
        ea_sites = [
            {"hostId": "h1", "hostname": "c1"},
            {"hostId": "h2", "hostname": "c2"},
        ]
        registry.get_ea_sites = AsyncMock(return_value=ea_sites)

        async def mock_get_sites(host_id, **kwargs):
            if host_id == "h1":
                raise RuntimeError("timeout")
            return [{"id": _UUID_S2, "description": "Good"}]

        registry.get_sites = AsyncMock(side_effect=mock_get_sites)

        pairs = await _get_all_host_site_pairs(registry)
        assert len(pairs) == 1
        assert pairs[0]["hostId"] == "h2"


class TestListAllDevicesFleet:
    async def test_returns_all_devices(self, client):
        devices = [
            {"name": "switch-1", "state": "online", "mac": "aa:bb:cc:dd:ee:01"},
            {"name": "ap-1", "state": "offline", "mac": "aa:bb:cc:dd:ee:02"},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _list_all_devices_fleet(client)

        assert result["count"] == 2
        assert len(result["devices"]) == 2
        client.paginate.assert_called_once_with("/ea/devices", key=None)

    async def test_filters_by_status(self, client):
        devices = [
            {"name": "switch-1", "state": "online"},
            {"name": "ap-1", "state": "offline"},
            {"name": "ap-2", "state": "offline"},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _list_all_devices_fleet(client, status_filter="offline")

        assert result["count"] == 2
        assert all(d["state"] == "offline" for d in result["devices"])

    async def test_status_filter_case_insensitive(self, client):
        devices = [{"name": "switch-1", "status": "Online"}]
        client.paginate = AsyncMock(return_value=devices)

        result = await _list_all_devices_fleet(client, status_filter="online")

        assert result["count"] == 1


class TestListAllClientsFleet:
    async def test_aggregates_clients_from_all_sites(self, client, registry):
        ea_sites = [
            {"hostId": "h1", "hostname": "console-1"},
            {"hostId": "h2", "hostname": "console-2"},
        ]
        registry.get_ea_sites = AsyncMock(return_value=ea_sites)

        async def mock_get_sites(host_id, **kwargs):
            if host_id == "h1":
                return [{"id": _UUID_S1, "description": "Site A"}]
            return [{"id": _UUID_S2, "description": "Site B"}]

        registry.get_sites = AsyncMock(side_effect=mock_get_sites)

        client_data_s1 = [{"mac": "aa:bb:01", "name": "laptop-1"}]
        client_data_s2 = [
            {"mac": "aa:bb:02", "name": "phone-1"},
            {"mac": "aa:bb:03", "name": "phone-2"},
        ]

        async def mock_get(path, **kwargs):
            if _UUID_S1 in path:
                return client_data_s1
            return client_data_s2

        client.get = AsyncMock(side_effect=mock_get)

        result = await _list_all_clients_fleet(client, registry)

        assert result["count"] == 3
        assert result["sitesQueried"] == 2
        assert "errors" not in result
        # Check annotations
        assert result["clients"][0]["_siteName"] == "Site A"

    async def test_handles_site_errors_gracefully(self, client, registry):
        ea_sites = [
            {"hostId": "h1", "hostname": "console-1"},
        ]
        registry.get_ea_sites = AsyncMock(return_value=ea_sites)
        registry.get_sites = AsyncMock(return_value=[{"id": _UUID_S1, "description": "Site A"}])
        client.get = AsyncMock(side_effect=Exception("Connection timeout"))

        with pytest.raises(RuntimeError, match="All 1 site"):
            await _list_all_clients_fleet(client, registry)


class TestFleetSummary:
    async def test_returns_summary(self, client, registry):
        hosts = [{"id": "h1"}, {"id": "h2"}]
        sites = [{"siteId": "s1"}, {"siteId": "s2"}, {"siteId": "s3"}]
        # Real EA API uses "state" for connectivity and "productLine" for product category
        devices = [
            {"state": "online", "productLine": "network"},
            {"state": "online", "productLine": "protect"},
            {"state": "offline", "productLine": "network"},
        ]

        call_count = 0

        async def mock_paginate(path, **kwargs):
            nonlocal call_count
            call_count += 1
            if "hosts" in path:
                return hosts
            if "sites" in path:
                return sites
            return devices

        client.paginate = AsyncMock(side_effect=mock_paginate)

        result = await _fleet_summary(client, registry)

        assert result["hosts"] == 2
        assert result["sites"] == 3
        assert result["devices"]["total"] == 3
        assert result["devices"]["byStatus"]["online"] == 2
        assert result["devices"]["byStatus"]["offline"] == 1
        assert result["devices"]["byType"]["network"] == 2
        assert result["devices"]["byType"]["protect"] == 1

    async def test_summary_falls_back_to_legacy_fields(self, client, registry):
        """Devices with legacy 'status'/'type' fields are still bucketed correctly."""
        hosts = [{"id": "h1"}]
        sites = [{"siteId": "s1"}]
        devices = [
            {"status": "online", "type": "usw"},
            {"status": "offline", "type": "uap"},
        ]

        async def mock_paginate(path, **kwargs):
            if "hosts" in path:
                return hosts
            if "sites" in path:
                return sites
            return devices

        client.paginate = AsyncMock(side_effect=mock_paginate)

        result = await _fleet_summary(client, registry)

        assert result["devices"]["total"] == 2
        assert result["devices"]["byStatus"]["online"] == 1
        assert result["devices"]["byStatus"]["offline"] == 1
        assert result["devices"]["byType"]["usw"] == 1
        assert result["devices"]["byType"]["uap"] == 1

    async def test_summary_unwraps_host_wrapper_objects(self, client, registry):
        """/ea/devices returns [{hostId, devices:[...]}, ...] — summary must unwrap."""
        hosts = [{"id": "h1"}]
        sites = [{"siteId": "s1"}]
        # Host-wrapper format returned by the real EA API
        wrapped_devices = [
            {
                "hostId": "h1",
                "devices": [
                    {"state": "online", "productLine": "network"},
                    {"state": "offline", "productLine": "network"},
                ],
            },
            {
                "hostId": "h2",
                "devices": [
                    {"state": "online", "productLine": "protect"},
                ],
            },
        ]

        async def mock_paginate(path, **kwargs):
            if "hosts" in path:
                return hosts
            if "sites" in path:
                return sites
            return wrapped_devices

        client.paginate = AsyncMock(side_effect=mock_paginate)

        result = await _fleet_summary(client, registry)

        assert result["devices"]["total"] == 3
        assert result["devices"]["byStatus"]["online"] == 2
        assert result["devices"]["byStatus"]["offline"] == 1
        assert result["devices"]["byType"]["network"] == 2
        assert result["devices"]["byType"]["protect"] == 1


class TestUnwrapEaDevices:
    def test_flat_list_passthrough(self):
        """Flat device objects (no wrapper) are returned as-is."""
        devices = [{"id": "d1"}, {"id": "d2"}]
        assert _unwrap_ea_devices(devices) == devices

    def test_host_wrapper_unwrapped(self):
        """Host-wrapper objects are unwrapped to their inner device lists."""
        raw = [
            {"hostId": "h1", "devices": [{"id": "d1"}, {"id": "d2"}]},
            {"hostId": "h2", "devices": [{"id": "d3"}]},
        ]
        result = _unwrap_ea_devices(raw)
        assert result == [{"id": "d1"}, {"id": "d2"}, {"id": "d3"}]

    def test_empty_inner_list(self):
        raw = [{"hostId": "h1", "devices": []}]
        assert _unwrap_ea_devices(raw) == []

    def test_empty_input(self):
        assert _unwrap_ea_devices([]) == []


class TestSearchDevice:
    async def test_search_by_name(self, client):
        devices = [
            {"name": "office-switch-1", "mac": "aa:bb:01", "model": "USW-24"},
            {"name": "lobby-ap", "mac": "aa:bb:02", "model": "U6-LR"},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "switch")

        assert result["count"] == 1
        assert result["matches"][0]["name"] == "office-switch-1"

    async def test_search_by_mac(self, client):
        devices = [
            {"name": "ap-1", "mac": "aa:bb:cc:dd:ee:01", "model": "U6"},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "aa:bb:cc")

        assert result["count"] == 1

    async def test_search_by_model(self, client):
        devices = [
            {"name": "ap-1", "mac": "aa:01", "model": "U6-LR"},
            {"name": "ap-2", "mac": "aa:02", "model": "U6-Pro"},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "U6")

        assert result["count"] == 2

    async def test_search_no_matches(self, client):
        devices = [{"name": "ap-1", "mac": "aa:01", "model": "U6"}]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "nonexistent")

        assert result["count"] == 0

    async def test_search_by_shortname(self, client):
        devices = [
            {"name": "device-1", "mac": "aa:01", "model": "UDMPRO", "shortname": "UDM Pro"},
            {"name": "device-2", "mac": "aa:02", "model": "U6-LR"},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "UDM")

        assert result["count"] == 1
        assert result["matches"][0]["name"] == "device-1"

    async def test_search_case_insensitive(self, client):
        devices = [
            {"name": "device-1", "mac": "aa:01", "model": "UDMPRO", "shortname": "UDM Pro"},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result_upper = await _search_device(client, "UDM")
        result_lower = await _search_device(client, "udm")

        assert result_upper["count"] == 1
        assert result_lower["count"] == 1

    async def test_search_by_hostname(self, client):
        devices = [
            {"name": "gw-1", "mac": "aa:01", "model": "UDR", "hostname": "gateway.local"},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "gateway")

        assert result["count"] == 1

    async def test_search_by_reported_state_hostname(self, client):
        devices = [
            {
                "name": "gw-2",
                "mac": "aa:02",
                "model": "UDR",
                "reportedState": {"hostname": "router.home"},
            },
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "router.home")

        assert result["count"] == 1

    async def test_search_by_ip(self, client):
        devices = [
            {"name": "ap-1", "mac": "aa:01", "model": "U6", "ip": "192.168.1.50"},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "192.168.1")

        assert result["count"] == 1

    async def test_search_by_reported_state_model(self, client):
        """Model stored in reportedState (real EA API format) is still searchable."""
        devices = [
            {
                "name": "",
                "mac": "",
                "reportedState": {"hostname": "udm-pro", "model": "UDMPRO", "shortname": "UDM Pro"},
            },
            {
                "name": "",
                "mac": "",
                "reportedState": {"hostname": "ap-lr", "model": "U6-LR", "shortname": "U6 LR"},
            },
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "UDM")

        assert result["count"] == 1
        assert result["matches"][0]["reportedState"]["model"] == "UDMPRO"

    async def test_search_by_reported_state_ip(self, client):
        """IP stored in reportedState is still searchable."""
        devices = [
            {"name": "", "reportedState": {"ip": "10.0.0.1", "hostname": "gw"}},
            {"name": "", "reportedState": {"ip": "10.0.0.2", "hostname": "ap"}},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "10.0.0.1")

        assert result["count"] == 1

    async def test_search_by_reported_state_mac(self, client):
        """MAC stored in reportedState is still searchable."""
        devices = [
            {"name": "", "reportedState": {"mac": "aa:bb:cc:dd:ee:01", "hostname": "sw"}},
        ]
        client.paginate = AsyncMock(return_value=devices)

        result = await _search_device(client, "aa:bb:cc")

        assert result["count"] == 1

    async def test_search_unwraps_host_wrapper(self, client):
        """When /ea/devices returns host-wrapper objects, inner devices are searchable."""
        wrapped = [
            {
                "hostId": "h1",
                "devices": [
                    {"name": "office-switch-1", "mac": "aa:bb:cc:dd:ee:01", "model": "USW-24"},
                    {"name": "lobby-ap", "mac": "aa:bb:cc:dd:ee:02", "model": "U6-LR"},
                ],
            },
            {
                "hostId": "h2",
                "devices": [
                    {"name": "remote-ap", "mac": "11:22:33:44:55:66", "model": "U6-Pro"},
                ],
            },
        ]
        client.paginate = AsyncMock(return_value=wrapped)

        result = await _search_device(client, "switch")

        assert result["count"] == 1
        assert result["matches"][0]["name"] == "office-switch-1"

    async def test_search_unwrap_empty_devices_list(self, client):
        """Host wrapper with empty devices list contributes no results."""
        wrapped = [
            {"hostId": "h1", "devices": []},
            {"hostId": "h2", "devices": [{"name": "ap-1", "mac": "aa:01", "model": "U6"}]},
        ]
        client.paginate = AsyncMock(return_value=wrapped)

        result = await _search_device(client, "ap")

        assert result["count"] == 1
        assert result["matches"][0]["name"] == "ap-1"


# --- _list_api_keys / list_configured_api_keys (previously ZERO coverage) ---


class TestListApiKeys:
    """The only tool with no test at any layer. Covers single-, multi-, and zero-key."""

    async def test_single_key_returns_one_entry(self):
        client = UniFiClient(Settings(api_key="test-key"))
        result = await _list_api_keys(client)
        assert result["count"] == 1
        assert result["keys"] == [{"label": "default", "is_org_key": False}]

    async def test_multi_key_returns_both_with_correct_is_org_key(self, multikey_client):
        # multikey_client: alpha (personal) + beta (organization).
        result = await _list_api_keys(multikey_client)
        assert result["count"] == 2
        by_label = {k["label"]: k["is_org_key"] for k in result["keys"]}
        assert by_label == {"alpha": False, "beta": True}

    async def test_zero_key_returns_empty(self):
        client = UniFiClient(Settings())  # neither api_key nor api_keys set
        result = await _list_api_keys(client)
        assert result["count"] == 0
        assert result["keys"] == []

    async def test_never_exposes_key_values(self, multikey_client):
        """Only label + is_org_key are surfaced — never the secret key material (SR-8)."""
        result = await _list_api_keys(multikey_client)
        for entry in result["keys"]:
            assert set(entry) == {"label", "is_org_key"}

    async def test_wrapper_list_configured_api_keys(self, multikey_client, registry):
        """The registered MCP wrapper returns the same payload as the underlying helper."""
        mcp = FastMCP("test")
        register(mcp, lambda: (multikey_client, registry))
        tool = await mcp.get_tool("list_configured_api_keys")
        result = await tool.fn()
        assert result == await _list_api_keys(multikey_client)


# --- Cross-key / cross-site partial failure during fan-out (issue #19 semantics) ---


class TestListAllClientsFleetPartialFailure:
    """One target valid, another 401ing during fan-out.

    Intended contract (mirrors _list_all_clients_fleet): partial results are returned
    with an error surface; a RuntimeError is raised only if EVERY target fails.
    """

    async def test_partial_failure_returns_results_and_error_surface(self, client, registry):
        ea_sites = [
            {"hostId": "h1", "hostname": "console-1"},
            {"hostId": "h2", "hostname": "console-2"},
        ]
        registry.get_ea_sites = AsyncMock(return_value=ea_sites)

        async def mock_get_sites(host_id, **kwargs):
            if host_id == "h1":
                return [{"id": _UUID_S1, "description": "Healthy Site"}]
            return [{"id": _UUID_S2, "description": "Unauthorized Site"}]

        registry.get_sites = AsyncMock(side_effect=mock_get_sites)

        async def mock_get(path, **kwargs):
            if _UUID_S1 in path:
                return [{"mac": "aa:bb:01", "name": "laptop-1"}]
            raise UniFiConnectionError("HTTP 401 from GET /clients")

        client.get = AsyncMock(side_effect=mock_get)

        result = await _list_all_clients_fleet(client, registry)

        # Partial results: only the healthy site's clients come back...
        assert result["count"] == 1
        assert result["clients"][0]["_siteName"] == "Healthy Site"
        # ...and the failure is surfaced rather than swallowed.
        assert "errors" in result
        assert len(result["errors"]) == 1
        assert "Unauthorized Site" in result["errors"][0]

    async def test_all_targets_fail_raises(self, client, registry):
        """Raise only when EVERY target fails — the all-or-nothing boundary."""
        registry.get_ea_sites = AsyncMock(return_value=[{"hostId": "h1", "hostname": "c1"}])
        registry.get_sites = AsyncMock(return_value=[{"id": _UUID_S1, "description": "Site A"}])
        client.get = AsyncMock(side_effect=UniFiConnectionError("HTTP 401"))

        with pytest.raises(RuntimeError, match="All 1 site"):
            await _list_all_clients_fleet(client, registry)


# --- Multi-key routing for a fleet tool that calls client.paginate directly ---


class TestListAllDevicesFleetMultiKey:
    """A tool calling client.paginate directly must ride the requested (non-first) key."""

    async def test_key_label_scopes_paginate_to_non_first_key(self, multikey_client):
        beta = multikey_client.get_key_by_label("beta")
        captured: dict[str, APIKeyConfig | None] = {}

        async def _paginate(path, *, key=None):
            captured["key"] = key
            return [{"name": "beta-switch", "state": "online"}]

        multikey_client.paginate = AsyncMock(side_effect=_paginate)

        result = await _list_all_devices_fleet(multikey_client, key_label="beta")

        # The request must ride the beta key — NOT the default (first/alpha) key.
        assert captured["key"] == beta
        assert captured["key"].label == "beta"
        assert result["key_label"] == "beta"
        assert result["count"] == 1
