"""Integration tests for TestConsole — key isolation, WiFi, device, and client tools.

Tests per-key isolation (key label config) and read-only operations for tools
not covered by other integration test files.

Requires UNIFI_API_KEY (and optionally UNIFI_API_BASE_URL) to be set.
Mutating / host-scoped tests additionally require UNIFI_TEST_HOST and UNIFI_TEST_SITE.

Run:
    UNIFI_API_KEY=<key> pytest tests/test_console_integration.py -v
    UNIFI_API_KEY=<key> UNIFI_TEST_HOST=<host> UNIFI_TEST_SITE=<site> \
        pytest tests/test_console_integration.py -v
"""

from __future__ import annotations

import os

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.clients import _list_clients as list_clients
from unifi_fabric.tools.device_mgmt import (
    _list_pending_devices as list_pending_devices,
)
from unifi_fabric.tools.device_mgmt import (
    _list_site_devices as list_site_devices,
)
from unifi_fabric.tools.network import get_wifi_broadcast, list_wifi_broadcasts
from unifi_fabric.tools.site_manager import list_hosts, list_sites

# These tests are gated on UNIFI_API_KEY so they are always skipped in CI where the
# env var is absent.  pytest --collect-only still succeeds because skipif is evaluated
# at collection time, not import time.  Run with a real key to execute them:
#   UNIFI_API_KEY=<key> pytest tests/test_console_integration.py -v
pytestmark = pytest.mark.skipif(
    not os.environ.get("UNIFI_API_KEY"),
    reason="UNIFI_API_KEY not set — skipping live integration tests",
)

_TEST_HOST = os.environ.get("UNIFI_TEST_HOST", "")
_TEST_SITE = os.environ.get("UNIFI_TEST_SITE", "")


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
# Per-key isolation — key label config
# ---------------------------------------------------------------------------


class TestKeyIsolation:
    def test_list_key_labels_returns_list(self, client):
        labels = client.list_key_labels()
        assert isinstance(labels, list), "list_key_labels must return a list"
        assert len(labels) >= 1, "At least one key label should be configured"

    def test_default_label_present(self, client):
        labels = client.list_key_labels()
        # When configured via UNIFI_API_KEY shorthand, label is 'default'
        assert "default" in labels, "Expected 'default' label when configured via UNIFI_API_KEY"

    def test_get_key_by_label_default(self, client):
        cfg = client.get_key_by_label("default")
        assert cfg.key, "Default key config must have a non-empty key"
        assert cfg.label == "default"

    def test_get_key_by_label_unknown_raises(self, client):
        with pytest.raises(KeyError):
            client.get_key_by_label("nonexistent-console")

    def test_key_label_matches_list(self, client):
        labels = client.list_key_labels()
        for label in labels:
            cfg = client.get_key_by_label(label)
            assert cfg.label == label


# ---------------------------------------------------------------------------
# WiFi (WLAN) — read-only
# ---------------------------------------------------------------------------


class TestListWifiBroadcastsIntegration:
    async def test_returns_broadcasts(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_wifi_broadcasts(client, registry, _TEST_HOST, _TEST_SITE)
        assert isinstance(result, dict), "list_wifi_broadcasts must return a dict"

    async def test_broadcast_has_name_field(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_wifi_broadcasts(client, registry, _TEST_HOST, _TEST_SITE)
        items = result.get("data", result.get("broadcasts", []))
        if not items:
            pytest.skip("No WiFi broadcasts on site — skipping field check")
        assert "name" in items[0], "Broadcast must have a name field"


class TestGetWifiBroadcastIntegration:
    async def test_get_broadcast_by_id(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_wifi_broadcasts(client, registry, _TEST_HOST, _TEST_SITE)
        items = result.get("data", result.get("broadcasts", []))
        if not items:
            pytest.skip("No WiFi broadcasts on site — skipping get test")
        broadcast_id = items[0].get("id") or items[0].get("_id")
        assert broadcast_id, "Could not determine broadcast id from list"

        broadcast = await get_wifi_broadcast(client, registry, _TEST_HOST, _TEST_SITE, broadcast_id)
        returned_id = broadcast.get("id") or broadcast.get("_id")
        assert returned_id == broadcast_id


# ---------------------------------------------------------------------------
# Device management — read-only (require UNIFI_TEST_HOST/SITE)
# ---------------------------------------------------------------------------


class TestListSiteDevicesIntegration:
    async def test_returns_list_or_dict(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_site_devices(client, registry, _TEST_HOST, _TEST_SITE)
        assert isinstance(result, (list, dict)), "list_site_devices must return list or dict"

    async def test_device_has_id_field(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_site_devices(client, registry, _TEST_HOST, _TEST_SITE)
        devices = result if isinstance(result, list) else result.get("data", [])
        if not devices:
            pytest.skip("No devices on this site — skipping field check")
        device = devices[0]
        assert "id" in device or "deviceId" in device or "mac" in device, (
            "Device must have an id, deviceId, or mac field"
        )


class TestListPendingDevicesIntegration:
    async def test_returns_list_or_dict(self, client, registry):
        if not _TEST_HOST:
            pytest.skip("UNIFI_TEST_HOST must be set")
        result = await list_pending_devices(client, registry, _TEST_HOST)
        assert isinstance(result, (list, dict)), "list_pending_devices must return list or dict"


# ---------------------------------------------------------------------------
# Client listing — read-only (require UNIFI_TEST_HOST/SITE)
# ---------------------------------------------------------------------------


class TestListClientsIntegration:
    async def test_returns_list_or_dict(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_clients(client, registry, _TEST_HOST, _TEST_SITE)
        assert isinstance(result, (list, dict)), "list_clients must return list or dict"

    async def test_client_has_expected_field(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_clients(client, registry, _TEST_HOST, _TEST_SITE)
        clients = result if isinstance(result, list) else result.get("data", [])
        if not clients:
            pytest.skip("No clients on this site — skipping field check")
        c = clients[0]
        assert "id" in c or "mac" in c or "hostname" in c, "Client must have id, mac, or hostname"


# ---------------------------------------------------------------------------
# Cross-check: same key resolves consistent hosts
# ---------------------------------------------------------------------------


class TestKeyConsistencyIntegration:
    async def test_list_hosts_consistent_across_calls(self, client, registry):
        """Two calls with the same key should return the same host set."""
        registry.invalidate()
        first = await list_hosts(client, registry)
        registry.invalidate()
        second = await list_hosts(client, registry)

        first_ids = {h.get("id") for h in first["hosts"]}
        second_ids = {h.get("id") for h in second["hosts"]}
        assert first_ids == second_ids, "Host list should be stable across calls"

    async def test_list_sites_consistent_across_calls(self, client, registry):
        """Two calls with the same key should return the same site set."""
        registry.invalidate()
        first = await list_sites(client, registry)
        registry.invalidate()
        second = await list_sites(client, registry)

        first_ids = {s.get("siteId") or s.get("id") for s in first["sites"]}
        second_ids = {s.get("siteId") or s.get("id") for s in second["sites"]}
        assert first_ids == second_ids, "Site list should be stable across calls"
