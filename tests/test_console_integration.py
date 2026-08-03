"""Integration tests for test console — key isolation, WiFi, device, and client tools.

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
import pytest_asyncio

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.clients import _list_clients as list_clients
from unifi_fabric.tools.device_mgmt import (
    _list_pending_devices as list_pending_devices,
)
from unifi_fabric.tools.device_mgmt import (
    _list_site_devices as list_site_devices,
)
from unifi_fabric.tools.innerspace import get_innerspace_summary
from unifi_fabric.tools.network import get_wifi_broadcast, list_wifi_broadcasts
from unifi_fabric.tools.site_manager import list_hosts, list_sites

# These tests are gated on UNIFI_API_KEY so they are always skipped in CI where the
# env var is absent.  pytest --collect-only still succeeds because skipif is evaluated
# at collection time, not import time.  Run with a real key to execute them:
#   UNIFI_API_KEY=<key> pytest tests/test_console_integration.py -v
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
    pytest.mark.asyncio(loop_scope="module"),
]

_TEST_HOST = os.environ.get("UNIFI_TEST_HOST", "")
_TEST_SITE = os.environ.get("UNIFI_TEST_SITE", "")


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
# Per-key isolation — key label config
# ---------------------------------------------------------------------------


class TestKeyIsolation:
    def test_list_key_labels_returns_list(self, client):
        labels = client.list_key_labels()
        assert isinstance(labels, list), "list_key_labels must return a list"
        assert len(labels) >= 1, "At least one key label should be configured"

    def test_default_key_label_present(self, client):
        # The default (first) key's label depends on configuration: "default" when configured
        # via the UNIFI_API_KEY shorthand, or the named label when configured via UNIFI_API_KEYS
        # (as in production). Assert the default key's label is actually among the configured
        # labels rather than hardcoding "default".
        labels = client.list_key_labels()
        default_label = client._default_key().label
        assert default_label in labels

    def test_get_key_by_default_label(self, client):
        default_label = client._default_key().label
        cfg = client.get_key_by_label(default_label)
        assert cfg.key, "Default key config must have a non-empty key"
        assert cfg.label == default_label

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


# ---------------------------------------------------------------------------
# InnerSpace — read-only; skips cleanly when the feature is not licensed
# ---------------------------------------------------------------------------


class TestInnerSpaceIntegration:
    """InnerSpace is a licensed add-on. On an estate without it the API returns 403.

    That is an environment limitation, not a defect: the tool surfaces the error and the
    test must SKIP with a clear reason rather than fail. If InnerSpace IS licensed, the
    summary must come back as a dict.
    """

    async def test_summary_or_skip_when_unlicensed(self, client, registry):
        if not _TEST_HOST:
            pytest.skip("UNIFI_TEST_HOST must be set for InnerSpace test")
        try:
            result = await get_innerspace_summary(client, registry, _TEST_HOST)
        except UniFiConnectionError as exc:
            if "403" in str(exc):
                pytest.skip(f"InnerSpace not licensed on this host (403): {exc}")
            raise
        assert isinstance(result, dict)
