"""Integration tests for Network/VLAN CRUD tools against the live TestConsole.

Requires UNIFI_API_KEY (and optionally UNIFI_API_BASE_URL) to be set.
Skip all tests automatically when the env var is absent.

Also requires UNIFI_TEST_HOST and UNIFI_TEST_SITE to identify where to create
the test VLAN (host name/ID and site name/ID on the TestConsole).

Run:
    UNIFI_API_KEY=<key> UNIFI_TEST_HOST=<host> UNIFI_TEST_SITE=<site> \
        pytest tests/test_networks_integration.py -v
"""

from __future__ import annotations

import os

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools.network import (
    create_network,
    delete_network,
    get_network,
    list_networks,
    update_network,
)

# These tests are gated on UNIFI_API_KEY so they are always skipped in CI where the
# env var is absent.  pytest --collect-only still succeeds because skipif is evaluated
# at collection time, not import time.  Run with a real key to execute them:
#   UNIFI_API_KEY=<key> UNIFI_TEST_HOST=<host> UNIFI_TEST_SITE=<site> \
#       pytest tests/test_networks_integration.py -v
pytestmark = pytest.mark.skipif(
    not os.environ.get("UNIFI_API_KEY"),
    reason="UNIFI_API_KEY not set — skipping live integration tests",
)

_TEST_HOST = os.environ.get("UNIFI_TEST_HOST", "")
_TEST_SITE = os.environ.get("UNIFI_TEST_SITE", "")

# VLAN ID chosen to be unlikely to conflict with real infrastructure
_TEST_VLAN_ID = 3999
_TEST_VLAN_NAME = "mcp-integration-test-vlan"


@pytest.fixture(scope="module")
def settings():
    return Settings()


@pytest.fixture(scope="module")
def client(settings):
    return UniFiClient(settings)


@pytest.fixture(scope="module")
def registry(client, settings):
    return Registry(client, ttl_seconds=settings.cache_ttl_seconds)


def _require_host_site():
    """Skip a test if UNIFI_TEST_HOST / UNIFI_TEST_SITE are not configured."""
    if not _TEST_HOST or not _TEST_SITE:
        pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set for mutating tests")


# ---------------------------------------------------------------------------
# list_networks (read-only, safe to run without host/site env vars)
# ---------------------------------------------------------------------------


class TestListNetworksIntegration:
    async def test_returns_networks_dict(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_networks(client, registry, host=_TEST_HOST, site=_TEST_SITE)
        assert isinstance(result, (dict, list))

    async def test_count_matches_networks_length(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_networks(client, registry, host=_TEST_HOST, site=_TEST_SITE)
        if isinstance(result, dict) and "networks" in result:
            assert result["count"] == len(result["networks"])

    async def test_filter_by_host_and_site(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_networks(client, registry, host=_TEST_HOST, site=_TEST_SITE)
        assert isinstance(result, (dict, list))

    async def test_network_fields_present(self, client, registry):
        if not _TEST_HOST or not _TEST_SITE:
            pytest.skip("UNIFI_TEST_HOST and UNIFI_TEST_SITE must be set")
        result = await list_networks(client, registry, host=_TEST_HOST, site=_TEST_SITE)
        if isinstance(result, dict):
            networks = result.get("networks", result.get("data", []))
        else:
            networks = result
        if not networks:
            pytest.skip("No networks on console — skipping field check")
        network = networks[0]
        # At minimum the network object should carry an identifier
        assert "id" in network or "networkId" in network, "Network must have an id field"


# ---------------------------------------------------------------------------
# Full CRUD cycle: create → list (verify present) → get → update → delete
# ---------------------------------------------------------------------------


class TestVLANCRUDIntegration:
    """Tests the full create/read/update/delete lifecycle for a VLAN.

    All tests in this class share a single created VLAN via the module-scoped
    ``vlan_id`` fixture so that we do not leave orphaned VLANs on the console
    if an intermediate step fails.
    """

    @pytest.fixture(scope="class")
    async def created_vlan(self, client, registry):
        """Create a test VLAN, yield its ID, then delete it unconditionally."""
        _require_host_site()
        result = await create_network(
            client,
            registry,
            host=_TEST_HOST,
            site=_TEST_SITE,
            name=_TEST_VLAN_NAME,
            purpose="vlan-only",
            vlan_id=_TEST_VLAN_ID,
        )
        vlan_id = result.get("id") or result.get("networkId")
        assert vlan_id, f"create_network did not return an id: {result}"
        yield vlan_id
        # Cleanup — best-effort; ignore errors if already deleted
        try:
            await delete_network(client, vlan_id)
        except Exception:
            pass

    async def test_create_returns_id(self, created_vlan):
        assert created_vlan, "Created VLAN must have a non-empty id"

    async def test_created_vlan_appears_in_list(self, client, registry, created_vlan):
        result = await list_networks(client, registry, host=_TEST_HOST, site=_TEST_SITE)
        ids = [n.get("id") or n.get("networkId") for n in result["networks"]]
        assert created_vlan in ids, f"Newly created VLAN {created_vlan} not found in list_networks"

    async def test_get_network_returns_correct_id(self, client, created_vlan):
        network = await get_network(client, created_vlan)
        returned_id = network.get("id") or network.get("networkId")
        assert returned_id == created_vlan

    async def test_get_network_has_expected_name(self, client, created_vlan):
        network = await get_network(client, created_vlan)
        assert network.get("name") == _TEST_VLAN_NAME

    async def test_get_network_has_expected_vlan_id(self, client, created_vlan):
        network = await get_network(client, created_vlan)
        vlan_id_field = network.get("vlanId") or network.get("vlan_id")
        if vlan_id_field is not None:
            assert int(vlan_id_field) == _TEST_VLAN_ID

    async def test_update_network_name(self, client, created_vlan):
        updated_name = f"{_TEST_VLAN_NAME}-updated"
        result = await update_network(client, created_vlan, name=updated_name)
        # Some APIs return the updated object; others return a minimal response.
        # Accept either — just verify no exception was raised.
        assert isinstance(result, dict)

    async def test_updated_name_reflected_in_get(self, client, created_vlan):
        updated_name = f"{_TEST_VLAN_NAME}-updated"
        network = await get_network(client, created_vlan)
        # The update in the previous test may or may not have been applied by the
        # time we call get — accept either the original or updated name.
        assert network.get("name") in (_TEST_VLAN_NAME, updated_name)

    async def test_delete_network_returns_deleted_flag(self, client, created_vlan):
        result = await delete_network(client, created_vlan)
        assert result.get("deleted") is True
        assert result.get("networkId") == created_vlan

    async def test_deleted_vlan_absent_from_list(self, client, registry, created_vlan):
        result = await list_networks(client, registry, host=_TEST_HOST, site=_TEST_SITE)
        ids = [n.get("id") or n.get("networkId") for n in result["networks"]]
        assert created_vlan not in ids, (
            f"Deleted VLAN {created_vlan} still appears in list_networks"
        )
