"""Multi-key routing tests for per-host tools (network / clients / device_mgmt / protect).

Why this file exists
--------------------
``Registry.resolve_key_for_host`` (issue #19) knows which configured API key OWNS a given
host. The **per-host** tools are now wired to it: each resolves the owning key first and
threads it through host/site resolution *and* the data request, so a host owned by a
non-first ("beta") key routes on the beta credential instead of silently riding the
default (first) key — the exact production bug an external user hit, and the exact bug a
single-key test can never see.

These tests assert the CORRECT end-state directly: a per-host tool acting on a host owned
by the non-first ("beta") key sends its data request on the beta key; a host owned by the
first ("alpha") key rides alpha. The registry's per-key host caches are seeded so
``resolve_key_for_host`` resolves the owner without any live ``/v1/hosts`` fetch, isolating
the assertion to *which key the data request carries*.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.registry import Registry
from unifi_fabric.tools.clients import _list_clients
from unifi_fabric.tools.device_mgmt import _list_site_devices
from unifi_fabric.tools.firewall_proxy import list_acl_rules
from unifi_fabric.tools.hotspot import _list_hotspot_operators
from unifi_fabric.tools.innerspace import get_innerspace_project
from unifi_fabric.tools.network import list_networks
from unifi_fabric.tools.network_services_proxy import list_traffic_matching_lists
from unifi_fabric.tools.protect import list_cameras
from unifi_fabric.tools.recognition import get_recognition_group_counts
from unifi_fabric.tools.site_manager import get_host
from unifi_fabric.tools.statistics import _get_site_statistics
from unifi_fabric.tools.vpn import _create_site_to_site_tunnel

# A host owned by the NON-FIRST (beta) key, and a synthetic UUID site on it.
_BETA_HOST_ID = "console-beta-1"
_BETA_SITE_UUID = "bbbbbbbb-0000-4000-8000-000000000001"
_ALPHA_HOST_ID = "console-alpha-1"


async def _seed_host_caches(client: UniFiClient, registry: Registry) -> None:
    """Prime each key's host cache so ``resolve_key_for_host`` resolves the owner offline."""
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await registry.set_hosts(hosts, key=client.get_key_by_label(label))


def _capture_key_on_get(client: UniFiClient) -> dict[str, APIKeyConfig | None]:
    """Replace client.get with a capturing stub; return the dict it records the key into."""
    captured: dict[str, APIKeyConfig | None] = {}

    async def _get(path, *, key=None, params=None):
        captured["key"] = key
        return {"data": []}

    client.get = AsyncMock(side_effect=_get)
    return captured


def _capture_key_on(client: UniFiClient, method: str) -> dict[str, APIKeyConfig | None]:
    """Replace an arbitrary client method with a capturing stub (records the ``key`` kwarg)."""
    captured: dict[str, APIKeyConfig | None] = {}

    async def _call(path, *args, key=None, **kwargs):
        captured["key"] = key
        return {"data": []}

    setattr(client, method, AsyncMock(side_effect=_call))
    return captured


def _stub_resolution(registry: Registry, host_id: str) -> None:
    """Pin host/site resolution so the test isolates *which key* the data request rides."""
    registry.resolve_host_id = AsyncMock(return_value=host_id)
    registry.resolve_site_id = AsyncMock(return_value=_BETA_SITE_UUID)
    registry.resolve_site_slug = AsyncMock(return_value="default")


def _assert_rode(captured: dict[str, APIKeyConfig | None], label: str) -> None:
    key = captured.get("key")
    assert key is not None, f"data request rode the default key, expected the {label!r} key"
    assert key.label == label, f"data request rode {key.label!r}, expected {label!r}"


async def test_list_networks_routes_to_owning_key(multikey_client, multikey_registry):
    await _seed_host_caches(multikey_client, multikey_registry)
    _stub_resolution(multikey_registry, _BETA_HOST_ID)
    captured = _capture_key_on_get(multikey_client)
    await list_networks(multikey_client, multikey_registry, "Beta-Branch", "Default")
    _assert_rode(captured, "beta")


async def test_list_clients_routes_to_owning_key(multikey_client, multikey_registry):
    await _seed_host_caches(multikey_client, multikey_registry)
    _stub_resolution(multikey_registry, _BETA_HOST_ID)
    captured = _capture_key_on_get(multikey_client)
    await _list_clients(multikey_client, multikey_registry, "Beta-Branch", "Default")
    _assert_rode(captured, "beta")


async def test_list_site_devices_routes_to_owning_key(multikey_client, multikey_registry):
    await _seed_host_caches(multikey_client, multikey_registry)
    _stub_resolution(multikey_registry, _BETA_HOST_ID)
    captured = _capture_key_on_get(multikey_client)
    await _list_site_devices(multikey_client, multikey_registry, "Beta-Branch", "Default")
    _assert_rode(captured, "beta")


async def test_list_cameras_routes_to_owning_key(multikey_client, multikey_registry):
    # Protect cameras are per-host (no site), but the routing requirement is identical.
    await _seed_host_caches(multikey_client, multikey_registry)
    multikey_registry.resolve_host_id = AsyncMock(return_value=_BETA_HOST_ID)
    captured = _capture_key_on_get(multikey_client)
    await list_cameras(multikey_client, multikey_registry, "Beta-Branch")
    _assert_rode(captured, "beta")


async def test_alpha_owned_host_routes_to_alpha(multikey_client, multikey_registry):
    # The first/default key still wins for a host it owns — routing is by ownership,
    # not a blanket "always use the last key".
    await _seed_host_caches(multikey_client, multikey_registry)
    _stub_resolution(multikey_registry, _ALPHA_HOST_ID)
    captured = _capture_key_on_get(multikey_client)
    await list_networks(multikey_client, multikey_registry, "Alpha-HQ", "Default")
    _assert_rode(captured, "alpha")


async def test_unknown_host_falls_back_to_default_key(multikey_client, multikey_registry):
    # A host no configured key claims resolves to None, preserving the prior behaviour
    # of riding the default (first) key rather than raising.
    await _seed_host_caches(multikey_client, multikey_registry)
    _stub_resolution(multikey_registry, "console-unknown")
    captured = _capture_key_on_get(multikey_client)
    await list_networks(multikey_client, multikey_registry, "Ghost-Console", "Default")
    assert captured.get("key") is None


# --- Remaining per-host modules (issue #172) ---------------------------------------------
# Each of the eight modules below now resolves the owning key first and threads it through
# its data request, exactly like the four modules fixed in #169. A beta-owned host must
# therefore ride the beta credential; a single-key deployment (resolve_key_for_host -> None)
# is structurally unaffected and is proven separately by every module's own unit suite.


async def test_list_acl_rules_routes_to_owning_key(multikey_client, multikey_registry):
    await _seed_host_caches(multikey_client, multikey_registry)
    _stub_resolution(multikey_registry, _BETA_HOST_ID)
    captured = _capture_key_on(multikey_client, "get")
    await list_acl_rules(multikey_client, multikey_registry, "Beta-Branch", "Default")
    _assert_rode(captured, "beta")


async def test_list_traffic_matching_lists_routes_to_owning_key(multikey_client, multikey_registry):
    await _seed_host_caches(multikey_client, multikey_registry)
    _stub_resolution(multikey_registry, _BETA_HOST_ID)
    captured = _capture_key_on(multikey_client, "get")
    await list_traffic_matching_lists(multikey_client, multikey_registry, "Beta-Branch", "Default")
    _assert_rode(captured, "beta")


async def test_create_site_to_site_tunnel_routes_to_owning_key(multikey_client, multikey_registry):
    # A write tool: the owning key must carry the mutating POST, not just reads.
    await _seed_host_caches(multikey_client, multikey_registry)
    _stub_resolution(multikey_registry, _BETA_HOST_ID)
    captured = _capture_key_on(multikey_client, "post")
    await _create_site_to_site_tunnel(
        multikey_client, multikey_registry, "Beta-Branch", "Default", {"name": "t"}
    )
    _assert_rode(captured, "beta")


async def test_list_hotspot_operators_routes_to_owning_key(multikey_client, multikey_registry):
    # Classic-REST (site_slug) tool: routing requirement is identical.
    await _seed_host_caches(multikey_client, multikey_registry)
    _stub_resolution(multikey_registry, _BETA_HOST_ID)
    captured = _capture_key_on(multikey_client, "get")
    await _list_hotspot_operators(multikey_client, multikey_registry, "Beta-Branch", "Default")
    _assert_rode(captured, "beta")


async def test_recognition_counts_routes_to_owning_key(multikey_client, multikey_registry):
    # Recognition tools are per-host (no site), like Protect cameras.
    await _seed_host_caches(multikey_client, multikey_registry)
    multikey_registry.resolve_host_id = AsyncMock(return_value=_BETA_HOST_ID)
    captured = _capture_key_on(multikey_client, "get")
    await get_recognition_group_counts(multikey_client, multikey_registry, "Beta-Branch", "face")
    _assert_rode(captured, "beta")


async def test_site_statistics_routes_to_owning_key(multikey_client, multikey_registry):
    await _seed_host_caches(multikey_client, multikey_registry)
    _stub_resolution(multikey_registry, _BETA_HOST_ID)
    captured = _capture_key_on(multikey_client, "get")
    await _get_site_statistics(multikey_client, multikey_registry, "Beta-Branch", "Default")
    _assert_rode(captured, "beta")


async def test_get_host_routes_to_owning_key(multikey_client, multikey_registry):
    # get_host reads Site Manager /v1/hosts/{id}, which only the owning key can see.
    await _seed_host_caches(multikey_client, multikey_registry)
    multikey_registry.resolve_host_id = AsyncMock(return_value=_BETA_HOST_ID)
    captured = _capture_key_on(multikey_client, "get")
    await get_host(multikey_client, multikey_registry, "Beta-Branch")
    _assert_rode(captured, "beta")


async def test_innerspace_project_routes_to_owning_key(multikey_client, multikey_registry):
    # InnerSpace is per-host (no site); the project fetch must ride the owning key.
    await _seed_host_caches(multikey_client, multikey_registry)
    multikey_registry.resolve_host_id = AsyncMock(return_value=_BETA_HOST_ID)
    captured = _capture_key_on(multikey_client, "get")
    await get_innerspace_project(multikey_client, multikey_registry, "Beta-Branch")
    _assert_rode(captured, "beta")
