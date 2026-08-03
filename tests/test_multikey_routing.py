"""Multi-key routing tests for per-host tools (network / clients / device_mgmt / protect).

Why this file exists
--------------------
``Registry.resolve_key_for_host`` (issue #19) knows which configured API key OWNS a given
host, and the *list/aggregate* tools were wired to fan out across keys. The **per-host**
tools were not: every one of them still does ``resolve_host_id(host)`` + ``client.get(...)``
with no ``key=`` argument, so in a multi-key deployment they always ride the DEFAULT
(first) key. A host owned by a non-first key therefore routes on the wrong credential —
the exact production bug an external user hit, and the exact bug a single-key test can
never see.

These tests assert the CORRECT end-state: a per-host tool acting on a host owned by the
non-first ("beta") key must send its data request on the beta key. That wiring does not
exist yet, so each test is marked ``xfail(strict=True)``:

* Today it xfails — making the gap visible and *counted* in every CI run.
* When someone wires ``resolve_key_for_host`` into these tools, the test xpasses; a strict
  xfail turns an unexpected pass into a FAILURE, forcing the stale marker to be removed.

Follow-up: wire ``resolve_key_for_host`` into the per-host tools (remainder of issue #19).
This is a representative sample (one tool per module), not exhaustive coverage of all
~165 per-host call sites — enough to establish the pattern and keep the gap measurable.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import APIKeyConfig
from unifi_fabric.registry import Registry
from unifi_fabric.tools.clients import _list_clients
from unifi_fabric.tools.device_mgmt import _list_site_devices
from unifi_fabric.tools.network import list_networks
from unifi_fabric.tools.protect import list_cameras

# A host owned by the NON-FIRST (beta) key, and a synthetic UUID site on it.
_BETA_HOST_ID = "console-beta-1"
_BETA_SITE_UUID = "bbbbbbbb-0000-4000-8000-000000000001"

_GAP_REASON = (
    "per-host tools are not yet wired to Registry.resolve_key_for_host, so they ride the "
    "default (first) key — remainder of issue #19"
)

pytestmark = pytest.mark.xfail(strict=True, raises=AssertionError, reason=_GAP_REASON)


def _capture_key_on_get(client: UniFiClient) -> dict[str, APIKeyConfig | None]:
    """Replace client.get with a capturing stub; return the dict it records the key into."""
    captured: dict[str, APIKeyConfig | None] = {}

    async def _get(path, *, key=None, params=None):
        captured["key"] = key
        return {"data": []}

    client.get = AsyncMock(side_effect=_get)
    return captured


def _stub_resolution(registry: Registry) -> None:
    """Pin host/site resolution so the test isolates *which key* the data request rides."""
    registry.resolve_host_id = AsyncMock(return_value=_BETA_HOST_ID)
    registry.resolve_site_id = AsyncMock(return_value=_BETA_SITE_UUID)


def _assert_rode_beta(captured: dict[str, APIKeyConfig | None]) -> None:
    key = captured.get("key")
    # `key is None` (today's behaviour) short-circuits to an AssertionError, not AttributeError.
    assert key is not None and key.label == "beta"


async def test_list_networks_routes_to_owning_key(multikey_client, multikey_registry):
    _stub_resolution(multikey_registry)
    captured = _capture_key_on_get(multikey_client)
    await list_networks(multikey_client, multikey_registry, "Beta-Branch", "Default")
    _assert_rode_beta(captured)


async def test_list_clients_routes_to_owning_key(multikey_client, multikey_registry):
    _stub_resolution(multikey_registry)
    captured = _capture_key_on_get(multikey_client)
    await _list_clients(multikey_client, multikey_registry, "Beta-Branch", "Default")
    _assert_rode_beta(captured)


async def test_list_site_devices_routes_to_owning_key(multikey_client, multikey_registry):
    _stub_resolution(multikey_registry)
    captured = _capture_key_on_get(multikey_client)
    await _list_site_devices(multikey_client, multikey_registry, "Beta-Branch", "Default")
    _assert_rode_beta(captured)


async def test_list_cameras_routes_to_owning_key(multikey_client, multikey_registry):
    # Protect cameras are per-host (no site), but the routing requirement is identical.
    multikey_registry.resolve_host_id = AsyncMock(return_value=_BETA_HOST_ID)
    captured = _capture_key_on_get(multikey_client)
    await list_cameras(multikey_client, multikey_registry, "Beta-Branch")
    _assert_rode_beta(captured)
