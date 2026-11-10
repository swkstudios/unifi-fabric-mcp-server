"""A one-key Site Manager listing in a multi-key deployment names the key it read.

``list_devices(host=...)`` reads ``/v1/devices`` on the key that owns the console; like
the ``key_label`` and paged branches (and ``list_hosts`` / ``list_sites``), its result
carries ``_key_labels`` naming that key. A single-key deployment adds nothing.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.site_manager.site_manager import list_devices, list_hosts, list_sites
from unifi_fabric.registry import Registry

HOSTS = "https://api.ui.com/v1/hosts"
DEVICES = "https://api.ui.com/v1/devices"
SITES = "https://api.ui.com/v1/sites"
KEY_TO_LABEL = {"k-alpha": "alpha", "k-beta": "beta"}


def _by_key(build):
    def handler(req: httpx.Request) -> httpx.Response:
        label = KEY_TO_LABEL.get(req.headers.get("x-api-key", ""), "alpha")
        return httpx.Response(200, json=build(label))

    return handler


def _devices(label: str) -> dict:
    host = MULTIKEY_HOSTS_BY_LABEL[label][0]["id"]
    return {"data": [{"hostId": host, "devices": [{"id": f"dev-{label}"}]}]}


def _mock_fleet(router: respx.Router) -> respx.Route:
    router.get(HOSTS).mock(
        side_effect=_by_key(lambda label: {"data": MULTIKEY_HOSTS_BY_LABEL[label]})
    )
    router.get(SITES).mock(side_effect=_by_key(lambda label: {"data": []}))
    return router.get(DEVICES).mock(side_effect=_by_key(_devices))


# Every one-key branch of the Site Manager listings, each with the key it must name.
ONE_KEY_CALLS = {
    "devices_host_alpha": (lambda c, r: list_devices(c, r, host="console-alpha-1"), "alpha"),
    "devices_host_beta": (lambda c, r: list_devices(c, r, host="console-beta-1"), "beta"),
    "devices_host_and_label": (
        lambda c, r: list_devices(c, r, host="console-beta-1", key_label="beta"),
        "beta",
    ),
    "devices_key_label": (lambda c, r: list_devices(c, r, key_label="beta"), "beta"),
    "hosts_key_label": (lambda c, r: list_hosts(c, r, key_label="beta"), "beta"),
    "sites_key_label": (lambda c, r: list_sites(c, r, key_label="alpha"), "alpha"),
}


@pytest.mark.parametrize("case", sorted(ONE_KEY_CALLS))
async def test_one_key_listing_names_its_key(multikey_client, multikey_registry, case):
    call, label = ONE_KEY_CALLS[case]
    with respx.mock(assert_all_called=False) as router:
        _mock_fleet(router)
        result = await call(multikey_client, multikey_registry)
    assert result["_key_labels"] == [label]


async def test_host_branch_reads_on_the_owning_key(multikey_client, multikey_registry):
    with respx.mock(assert_all_called=False) as router:
        devices = _mock_fleet(router)
        result = await list_devices(multikey_client, multikey_registry, host="console-beta-1")
    assert {c.request.headers["x-api-key"] for c in devices.calls} == {"k-beta"}
    assert result["data"][0]["devices"] == [{"id": "dev-beta"}]


async def test_single_key_host_listing_adds_no_key_labels():
    client = UniFiClient(Settings(api_key="k-alpha"))
    registry = Registry(client, ttl_seconds=60)
    with respx.mock(assert_all_called=False) as router:
        _mock_fleet(router)
        result = await list_devices(client, registry, host="console-alpha-1")
    assert "_key_labels" not in result
