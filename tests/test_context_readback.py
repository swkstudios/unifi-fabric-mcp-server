"""Server-added context is read back from server provenance, never from colliding upstream.

Every reader of a field the server adds through ``with_context`` (``_incompleteReason``,
``_incomplete``, ``_siteLabel``, ``_resolvedSiteId``, ``incomplete``/``incompleteReason``)
must use ``context_value``; a colliding upstream sentinel must never be attributed as the
server's own partial-resolution reason.
"""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.families.carrier import carrier_fabric
from unifi_fabric.families.innerspace import placement_snapshot
from unifi_fabric.families.mobility import mobility
from unifi_fabric.families.site_manager import site_manager
from unifi_fabric.families.vpn import vpn
from unifi_fabric.registry import Registry
from unifi_fabric.resolution_state import with_resolution_state
from unifi_fabric.shared_shapes._keys import context_value, with_context

UPSTREAM = "UPSTREAM-SENTINEL"
SITE_UUID = "00000000-0000-4000-8000-000000000001"


@pytest.fixture
async def client():
    value = UniFiClient(Settings(api_key="synthetic-key"))
    yield value
    await value.close()


@pytest.fixture
def registry(client):
    return Registry(client, ttl_seconds=0)


def _colliding(upstream: dict, server: dict) -> dict:
    return with_context(upstream, server)


class TestContextValueStrict:
    def test_strict_ignores_upstream_field_on_context_record(self):
        record = with_context({"_incompleteReason": UPSTREAM}, {"_resolvedSiteId": "s"})
        assert context_value(record, "_incompleteReason", strict=True) is None
        assert context_value(record, "_incompleteReason") == UPSTREAM

    def test_strict_falls_back_on_plain_server_dict(self):
        assert context_value({"_incompleteReason": "server"}, "_incompleteReason", strict=True) == (
            "server"
        )


class TestResolutionMetadata:
    def test_colliding_reason_reads_server_value(self):
        source = _colliding({"_incompleteReason": UPSTREAM}, {"_incompleteReason": "server"})
        result = site_manager._resolution_metadata({}, source)
        assert result["_incompleteReason"] == "server"
        assert UPSTREAM not in str(result)

    def test_upstream_only_reason_is_not_attributed(self):
        source = with_context({"_incompleteReason": UPSTREAM}, {"_resolvedSiteId": "s"})
        result = site_manager._resolution_metadata({}, source)
        assert result == {}

    def test_unmarked_result_never_reads_upstream_reason_later(self):
        # A console site with no server reason still carries server provenance, so a
        # later reader cannot mistake its upstream _incompleteReason for the server's.
        result = site_manager._resolution_metadata({"_incompleteReason": UPSTREAM}, {})
        assert result == {"_incompleteReason": UPSTREAM}
        assert context_value(result, "_incompleteReason", strict=True) is None


class TestCompareSitePerformance:
    async def test_colliding_reason_and_label(self, client, registry, monkeypatch):
        body = _colliding(
            {"_incomplete": "UPSTREAM", "_incompleteReason": UPSTREAM, "_siteLabel": UPSTREAM},
            {"_incomplete": True, "_incompleteReason": "server-reason"},
        )
        monkeypatch.setattr(site_manager, "get_site_health_summary", AsyncMock(return_value=body))
        result = await site_manager.compare_site_performance(client, registry, ["site-a"])
        assert result["incompleteReason"] == "site-a: server-reason"
        assert result["_comparison"][0]["_siteLabel"] == UPSTREAM

    async def test_upstream_only_reason_is_not_attributed(self, client, registry, monkeypatch):
        body = {"_incomplete": True, "_incompleteReason": UPSTREAM, "data": []}
        monkeypatch.setattr(site_manager, "get_site_health_summary", AsyncMock(return_value=body))
        result = await site_manager.compare_site_performance(client, registry, ["site-a"])
        assert "incomplete" not in result
        assert result["_comparison"][0] == {**body, "_siteLabel": "site-a"}

    async def test_upstream_error_body_is_not_a_failed_site(self, client, registry, monkeypatch):
        body = {"error": UPSTREAM}
        monkeypatch.setattr(site_manager, "get_site_health_summary", AsyncMock(return_value=body))
        result = await site_manager.compare_site_performance(client, registry, ["site-a"])
        assert result["_comparison"] == [{"error": UPSTREAM, "_siteLabel": "site-a"}]

    async def test_upstream_label_and_error_body_is_not_a_failed_site(
        self, client, registry, monkeypatch
    ):
        body = {"error": UPSTREAM, "_siteLabel": UPSTREAM}
        monkeypatch.setattr(site_manager, "get_site_health_summary", AsyncMock(return_value=body))
        result = await site_manager.compare_site_performance(client, registry, ["site-a"])
        assert result["_comparison"][0]["_wrapperFields"] == {"_siteLabel": "site-a"}


class TestSearchAcrossSitesResolutionReason:
    async def _search(self, client, registry, monkeypatch, proxy_site):
        registry.get_ea_sites = AsyncMock(return_value=[{"hostId": "host-h1", "siteId": "s1"}])
        registry.resolve_key_for_host = AsyncMock(return_value=None)
        monkeypatch.setattr(site_manager, "_proxy_site_for_ea", AsyncMock(return_value=proxy_site))

        async def collect(client, path, **kwargs):
            return {"items": [{"name": "match"}], "incomplete": False}

        monkeypatch.setattr(site_manager, "collect_offset", collect)
        return await site_manager.search_across_sites(client, registry, "match")

    async def test_colliding_reason_reads_server_value(self, client, registry, monkeypatch):
        proxy_site = _colliding(
            {"id": SITE_UUID, "_incompleteReason": UPSTREAM}, {"_incompleteReason": "server"}
        )
        result = await self._search(client, registry, monkeypatch, proxy_site)
        assert result["incompleteReason"] == f"{SITE_UUID} resolution: server"

    async def test_upstream_only_reason_is_not_attributed(self, client, registry, monkeypatch):
        proxy_site = site_manager._resolution_metadata(
            {"id": SITE_UUID, "_incompleteReason": UPSTREAM}, {"hostId": "host-h1"}
        )
        result = await self._search(client, registry, monkeypatch, proxy_site)
        assert "incomplete" not in result
        assert result["_sitesIncomplete"] == 0


async def test_proxy_site_error_names_server_resolved_site(registry):
    record = _colliding(
        {"hostId": "host-h1", "_resolvedSiteId": UPSTREAM, "meta": {"name": "nope"}},
        {"_resolvedSiteId": "server-site"},
    )
    registry.get_sites = AsyncMock(return_value=[{"id": SITE_UUID, "internalReference": "x"}])
    with pytest.raises(ValueError, match="server-site") as exc:
        await site_manager._proxy_site_for_ea(registry, record, None)
    assert UPSTREAM not in str(exc.value)


class TestIncompleteListReaders:
    def _list(self, upstream_incomplete):
        return _colliding(
            {"data": [], "incomplete": upstream_incomplete, "incompleteReason": UPSTREAM},
            {"incomplete": True, "incompleteReason": "server-cap"},
        )

    def test_vpn_select_reads_server_incomplete(self):
        with pytest.raises(ValueError, match=r"incomplete \(server-cap\)"):
            vpn._select_by_id(self._list(False), "missing", "VPN server", "list", "VPN server")

    def test_vpn_select_ignores_upstream_only_incomplete(self):
        result = with_context(
            {"data": [], "incomplete": True, "incompleteReason": UPSTREAM}, {"_count": 0}
        )
        with pytest.raises(ValueError, match="not found") as exc:
            vpn._select_by_id(result, "missing", "VPN server", "list", "VPN server")
        assert UPSTREAM not in str(exc.value)

    def test_placement_snapshot_reads_server_incomplete(self):
        empty = {"data": []}
        snapshot = placement_snapshot._project_snapshot(
            placement_snapshot.datetime.now(placement_snapshot.UTC),
            project_result={},
            cameras_result=self._list(False),
            sensors_result=empty,
            devices_result=empty,
        )
        assert snapshot["incompleteReason"] == "protect.cameras: server-cap"

    @pytest.mark.parametrize(
        "module,fn",
        [
            (mobility, "list_mobility_workspaces"),
            (carrier_fabric, "list_carrier_service_plans"),
        ],
    )
    async def test_multi_key_merge_reads_server_incomplete(self, client, monkeypatch, module, fn):
        parts = [("k1", self._list(False)), ("k2", self._list(True))]
        upstream_only = with_context(
            {"data": [], "incomplete": True, "incompleteReason": UPSTREAM}, {"_count": 0}
        )
        parts.append(("k3", upstream_only))
        monkeypatch.setattr(module, "fan_out", AsyncMock(return_value=(parts, [], True)))
        result = await getattr(module, fn)(client)
        assert result["incompleteReason"] == "k1: server-cap; k2: server-cap"


def test_resolution_state_merges_server_reason():
    result = _colliding({"_incompleteReason": UPSTREAM}, {"_incompleteReason": "server"})
    merged = with_resolution_state(result, ["late"])
    # The merged reason is the server's own; the upstream field keeps its value.
    assert context_value(merged, "_incompleteReason") == "server; late"
    assert merged["_incompleteReason"] == UPSTREAM
    assert merged["_wrapperFields"] == {"_incompleteReason": "server"}
    assert merged["_wrapperFields_2"] == {"_incompleteReason": "server; late"}
    assert merged["_incomplete"] is True
