"""Core data-path regressions: site aliases, registry lock reclamation, device/wrapper
context separation, fan-out cancellation, offset drains from a nonzero start, the Classic
device read twin of the connector relay, and search_across_sites key/console context.

Every test here failed on the code before its fix (the commit body maps each one).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from unifi_fabric.client import UniFiClient, UniFiConnectionError, gather_or_cancel
from unifi_fabric.config import Settings
from unifi_fabric.families.connector import connector
from unifi_fabric.families.innerspace import placement_snapshot
from unifi_fabric.families.site_manager import aggregation, site_manager
from unifi_fabric.registry import Registry
from unifi_fabric.shared_shapes._keys import tag_items, with_context

H = "AA:1"
U1 = "11111111-1111-1111-1111-111111111111"
U2 = "22222222-2222-2222-2222-222222222222"


def _site_registry(sites: list[dict[str, Any]]) -> Registry:
    client = AsyncMock()
    client.list_key_labels = MagicMock(return_value=["default"])
    client.paginate_offset = AsyncMock(return_value=list(sites))
    return Registry(client, ttl_seconds=0)


# --------------------------------------------------------------------------------------
# 1. A site's description no longer hides its name (registry + site_manager sibling)
# --------------------------------------------------------------------------------------


class TestSiteAliases:
    DUAL = {
        "id": U1,
        "description": "Human Lab",
        "name": "Machine Lab",
        "internalReference": "default",
    }

    async def test_both_aliases_resolve_to_the_same_site(self):
        reg = _site_registry([self.DUAL])
        assert await reg.resolve_site_id("Human Lab", "console-a") == U1
        assert await reg.resolve_site_id("Machine Lab", "console-a") == U1
        assert await reg.resolve_site_slug("Machine Lab", "console-a") == "default"

    async def test_name_alias_matches_in_the_name_tiers(self):
        reg = _site_registry([self.DUAL])
        assert await reg.resolve_site_id("machine lab", "console-a") == U1

    async def test_one_sites_name_and_anothers_description_is_ambiguous(self):
        reg = _site_registry(
            [
                {"id": U1, "description": "Lab", "name": "default"},
                {"id": U2, "name": "Lab"},
            ]
        )
        with pytest.raises(ValueError, match="ambiguous site 'Lab'"):
            await reg.resolve_site_id("Lab", "console-a")

    async def test_not_found_lists_both_aliases(self):
        reg = _site_registry([self.DUAL])
        with pytest.raises(ValueError, match=r"Human Lab / Machine Lab \(" + U1):
            await reg.resolve_site_id("Nowhere", "console-a")

    async def test_site_manager_label_fallback_checks_the_name_too(self):
        registry = MagicMock()
        registry.get_sites = AsyncMock(return_value=[self.DUAL])
        record = {
            "hostId": H,
            "siteId": "a" * 24,
            "meta": {"name": "no-such-ref", "desc": "Machine Lab"},
            "_resolvedSiteId": "a" * 24,
        }
        mapped = await site_manager._proxy_site_for_ea(registry, record, None)
        assert mapped["id"] == U1


# --------------------------------------------------------------------------------------
# 2. Per-entry registry locks are reclaimed when idle
# --------------------------------------------------------------------------------------


class TestRegistryLockReclamation:
    async def test_locks_do_not_accumulate_per_console(self):
        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.paginate_offset = AsyncMock(return_value=[])
        client.paginate = AsyncMock(return_value=[])
        reg = Registry(client, ttl_seconds=900)
        for i in range(200):
            await reg.get_sites(f"host-{i}")
        await reg.get_hosts()
        await reg.get_ea_sites()
        assert reg._locks == {}

    async def test_invalidate_leaves_no_lock(self):
        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.paginate_offset = AsyncMock(return_value=[])
        reg = Registry(client, ttl_seconds=900)
        await reg.get_sites("host-1")
        reg.invalidate()
        assert reg._locks == {}

    async def test_waiters_share_one_lock_and_fetch_once(self):
        release = asyncio.Event()
        calls = 0

        async def slow(path, *, key=None):
            nonlocal calls
            calls += 1
            await release.wait()
            return [{"id": U1, "description": "Lab"}]

        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.paginate_offset = AsyncMock(side_effect=slow)
        reg = Registry(client, ttl_seconds=900)
        first = asyncio.create_task(reg.get_sites("host-1"))
        second = asyncio.create_task(reg.get_sites("host-1"))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert list(reg._locks) == [("sites", "default", "host-1")]
        assert reg._locks[("sites", "default", "host-1")].users == 2
        release.set()
        assert await first == await second
        assert calls == 1
        assert reg._locks == {}

    async def test_cancelled_waiter_releases_its_claim(self):
        release = asyncio.Event()

        async def slow(path, *, key=None):
            await release.wait()
            return []

        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.paginate_offset = AsyncMock(side_effect=slow)
        reg = Registry(client, ttl_seconds=900)
        holder = asyncio.create_task(reg.get_sites("host-1"))
        waiter = asyncio.create_task(reg.get_sites("host-1"))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert reg._locks[("sites", "default", "host-1")].users == 1
        release.set()
        await holder
        assert reg._locks == {}


# --------------------------------------------------------------------------------------
# 3. Device payload and wrapper context are kept apart (+ clients, _keyLabel siblings)
# --------------------------------------------------------------------------------------


class TestWrapperContextSeparation:
    def test_device_updated_at_is_the_devices_own(self):
        wrapper = {
            "hostId": H,
            "hostName": "c1",
            "updatedAt": "host-age",
            "devices": [{"id": "dev1", "_updatedAt": "device-age"}],
        }
        (device,) = aggregation._unwrap_ea_devices([wrapper])
        assert device["_updatedAt"] == "device-age"
        assert device["_wrapperFields"] == {"_updatedAt": "host-age"}
        assert device["_hostId"] == H

    def test_wrapper_console_routes_without_overwriting_host_id(self):
        wrapper = {"hostId": H, "devices": [{"id": "dev1", "_hostId": "BB:2"}]}
        (device,) = aggregation._unwrap_ea_devices([wrapper])
        assert device["_hostId"] == "BB:2"
        assert device["_wrapperFields"] == {"_hostId": H}
        assert aggregation._device_host(device) == H

    def test_no_collision_adds_no_bookkeeping_key(self):
        wrapper = {"hostId": H, "updatedAt": "t", "devices": [{"id": "dev1", "mac": "x"}]}
        (device,) = aggregation._unwrap_ea_devices([wrapper])
        assert device == {"id": "dev1", "mac": "x", "_hostId": H, "_updatedAt": "t"}

    def test_with_context_never_mutates_the_record(self):
        record = {"id": "r", "_siteId": "old"}
        merged = with_context(record, {"_siteId": "new", "_extra": 1})
        assert record == {"id": "r", "_siteId": "old"}
        assert merged == {
            "id": "r",
            "_siteId": "old",
            "_extra": 1,
            "_wrapperFields": {"_siteId": "new"},
        }

    def test_tag_items_key_label_preserves_upstream(self):
        tagged = tag_items([{"id": "A", "_keyLabel": "stale"}], "alpha", True)
        assert tagged == [
            {"id": "A", "_keyLabel": "stale", "_wrapperFields": {"_keyLabel": "alpha"}}
        ]

    async def test_client_records_keep_their_own_colliding_fields(self):
        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.get = AsyncMock(
            return_value={"data": [{"id": "c1", "_siteId": "theirs"}], "totalCount": 1}
        )
        registry = MagicMock()
        pair = {"hostId": H, "siteId": U1, "hostName": "c", "siteName": "s"}
        with patch.object(aggregation, "_get_all_host_site_pairs", AsyncMock(return_value=[pair])):
            result = await aggregation._list_all_clients_fleet(client, registry)
        (record,) = result["data"]
        assert record["_siteId"] == "theirs"
        assert record["_wrapperFields"] == {"_siteId": U1}


# --------------------------------------------------------------------------------------
# 4. A failing fan-out cancels and awaits its siblings
# --------------------------------------------------------------------------------------


class _Blocker:
    """Coroutines that block forever and record their cancellation."""

    def __init__(self) -> None:
        self.started: list[str] = []
        self.cancelled: list[str] = []

    async def block(self, name: str) -> Any:
        self.started.append(name)
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.append(name)
            raise


class TestFanOutCancellation:
    async def test_gather_or_cancel_cancels_siblings_and_raises_the_original(self):
        blocker = _Blocker()

        async def fail() -> None:
            await asyncio.sleep(0)
            raise UniFiConnectionError("boom")

        with pytest.raises(UniFiConnectionError, match="boom"):
            await gather_or_cancel(blocker.block("a"), fail(), blocker.block("b"))
        assert sorted(blocker.cancelled) == ["a", "b"]

    async def test_gather_or_cancel_returns_results_in_order(self):
        async def value(v: int, delay: float) -> int:
            await asyncio.sleep(delay)
            return v

        assert await gather_or_cancel(value(1, 0.02), value(2, 0), value(3, 0.01)) == [1, 2, 3]

    async def test_cancelling_the_caller_cancels_every_sibling(self):
        blocker = _Blocker()
        outer = asyncio.create_task(gather_or_cancel(blocker.block("a"), blocker.block("b")))
        await asyncio.sleep(0.01)
        outer.cancel()
        with pytest.raises(asyncio.CancelledError):
            await outer
        assert sorted(blocker.cancelled) == ["a", "b"]

    async def test_fleet_summary_failure_cancels_sibling_drains(self):
        blocker = _Blocker()

        async def paginate(path, *, key=None):
            if path == "/v1/hosts":
                await asyncio.sleep(0)
                raise UniFiConnectionError("hosts down")
            return await blocker.block(path)

        client = AsyncMock()
        client.list_key_labels = MagicMock(return_value=["default"])
        client.paginate = AsyncMock(side_effect=paginate)
        with pytest.raises(UniFiConnectionError, match="hosts down"):
            await aggregation._fleet_summary(client, MagicMock())
        assert sorted(blocker.cancelled) == ["/v1/devices", "/v1/sites"]

    async def test_client_gather_failure_cancels_queued_and_running(self):
        client = UniFiClient(Settings(api_key="k", max_concurrency=2))
        blocker = _Blocker()

        async def fail() -> None:
            await asyncio.sleep(0)
            raise ValueError("bad site")

        with _no_never_awaited():
            with pytest.raises(ValueError, match="bad site"):
                await client.gather([blocker.block("a"), fail(), blocker.block("b")])
        assert blocker.cancelled  # the running sibling was cancelled, not left behind
        assert set(blocker.started) == set(blocker.cancelled)

    async def test_site_inventory_failure_cancels_the_other_list(self, monkeypatch):
        blocker = _Blocker()

        async def collect(client, path, *, key=None, **kwargs):
            if path.endswith("/devices"):
                await asyncio.sleep(0)
                raise UniFiConnectionError("devices down")
            return await blocker.block("clients")

        monkeypatch.setattr(site_manager, "collect_offset", collect)
        monkeypatch.setattr(
            site_manager,
            "_resolve_ea_site_record",
            AsyncMock(return_value={"hostId": H, "siteId": "a" * 24}),
        )
        monkeypatch.setattr(site_manager, "_proxy_site_for_ea", AsyncMock(return_value={"id": U1}))
        registry = MagicMock()
        registry.resolve_key_for_host = AsyncMock(return_value=None)
        with pytest.raises(UniFiConnectionError, match="devices down"):
            await site_manager.get_site_inventory(AsyncMock(), registry, "Default")
        assert blocker.cancelled == ["clients"]

    async def test_placement_snapshot_failure_cancels_the_other_sources(self, monkeypatch):
        blocker = _Blocker()

        async def fail(*args, **kwargs):
            await asyncio.sleep(0)
            raise UniFiConnectionError("innerspace down")

        async def block_named(name):
            async def _source(*args, **kwargs):
                return await blocker.block(name)

            return _source

        monkeypatch.setattr(placement_snapshot, "_innerspace_project", fail)
        monkeypatch.setattr(placement_snapshot.protect, "list_cameras", await block_named("cams"))
        monkeypatch.setattr(placement_snapshot.protect, "list_sensors", await block_named("sens"))
        monkeypatch.setattr(
            placement_snapshot.site_manager, "list_devices", await block_named("devs")
        )
        with pytest.raises(UniFiConnectionError, match="innerspace down"):
            await placement_snapshot.get_unifi_placement_snapshot(MagicMock(), MagicMock(), "h")
        assert sorted(blocker.cancelled) == ["cams", "devs", "sens"]


class _no_never_awaited:
    """Fail when a 'coroutine ... was never awaited' warning is raised in the block."""

    def __enter__(self) -> _no_never_awaited:
        import warnings

        self._catch = warnings.catch_warnings(record=True)
        self._seen = self._catch.__enter__()
        warnings.simplefilter("always")
        return self

    def __exit__(self, *exc: object) -> None:
        import gc

        gc.collect()
        self._catch.__exit__(*exc)
        never = [w for w in self._seen if "never awaited" in str(w.message)]
        assert not never, [str(w.message) for w in never]


# --------------------------------------------------------------------------------------
# 5. An offset drain that starts past zero completes at the end of the collection
# --------------------------------------------------------------------------------------


class TestOffsetDrainFromNonzeroStart:
    async def test_offset_one_reaches_the_end_without_a_false_abort(self):
        client = UniFiClient(Settings(api_key="k"))
        pages = [
            {"data": [{"id": 1}, {"id": 2}], "totalCount": 3},
            {"data": [], "totalCount": 3},
        ]
        calls: list[dict[str, Any]] = []

        async def get(path, *, key=None, params=None):
            calls.append(dict(params or {}))
            return pages[len(calls) - 1]

        client.get = get  # type: ignore[method-assign]
        drained = await client.paginate_offset("/probe", params={"offset": 1}, page_size=2)
        assert list(drained) == [{"id": 1}, {"id": 2}]
        assert drained.total_count == 3
        assert [c["offset"] for c in calls] == [1]

    async def test_short_drain_from_a_start_offset_still_aborts(self):
        from unifi_fabric.client import PaginationAbortedError

        client = UniFiClient(Settings(api_key="k"))
        pages = [{"data": [{"id": 1}], "totalCount": 5}, {"data": [], "totalCount": 5}]
        calls: list[int] = []

        async def get(path, *, key=None, params=None):
            calls.append(params["offset"])
            return pages[len(calls) - 1]

        client.get = get  # type: ignore[method-assign]
        with pytest.raises(PaginationAbortedError, match="starting at offset 2") as exc:
            await client.paginate_offset("/probe", params={"offset": 2}, page_size=2)
        assert exc.value.items == [{"id": 1}]


# --------------------------------------------------------------------------------------
# 6. Classic rest/device writes read their twin through stat/device
# --------------------------------------------------------------------------------------

DEV_ID = "c0e6be15-9f44-4170-bd66-2b27d120db2b"
CONSOLE = "aabbccddeeff0000:12345"


class _Resp:
    def __init__(self, status: int, body: Any) -> None:
        import json as _json

        self.status_code = status
        self._body = body
        self.text = _json.dumps(body)
        self.content = self.text.encode()
        self.headers = {"content-type": "application/json"}

    def json(self) -> Any:
        return self._body


def _relay_registry() -> AsyncMock:
    reg = AsyncMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value=CONSOLE)
    reg.resolve_site_slug = AsyncMock(return_value="default")
    return reg


def _device_row(name: str, uptime: int) -> dict[str, Any]:
    return {"_id": DEV_ID, "mac": "02:00:5e:00:00:01", "name": name, "uptime": uptime}


def _relay_client(reads: list[list[dict[str, Any]]], write_status: int = 200) -> AsyncMock:
    calls: list[tuple[str, str]] = []
    pending = list(reads)

    async def request(method, url, **kwargs):
        calls.append((method, url))
        if method == "GET":
            if url.endswith("/rest/device/" + DEV_ID):
                return _Resp(404, {"meta": {"rc": "error", "msg": "api.err.NotFound"}, "data": []})
            return _Resp(200, {"meta": {"rc": "ok"}, "data": pending.pop(0)})
        return _Resp(write_status, {"meta": {"rc": "ok"}, "data": []})

    client = AsyncMock()
    client.request = AsyncMock(side_effect=request)
    client.calls = calls
    return client


class TestClassicDeviceReadTwin:
    PATH = "network/api/s/{site}/rest/device/" + DEV_ID
    OTHER = {"_id": "ffffffffffffffffffffffff", "mac": "02:00:5e:00:00:02", "name": "x"}

    async def _put(self, client: AsyncMock, body: dict[str, Any]) -> dict[str, Any]:
        return await connector.connector_write(
            client,
            _relay_registry(),
            "h",
            "PUT",
            self.PATH,
            site="Default",
            body=body,
            scope="device",
        )

    async def test_same_value_write_is_a_noop_despite_volatile_stats(self):
        client = _relay_client(
            [[self.OTHER, _device_row("AP", 100)], [_device_row("AP", 160), self.OTHER]]
        )
        result = await self._put(client, {"name": "AP"})
        assert result["noOp"] is True
        assert result["changed"] is False
        assert result["noOpBasis"] == {
            "readPath": "network/api/s/default/stat/device",
            "fields": ["name"],
        }
        reads = [url for method, url in client.calls if method == "GET"]
        assert all(url.endswith("/network/api/s/default/stat/device") for url in reads)
        assert result["readBefore"]["body"]["data"] == [self.OTHER, _device_row("AP", 100)]
        assert result["readBefore"]["comparisonRecords"] == [_device_row("AP", 100)]
        assert result["readBefore"]["twin"]["path"] == "network/api/s/default/stat/device"
        assert "readAfterError" not in result

    async def test_changed_write_is_reported_changed(self):
        client = _relay_client([[_device_row("AP", 1)], [_device_row("AP zz", 2)]])
        result = await self._put(client, {"name": "AP zz"})
        assert result["noOp"] is False
        assert result["changed"] is True

    async def test_device_missing_from_stat_list_is_unknown(self):
        client = _relay_client([[self.OTHER], [self.OTHER]])
        result = await self._put(client, {"name": "AP"})
        assert result["noOp"] is None
        assert "changed" not in result
        assert "no device with _id" in result["readAfterError"]

    async def test_written_field_absent_from_the_record_is_unknown(self):
        client = _relay_client([[_device_row("AP", 1)], [_device_row("AP", 2)]])
        result = await self._put(client, {"config_only_field": 1})
        assert result["noOp"] is None

    async def test_other_classic_rest_routes_keep_their_same_path_twin(self):
        client = _relay_client([])
        client.request = AsyncMock(
            return_value=_Resp(200, {"meta": {"rc": "ok"}, "data": [{"name": "x"}]})
        )
        result = await connector.connector_write(
            client,
            _relay_registry(),
            "h",
            "PUT",
            "network/api/s/{site}/rest/user/abc",
            site="Default",
            body={"name": "x"},
        )
        urls = [c.args[1] for c in client.request.await_args_list if c.args[0] == "GET"]
        assert all(url.endswith("/network/api/s/default/rest/user/abc") for url in urls)
        assert "noOpBasis" not in result
        assert result["noOp"] is True
        assert result["changed"] is False


# --------------------------------------------------------------------------------------
# 7. search_across_sites matches carry _hostId (and _keyLabel with several keys)
# --------------------------------------------------------------------------------------


class TestSearchAcrossSitesContext:
    async def test_multi_key_matches_name_their_key_and_console(
        self, multikey_client, multikey_registry
    ):
        async def ea_sites(*, key=None):
            host = "AA:1" if key.label == "alpha" else "BB:2"
            return [{"hostId": host, "siteId": key.label * 4}]

        multikey_registry.get_ea_sites = AsyncMock(side_effect=ea_sites)
        multikey_client.get = AsyncMock(return_value={"data": [{"name": "match"}], "totalCount": 1})

        async def proxy_site(registry, record, key):
            return {"id": U1 if record["hostId"] == "AA:1" else U2}

        with patch.object(site_manager, "_proxy_site_for_ea", side_effect=proxy_site):
            result = await site_manager.search_across_sites(
                multikey_client, multikey_registry, "match"
            )
        by_host = {m["_hostId"]: m for m in result["data"]}
        assert by_host["AA:1"]["_keyLabel"] == "alpha"
        assert by_host["BB:2"]["_keyLabel"] == "beta"
        assert {m["_type"] for m in result["data"]} == {"device", "client"}

    async def test_single_key_matches_name_their_console_only(self):
        client = UniFiClient(Settings(api_key="k"))
        client.get = AsyncMock(return_value={"data": [{"name": "match"}], "totalCount": 1})  # type: ignore[method-assign]
        registry = MagicMock()
        registry.get_ea_sites = AsyncMock(return_value=[{"hostId": H, "siteId": "a" * 24}])
        registry.resolve_key_for_host = AsyncMock(return_value=None)
        with patch.object(site_manager, "_proxy_site_for_ea", AsyncMock(return_value={"id": U1})):
            result = await site_manager.search_across_sites(client, registry, "match")
        assert {m["_hostId"] for m in result["data"]} == {H}
        assert all("_keyLabel" not in m for m in result["data"])


# --------------------------------------------------------------------------------------
# 8. L13-N closure gaps: reverse-case console order, first-key console-name precedence
# --------------------------------------------------------------------------------------


class TestFleetMembershipOrder:
    @pytest.mark.parametrize(("first", "later"), [("ABCDEF", "abcdef"), ("abcdef", "ABCDEF")])
    def test_case_variants_are_one_console_in_either_order(self, first, later):
        claimed = aggregation._consoles([{"id": first}], aggregation._host_record_id)
        assert aggregation._unclaimed([{"id": later}], claimed, aggregation._host_record_id) == []

    @pytest.mark.parametrize(("alpha", "beta"), [("ABCDEF", "abcdef"), ("abcdef", "ABCDEF")])
    async def test_summary_counts_first_key_in_either_case_order(
        self, multikey_client, multikey_registry, alpha, beta
    ):
        async def pages(path, *, key):
            host = alpha if key.label == "alpha" else beta
            return {
                "/v1/hosts": [{"id": host}],
                "/v1/sites": [{"hostId": host}],
                "/v1/devices": [{"hostId": host, "devices": [{"id": "d", "status": key.label}]}],
            }[path]

        multikey_client.paginate = AsyncMock(side_effect=pages)
        result = await aggregation._fleet_summary(multikey_client, multikey_registry)
        assert result["hosts"] == result["sites"] == result["devices"]["total"] == 1
        assert result["devices"]["byStatus"] == {"alpha": 1}

    async def test_first_listed_console_name_wins(self):
        registry = MagicMock()
        registry.get_ea_sites = AsyncMock(return_value=[{"hostId": H}])
        registry.get_hosts = AsyncMock(
            return_value=[{"id": H, "name": "first"}, {"id": "aa:1", "name": "last"}]
        )
        registry.get_sites = AsyncMock(return_value=[{"id": U1, "description": "s"}])
        pairs = await aggregation._get_all_host_site_pairs(registry)
        assert pairs[0]["hostName"] == "first"
