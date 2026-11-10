"""Successive context merges keep every preserved field; no fan-out task outlives its call.

1. ``with_context`` is applied more than once to the same record (the /v1/devices
   wrapper context, then the multi-key ``_keyLabel``). Each collision's preserved value
   (``_wrapperFields`` and numbered buckets for later merges) must
   ACCUMULATE: a later merge never drops what an earlier one preserved, and a record's
   original own value is never replaced by a context value a previous merge set.
2. Every concurrent fan-out (per key, per site) runs its children so that none outlives
   the tool call, even when one child is cancelled on its own (a cancellation that is
   not an ``Exception`` and so escapes the per-child error capture).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from unifi_fabric.config import APIKeyConfig
from unifi_fabric.families.site_manager import aggregation, site_manager
from unifi_fabric.registry import Registry
from unifi_fabric.shared_shapes import _keys
from unifi_fabric.shared_shapes._keys import tag_items, with_context

H = "AA:1"
H2 = "CC:3"
KEYS = {label: APIKeyConfig(key=f"k-{label}", label=label) for label in ("a", "b")}


def _multikey_client() -> MagicMock:
    client = MagicMock()
    client.list_key_labels = MagicMock(return_value=list(KEYS))
    client.get_key_by_label = MagicMock(side_effect=lambda label: KEYS[label])
    return client


# --------------------------------------------------------------------------------------
# 1. Context merges accumulate their collision metadata
# --------------------------------------------------------------------------------------


class TestContextMergesAccumulate:
    def test_association_collisions_from_two_merges_are_both_kept(self):
        record = {"id": "dev1", "_hostId": "BB:2", "_keyLabel": "stale"}
        first = with_context(record, {"_hostId": H})
        (second,) = tag_items([first], "a", True)
        assert second["_hostId"] == "BB:2"
        assert second["_keyLabel"] == "stale"
        assert second["_wrapperFields"] == {"_hostId": H}
        assert second["_wrapperFields_2"] == {"_keyLabel": "a"}

    def test_wrapper_collisions_from_two_merges_are_both_kept(self):
        record = {"id": "dev1", "_updatedAt": "device-age", "_note": "mine"}
        first = with_context(record, {"_updatedAt": "host-age"})
        second = with_context(first, {"_note": "wrapper-note"})
        assert second["_updatedAt"] == "device-age"
        assert second["_note"] == "mine"
        assert second["_wrapperFields"] == {"_updatedAt": "host-age"}
        assert second["_wrapperFields_2"] == {"_note": "wrapper-note"}

    def test_a_records_original_own_value_is_never_replaced(self):
        record = {"id": "dev1", "_hostId": "BB:2"}
        twice = with_context(with_context(record, {"_hostId": H}), {"_hostId": H2})
        assert twice["_hostId"] == "BB:2"
        assert twice["_wrapperFields"] == {"_hostId": H}
        assert twice["_wrapperFields_2"] == {"_hostId": H2}

    def test_merging_never_mutates_an_earlier_merge(self):
        first = with_context({"id": "d", "_hostId": "BB:2"}, {"_hostId": H})
        snapshot = {k: (dict(v) if isinstance(v, dict) else v) for k, v in first.items()}
        with_context(first, {"_keyLabel": "a", "_siteId": "x"} | {"_hostId": H2})
        assert first == snapshot

    async def test_fleet_devices_keep_both_preserved_fields(self):
        client = _multikey_client()
        device = {"id": "dev1", "_hostId": "BB:2", "_keyLabel": "stale"}

        async def paginate(path, *, key=None, **kwargs):
            return [{"hostId": H, "devices": [dict(device)]}] if key is KEYS["a"] else []

        client.paginate = AsyncMock(side_effect=paginate)
        devices, answering, errors, _ = await aggregation._fleet_devices(client, None)
        assert errors == [] and answering == ["a", "b"]
        (merged,) = devices
        assert merged["_hostId"] == "BB:2" and merged["_keyLabel"] == "stale"
        assert merged["_wrapperFields"] == {"_hostId": H}
        assert merged["_wrapperFields_2"] == {"_keyLabel": "a"}

    async def test_site_manager_key_aggregation_preserves_a_records_own_key_label(self):
        client = _multikey_client()

        async def fetch(key):
            return [{"id": f"r-{key.label}", "_keyLabel": "stale"}]

        records, _answering, _errors, _ = await site_manager._aggregate_lists_over_keys(
            client, list(KEYS), fetch, identity=lambda r: r.get("id")
        )
        assert [r["_keyLabel"] for r in records] == ["stale", "stale"]
        assert [r["_wrapperFields"] for r in records] == [{"_keyLabel": "a"}, {"_keyLabel": "b"}]

    async def test_site_manager_key_aggregation_adds_no_bookkeeping_without_collision(self):
        client = _multikey_client()

        async def fetch(key):
            return [{"id": f"r-{key.label}"}]

        records, *_ = await site_manager._aggregate_lists_over_keys(
            client, list(KEYS), fetch, identity=lambda r: r.get("id")
        )
        assert records == [{"id": "r-a", "_keyLabel": "a"}, {"id": "r-b", "_keyLabel": "b"}]


# --------------------------------------------------------------------------------------
# 2. No fan-out child outlives the tool call
# --------------------------------------------------------------------------------------


class _Children:
    """The first child cancels after a sibling starts; siblings record their drain."""

    def __init__(self) -> None:
        self.finished: list[str] = []
        self._first: str | None = None
        self.sibling_started = asyncio.Event()
        self.first_cancelled = asyncio.Event()

    async def run(self, name: str, value: Any = None) -> Any:
        if self._first is None or self._first == name:
            self._first = name
            await self.sibling_started.wait()
            self.first_cancelled.set()
            raise asyncio.CancelledError
        self.sibling_started.set()
        try:
            await self.first_cancelled.wait()
            return value
        finally:
            self.finished.append(name)


async def _assert_no_child_outlives(call: Callable[[], Awaitable[Any]]) -> None:
    before = asyncio.all_tasks()
    try:
        await call()
    except asyncio.CancelledError:
        pass
    leftover = [t for t in asyncio.all_tasks() - before if not t.done()]
    for task in leftover:  # do not leak into the next test either way
        task.cancel()
    await asyncio.gather(*leftover, return_exceptions=True)
    assert leftover == [], f"{len(leftover)} fan-out task(s) outlived the call"


def _fan_out_scopes(children: _Children) -> Callable[[], Awaitable[Any]]:
    async def fetch(key):
        return await children.run(key.label, [])

    return lambda: _keys.fan_out_scopes(list(KEYS.items()), fetch)


def _first_success(children: _Children) -> Callable[[], Awaitable[Any]]:
    async def fetch(key):
        return await children.run(key.label, [])

    return lambda: _keys.first_success(_multikey_client(), None, fetch)


def _fleet_devices(children: _Children) -> Callable[[], Awaitable[Any]]:
    client = _multikey_client()

    async def paginate(path, *, key=None, **kwargs):
        return await children.run(key.label, [])

    client.paginate = AsyncMock(side_effect=paginate)
    return lambda: aggregation._fleet_devices(client, None)


def _fleet_clients(children: _Children, monkeypatch: Any) -> Callable[[], Awaitable[Any]]:
    pairs = [
        {"hostId": H, "siteId": f"s{i}", "hostName": "c", "siteName": f"site{i}"} for i in range(2)
    ]
    monkeypatch.setattr(aggregation, "_get_all_host_site_pairs", AsyncMock(return_value=pairs))

    async def collect(client, path, *, key=None, **kwargs):
        return await children.run(path, {"items": [], "incomplete": False})

    monkeypatch.setattr(aggregation, "collect_offset", collect)
    client = MagicMock()
    client.list_key_labels = MagicMock(return_value=["default"])
    return lambda: aggregation._list_all_clients_fleet(client, MagicMock())


def _resolve_key_for_host(children: _Children) -> Callable[[], Awaitable[Any]]:
    registry = Registry(_multikey_client(), ttl_seconds=0)

    async def get_hosts(*, key=None):
        return await children.run(key.label, [{"id": H, "reportedState": {"hostname": "c"}}])

    registry.get_hosts = get_hosts  # type: ignore[method-assign]
    return lambda: registry.resolve_key_for_host(H)


def _aggregate_lists_over_keys(children: _Children) -> Callable[[], Awaitable[Any]]:
    async def fetch(key):
        return await children.run(key.label, [])

    return lambda: site_manager._aggregate_lists_over_keys(
        _multikey_client(), list(KEYS), fetch, identity=lambda r: None
    )


def _compare_site_performance(
    children: _Children, monkeypatch: Any
) -> Callable[[], Awaitable[Any]]:
    async def health(client, registry, site):
        return await children.run(site, {"ok": True})

    monkeypatch.setattr(site_manager, "get_site_health_summary", health)
    return lambda: site_manager.compare_site_performance(MagicMock(), MagicMock(), ["s1", "s2"])


FAN_OUTS = {
    "_keys.fan_out_scopes": lambda c, mp: _fan_out_scopes(c),
    "_keys.first_success": lambda c, mp: _first_success(c),
    "aggregation._fleet_devices": lambda c, mp: _fleet_devices(c),
    "aggregation._list_all_clients_fleet": _fleet_clients,
    "registry.resolve_key_for_host": lambda c, mp: _resolve_key_for_host(c),
    "site_manager._aggregate_lists_over_keys": lambda c, mp: _aggregate_lists_over_keys(c),
    "site_manager.compare_site_performance": _compare_site_performance,
}


@pytest.mark.parametrize("name", sorted(FAN_OUTS))
async def test_no_fan_out_child_outlives_the_call(monkeypatch, name):
    children = _Children()
    await _assert_no_child_outlives(FAN_OUTS[name](children, monkeypatch))


def test_every_fan_out_site_is_covered():
    """Every concurrent fan-out in the owned modules goes through gather_or_cancel (the
    cancellation-draining helper); a bare asyncio.gather would let a sibling outlive a child
    that is cancelled on its own."""
    import inspect

    from unifi_fabric import registry as registry_module

    for module in (_keys, aggregation, site_manager, registry_module):
        source = inspect.getsource(module)
        # The moved query_isp_metrics wrapper (tools/site_manager.register) was outside
        # this guard in server.py before the move; it alone keeps its bare gather.
        allowed = 1 if module is site_manager else 0
        assert source.count("asyncio.gather(") == allowed, module.__name__
    register_source = inspect.getsource(site_manager.register)
    assert register_source.count("asyncio.gather(") == 1
    assert "async def query_isp_metrics" in register_source


class _BlockedChildren(_Children):
    async def run(self, name: str, value: Any = None) -> Any:
        if self._first is None or self._first == name:
            self._first = name
            await self.sibling_started.wait()
            raise asyncio.CancelledError
        self.sibling_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            self.finished.append(name)


@pytest.mark.parametrize("name", sorted(FAN_OUTS))
async def test_child_cancellation_cancels_forever_blocked_sibling(monkeypatch, name):
    children = _BlockedChildren()
    outer = asyncio.create_task(FAN_OUTS[name](children, monkeypatch)())
    try:
        with pytest.raises(asyncio.CancelledError):
            await outer
        assert outer.done(), "child cancellation did not terminate fan-out"
        assert children.finished, "blocked sibling was not cancelled and awaited"
    finally:
        outer.cancel()
        await asyncio.gather(outer, return_exceptions=True)
