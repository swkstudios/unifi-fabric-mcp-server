"""Snapshot reconciliation, exercised through the shared MSP substrate.

ID/slug resolution and key routing have no separate stored mappings: these tests
check their observable behaviour after replacing the three registry snapshots.
"""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.families.network.network import list_local_sites
from unifi_fabric.families.site_manager.aggregation import _fleet_summary
from unifi_fabric.families.site_manager.site_manager import (
    list_all_sites_aggregated,
    list_hosts,
    list_sites,
)
from unifi_fabric.registry import FetchedRecords, incomplete_reason

FAMILIES = ("hosts", "ea_sites", "sites")
RESOLVERS = ("host", "ea_site", "site_id", "site_slug", "routing")
MODES = ("single", "multi")
HOST = "console-reconciliation"
OLD_UUID = "aaaaaaaa-0000-4000-8000-000000000001"
NEW_UUID = "bbbbbbbb-0000-4000-8000-000000000002"


def _keys(client, monkeypatch, mode):
    """Select a deployment shape from the shared fixture; never build another client."""
    if mode == "single":
        monkeypatch.setattr(client._settings, "api_keys", client._settings.api_keys[:1])
    return [client.get_key_by_label(label) for label in client.list_key_labels()]


def _rows(family, label, generation):
    name = f"{label}-{generation}"
    if family == "hosts":
        return [{"id": f"console-{name}", "reportedState": {"hostname": name}}]
    if family == "ea_sites":
        return [{"siteId": f"fabric-{name}", "hostId": HOST, "meta": {"name": name}}]
    return [
        {
            "id": OLD_UUID if generation == "old" else NEW_UUID,
            "description": name,
            "internalReference": f"slug-{name}",
        }
    ]


async def _set(registry, family, rows, key):
    if family == "sites":
        await registry.set_sites(HOST, rows, key=key)
    else:
        await getattr(registry, f"set_{family}")(rows, key=key)


async def _get(registry, family, key):
    if family == "sites":
        return await registry.get_sites(HOST, key=key)
    return await getattr(registry, f"get_{family}")(key=key)


def _cache(registry, family, key):
    cache_key = (key.label, HOST) if family == "sites" else key.label
    return getattr(registry, f"_{family}"), cache_key


async def _resolve(registry, resolver, selector, key):
    if resolver == "routing":
        return await registry.resolve_key_for_host(selector)
    if resolver == "host":
        return await registry.resolve_host_id(selector, key=key)
    if resolver == "ea_site":
        return await registry.resolve_ea_site_id(selector, host_id=HOST, key=key)
    return await getattr(registry, f"resolve_{resolver}")(selector, HOST, key=key)


def _family(resolver):
    return (
        "hosts"
        if resolver in ("host", "routing")
        else ("ea_sites" if resolver == "ea_site" else "sites")
    )


def _id(family, row):
    return row["siteId"] if family == "ea_sites" else row["id"]


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("empty", (False, True), ids=("replacement", "empty"))
async def test_complete_snapshot_evicts_vanished_entries(
    multikey_client, multikey_registry, monkeypatch, family, mode, empty
):
    keys = _keys(multikey_client, monkeypatch, mode)
    for key in keys:
        await _set(multikey_registry, family, _rows(family, key.label, "old"), key)
    for key in keys:
        current = [] if empty else _rows(family, key.label, "new")
        await _set(multikey_registry, family, current, key)
        assert await _get(multikey_registry, family, key) == current
    # A refresh is scoped to its key, even if other keys have cached lists.
    if len(keys) > 1:
        await _set(multikey_registry, family, [], keys[0])
        assert await _get(multikey_registry, family, keys[1]) == (
            [] if empty else _rows(family, keys[1].label, "new")
        )


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("reason", ("page 2 failed", "page cap of 1 reached"))
async def test_partial_snapshot_preserves_prior_entries(
    multikey_client, multikey_registry, monkeypatch, family, mode, reason
):
    keys = _keys(multikey_client, monkeypatch, mode)
    assert {key.label for key in keys} == ({"alpha"} if mode == "single" else {"alpha", "beta"})
    for key in keys:
        old = _rows(family, key.label, "old")
        await _set(multikey_registry, family, old, key)
        await _set(multikey_registry, family, FetchedRecords([], reason), key)
        assert await _get(multikey_registry, family, key) == old
        await _set(
            multikey_registry, family, FetchedRecords(_rows(family, key.label, "new"), reason), key
        )
        assert await _get(multikey_registry, family, key) == old
        assert incomplete_reason(await _get(multikey_registry, family, key)) is None


@pytest.mark.parametrize("resolver", RESOLVERS)
@pytest.mark.parametrize("mode", MODES)
async def test_stale_selector_after_complete_refresh_lists_current_choices(
    multikey_client, multikey_registry, monkeypatch, resolver, mode
):
    keys = _keys(multikey_client, monkeypatch, mode)
    family = _family(resolver)
    for key in keys:
        await _set(multikey_registry, family, _rows(family, key.label, "old"), key)
    # Single-key routing intentionally has no lookup; host resolution validates it.
    if resolver == "routing" and mode == "single":
        resolver = "host"
    target = keys[-1]
    old = _rows(family, target.label, "old")[0]
    assert await _resolve(multikey_registry, resolver, f"{target.label}-old", target)
    for key in keys:
        await _set(multikey_registry, family, _rows(family, key.label, "new"), key)
    for selector in (f"{target.label}-old", _id(family, old)):
        with pytest.raises(ValueError) as caught:
            await _resolve(multikey_registry, resolver, selector, target)
        message = str(caught.value)
        assert "valid" in message
        assert f"{target.label}-new" in message
        if family != "ea_sites":
            assert _id(family, _rows(family, target.label, "new")[0]) in message
    get = AsyncMock(side_effect=AssertionError("cached resolution must fail before upstream"))
    monkeypatch.setattr(multikey_client, "get", get)
    with pytest.raises(ValueError):
        await _resolve(multikey_registry, resolver, f"{target.label}-old", target)
    get.assert_not_awaited()


@pytest.mark.parametrize("resolver", RESOLVERS)
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("fault", ("capped", "page_failure", "all_fail"))
async def test_uncacheable_fetches_do_not_poison_resolution(
    multikey_client, multikey_registry, monkeypatch, resolver, mode, fault
):
    keys = _keys(multikey_client, monkeypatch, mode)
    family = _family(resolver)
    if resolver == "routing" and mode == "single":
        resolver = "host"
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append((path, key.label, dict(params or {})))
        later = bool(params.get("nextToken")) or bool(params.get("offset"))
        if fault == "all_fail" or (fault == "page_failure" and later):
            raise UniFiConnectionError(f"{key.label}: synthetic page failure")
        rows = _rows(family, key.label, "new")
        if family == "sites":
            return {"data": rows, "offset": 0, "count": 1, "totalCount": 2}
        return {"data": rows, "nextToken": "page-2"}

    monkeypatch.setattr(multikey_client, "get", AsyncMock(side_effect=get))
    if fault == "capped":
        monkeypatch.setattr(multikey_client._settings, "paginate_max_pages", 1)
    target = keys[-1]
    with pytest.raises((RuntimeError, UniFiConnectionError, ValueError)) as caught:
        await _resolve(multikey_registry, resolver, f"{target.label}-new", target)
    if fault == "capped":
        assert "incomplete" in str(caught.value)
        # Exact ids remain usable on a partial snapshot, without caching it.
        row = _rows(family, target.label, "new")[0]
        assert await _resolve(multikey_registry, resolver, _id(family, row), target)
    else:
        assert "synthetic page failure" in str(caught.value)
    for key in keys:
        cache, cache_key = _cache(multikey_registry, family, key)
        assert cache_key not in cache
    if resolver == "routing":
        assert {label for _, label, _ in calls} == {key.label for key in keys}

    # Next complete list is authoritative, including after an all-keys failure.
    async def complete(path, *, key=None, params=None):
        rows = _rows(family, key.label, "old")
        return {"data": rows, "totalCount": 1} if family == "sites" else {"data": rows}

    monkeypatch.setattr(multikey_client, "get", AsyncMock(side_effect=complete))
    assert await _resolve(multikey_registry, resolver, f"{target.label}-old", target)
    with pytest.raises(ValueError) as caught:
        await _resolve(multikey_registry, resolver, f"{target.label}-new", target)
    assert f"{target.label}-old" in str(caught.value)


@pytest.mark.parametrize("family", ("hosts", "ea_sites"))
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("fault", ("complete", "capped", "page_failure", "all_fail"))
async def test_list_tool_refresh_reconciles_or_preserves_cache(
    multikey_client, multikey_registry, monkeypatch, family, mode, fault
):
    keys = _keys(multikey_client, monkeypatch, mode)
    for key in keys:
        await _set(multikey_registry, family, _rows(family, key.label, "old"), key)
    calls = []

    async def get(path, *, key=None, params=None):
        # Single-key list tools may use the default key rather than an explicit key.
        key = key or keys[0]
        calls.append((key.label, dict(params or {})))
        later = bool(params.get("nextToken"))
        if fault == "all_fail" or (fault == "page_failure" and later):
            raise UniFiConnectionError(f"{key.label}: synthetic page failure")
        rows = [] if later else _rows(family, key.label, "new")
        return {"data": rows, **({"nextToken": "page-2"} if not later else {})}

    monkeypatch.setattr(multikey_client, "get", AsyncMock(side_effect=get))
    if fault == "capped":
        monkeypatch.setattr(multikey_client._settings, "paginate_max_pages", 1)
    tool = list_hosts if family == "hosts" else list_sites
    # Explicit scope ensures the seeded key-specific cache is the refreshed one.
    scope = {"key_label": keys[0].label} if mode == "single" else {}
    if fault in ("page_failure", "all_fail"):
        with pytest.raises((RuntimeError, UniFiConnectionError)) as caught:
            await tool(multikey_client, multikey_registry, **scope)
        assert "synthetic page failure" in str(caught.value)
        if mode == "multi":
            assert all(key.label in str(caught.value) for key in keys)
    else:
        result = await tool(multikey_client, multikey_registry, **scope)
        assert bool(result.get("incomplete")) == (fault == "capped")
    for key in keys:
        expected = _rows(family, key.label, "new" if fault == "complete" else "old")
        assert await _get(multikey_registry, family, key) == expected
    assert {label for label, _ in calls} == {key.label for key in keys}


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("mode", MODES)
async def test_fetch_drain_caches_only_complete_snapshot(
    multikey_client, multikey_registry, monkeypatch, family, mode
):
    keys = _keys(multikey_client, monkeypatch, mode)
    assert {key.label for key in keys} == ({"alpha"} if mode == "single" else {"alpha", "beta"})
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append((key.label, dict(params)))
        later = bool(params.get("nextToken")) or bool(params.get("offset"))
        row = _rows(family, key.label, "new" if later else "old")
        if family == "sites":
            return {"data": row, "offset": 1 if later else 0, "totalCount": 2}
        return {"data": row, **({"nextToken": "page-2"} if not later else {})}

    monkeypatch.setattr(multikey_client, "get", AsyncMock(side_effect=get))
    for key in keys:
        expected = _rows(family, key.label, "old") + _rows(family, key.label, "new")
        assert await _get(multikey_registry, family, key) == expected
        count = len(calls)
        assert await _get(multikey_registry, family, key) == expected
        assert len(calls) == count
        assert count == 2 * (keys.index(key) + 1)


@pytest.mark.parametrize("reverse", (False, True))
@pytest.mark.parametrize("partial", (False, True))
async def test_overlapping_console_uses_config_order_not_fetch_completion(
    multikey_client, multikey_registry, monkeypatch, reverse, partial
):
    import asyncio

    if reverse:
        monkeypatch.setattr(
            multikey_client._settings,
            "api_keys",
            list(reversed(multikey_client._settings.api_keys)),
        )
    keys = [multikey_client.get_key_by_label(label) for label in multikey_client.list_key_labels()]
    completed = []

    async def get(path, *, key=None, params=None):
        if key == keys[0]:
            await asyncio.sleep(0.01)
        completed.append(key.label)
        return {
            "data": [{"id": HOST, "reportedState": {"hostname": "shared"}}],
            **({"nextToken": "page-2"} if partial else {}),
        }

    monkeypatch.setattr(multikey_client, "get", AsyncMock(side_effect=get))
    if partial:
        monkeypatch.setattr(multikey_client._settings, "paginate_max_pages", 1)
    assert await multikey_registry.resolve_key_for_host(HOST) == keys[0]
    assert completed == [keys[1].label, keys[0].label]
    if not partial:
        assert await multikey_registry.resolve_key_for_host("shared") == keys[0]
        result = await list_hosts(multikey_client, multikey_registry)
        assert len(result["data"]) == 1
        assert result["data"][0]["_keyLabel"] == keys[0].label
    else:
        assert not multikey_registry._hosts


@pytest.mark.parametrize("family", ("hosts", "ea_sites"))
@pytest.mark.parametrize("fault", ("capped", "page_failure", "all_fail"))
async def test_one_key_failure_preserves_its_snapshot_while_sibling_refreshes(
    multikey_client, multikey_registry, monkeypatch, family, fault
):
    keys = [multikey_client.get_key_by_label(label) for label in multikey_client.list_key_labels()]
    for key in keys:
        await _set(multikey_registry, family, _rows(family, key.label, "old"), key)

    async def get(path, *, key=None, params=None):
        rows = _rows(family, key.label, "new")
        if key == keys[1]:
            return {"data": rows}
        if fault == "all_fail" or params.get("nextToken"):
            raise UniFiConnectionError("alpha: synthetic page failure")
        return {"data": rows, "nextToken": "page-2"}

    monkeypatch.setattr(multikey_client, "get", AsyncMock(side_effect=get))
    if fault == "capped":
        monkeypatch.setattr(multikey_client._settings, "paginate_max_pages", 1)
    tool = list_hosts if family == "hosts" else list_sites
    result = await tool(multikey_client, multikey_registry)
    assert await _get(multikey_registry, family, keys[0]) == _rows(family, "alpha", "old")
    assert await _get(multikey_registry, family, keys[1]) == _rows(family, "beta", "new")
    if fault == "capped":
        assert result["incomplete"] is True
        assert "alpha" in result["incompleteReason"]
    else:
        assert "alpha" in str(result["errors"])


async def test_routing_reconciles_owner_only_after_complete_snapshot(
    multikey_client, multikey_registry
):
    keys = [multikey_client.get_key_by_label(label) for label in multikey_client.list_key_labels()]
    shared = [{"id": HOST, "reportedState": {"hostname": "shared"}}]
    for key in keys:
        await multikey_registry.set_hosts(shared, key=key)
    assert await multikey_registry.resolve_key_for_host(HOST) == keys[0]
    await multikey_registry.set_hosts(FetchedRecords([], "page cap of 1 reached"), key=keys[0])
    assert await multikey_registry.resolve_key_for_host(HOST) == keys[0]
    await multikey_registry.set_hosts([], key=keys[0])
    assert await multikey_registry.resolve_key_for_host(HOST) == keys[1]
    assert await multikey_registry.resolve_key_for_host("shared") == keys[1]


async def test_single_key_routing_shortcut_still_validates_selector_in_host_cache(
    multikey_client, multikey_registry, monkeypatch
):
    key = _keys(multikey_client, monkeypatch, "single")[0]
    get = AsyncMock(side_effect=AssertionError("routing shortcut must not enumerate"))
    monkeypatch.setattr(multikey_client, "get", get)
    assert await multikey_registry.resolve_key_for_host("alpha-old") is None
    await multikey_registry.set_hosts(_rows("hosts", "alpha", "new"), key=key)
    with pytest.raises(ValueError, match="alpha-new"):
        await multikey_registry.resolve_host_id("alpha-old", key=key)
    get.assert_not_awaited()


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("default_first", (False, True))
async def test_default_and_first_key_share_one_snapshot(
    multikey_client, multikey_registry, monkeypatch, family, mode, default_first
):
    keys = _keys(multikey_client, monkeypatch, mode)
    seed, refresh = (None, keys[0]) if default_first else (keys[0], None)
    await _set(multikey_registry, family, _rows(family, "alpha", "old"), seed)
    if len(keys) > 1:
        await _set(multikey_registry, family, _rows(family, "beta", "old"), keys[1])
    await _set(multikey_registry, family, _rows(family, "alpha", "new"), refresh)
    upstream = AsyncMock(side_effect=AssertionError("aliases must share the cached snapshot"))
    monkeypatch.setattr(multikey_client, "get", upstream)
    for alias in (None, keys[0]):
        assert await _get(multikey_registry, family, alias) == _rows(family, "alpha", "new")
    cache, _ = _cache(multikey_registry, family, keys[0])
    assert len(cache) == len(keys)
    if len(keys) > 1:
        assert await _get(multikey_registry, family, keys[1]) == _rows(family, "beta", "old")
    multikey_registry.invalidate(key=keys[0])
    cache, cache_key = _cache(multikey_registry, family, keys[0])
    assert cache_key not in cache
    assert ((None, HOST) if family == "sites" else None) not in cache
    upstream.assert_not_awaited()


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("producer", ("setter", "list_sites", "aggregate", "fleet"))
@pytest.mark.parametrize(
    "shape",
    ("null_only", "mixed", "invalid_string", "invalid_number", "invalid_bool", "invalid_array"),
)
async def test_nullable_site_snapshot_reconciliation(
    multikey_client, multikey_registry, monkeypatch, mode, producer, shape
):
    keys = _keys(multikey_client, monkeypatch, mode)
    invalid = {
        "invalid_string": "bad",
        "invalid_number": 7,
        "invalid_bool": True,
        "invalid_array": [],
    }
    for key in keys:
        await multikey_registry.set_ea_sites(_rows("ea_sites", key.label, "old"), key=key)
        await multikey_registry.set_hosts([], key=key)

    def rows(key):
        return [None] + (
            _rows("ea_sites", key.label, "new")
            if shape == "mixed"
            else ([invalid[shape]] if shape in invalid else [])
        )

    async def get(path, *, key=None, params=None):
        key = key or keys[0]
        return {"data": rows(key) if path == "/v1/sites" else []}

    monkeypatch.setattr(multikey_client, "get", AsyncMock(side_effect=get))
    if producer == "setter":
        for key in keys:
            await multikey_registry.set_ea_sites(rows(key), key=key)
    else:
        tool = {
            "list_sites": list_sites,
            "aggregate": list_all_sites_aggregated,
            "fleet": _fleet_summary,
        }[producer]
        if shape in invalid and (mode == "multi" or producer == "fleet"):
            with pytest.raises((UniFiConnectionError, RuntimeError)):
                await tool(multikey_client, multikey_registry)
        else:
            result = await tool(multikey_client, multikey_registry)
            if producer != "fleet":
                assert None in result["data"]
    for key in keys:
        expected = _rows("ea_sites", key.label, "old" if shape in invalid else "new")
        if shape == "null_only":
            expected = []
        assert await multikey_registry.get_ea_sites(key=key) == expected


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "options", ({"offset": 0}, {"limit": 1}, {"filter": "name.eq(test)"}, {"filter": ""})
)
async def test_local_sites_partial_or_filtered_snapshot_preserves_cache(
    multikey_client, multikey_registry, monkeypatch, mode, options
):
    keys = _keys(multikey_client, monkeypatch, mode)
    target = keys[-1]
    for key in keys:
        await multikey_registry.set_hosts([{"id": HOST}] if key == target else [], key=key)
        await multikey_registry.set_sites(HOST, _rows("sites", key.label, "old"), key=key)
    fresh = _rows("sites", target.label, "new")
    monkeypatch.setattr(
        multikey_client, "get", AsyncMock(return_value={"data": fresh, "totalCount": 1})
    )
    result = await list_local_sites(multikey_client, multikey_registry, HOST, **options)
    assert result["data"] == fresh
    for key in keys:
        assert await multikey_registry.get_sites(HOST, key=key) == _rows("sites", key.label, "old")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("empty", (False, True))
async def test_local_sites_refresh_updates_uuid_slug_and_evicts_vanished(
    multikey_client, multikey_registry, monkeypatch, mode, empty
):
    keys = _keys(multikey_client, monkeypatch, mode)
    target = keys[-1]
    for key in keys:
        await multikey_registry.set_hosts([{"id": HOST}] if key == target else [], key=key)
        await multikey_registry.set_sites(HOST, _rows("sites", key.label, "old"), key=key)
    fresh = [] if empty else _rows("sites", target.label, "new")
    monkeypatch.setattr(
        multikey_client, "get", AsyncMock(return_value={"data": fresh, "totalCount": len(fresh)})
    )
    result = await list_local_sites(multikey_client, multikey_registry, HOST)
    assert result["data"] == fresh
    no_request = AsyncMock(side_effect=AssertionError("resolution must use refreshed snapshot"))
    monkeypatch.setattr(multikey_client, "get", no_request)
    for selector in (OLD_UUID, f"{target.label}-old"):
        for resolver in ("site_id", "site_slug"):
            with pytest.raises(ValueError, match="valid"):
                await _resolve(multikey_registry, resolver, selector, target)
    if fresh:
        assert (
            await multikey_registry.resolve_site_id(f"{target.label}-new", HOST, key=target)
            == NEW_UUID
        )
        assert (
            await multikey_registry.resolve_site_slug(NEW_UUID, HOST, key=target)
            == f"slug-{target.label}-new"
        )
    no_request.assert_not_awaited()


PRODUCERS = (
    ("hosts", list_hosts),
    ("hosts", _fleet_summary),
    ("ea_sites", list_sites),
    ("ea_sites", list_all_sites_aggregated),
    ("ea_sites", _fleet_summary),
    ("sites", list_local_sites),
)


@pytest.mark.parametrize("family,producer", PRODUCERS)
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("fault", ("complete", "capped", "page_failure", "all_fail"))
async def test_every_list_producer_refreshes_only_complete_snapshot(
    multikey_client, multikey_registry, monkeypatch, family, producer, mode, fault
):
    keys = _keys(multikey_client, monkeypatch, mode)
    target = keys[-1]
    for key in keys:
        await _set(multikey_registry, family, _rows(family, key.label, "old"), key)
        if family == "sites":
            await multikey_registry.set_hosts([{"id": HOST}] if key == target else [], key=key)
    calls = []

    async def get(path, *, key=None, params=None):
        key = key or keys[0]
        calls.append((path, key.label))
        if family == "sites":
            is_target = path.endswith("/sites")
        else:
            is_target = path == ("/v1/hosts" if family == "hosts" else "/v1/sites")
        if not is_target:
            return {"data": []}
        later = bool(params.get("nextToken")) or bool(params.get("offset"))
        if fault == "all_fail" or (fault == "page_failure" and later):
            raise UniFiConnectionError(f"{key.label}: synthetic page failure")
        rows = _rows(family, key.label, "new") if not later else []
        if family == "sites":
            return {"data": rows, "totalCount": 1 if fault == "complete" else 2}
        return {
            "data": rows,
            **({"nextToken": "page-2"} if fault != "complete" and not later else {}),
        }

    monkeypatch.setattr(multikey_client, "get", AsyncMock(side_effect=get))
    if fault == "capped":
        monkeypatch.setattr(multikey_client._settings, "paginate_max_pages", 1)
    args = (HOST,) if family == "sites" else ()
    if fault in ("page_failure", "all_fail"):
        with pytest.raises((RuntimeError, UniFiConnectionError)) as caught:
            await producer(multikey_client, multikey_registry, *args)
        assert "synthetic page failure" in str(caught.value)
    else:
        result = await producer(multikey_client, multikey_registry, *args)
        assert bool(result.get("incomplete")) == (fault == "capped")
    for key in keys:
        refreshed = fault == "complete" and (family != "sites" or key == target)
        assert await _get(multikey_registry, family, key) == _rows(
            family, key.label, "new" if refreshed else "old"
        )
    assert {label for _, label in calls} == (
        {target.label} if family == "sites" else {key.label for key in keys}
    )


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("bad", (None, "bad", 7, True, []))
async def test_record_shape_generator_keeps_invalid_snapshots_out_of_each_cache(
    multikey_client, multikey_registry, monkeypatch, family, mode, bad
):
    keys = _keys(multikey_client, monkeypatch, mode)
    assert {key.label for key in keys} == ({"alpha"} if mode == "single" else {"alpha", "beta"})
    for key in keys:
        old = _rows(family, key.label, "old")
        await _set(multikey_registry, family, old, key)
        rows = [bad, *_rows(family, key.label, "new")]
        await _set(multikey_registry, family, rows, key)
        expected = _rows(family, key.label, "new") if family == "ea_sites" and bad is None else old
        assert await _get(multikey_registry, family, key) == expected
