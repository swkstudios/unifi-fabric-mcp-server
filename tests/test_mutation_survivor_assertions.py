"""Assertions that kill the surviving mutants of the core data-path modules.

A mutation campaign over client, registry, matching, macs, aggregation, pagination,
results, keys and Classic-object resolution left mutants the suite did not detect. Each
test below pins the behaviour one of them changed (named in the test's docstring as
``module:construct -- mutation``), so the same change now fails a test.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from unifi_fabric.client import (
    PaginationAbortedError,
    RateLimitError,
    UniFiClient,
    UniFiConnectionError,
    validate_selector,
)
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.matching import find_by_id
from unifi_fabric.registry import FetchedRecords, Registry
from unifi_fabric.tools import (
    _classic_objects,
    _keys,
    _pagination,
    _results,
    aggregation,
    device_mgmt,
)

H = "AA:1"
S = "11111111-0000-4000-8000-000000000001"
S2 = "22222222-0000-4000-8000-000000000002"
U1 = "11111111-1111-1111-1111-111111111111"
U2 = "22222222-2222-2222-2222-222222222222"
T = "2026-10-11T12:00:00Z"
A, B = "a" * 24, "b" * 24


def _client_with_pages(*pages: Any) -> tuple[UniFiClient, list[dict[str, Any]]]:
    """A real client whose GET answers ``pages`` in turn, recording each request's params."""
    client = UniFiClient(Settings(api_key="k"))
    calls: list[dict[str, Any]] = []

    async def get(path: str, *, key: Any = None, params: Any = None) -> Any:
        calls.append(dict(params or {}))
        page = pages[min(len(calls), len(pages)) - 1]
        if isinstance(page, Exception):
            raise page
        return page

    client.get = get  # type: ignore[method-assign]
    return client, calls


def _query_items(params: dict[str, Any]) -> set[tuple[str, Any]]:
    """The query-string items of a params dict (a list value is one item per element)."""
    out: set[tuple[str, Any]] = set()
    for name, value in params.items():
        for item in value if isinstance(value, list) else [value]:
            out.add((name, item))
    return out


# --------------------------------------------------------------------------------------
# client.py
# --------------------------------------------------------------------------------------


@respx.mock
async def test_retry_backoff_reaches_the_32s_ceiling(monkeypatch):
    """client.py:retry backoff -- ceiling 32 -> 16."""
    respx.get("https://api.ui.com/v1/probe").mock(return_value=httpx.Response(429, json={}))
    delays: list[float] = []

    async def sleep(seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr("unifi_fabric.client.asyncio.sleep", sleep)
    monkeypatch.setattr("unifi_fabric.client._secure_random.uniform", lambda a, b: 0)
    client = UniFiClient(Settings(api_key="k"))
    with pytest.raises(RateLimitError):
        await client.request("GET", "/v1/probe", max_retries=6)
    assert delays == [1, 2, 4, 8, 16, 32]


def test_selector_with_embedded_newline_is_rejected():
    """client.py:validate_selector -- control-or-whitespace check or -> and."""
    with pytest.raises(ValueError):
        validate_selector("ab\ncd", "client_id")


async def test_total_count_wins_over_total():
    """client.py:page_total -- field priority reversed (total before totalCount)."""
    client, _calls = _client_with_pages({"data": [{"id": 1}], "totalCount": 1, "total": 0})
    drained = await client.paginate_offset("/probe")
    assert drained.total_count == 1


async def test_cursor_drain_reports_its_array_key():
    """client.py:paginate (cursor) -- returned array_key becomes None."""
    client, _calls = _client_with_pages({"data": []})
    result = await _pagination.collect_cursor(client, "/v1/probe")
    assert result["array_key"] == "data"


async def test_cursor_stall_stops_after_two_requests():
    """client.py:paginate (cursor) -- cycle guard disabled (bounded oracle)."""
    page = {"data": [{"id": "host-1"}], "nextToken": "again"}
    client, calls = _client_with_pages(page, page, RuntimeError("third request"))
    with pytest.raises(PaginationAbortedError, match="stall detected") as exc:
        await client.paginate("/probe")
    assert len(calls) == 2
    assert exc.value.items == [{"id": "host-1"}]


# --------------------------------------------------------------------------------------
# registry.py
# --------------------------------------------------------------------------------------


def _proxy_registry(sites: list[dict[str, Any]]) -> Registry:
    client = AsyncMock()
    client.list_key_labels = MagicMock(return_value=["default"])
    client.paginate_offset = AsyncMock(return_value=list(sites))
    return Registry(client, ttl_seconds=0)


async def test_proxy_site_id_wins_over_underscore_id():
    """registry.py:_proxy_site_id -- id/_id priority reversed."""
    reg = _proxy_registry([{"id": U1, "_id": U2, "name": "Lab"}])
    assert await reg.resolve_site_id("Lab", "console-a") == U1


async def test_site_description_resolves_when_a_name_is_also_set():
    """registry.py:site labels -- description/name priority reversed."""
    reg = _proxy_registry([{"id": U1, "description": "Human Lab", "name": "Machine Lab"}])
    assert await reg.resolve_site_id("Human Lab", "console-a") == U1


async def test_ea_site_cache_is_bounded_by_the_host_bound():
    """registry.py:Registry.__init__ -- EA cache sized by cache_max_sites."""
    client = AsyncMock()
    client.list_key_labels = MagicMock(return_value=["default"])
    client.paginate = AsyncMock(return_value=[])
    reg = Registry(client, ttl_seconds=900, cache_max_hosts=2, cache_max_sites=7)
    for label in ("one", "two", "three"):
        await reg.get_ea_sites(key=APIKeyConfig(key=f"k-{label}", label=label))
    assert len(reg._ea_sites) == 2


# --------------------------------------------------------------------------------------
# macs.py / matching.py
# --------------------------------------------------------------------------------------


async def test_upstream_mac_with_surrounding_whitespace_is_read():
    """macs.py:record_mac -- surrounding-whitespace strip removed."""
    client = AsyncMock()
    client.get = AsyncMock(return_value={"macAddress": " AA:BB:CC:DD:EE:FF "})
    assert await device_mgmt._device_mac(client, H, S, S2, key=None) == "aa:bb:cc:dd:ee:ff"


async def test_malformed_upstream_mac_is_a_shape_error():
    """macs.py:record_mac -- MAC-validity guard removed."""
    client = AsyncMock()
    client.get = AsyncMock(return_value={"macAddress": "garbage"})
    with pytest.raises(UniFiConnectionError, match="valid 'macAddress'"):
        await device_mgmt._device_mac(client, H, S, S2, key=None)


def test_repeated_native_id_keeps_the_first_row():
    """matching.py:find_by_id -- setdefault -> assignment (last row wins)."""
    first = {"id": "AA", "marker": "first"}
    last = {"id": "aa", "marker": "last"}
    assert find_by_id([first, last], "AA", "id") is first


async def test_name_tiers_casefold_not_lower():
    """matching.py:name_keys -- casefold -> lower."""
    client = AsyncMock()
    client.list_key_labels = MagicMock(return_value=["default"])
    client.paginate = AsyncMock(return_value=[{"id": H, "name": "Straße"}])
    assert await Registry(client, ttl_seconds=0).resolve_host_id("STRASSE") == H


# --------------------------------------------------------------------------------------
# tools/aggregation.py
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("label", ["forwarded parameters", "time parameter"])
async def test_fleet_device_filters_reach_the_request(label):
    """aggregation.py:_fleet_devices -- forwarded params replaced with {};
    aggregation.py:_list_all_devices_fleet -- time parameter dropped."""
    client, calls = _client_with_pages({"data": []})
    await aggregation._list_all_devices_fleet(client, host_ids=[H], time=T)
    assert {("hostIds[]", H), ("time", T)} <= _query_items(calls[0])


async def test_partial_site_manager_list_is_reported():
    """aggregation.py:_get_all_host_site_pairs -- partial-site reason dropped."""
    registry = MagicMock()
    registry.get_ea_sites = AsyncMock(return_value=FetchedRecords([], "page cap reached"))
    registry.get_hosts = AsyncMock(return_value=[])
    incomplete: list[str] = []
    await aggregation._get_all_host_site_pairs(registry, incomplete=incomplete)
    assert incomplete == ["Site Manager site list: page cap reached"]


async def test_first_console_name_is_kept():
    """aggregation.py:_get_all_host_site_pairs -- names.setdefault -> assignment."""
    registry = MagicMock()
    registry.get_ea_sites = AsyncMock(return_value=[{"hostId": H}])
    registry.get_hosts = AsyncMock(
        return_value=[{"id": H, "name": "first"}, {"id": "aa:1", "name": "last"}]
    )
    registry.get_sites = AsyncMock(return_value=[{"id": S, "description": "s"}])
    pairs = await aggregation._get_all_host_site_pairs(registry)
    assert pairs[0]["hostName"] == "first"


async def test_proxy_site_id_wins_in_pairs():
    """aggregation.py:_get_all_host_site_pairs -- proxy site id/_id priority reversed."""
    registry = MagicMock()
    registry.get_ea_sites = AsyncMock(return_value=[{"hostId": H}])
    registry.get_hosts = AsyncMock(return_value=[])
    registry.get_sites = AsyncMock(return_value=[{"id": S, "_id": S2, "description": "s"}])
    pairs = await aggregation._get_all_host_site_pairs(registry)
    assert pairs[0]["siteId"] == S


async def _clients_with_one_partial_site() -> dict[str, Any]:
    client = AsyncMock()
    client.list_key_labels = MagicMock(return_value=["default"])
    pair = {"hostId": H, "siteId": S, "hostName": "c", "siteName": "s"}
    collected = {
        "items": [{"id": "c1"}],
        "totalCount": 2,
        "incomplete": True,
        "incompleteReason": "page cap reached",
        "envelope": {"totalCount": 2, "traceId": "T"},
    }
    with (
        patch.object(aggregation, "_get_all_host_site_pairs", AsyncMock(return_value=[pair])),
        patch.object(aggregation, "collect_offset", AsyncMock(return_value=collected)),
    ):
        return await aggregation._list_all_clients_fleet(client, MagicMock())


async def test_partial_site_is_not_counted_succeeded():
    """aggregation.py:_list_all_clients_fleet -- incomplete-site subtraction omitted."""
    result = await _clients_with_one_partial_site()
    assert result["_sitesSucceeded"] == 0


async def test_partial_site_keeps_its_envelope():
    """aggregation.py:_list_all_clients_fleet -- site envelopes dropped."""
    result = await _clients_with_one_partial_site()
    assert result["_siteEnvelopes"] == {H + "/" + S: {"totalCount": 2, "traceId": "T"}}


def test_device_is_associated_with_its_wrapper_console():
    """aggregation.py:_unwrap_ea_devices -- device/context precedence reversed."""
    wrapper = {"hostId": H, "devices": [{"id": "dev1", "_hostId": "BB:2"}]}
    result = aggregation._unwrap_ea_devices([wrapper])[0]
    assert result["_hostId"] == "BB:2"
    assert _keys.context_value(result, "_hostId") == H
    assert result["_wrapperFields"] == {"_hostId": H}
    assert wrapper["devices"][0]["_hostId"] == "BB:2"


async def _summary_with_capped(path_capped: str) -> MagicMock:
    async def paginate(path, *, key=None):
        if path == path_capped:
            raise PaginationAbortedError(path, 1, "page cap of 1 reached", items=[])
        return []

    client = AsyncMock()
    client.list_key_labels = MagicMock(return_value=["default"])
    client.paginate = AsyncMock(side_effect=paginate)
    registry = MagicMock()
    registry.set_hosts = AsyncMock()
    registry.set_ea_sites = AsyncMock()
    await aggregation._fleet_summary(client, registry)
    return registry


async def test_capped_host_list_is_not_cached():
    """aggregation.py:_fleet_summary -- host-cap cache guard inverted."""
    registry = await _summary_with_capped("/v1/hosts")
    registry.set_hosts.assert_not_awaited()
    registry.set_ea_sites.assert_awaited()


async def test_capped_site_list_is_not_cached():
    """aggregation.py:_fleet_summary -- site-cap cache guard inverted."""
    registry = await _summary_with_capped("/v1/sites")
    registry.set_ea_sites.assert_not_awaited()
    registry.set_hosts.assert_awaited()


@pytest.mark.parametrize(
    "row",
    [
        {"id": "dev1", "displayName": "Needle"},
        {"id": "dev1", "reportedState": {"shortname": "Needle"}},
        {"id": "dev1", "reportedState": {"name": "Needle"}},
    ],
    ids=["displayName", "reportedState.shortname", "reportedState.name"],
)
async def test_search_device_fields(row):
    """aggregation.py:_search_device -- displayName / reportedState.shortname /
    reportedState.name removed from the searched fields."""
    client = AsyncMock()
    client.list_key_labels = MagicMock(return_value=["default"])
    client.paginate = AsyncMock(return_value=[{"devices": [row]}])
    assert (await aggregation._search_device(client, "needle"))["data"] == [row]


async def test_search_device_echoes_the_query():
    """aggregation.py:_search_device -- query echo becomes None."""
    client = AsyncMock()
    client.list_key_labels = MagicMock(return_value=["default"])
    client.paginate = AsyncMock(return_value=[])
    assert (await aggregation._search_device(client, "needle"))["_query"] == "needle"


# --------------------------------------------------------------------------------------
# tools/_pagination.py / tools/_results.py
# --------------------------------------------------------------------------------------


async def test_collect_cursor_keeps_the_array_key():
    """_pagination.py:collect_cursor -- array-key metadata becomes None."""
    client, _calls = _client_with_pages({"data": []})
    collected = await _pagination.collect_cursor(client, "/v1/probe")
    assert collected["array_key"] == "data"


async def test_links_drain_default_page_size():
    """Recognition drains use the measured 100-record maximum, starting at page one."""
    client, calls = _client_with_pages({"groups": [{"id": "g"}], "links": {"next": None}})
    await _pagination.collect_links(client, "/recognition/face/groups", "groups")
    assert calls == [{"pageSize": 100, "page": 1}]


def test_tool_owned_key_beats_the_envelope():
    """_pagination.py:with_envelope -- envelope/result merge precedence reversed."""
    result = _pagination.with_envelope(
        {"data": [{"id": "r"}], "_count": 1}, {"envelope": {"_count": 99, "traceId": "t"}}
    )
    assert result["_count"] == 99
    assert _keys.context_value(result, "_count") == 1
    assert result["_wrapperFields"] == {"_count": 1}
    assert result["data"] == [{"id": "r"}]
    assert result["traceId"] == "t"


def test_dry_run_never_short_circuits_as_no_op():
    """_results.py:short_circuit_no_op -- dry-run guard removed."""
    client = MagicMock()
    client.dry_run = True
    assert _results.short_circuit_no_op(client, True) is False
    client.dry_run = False
    assert _results.short_circuit_no_op(client, True) is True


# --------------------------------------------------------------------------------------
# tools/_keys.py
# --------------------------------------------------------------------------------------


async def test_first_success_takes_the_first_configured_key(multikey_client):
    """_keys.py:first_success -- first-success selection reversed."""

    async def fetch(key: APIKeyConfig | None) -> dict[str, Any]:
        await asyncio.sleep(0.01 if key is not None and key.label == "alpha" else 0)
        return {"owner": key.label if key is not None else None}

    key, body = await _keys.first_success(multikey_client, None, fetch)
    assert {"key": key.label, "body": body} == {"key": "alpha", "body": {"owner": "alpha"}}


def test_key_errors_come_before_existing_errors():
    """_keys.py:report_keys -- error-list concatenation reversed."""
    result = _keys.report_keys(
        {"errors": ["site: synthetic failure"]}, [], ["beta: synthetic failure"], multi=True
    )
    assert result["errors"] == ["site: synthetic failure"]
    assert result["_wrapperFields"] == {"errors": ["beta: synthetic failure"]}
    assert result["_key_labels"] == []


def test_tag_items_keeps_scalar_rows():
    """_keys.py:tag_items -- scalar row replaced with None."""
    tagged = _keys.tag_items(["scalar-row", {"id": "A"}], "alpha", True)
    assert tagged == ["scalar-row", {"id": "A", "_keyLabel": "alpha"}]


def test_first_id_accepts_a_falsy_identity():
    """_keys.py:first_id -- ``found is not None`` -> truthiness."""
    identity = _keys.first_id(lambda record: 0, lambda record: "fallback")
    assert identity({"id": "A"}) == 0


# --------------------------------------------------------------------------------------
# tools/_classic_objects.py
# --------------------------------------------------------------------------------------


async def test_device_tag_native_id_beats_a_name():
    """_classic_objects.py:resolve_device_tag_record -- name matched before native id."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=[{"_id": A, "name": "target"}, {"_id": B, "name": A}])
    registry = MagicMock()
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value=H)
    registry.resolve_site_slug = AsyncMock(return_value="default")
    *_rest, resolved_record = await _classic_objects.resolve_device_tag_record(
        client, registry, "h", "Default", A
    )
    assert resolved_record["_id"] == A


def test_device_tag_partial_delta_gets_the_hint():
    """_classic_objects.py:device_tag_update_hint -- required delta keys all -> any."""
    body = {"device_mac_additions": []}
    assert _classic_objects.device_tag_update_hint(body) == _classic_objects.DEVICE_TAG_UPDATE_HINT


async def test_listed_record_with_a_malformed_native_id_is_refused():
    """_classic_objects.py:require_listed_record -- listed-record id validation removed."""
    client = AsyncMock()
    client.get = AsyncMock(return_value={"data": [{"_id": "../target", "name": "bad-native-id"}]})
    with pytest.raises(ValueError):
        await _classic_objects.require_listed_record(
            client, "/list", "../target", key=None, kind="Tag", list_tool="list_tags"
        )


def test_record_label_keeps_a_zero_value():
    """_classic_objects.py:_record_label -- non-empty check -> truthiness."""
    row = {"name": 0, "mac": "aa:bb:cc:dd:ee:ff"}
    assert _classic_objects._record_label(row, ("name", "mac")) == 0
