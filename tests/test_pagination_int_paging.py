"""Integration-round paging regressions; synthetic upstreams only.

- F1: ``nextOffset`` is the physical position reached, so a resumed call after an
  insertion between calls returns no record twice (PAGING-ROUND2 ruling 1).
- U1: rows of one page are compared only against earlier pages, never against each other.
- U4/U10: a page that returns only records earlier pages returned ends the offset drain in
  both drainers, with the same decision (REPEATED-OVERSIZED-TOTAL).
- U2/U5: number-family windows on an unpaged bare array and on a short page 0.
- F2/F3: PAGING-VALIDATION-A1 rules 1 to 3 over every tool's actual pagination arguments.
"""

from __future__ import annotations

import functools
import logging
from types import SimpleNamespace
from typing import Any

import pytest

from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize
from tests._tool_catalog import tools as catalog_tools
from unifi_fabric import refusals, server
from unifi_fabric.client import PaginationAbortedError, UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.generated_api_facts._spec_limits_table import SPEC_LIMITS
from unifi_fabric.shared_shapes._number_window import collect_number_window
from unifi_fabric.shared_shapes._pagination import (
    collect_batch,
    collect_offset,
    validate_pagination,
)


def _client(get: Any) -> UniFiClient:
    client = UniFiClient(Settings(api_key="synthetic-int-paging"))
    client.get = get  # type: ignore[method-assign]
    return client


# --------------------------------------------------------------------------- F1


async def test_f1_resume_after_insertion_returns_no_record_twice():
    source = [{"id": f"r{i}"} for i in range(20)]
    calls: list[dict[str, Any]] = []

    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        if len(calls) == 2:
            # A record is inserted at the front between the first and second request.
            source.insert(0, {"id": "inserted"})
        offset = controls.get("offset", 0)
        return {"data": source[offset : offset + controls["limit"]]}

    first = await collect_batch(fetch, requested=10, known_max=5, family="offset")
    first_ids = [row["id"] for row in first["items"]]
    assert first_ids == [f"r{i}" for i in range(10)]
    assert not first["incomplete"]
    # Offsets 0-10 were consumed: r4 was dropped once as already returned, so the
    # records kept (10) would resume one position too early, at r9.
    assert first["nextOffset"] == 11
    resumed = await collect_batch(fetch, requested=10, known_max=5, family="offset", start=11)
    resumed_ids = [row["id"] for row in resumed["items"]]
    assert resumed_ids == [f"r{i}" for i in range(10, 20)]
    assert not set(first_ids) & set(resumed_ids)
    assert sorted(first_ids + resumed_ids) == sorted(f"r{i}" for i in range(20))


async def test_f1_trimmed_overlap_resumes_just_past_the_last_returned_record():
    source = [{"id": i} for i in range(12)]
    calls: list[dict[str, Any]] = []

    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        offset = controls.get("offset", 0)
        if len(calls) == 1:
            return {"data": source[0:4]}
        # Two records inserted before the second request: offsets 4-5 repeat ids 2-3.
        shifted = source[:2] + [{"id": "a"}, {"id": "b"}] + source[2:]
        return {"data": shifted[offset : offset + 8]}

    result = await collect_batch(fetch, requested=6, known_max=8, family="offset")
    assert [row["id"] for row in result["items"]] == [0, 1, 2, 3, 4, 5]
    # Page 2 started at offset 4 and held 2, 3 (dropped), 4, 5 (kept), 6, 7: the last
    # returned record sits at offset 7, so the resume position is 8.
    assert result["nextOffset"] == 8
    assert not result["incomplete"]


# --------------------------------------------------------------------------- U1


@pytest.mark.parametrize("adapter", ["client", "batch", "collect"])
async def test_u1_rows_repeated_within_one_page_pass_through(adapter):
    page = [{"id": 1, "v": "a"}, {"id": 1, "v": "b"}, {"id": 2}]
    calls: list[dict[str, Any]] = []

    async def get(path: str, *, key: Any = None, params: dict[str, Any]) -> Any:
        calls.append(dict(params))
        assert len(calls) <= 2
        return {"data": page if len(calls) == 1 else []}

    if adapter == "client":
        records = await _client(get).paginate_offset("/synthetic", page_size=200)
    elif adapter == "batch":
        result = await collect_batch(
            lambda controls: get("/synthetic", params=controls), requested=None, family="offset"
        )
        assert not result["incomplete"]
        records = result["items"]
    else:
        result = await collect_offset(
            SimpleNamespace(get=get, paginate_max_pages=None), "/synthetic", limit=3
        )
        assert not result["incomplete"]
        records = result["items"]
    assert records == page
    assert len(calls) == 2
    if adapter == "collect":
        assert calls == [{"limit": 3}, {"offset": 3, "limit": 1}]
        assert result["pages"] == 2
        assert result["_pageSize"] == {
            "requested": 3,
            "sent": [3, 1],
            "effective": 3,
            "returned": 3,
        }


async def test_u1_collect_terminal_total_and_native_offset_are_single_page():
    page = [{"id": 1, "v": "a"}, {"id": 1, "v": "b"}, {"id": 2}]
    calls: list[dict[str, Any]] = []

    async def get(path: str, *, key: Any = None, params: dict[str, Any]) -> Any:
        calls.append(dict(params))
        return {"data": page, "total": 3}

    client = SimpleNamespace(get=get, paginate_max_pages=None)
    result = await collect_offset(client, "/synthetic", limit=3)
    assert result["items"] == page
    assert not result["incomplete"]
    assert calls == [{"limit": 3}]

    calls.clear()
    result = await collect_offset(client, "/synthetic", offset=0, limit=3)
    assert result["items"] == page
    assert not result["incomplete"]
    assert calls == [{"offset": 0, "limit": 3}]


# --------------------------------------------------------------------------- U4 / U10


def _shuffled_feed(size: int, calls: list[dict[str, Any]]) -> Any:
    async def get(path: str, *, key: Any = None, params: dict[str, Any]) -> Any:
        calls.append(dict(params))
        assert len(calls) <= 3, "the drain did not stop"
        rows = [{"id": i, "live": len(calls)} for i in range(size)]
        # Ignores offset and limit, and answers in a different order on every call.
        return {"data": rows if len(calls) % 2 else rows[::-1]}

    return get


@pytest.mark.parametrize("adapter", ["client", "batch"])
async def test_u4_reordered_repeat_of_a_paged_size_aborts(adapter):
    calls: list[dict[str, Any]] = []
    get = _shuffled_feed(3, calls)
    reason = (
        "page 2 at offset 3 returned only records already returned on earlier pages: the "
        "upstream ignores offset, so records past the first page cannot be reached by paging"
    )
    if adapter == "client":
        with pytest.raises(PaginationAbortedError) as error:
            await _client(get).paginate_offset("/synthetic", page_size=3)
        records, total = error.value.items, error.value.total_count
        assert error.value.reason == reason
    else:
        result = await collect_batch(
            lambda controls: get("/synthetic", params=controls),
            requested=None,
            family="offset",
            default_size=3,
        )
        records, total = result["items"], result["totalCount"]
        assert result["incomplete"]
        assert result["incompleteReason"] == reason
        assert result["nextOffset"] is None
    assert [row["id"] for row in records] == [0, 1, 2]
    assert total is None
    assert len(calls) == 2


@pytest.mark.parametrize("adapter", ["client", "batch"])
async def test_u4_reordered_repeat_of_an_oversized_page_is_unpaged_and_complete(adapter):
    calls: list[dict[str, Any]] = []
    get = _shuffled_feed(250, calls)
    if adapter == "client":
        records = await _client(get).paginate_offset("/synthetic", page_size=200)
    else:
        result = await collect_batch(
            lambda controls: get("/synthetic", params=controls), requested=None, family="offset"
        )
        assert not result["incomplete"]
        records = result["items"]
    assert [row["id"] for row in records] == list(range(250))
    assert len(calls) == 2


@pytest.mark.parametrize("adapter", ["client", "batch"])
async def test_u4_reordered_repeat_with_outstanding_total_aborts_with_the_total(adapter):
    calls: list[dict[str, Any]] = []
    feed = _shuffled_feed(250, calls)

    async def get(path: str, *, key: Any = None, params: dict[str, Any]) -> Any:
        return {**(await feed(path, params=params)), "totalCount": 900}

    if adapter == "client":
        with pytest.raises(PaginationAbortedError) as error:
            await _client(get).paginate_offset("/synthetic", page_size=200)
        records, total, reason = error.value.items, error.value.total_count, error.value.reason
    else:
        result = await collect_batch(
            lambda controls: get("/synthetic", params=controls), requested=None, family="offset"
        )
        records, total, reason = result["items"], result["totalCount"], result["incompleteReason"]
    assert len(records) == 250
    assert len({row["id"] for row in records}) == 250
    assert total == 900
    assert reason.endswith("although it declared totalCount 900 (250 of 900 records gathered)")
    assert len(calls) == 2


# --------------------------------------------------------------------------- U2 / U5


def _number_fetch(response: Any, calls: list[dict[str, Any]]) -> Any:
    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        return response(controls) if callable(response) else response

    return fetch


@pytest.mark.parametrize(
    ("page", "expected", "next_page", "requests"),
    [(0, [0, 1], 1, 1), (1, [2, 3], None, 2), (2, [], None, 2)],
)
async def test_u2_unpaged_bare_array_selects_the_window(page, expected, next_page, requests):
    records = [{"id": i} for i in range(4)]
    calls: list[dict[str, Any]] = []
    result = await collect_number_window(
        _number_fetch(lambda _controls: list(records), calls),
        page=page,
        page_size=2,
        max_pages=None,
    )
    assert [row["id"] for row in result["items"]] == expected
    assert result["nextPage"] == next_page
    assert not result["incomplete"]
    assert len(calls) == requests


async def test_u2_contiguous_windows_over_an_unpaged_bare_array():
    records = [{"id": i} for i in range(7)]
    gathered: list[Any] = []
    page: int | None = 0
    while page is not None:
        result = await collect_number_window(
            _number_fetch(lambda _controls: list(records), []),
            page=page,
            page_size=3,
            max_pages=None,
        )
        assert not result["incomplete"]
        gathered.extend(result["items"])
        page = result["nextPage"]
    assert gathered == records


async def test_u2_unpaged_repeat_with_a_declared_larger_total_stays_incomplete():
    records = [{"id": i} for i in range(4)]
    calls: list[dict[str, Any]] = []
    result = await collect_number_window(
        _number_fetch(lambda _controls: {"data": list(records), "total_element_count": 10}, calls),
        page=1,
        page_size=2,
        max_pages=None,
    )
    assert result["items"] == []
    assert result["incomplete"]
    assert result["nextPage"] is None
    assert len(calls) == 2


async def test_u2_system_log_window_over_an_unpaged_bare_array():
    from unittest.mock import AsyncMock

    from unifi_fabric.families.statistics import system_log

    client = AsyncMock()
    client.paginate_max_pages = None
    records = [{"id": number} for number in range(4)]
    client.post.return_value = records
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = None
    registry.resolve_host_id.return_value = "host-001"
    registry.resolve_site_slug.return_value = "default"
    result = await system_log._read_system_log(
        client, registry, "h", "Default", "critical", None, page=1, page_size=2
    )
    assert result["data"] == records[2:4]
    assert "_nextPage" not in result
    assert "incomplete" not in result
    assert client.post.await_count == 2


async def test_u5_short_page_zero_without_total_is_complete():
    # SHORTPAGE-EXPECTATIONS (canonical sentence, T10 and note N4): a short page 0 with no
    # total, page count or size echo is not final; the window continues at the console
    # size 3 and the empty page 1 proves the end. A fixture that answered every request
    # with the same page would be a repeat, not completion evidence.
    calls: list[dict[str, Any]] = []
    rows = [{"id": i} for i in range(3)]
    pages = iter([{"data": rows}, {"data": []}])
    result = await collect_number_window(
        _number_fetch(lambda _controls: next(pages), calls), page=0, page_size=10, max_pages=None
    )
    assert result["items"] == rows
    assert not result["incomplete"]
    assert result["nextPage"] is None
    assert result["totalCount"] is None
    assert calls == [{"pageNumber": 0, "pageSize": 10}, {"pageNumber": 1, "pageSize": 3}]
    assert result["_pageSize"] == {"requested": 10, "sent": [10, 3], "effective": 3, "returned": 3}


# --------------------------------------------------------------------------- F2 / F3

#: Zero-based page arguments (number-family tools), per PAGING-VALIDATION-A1 rule 1.
ZERO_BASED = {("get_sites_overview", "page"), ("get_system_log", "page")}
ZERO_BASED_NAMES = {"page_number"}
COUNT_NAMES = {"limit", "page_size"}
PAGING_NAMES = {"limit", "page_size", "offset", "page", "page_number"}


#: A ``limit`` that is not a pagination control: one verbatim GET forwards it unchanged,
#: with no offset, page or logical total (get_protect_automation_history).
NOT_PAGINATION = {("get_protect_automation_history", "limit")}


@functools.cache
def _paging_arguments() -> tuple[tuple[str, str], ...]:
    # Built on first use (generate time or a test body), never at module import.
    return tuple(
        sorted(
            (tool.name, arg)
            for tool in catalog_tools()
            for arg in tool.parameters.get("properties", {})
            if arg in PAGING_NAMES and (tool.name, arg) not in NOT_PAGINATION
        )
    )


def _kind(tool: str, arg: str) -> str:
    if arg in COUNT_NAMES:
        return "count"
    if arg == "offset":
        return "offset"
    if arg in ZERO_BASED_NAMES or (tool, arg) in ZERO_BASED:
        return "zero"
    return "one"


def _expected(arg: str, kind: str, value: Any) -> str:
    if kind == "count":
        return (
            f"{arg} must be a positive integer (1 or more); got {value}. "
            f"Omit {arg} to read the whole collection."
        )
    if kind == "offset":
        return f"{arg} must be 0 or more; got {value}."
    if kind == "zero":
        return f"{arg} is zero-based and must be 0 or more; got {value}."
    return f"{arg} is 1-based and must be 1 or more; got {value}."


def _refusal_cases() -> list[Any]:
    values = {
        "count": (0, -1, -5, True, 1.5),
        "one": (0, -1, -5, True, 1.5),
        "zero": (-1, -5, True, 1.5),
        "offset": (-1, -5, True, 1.5),
    }
    return [
        pytest.param(tool, arg, value, id=f"{tool}-{arg}={value}")
        for tool, arg in _paging_arguments()
        for value in values[_kind(tool, arg)]
    ]


async def _call(name: str, args: dict[str, Any]) -> tuple[str | None, uh.FakeUpstream]:
    up = uh.FakeUpstream(replay_recordings=False)
    logging.disable(logging.CRITICAL)
    try:
        with pytest.MonkeyPatch.context() as mp:
            for key, value in tool_args.TOOL_ENV.get(name, {}).items():
                mp.setenv(key, value)
            uh.install(mp, up)
            try:
                await server.mcp.call_tool(name, args)
            except Exception as exc:  # noqa: BLE001 - the message is the assertion
                return str(exc), up
    finally:
        logging.disable(logging.NOTSET)
    return None, up


async def _base(name: str) -> dict[str, Any]:
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    args = tool_args.generated_args(tools[name])
    # Only the argument under test is a paging control.
    return {k: v for k, v in args.items() if k not in PAGING_NAMES}


def test_paging_argument_inventory_is_complete():
    found = _paging_arguments()
    assert ("get_sites_overview", "page") in found
    assert ("query_teleport_invitations", "page_number") in found
    assert ("list_recognition_groups", "page") in found
    assert ("list_networks", "limit") in found
    assert ("list_hosts", "page_size") in found
    assert len(found) >= 60


def _spec_bounded(tool: str, arg: str, value: Any) -> bool:
    """Whether the vendored spec fragment itself refuses ``value`` (SpecLimitMiddleware)."""
    minimum = SPEC_LIMITS.get(tool, {}).get(arg, {}).get("minimum")
    return isinstance(minimum, int) and isinstance(value, int) and value < minimum


@lazy_parametrize(("tool", "arg", "value"), _refusal_cases)
async def test_every_pagination_argument_is_refused_before_any_request(tool, arg, value):
    message, up = await _call(tool, {**(await _base(tool)), arg: value})
    assert message is not None, f"{tool}({arg}={value!r}) was not refused"
    message = message.removeprefix(f"Error calling tool '{tool}': ")
    registered = refusals.classify(message)
    assert registered is not None, message
    if isinstance(value, bool) or not isinstance(value, int):
        # A boolean or non-integer is refused by the argument layers before the tool runs
        # (PAGING-VALIDATION-A1 rule 2 allows a refusal ahead of the tool's own check);
        # the tool's own message for it is pinned in test_validator_names_the_argument.
        assert arg in message, message
    elif _spec_bounded(tool, arg, value):
        # The vendored spec bounds this value; SpecLimitMiddleware refuses it (rule 2).
        assert registered.id == "spec-limits", message
        assert f"'{arg}' is {value}:" in message
    else:
        assert message == _expected(arg, _kind(tool, arg), value)
        assert registered.id == "logical-pagination-integer"
    # No request at all: no host or site resolution and no target request.
    assert up.served == []


@pytest.mark.parametrize(
    ("kind", "arg"),
    [
        ("count", "limit"),
        ("count", "page_size"),
        ("offset", "offset"),
        ("zero", "page"),
        ("zero", "page_number"),
        ("one", "page"),
    ],
)
@pytest.mark.parametrize("value", [True, 1.5, "2"])
def test_validator_names_the_argument_for_booleans_and_non_integers(kind, arg, value):
    keyword = {"count": "page_size", "offset": "offset", "zero": "zero_page", "one": "page"}[kind]
    with pytest.raises(ValueError) as error:
        validate_pagination(**{keyword: value}, names={keyword: arg})
    assert str(error.value) == _expected(arg, kind, value)
    assert refusals.classify(str(error.value)).id == "logical-pagination-integer"


@lazy_parametrize(("tool", "arg"), _paging_arguments)
async def test_no_pagination_refusal_names_an_argument_the_tool_lacks(tool, arg):
    tools = {t.name: t for t in await server.mcp.list_tools()}
    message, _up = await _call(tool, {**(await _base(tool)), arg: -5})
    assert message is not None
    named = message.removeprefix(f"Error calling tool '{tool}': ").split(" ", 1)[0].strip("'")
    assert named in tools[tool].parameters["properties"], (tool, message)


def _control_cases() -> list[Any]:
    controls = []
    for tool, arg in _paging_arguments():
        kind = _kind(tool, arg)
        value = {"count": 1, "zero": 0, "offset": 0}.get(kind)
        if value is not None:
            controls.append(pytest.param(tool, arg, value, id=f"{tool}-{arg}={value}"))
    return controls


@lazy_parametrize(("tool", "arg", "value"), _control_cases)
async def test_smallest_meaningful_pagination_value_reaches_the_route(tool, arg, value):
    message, up = await _call(tool, {**(await _base(tool)), arg: value})
    assert message is None or not message.split(": ")[-1].startswith(f"{arg} "), message
    # A console or site listing tool's own route is the enumeration endpoint.
    primary = {"list_hosts", "list_sites", "list_local_sites", "list_all_sites_aggregated"}
    assert any(tool in primary or not served.resolution for served in up.served), (
        tool,
        arg,
        message,
    )
