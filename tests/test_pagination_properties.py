"""Offline paging oracle; UNIFI_PAGINATION_PROFILE=nightly selects the long run."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from unifi_fabric.client import PaginationAbortedError, UniFiClient
from unifi_fabric.tools._pagination import collect_batch, collect_links, collect_offset

SIZES = (1, 25, 100, 101, 250, 275)
FAMILIES = ("offset", "number", "links", "cursor", "carrier")
settings.register_profile(
    "pagination", max_examples=480, derandomize=True, database=None, deadline=None
)
settings.register_profile(
    "pagination-nightly", max_examples=4000, derandomize=True, database=None, deadline=None
)
PAGING = settings.get_profile(
    "pagination-nightly"
    if os.environ.get("UNIFI_PAGINATION_PROFILE") == "nightly"
    else "pagination"
)


@dataclass(frozen=True)
class Case:
    total: int
    behavior: str
    native_size: int
    shape: str
    identities: str | None
    empty_final: bool

    def size(self, sent):
        if self.behavior == "honours":
            return sent
        if self.behavior == "clamps":
            return min(sent, self.native_size)
        return self.native_size

    def records(self, start=0, stop=None):
        return [
            {self.identities or "ordinal": i, "payload": {"synthetic": i}}
            for i in range(start, min(self.total, stop if stop is not None else self.total))
        ]


CASES = st.builds(
    Case,
    total=st.integers(0, 1600),
    behavior=st.sampled_from(("honours", "clamps", "ignores")),
    native_size=st.sampled_from((1, 25, 37, 100, 200, 500)),
    shape=st.sampled_from(("bare", "object", "echo", "total", "both")),
    identities=st.sampled_from((None, "id", "_id", "uuid", "mac")),
    empty_final=st.booleans(),
)


class Upstream:
    """Stable records; native index tokens expose a change of wire size."""

    paginate_max_pages = None
    _settings = SimpleNamespace(paginate_max_pages=None)

    def __init__(self, case, family):
        self.case, self.family = case, family
        self.calls = []

    async def get(self, path, *, key=None, params=None):
        del path, key
        controls = dict(params or {})
        self.calls.append(controls)
        family, case = self.family, self.case
        size_key = "limit" if family in {"offset", "carrier"} else "pageSize"
        size = case.size(controls.get(size_key, 200))
        if family == "offset":
            start = controls.get("offset", 0)
        elif family in {"number", "links"}:
            origin = 1 if family == "links" else 0
            page_key = "page" if family == "links" else "pageNumber"
            start = (controls.get(page_key, origin) - origin) * size
        else:
            token = controls.get("cursor" if family == "carrier" else "nextToken")
            start = int(token.split(":")[1]) * size if token else 0
        rows = case.records(start, start + size)
        stop = start + len(rows)
        more = stop < case.total or (case.empty_final and bool(rows) and stop == case.total)
        token = f"native:{start // size + 1}" if more else None
        if family in {"offset", "number"} and case.shape == "bare":
            return rows
        body = {"data": rows, "upstream": {"synthetic": "retained"}}
        if case.shape in {"echo", "both"}:
            body["limit"] = size
        if case.shape in {"total", "both"}:
            body["totalCount"] = case.total
        if family == "number":
            body["page_number"] = controls.get("pageNumber", 0)
            body["total_page_count"] = math.ceil(case.total / size) + (
                1 if case.empty_final and case.total else 0
            )
        elif family == "links":
            number = controls.get("page", 1)
            body["links"] = {
                "next": f"?page={number + 1}&pageSize={size}" if more else None,
                "prev": f"?page={number - 1}&pageSize={size}" if number > 1 else None,
            }
        elif family == "cursor":
            body["nextToken"] = token
        elif family == "carrier":
            body["meta"] = {"hasMore": more, "nextCursor": token, "limit": size}
        return body

    async def fetch(self, controls):
        return await self.get("/synthetic/paging", params=controls)


def items(result):
    return result.get("items", result.get("raw", []))


def assert_complete(result, expected):
    assert not result.get("incomplete"), result.get("incompleteReason")
    assert items(result) == expected


def assert_contract(result, expected, upstream):
    if not result.get("incomplete"):
        assert_complete(result, expected)
        return
    # The no-identity ambiguity is deliberately unknowable to a real client,
    # even though this fake upstream knows that its two pages were distinct.
    assert upstream.family in {"offset", "number"}
    assert not upstream.case.identities
    assert len(upstream.calls) == 2
    size_key = "limit" if upstream.family == "offset" else "pageSize"
    first, second = (call[size_key] for call in upstream.calls)
    effective = upstream.case.size(first)
    assert effective > first
    assert min(upstream.case.total - effective, upstream.case.size(second)) > second
    assert items(result) == upstream.case.records(0, effective)
    assert "no id, _id, uuid or mac" in result["incompleteReason"]
    for field in ("nextPage", "nextOffset", "nextToken", "nextCursor"):
        assert result.get(field) is None


def assert_once(rows, identities):
    key = ("id" if identities is True else identities) or "ordinal"
    assert len({row[key] for row in rows}) == len(rows)


@pytest.mark.parametrize("family", FAMILIES)
@PAGING
@given(case=CASES)
async def test_full_drain_equals_dataset(family, case):
    upstream = Upstream(case, family)
    result = await collect_batch(
        upstream.fetch,
        requested=None,
        family=family,
        start=1 if family == "links" else 0,
        known_max=100 if family == "links" else 200,
    )
    assert_contract(result, case.records(), upstream)
    assert_once(items(result), case.identities)
    assert result.get("nextPage") is None
    if family not in {"offset", "number"} or case.shape != "bare":
        assert result["envelope"]["upstream"] == {"synthetic": "retained"}


@PAGING
@given(case=CASES, size=st.sampled_from(SIZES))
async def test_client_offset_and_adapter_drain_equal_dataset(case, size):
    client = Upstream(case, "offset")
    try:
        result = await UniFiClient.paginate_offset(client, "/synthetic/paging", page_size=size)
    except PaginationAbortedError as error:
        assert_contract(
            {"items": error.items, "incomplete": True, "incompleteReason": str(error)},
            case.records(),
            client,
        )
    else:
        assert result == case.records()
        assert_once(result, case.identities)
    upstream = Upstream(case, "offset")
    collected = await collect_offset(upstream, "/synthetic/paging", page_size=size)
    assert_contract(collected, case.records(), upstream)


@pytest.mark.parametrize("family", ("offset", "links"))
@PAGING
@given(case=CASES, page=st.integers(1, 12), size=st.sampled_from(SIZES))
@example(case=Case(25, "ignores", 100, "echo", "id", False), page=2, size=1)
async def test_logical_window_and_same_size_resume(family, case, page, size):
    upstream = Upstream(case, family)
    start = (page - 1) * size

    async def window(position):
        if family == "links":
            return await collect_links(
                upstream, "/synthetic/paging", "data", page=position, page_size=size
            )
        return await collect_batch(
            upstream.fetch,
            requested=size,
            family=family,
            start=position,
            known_max=200,
            omit_initial_offset=False,
        )

    result = await window(page if family == "links" else start)
    assert_complete(result, case.records(start, start + size))
    assert_once(items(result), case.identities)
    continuation = result.get("nextPage" if family == "links" else "nextOffset")
    if continuation is not None:
        assert continuation == (page + 1 if family == "links" else start + size)
        second = await window(continuation)
        assert_complete(second, case.records(start + size, start + 2 * size))
        rows = items(result) + items(second)
        assert rows == case.records(start, start + 2 * size)
        assert_once(rows, case.identities)
    else:
        assert start + size >= case.total


@PAGING
@given(total=st.integers(2, 100), start=st.integers(1, 12))
async def test_offset_ignoring_single_window_never_exposes_resume(total, start):
    """An upstream ignoring offset repeats its first body at the probe boundary."""
    case = Case(total, "honours", 1, "bare", "id", False)
    upstream = Upstream(case, "offset")
    controls_sent = []

    async def ignores_offset(controls):
        controls_sent.append(dict(controls))
        return await upstream.fetch({**controls, "offset": 0})

    result = await collect_batch(
        ignores_offset, requested=1, family="offset", start=start, omit_initial_offset=False
    )
    assert items(result) == case.records(0, 1)
    assert result["incomplete"] is True
    assert result["nextOffset"] is None
    assert result["pages"] == 2
    assert result["_pageSize"]["sent"] == [1, 1]
    assert controls_sent == [
        {"offset": start, "limit": 1},
        {"offset": start + 1, "limit": 1},
    ]


@pytest.mark.parametrize("family", ("number", "cursor", "carrier"))
@PAGING
@given(case=CASES, size=st.sampled_from(SIZES))
@example(case=Case(26, "honours", 1, "object", None, True), size=25)
@example(case=Case(27, "honours", 1, "object", None, True), size=25)
async def test_native_tail_and_same_size_resume_are_contiguous(family, case, size):
    upstream = Upstream(case, family)
    position, token, records = 0, None, []
    while True:
        result = await collect_batch(
            upstream.fetch,
            requested=size,
            family=family,
            start=position,
            token=token,
            known_max=200,
        )
        effective = case.size(min(size, 200))
        end = min(case.total, len(records) + math.ceil(size / effective) * effective)
        assert_complete(result, case.records(len(records), end))
        records.extend(items(result))
        assert_once(records, case.identities)
        if family == "number":
            position = result.get("nextPage")
            if position is None:
                break
        else:
            token = result.get("_continuation")
            if token is None:
                break
        # A full final page with no total/size evidence needs an empty probe.
        assert len(records) <= case.total
    assert records == case.records()


@pytest.mark.parametrize("family", FAMILIES)
@PAGING
@given(
    size=st.sampled_from(SIZES),
    extra=st.integers(1, 100),
    evidence=st.sampled_from(("none", "total", "continuation")),
    live=st.booleans(),
)
async def test_repeated_oversized_page_never_duplicates_or_hides_evidence(
    family, size, extra, evidence, live
):
    if family == "offset" and evidence == "continuation":
        evidence = "total"
    count, calls = size + extra, []

    async def fetch(controls):
        calls.append(dict(controls))
        assert len(calls) <= 3, "a repeated page must stop on its second response"
        response = {"data": [{"id": i, "live": len(calls) if live else 0} for i in range(count)]}
        if evidence == "total":
            response["totalCount"] = count * 3
        if family == "cursor":
            response["nextToken"] = f"next:{len(calls)}" if evidence != "none" else None
        elif family == "carrier":
            response["meta"] = {
                "hasMore": evidence != "none",
                "nextCursor": f"next:{len(calls)}" if evidence != "none" else None,
            }
        elif family == "links":
            response["links"] = {"next": f"?page={len(calls) + 1}" if evidence != "none" else None}
        elif family == "number":
            response["page_number"] = controls["pageNumber"]
            if evidence == "continuation":
                response["total_page_count"] = 100
        return response

    result = await collect_batch(
        fetch, requested=None, family=family, default_size=size, start=1 if family == "links" else 0
    )
    assert items(result) == [{"id": i, "live": 1 if live else 0} for i in range(count)]
    assert_once(items(result), True)
    if evidence == "none" and family in {"cursor", "carrier", "links"}:
        assert len(calls) == 1
    else:
        assert len(calls) == 2
    assert result["incomplete"] is (evidence != "none")
    if result["incomplete"]:
        assert result["incompleteReason"]
        for field in ("nextPage", "nextOffset", "nextToken", "nextCursor"):
            assert result.get(field) is None
    if evidence == "total":
        assert result["totalCount"] == count * 3


@PAGING
@given(
    size=st.sampled_from(SIZES),
    extra=st.integers(1, 100),
    declared=st.booleans(),
    identities=st.booleans(),
    bare=st.booleans(),
)
async def test_client_repeated_unpaged_preserves_first_body(
    size, extra, declared, identities, bare
):
    count, calls = size + extra, []

    async def get(path, *, key=None, params=None):
        del path, key
        calls.append(dict(params or {}))
        assert len(calls) <= 3, "unpaged repetition must terminate on response two"
        rows = [{"id" if identities else "ordinal": i, "live": len(calls)} for i in range(count)]
        if bare and not declared:
            return rows
        return {"data": rows, **({"totalCount": count * 3} if declared else {})}

    client = SimpleNamespace(get=get, _settings=SimpleNamespace(paginate_max_pages=None))
    if declared or not identities:
        with pytest.raises(PaginationAbortedError) as caught:
            await UniFiClient.paginate_offset(client, "/synthetic/paging", page_size=size)
        result = caught.value.items
        assert str(caught.value)
        assert caught.value.total_count == (count * 3 if declared else None)
    else:
        result = await UniFiClient.paginate_offset(client, "/synthetic/paging", page_size=size)
    assert len(calls) == 2
    assert result == [{"id" if identities else "ordinal": i, "live": 1} for i in range(count)]


@pytest.mark.parametrize("entry", ("client", "requested", "drain"))
@PAGING
@given(
    total=st.integers(1, 1600),
    size=st.sampled_from(SIZES),
    identities=st.sampled_from((None, "id", "_id", "uuid", "mac")),
    live=st.booleans(),
    declared=st.booleans(),
)
async def test_upstream_ignoring_offset_never_duplicates(
    entry, total, size, identities, live, declared
):
    # Without an identity a changed live field is indistinguishable from a new record.
    live = live and identities is not None
    key, calls = identities or "ordinal", []

    async def get(path, *, key=None, params=None):
        del path, key
        calls.append(dict(params or {}))
        assert len(calls) <= 3, "an ignored offset must stop on the first repeated prefix"
        limit = calls[-1].get("limit", 200)
        rows = [
            {identities or "ordinal": i, "live": len(calls) if live else 0}
            for i in range(min(total, limit))
        ]
        return {"data": rows, **({"totalCount": total} if declared else {})}

    client = SimpleNamespace(
        get=get, paginate_max_pages=None, _settings=SimpleNamespace(paginate_max_pages=None)
    )
    if entry == "client":
        try:
            drained = await UniFiClient.paginate_offset(client, "/synthetic/paging", page_size=size)
        except PaginationAbortedError as error:
            assert error.total_count == (total if declared else None)
            result = {"items": error.items, "incomplete": True, "incompleteReason": str(error)}
        else:
            result = {"items": list(drained), "incomplete": False}
    elif entry == "requested":
        result = await collect_offset(client, "/synthetic/paging", limit=size)
    else:
        result = await collect_offset(client, "/synthetic/paging", page_size=size)
    rows = items(result)
    assert [row[key] for row in rows] == list(range(len(rows)))
    if result.get("incomplete"):
        assert result["incompleteReason"]
        for field in ("nextPage", "nextOffset", "nextToken", "nextCursor"):
            assert result.get(field) is None
        if declared and entry != "client":
            assert result["totalCount"] == total
    else:
        assert len(rows) == (min(total, size) if entry == "requested" else total)


@pytest.mark.parametrize("entry", ("batch", "offset", "links"))
@PAGING
@given(value=st.sampled_from((0, -1, -5, False, True, 1.5, "25")))
async def test_invalid_size_rejected_before_any_upstream_call(entry, value):
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append((path, params))
        raise AssertionError("invalid paging input reached upstream")

    client = SimpleNamespace(get=get, paginate_max_pages=None)
    with pytest.raises(ValueError, match="positive integer"):
        if entry == "batch":
            await collect_batch(
                lambda controls: get("/synthetic", params=controls), requested=value
            )
        elif entry == "offset":
            await collect_offset(client, "/synthetic", limit=value)
        else:
            await collect_links(client, "/synthetic", "data", page_size=value)
    assert calls == []


@pytest.mark.parametrize("entry", ("links-page", "offset", "batch-offset", "batch-number"))
@PAGING
@given(value=st.sampled_from((-1, -5, False, True, 1.5, "25")))
async def test_invalid_positions_rejected_before_any_upstream_call(entry, value):
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append((path, params))
        raise AssertionError("invalid paging position reached upstream")

    client = SimpleNamespace(get=get, paginate_max_pages=None)
    with pytest.raises(ValueError, match="(1-based|0 or more)"):
        if entry == "links-page":
            await collect_links(client, "/synthetic", "data", page=value)
        elif entry == "offset":
            await collect_offset(client, "/synthetic", offset=value)
        else:
            await collect_batch(
                lambda controls: get("/synthetic", params=controls),
                requested=25,
                family="offset" if entry == "batch-offset" else "number",
                start=value,
            )
    assert calls == []


async def test_zero_page_rejected_before_any_upstream_call():
    async def get(*args, **kwargs):
        raise AssertionError("zero page reached upstream")

    with pytest.raises(ValueError, match="1-based"):
        await collect_links(
            SimpleNamespace(get=get, paginate_max_pages=None),
            "/synthetic",
            "data",
            page=0,
        )


@pytest.mark.parametrize("family", ("cursor", "carrier", "links"))
@PAGING
@given(total=st.integers(0, 1600), size=st.sampled_from(SIZES), identity=st.booleans())
async def test_bare_unpaged_terminal_body_is_preserved(family, total, size, identity):
    rows = [{"id" if identity else "ordinal": i, "payload": {"synthetic": i}} for i in range(total)]
    calls = []

    async def fetch(controls):
        calls.append(dict(controls))
        return rows

    result = await collect_batch(
        fetch,
        requested=None,
        family=family,
        default_size=size,
        start=1 if family == "links" else 0,
    )
    assert_complete(result, rows)
    assert_once(items(result), identity)
    assert result["array_key"] is None
    assert len(calls) == 1
    for field in ("nextPage", "nextOffset", "nextToken", "nextCursor"):
        assert result.get(field) is None
