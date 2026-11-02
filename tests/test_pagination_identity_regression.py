"""Pagination T23/T24 and repeated-total evidence regressions; synthetic upstreams only."""

from types import SimpleNamespace

import pytest

from unifi_fabric.client import PaginationAbortedError, UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.tools._pagination import collect_batch, collect_offset


@pytest.mark.parametrize("adapter", ["client", "batch", "collect"])
@pytest.mark.parametrize("case", ["identity", "total", "no-id", "minimum", "overlap"])
async def test_t23_identity_repeat_or_contiguous_control(adapter, case):
    calls = []
    first = []

    async def get(path, *, key=None, params):
        nonlocal first
        calls.append(dict(params))
        offset = params.get("offset", 0)
        if case in {"identity", "total", "no-id"}:
            assert len(calls) <= 3
            data = [
                {"live": len(calls), **({"id": i} if case != "no-id" else {})} for i in range(250)
            ]
        elif case == "minimum":
            data = [{"id": i} for i in range(offset, min(offset + 500, 1200))]
        else:
            pages = {0: [0, 1, 2], 3: [2, 3, 4], 6: []}
            data = [{"id": i} for i in pages[offset]]
        if len(calls) == 1:
            first = data
        return {"data": data, **({"totalCount": 1000} if case == "total" else {})}

    if adapter == "client":
        client = UniFiClient(Settings(api_key="synthetic-identity-regression"))
        client.get = get
        if case in {"total", "no-id"}:
            with pytest.raises(PaginationAbortedError) as error:
                await client.paginate_offset("/synthetic", page_size=200)
            records = error.value.items
            assert error.value.total_count == (1000 if case == "total" else None)
            assert ("1000" if case == "total" else "no id, _id, uuid or mac") in str(error.value)
        else:
            records = await client.paginate_offset("/synthetic", page_size=200)
    else:
        if adapter == "batch":
            result = await collect_batch(
                lambda c: get("/synthetic", params=c), requested=None, family="offset"
            )
        else:
            result = await collect_offset(
                SimpleNamespace(get=get, paginate_max_pages=None), "/synthetic"
            )
        records = result["items"]
        assert result["incomplete"] is (case in {"total", "no-id"})
        assert result["totalCount"] == (1000 if case == "total" else None)
        if result["incomplete"]:
            assert result.get("nextOffset") is None
            assert ("1000" if case == "total" else "no id, _id, uuid or mac") in result[
                "incompleteReason"
            ]
    expected = 1200 if case == "minimum" else 5 if case == "overlap" else 250
    assert len(records) == expected
    if case in {"identity", "total", "no-id"}:
        assert len(calls) == 2
        assert records == first
    else:
        assert [row["id"] for row in records] == list(range(expected))


async def test_t24_offset_prefix_repeat_has_no_continuation():
    calls = []

    async def fetch(controls):
        calls.append(controls)
        assert len(calls) <= 2
        return {"data": [{"id": i} for i in range(controls["limit"])]}

    result = await collect_batch(fetch, requested=300, known_max=200, family="offset")
    # The exact requests: the first page at the route maximum (no offset is sent for 0),
    # then the 100-record remainder from offset 200 (PAGING-CONTINUITY), which repeats
    # records 0-99.
    assert calls == [{"limit": 200}, {"offset": 200, "limit": 100}]
    assert result["items"] == [{"id": i} for i in range(200)]
    assert result["incomplete"]
    assert result["nextOffset"] is None
    assert result["incompleteReason"] == (
        "page 2 at offset 200 returned the records already returned at offsets 0-99: "
        "the upstream ignores offset, so records past the first page cannot be reached "
        "by paging (200 of 300 requested records gathered)"
    )


async def test_t24_collect_offset_prefix_repeat_returns_records_once():
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append(dict(params))
        assert len(calls) <= 2
        return {"data": [{"id": i} for i in range(params["limit"])], "totalCount": 1000}

    client = SimpleNamespace(get=get, paginate_max_pages=None)
    result = await collect_offset(client, "/synthetic", limit=300)
    ids = [row["id"] for row in result["items"]]
    assert ids == list(range(200))
    assert len(set(ids)) == len(ids)
    assert len(calls) == 2
    assert [call["limit"] for call in calls] == [200, 100]
    assert result["incomplete"]
    assert result["totalCount"] == 1000
    assert result["nextOffset"] is None
    assert result["incompleteReason"].startswith(
        "page 2 at offset 200 returned the records already returned at offsets 0-99: "
        "the upstream ignores offset, so records past the first page cannot be reached "
        "by paging (200 of 300 requested records gathered)"
    )


async def test_t24_paginate_offset_repeat_raises_with_records_once():
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append(dict(params))
        assert len(calls) <= 2
        return {"data": [{"id": i} for i in range(params["limit"])], "totalCount": 300}

    client = UniFiClient(Settings(api_key="synthetic-identity-regression"))
    client.get = get
    with pytest.raises(PaginationAbortedError) as error:
        await client.paginate_offset("/synthetic", page_size=200)
    ids = [row["id"] for row in error.value.items]
    assert ids == list(range(200))
    assert len(set(ids)) == len(ids)
    assert len(calls) == 2
    assert error.value.total_count == 300
    assert "page 2 at offset 200 returned the records already returned at offsets 0-199" in str(
        error.value
    )


@pytest.mark.parametrize("family", ["offset", "cursor", "carrier", "links", "number"])
@pytest.mark.parametrize("evidence", ["total", "continuation", "reached", "none"])
async def test_repeated_oversized_collection_requires_no_outstanding_evidence(family, evidence):
    calls = []
    rows = [{"id": i} for i in range(3)]

    async def fetch(controls):
        calls.append(controls)
        assert len(calls) <= 3
        response = {"data": rows}
        if evidence in {"total", "reached"}:
            response["totalCount"] = 8 if evidence == "total" else 3
        if evidence == "continuation":
            if family == "cursor":
                response["nextToken"] = str(len(calls))
            elif family == "carrier":
                response["meta"] = {"hasMore": True, "nextCursor": str(len(calls))}
            elif family == "links":
                response["links"] = {"next": "/synthetic?page=3&pageSize=2"}
            elif family == "number":
                response["total_page_count"] = 8
            else:
                response["totalCount"] = 8
        elif family in {"cursor", "carrier", "links"} and evidence != "reached":
            # The first nonterminal page allows the second oversized page to prove
            # unpaged completion only when its continuation becomes terminal.
            if family == "cursor":
                response["nextToken"] = "next" if len(calls) == 1 else None
            elif family == "carrier":
                response["meta"] = {
                    "hasMore": len(calls) == 1,
                    "nextCursor": "next" if len(calls) == 1 else None,
                }
            else:
                response["links"] = {
                    "next": "/synthetic?page=2&pageSize=2" if len(calls) == 1 else None
                }
        return response

    result = await collect_batch(fetch, requested=None, default_size=2, family=family)
    assert result["items"] == rows
    assert result["incomplete"] is (evidence in {"total", "continuation"})
    assert result["totalCount"] == (
        8
        if evidence == "total" or (evidence == "continuation" and family == "offset")
        else 3
        if evidence == "reached"
        else None
    )
    if result["incomplete"]:
        assert result.get("nextOffset") is None
        assert result.get("nextPage") is None
        assert result.get("nextToken") is None
        assert result.get("nextCursor") is None
        # REPEATED-OVERSIZED-TOTAL: the reason names the exact outstanding evidence, as
        # "although it declared <field> ..." or "although its continuation <field> is still
        # non-terminal".
        suffix = (
            " although it declared totalCount 8 (3 of 8 records gathered)"
            if evidence == "total" or family == "offset"
            else {
                "cursor": " although its continuation nextToken is still non-terminal",
                "carrier": (
                    " although its continuation meta.hasMore/nextCursor is still non-terminal"
                ),
                "links": " although its continuation links.next is still non-terminal",
                "number": " although its total_page_count 8 still has outstanding pages",
            }[family]
        )
        assert result["incompleteReason"].endswith(suffix)


@pytest.mark.parametrize("with_total", [False, True])
async def test_number_short_terminal_page_keeps_wire_size_on_resume(with_total):
    calls = []

    async def fetch(controls):
        calls.append(controls)
        size = controls["pageSize"]
        number = controls["pageNumber"]
        return {
            "data": list(range(number * size, min((number + 1) * size, 26))),
            **({"total_element_count": 26} if with_total else {}),
        }

    result = await collect_batch(fetch, requested=25, family="number", start=1)
    assert result["items"] == [25]
    assert not result["incomplete"]
    assert all(call["pageSize"] == 25 for call in calls)


async def test_number_native_clamp_total_does_not_silently_truncate():
    async def fetch(controls):
        size = min(25, controls["pageSize"])
        number = controls["pageNumber"]
        return {
            "data": list(range(number * size, min((number + 1) * size, 51))),
            "total_element_count": 51,
        }

    result = await collect_batch(fetch, requested=100, family="number", start=1)
    assert result["items"] == list(range(25, 51))
    assert not result["incomplete"]


async def test_number_distinct_resumed_page_proves_oversized_discovery_width():
    calls = []

    async def fetch(controls):
        calls.append(controls.copy())
        start = controls["pageNumber"] * 200
        return {"data": [{"id": i} for i in range(start, start + 200)]}

    result = await collect_batch(fetch, requested=100, family="number", start=1)
    assert result["items"] == [{"id": i} for i in range(200, 400)]
    assert not result["incomplete"]
    assert result["nextPage"] == 2
    assert result["pages"] == 2
    assert result["_pageSize"] == {
        "requested": 100,
        "sent": [100, 100],
        "effective": 200,
        "returned": 200,
    }
    assert calls == [
        {"pageNumber": 1, "pageSize": 100},
        {"pageNumber": 0, "pageSize": 100},
    ]


async def test_number_unresolved_oversized_discovery_retains_original_page():
    calls = []

    async def fetch(controls):
        calls.append(controls.copy())
        return {"data": [{"id": i} for i in range(200)]}

    result = await collect_batch(fetch, requested=100, family="number", start=1)
    assert result["items"] == [{"id": i} for i in range(200)]
    assert result["incomplete"]
    assert "physical width and page-1 origin cannot be established" in result["incompleteReason"]
    assert result["nextPage"] is None
    assert result["pages"] == 2
    assert result["_pageSize"] == {
        "requested": 100,
        "sent": [100, 100],
        "effective": None,
        "returned": 200,
    }
    assert calls == [
        {"pageNumber": 1, "pageSize": 100},
        {"pageNumber": 0, "pageSize": 100},
    ]


@pytest.mark.parametrize(
    "marker",
    [
        {"total_element_count": 8},
        {"total_page_count": 3},
        {"has_next": True},
        {"nextToken": "next"},
        {"meta": {"hasMore": True}},
        {"meta": {"nextCursor": "next"}},
        {"links": {"next": "/next"}},
    ],
)
@pytest.mark.parametrize("adapter", ["client", "offset", "number"])
async def test_oversized_repeat_honors_every_present_outstanding_marker(adapter, marker):
    first = [{"id": i} for i in range(3)]
    calls = []

    async def get(path, *, key=None, params):
        calls.append(params.copy())
        return {"data": first, **marker}

    if adapter == "client":
        client = UniFiClient(Settings(api_key="synthetic-repeat-evidence"))
        client.get = get
        with pytest.raises(PaginationAbortedError) as error:
            await client.paginate_offset("/synthetic", page_size=2)
        assert error.value.items == first
        assert error.value.total_count == marker.get("total_element_count")
        assert next(iter(marker)) in str(error.value)
    else:
        result = await collect_batch(
            lambda controls: get("/synthetic", params=controls),
            requested=None,
            default_size=2,
            family=adapter,
        )
        assert result["items"] == first
        assert result["incomplete"]
        assert result["nextPage"] is None
        assert result["totalCount"] == marker.get("total_element_count")
        assert next(iter(marker)) in result["incompleteReason"]
    assert len(calls) == 2


async def test_offset_page_larger_than_declared_remainder_is_not_placed():
    calls = []

    async def fetch(controls):
        calls.append(dict(controls))
        return {"data": [{"id": i} for i in range(100)], "totalCount": 100}

    result = await collect_batch(
        fetch, requested=25, family="offset", start=50, omit_initial_offset=False
    )
    assert result["items"] == []
    assert result["incomplete"]
    assert result["nextOffset"] is None
    assert result["totalCount"] == 100
    assert len(calls) == 1
    assert "at most 50 records follow offset 50" in result["incompleteReason"]


async def test_client_offset_page_larger_than_declared_remainder_aborts():
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append(dict(params))
        return {"data": [{"id": i} for i in range(100)], "totalCount": 100}

    client = UniFiClient(Settings(api_key="synthetic-identity-regression"))
    client.get = get
    with pytest.raises(PaginationAbortedError) as error:
        await client.paginate_offset("/synthetic", params={"offset": 50}, page_size=25)
    assert error.value.items == []
    assert error.value.total_count == 100
    assert len(calls) == 1
    assert "at most 50 records follow offset 50" in str(error.value)
