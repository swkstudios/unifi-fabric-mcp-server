"""Pagination round-two linked-window and zero-I/O validation regressions T25-T27."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.shared_shapes._pagination import (
    collect_batch,
    collect_cursor,
    collect_links,
    collect_offset,
    validate_pagination,
)


@pytest.mark.parametrize("continuation", ["?page=4", None])
async def test_t25_empty_probe_requires_terminal_link(continuation):
    envelope = {"links": {"next": continuation}, "traceId": "synthetic-empty-probe"}
    get = AsyncMock(return_value={"data": [], **envelope})
    client = SimpleNamespace(get=get, paginate_max_pages=None)
    result = await collect_links(client, "/synthetic", "data", page=3, page_size=50)
    assert result["items"] == []
    assert result["totalCount"] is None
    assert result["incomplete"] is (continuation is not None)
    assert result["nextPage"] is None
    assert result["envelope"] == envelope
    assert result["pages"] == get.await_count == 1
    assert result["_pageSize"] == {
        "requested": 50,
        "sent": [50],
        "effective": None,
        "returned": 0,
    }
    if continuation is not None:
        assert result["incompleteReason"] == (
            "page 3 (pageSize 50) returned no records but links.next is still present, "
            "so record positions cannot be computed from page numbers on this endpoint; "
            "read it natively with page=4 and no page_size, following _nextPage"
        )
    else:
        assert result["incompleteReason"] is None


async def test_t25_empty_nonterminal_gather_page_keeps_only_contiguous_prefix():
    rows = [{"id": str(index)} for index in range(100)]
    get = AsyncMock(
        side_effect=[
            {"data": rows, "links": {"next": "?page=2&pageSize=100"}},
            {"data": [], "links": {"next": "?page=3&pageSize=100"}},
        ]
    )
    client = SimpleNamespace(get=get, paginate_max_pages=None)
    result = await collect_links(client, "/synthetic", "data", page=1, page_size=150)
    assert result["items"] == rows
    assert result["totalCount"] is None
    assert result["incomplete"] is True
    assert result["nextPage"] is None
    assert result["pages"] == get.await_count == 2
    assert "page 2 (pageSize 100)" in result["incompleteReason"]
    assert "page=3 and no page_size" in result["incompleteReason"]


async def test_t26_page_cap_has_no_continuation_and_actionable_same_window_resume():
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append(dict(params))
        start = (params["page"] - 1) * 100
        return {
            "data": [{"id": str(index)} for index in range(start, start + 100)],
            "links": {"next": f"?page={params['page'] + 1}&pageSize=100"},
        }

    client = SimpleNamespace(get=get, paginate_max_pages=2)
    result = await collect_links(client, "/synthetic", "data", page=1, page_size=275)
    assert result["items"] == [{"id": str(index)} for index in range(200)]
    assert result["incomplete"] is True
    assert result["nextPage"] is None
    assert result["pages"] == len(calls) == 2
    assert result["incompleteReason"] == (
        "UNIFI_PAGINATE_MAX_PAGES page cap of 2 reached after 200 of 275 records of "
        "window page=1, page_size=275; this window needs more requests than the cap allows: "
        "raise or unset UNIFI_PAGINATE_MAX_PAGES and call again with page=1, page_size=275"
    )


@pytest.mark.parametrize("value", [0, -1, -5, False, True, 1.5, "2"])
@pytest.mark.parametrize("entry", ["links", "offset_size", "offset_limit", "cursor", "batch"])
async def test_t27_invalid_size_never_reaches_upstream(entry, value):
    get = AsyncMock()
    client = SimpleNamespace(get=get, paginate_max_pages=None)
    fetch = AsyncMock()
    with pytest.raises(ValueError) as error:
        if entry == "links":
            await collect_links(client, "/synthetic", "data", page_size=value)
        elif entry == "offset_size":
            await collect_offset(client, "/synthetic", page_size=value)
        elif entry == "offset_limit":
            await collect_offset(client, "/synthetic", limit=value)
        elif entry == "cursor":
            await collect_cursor(client, "/synthetic", page_size=value)
        else:
            await collect_batch(fetch, requested=value)
    # PAGING-VALIDATION-A1 rule 3: collect_offset names its caller's limit argument.
    name = "limit" if entry == "offset_limit" else "page_size"
    assert str(error.value) == (
        f"{name} must be a positive integer (1 or more); got {value}. "
        f"Omit {name} to read the whole collection."
    )
    assert get.await_count == fetch.await_count == 0


@pytest.mark.parametrize("value", [0, -1, -5, False, True, 1.5, "2"])
async def test_t27_invalid_link_page_never_reaches_upstream(value):
    get = AsyncMock()
    client = SimpleNamespace(get=get, paginate_max_pages=None)
    with pytest.raises(ValueError) as error:
        await collect_links(client, "/synthetic", "data", page=value)
    assert str(error.value) == f"page is 1-based and must be 1 or more; got {value}."
    assert get.await_count == 0


@pytest.mark.parametrize("value", [-1, -5, False, True, 1.5, "2"])
async def test_t27_invalid_offset_never_reaches_upstream(value):
    get = AsyncMock()
    client = SimpleNamespace(get=get, paginate_max_pages=None)
    with pytest.raises(ValueError) as error:
        await collect_offset(client, "/synthetic", offset=value)
    assert str(error.value) == f"offset must be 0 or more; got {value}."
    assert get.await_count == 0


def test_t27_validation_has_no_upper_bound():
    validate_pagination(page=10**100, page_size=10**100, offset=10**100)


async def test_declared_total_contradicting_page_placement_is_incomplete():
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append(dict(params))
        start = (params["page"] - 1) * 100  # the console ignores pageSize
        rows = [{"id": str(index)} for index in range(start, min(start + 100, 120))]
        return {"data": rows, "links": {}, "totalCount": 120}

    client = SimpleNamespace(get=get, paginate_max_pages=None)
    result = await collect_links(client, "/synthetic", "data", page=7, page_size=1)
    assert result["items"] == []
    assert result["incomplete"] is True
    assert result["nextPage"] is None
    assert len(calls) == 1
    assert result["incompleteReason"].startswith(
        "the upstream declared totalCount 120, so window page=7, page_size=1 holds 1 records, "
        "but page-number positions placed 0"
    )


async def test_identical_oversized_terminal_pages_select_window_from_unpaged_collection():
    rows = [{"id": str(index)} for index in range(150)]
    get = AsyncMock(return_value={"data": rows, "links": {}})
    client = SimpleNamespace(get=get, paginate_max_pages=None)
    result = await collect_links(client, "/synthetic", "data", page=2, page_size=50)
    assert result["items"] == rows[50:100]
    assert result["incomplete"] is False
    assert result["nextPage"] == 3
    assert result["pages"] == get.await_count == 2


async def test_reached_declared_total_ends_window_despite_stale_next_link():
    async def get(path, *, key=None, params=None):
        index = params["page"] - 1
        return {
            "data": [{"id": str(index)}] if index < 2 else [],
            "links": {"next": f"?page={params['page'] + 1}&pageSize=1"},
            "totalCount": 2,
        }

    client = SimpleNamespace(get=get, paginate_max_pages=None)
    result = await collect_links(client, "/synthetic", "data", page=2, page_size=1)
    assert result["items"] == [{"id": "1"}]
    assert result["incomplete"] is False
    assert result["nextPage"] is None
