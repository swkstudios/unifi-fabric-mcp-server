"""Single-response offset continuations require a physical boundary witness."""

import pytest

from unifi_fabric.shared_shapes._pagination import collect_batch


@pytest.mark.asyncio
@pytest.mark.parametrize("identified", [True, False])
async def test_ignoring_offset_suppresses_resume(identified):
    row = {"id": 0} if identified else "zero"
    calls = []

    async def fetch(controls):
        calls.append(controls)
        return [row]

    result = await collect_batch(fetch, requested=1, family="offset")
    assert result["items"] == [row]
    assert result["incomplete"] is True
    assert result["nextOffset"] is None
    assert result["pages"] == 2
    assert result["_pageSize"]["sent"] == [1, 1]
    assert calls == [{"limit": 1}, {"offset": 1, "limit": 1}]


@pytest.mark.asyncio
@pytest.mark.parametrize("upstream", ["honors", "empty", "oversized", "ignored_oversized"])
async def test_boundary_witness_and_preserved_original_envelope(upstream):
    calls = []

    async def fetch(controls):
        calls.append(controls)
        if len(calls) == 1:
            return {
                "data": [{"id": 0}, {"id": 1}] if "oversized" in upstream else [{"id": 0}],
                "marker": "original",
            }
        return {
            "data": {
                "honors": [{"id": 1}],
                "empty": [],
                "oversized": [{"id": 1}, {"id": 2}],
                "ignored_oversized": [{"id": 0}, {"id": 1}],
            }[upstream],
            "marker": "probe",
        }

    result = await collect_batch(fetch, requested=1, family="offset")
    assert result["items"] == [{"id": 0}]
    assert result["envelope"]["marker"] == "original"
    assert result["pages"] == 2
    assert result["_pageSize"]["sent"] == [1, 1]
    assert calls[1] == {"offset": 1, "limit": 1}
    assert result["nextOffset"] == (1 if upstream in {"honors", "oversized"} else None)
    assert result["incomplete"] is (upstream == "ignored_oversized")


@pytest.mark.asyncio
async def test_cap_prevents_probe_and_continuation():
    calls = []

    async def fetch(controls):
        calls.append(controls)
        return [{"id": 0}]

    result = await collect_batch(fetch, requested=1, family="offset", max_pages=1)
    assert result["items"] == [{"id": 0}]
    assert result["incomplete"] is True
    assert (
        "raise or unset UNIFI_PAGINATE_MAX_PAGES and retry the same window"
        in (result["incompleteReason"])
    )
    assert result["nextOffset"] is None
    assert result["pages"] == 1
    assert result["_pageSize"]["sent"] == [1]
    assert calls == [{"limit": 1}]


@pytest.mark.asyncio
@pytest.mark.parametrize("malformed", [None, "invalid", {"unexpected": []}])
async def test_malformed_probe_preserves_first_response(malformed):
    from unittest.mock import AsyncMock

    first = {"data": [{"id": 0}], "marker": "original"}
    fetch = AsyncMock(side_effect=[first, malformed])
    result = await collect_batch(fetch, requested=1, family="offset")
    assert result["items"] == first["data"]
    assert result["envelope"]["marker"] == "original"
    assert result["incomplete"] is True
    assert "without a records array" in result["incompleteReason"]
    assert result["nextOffset"] is None
    assert result["pages"] == 2
    assert result["_pageSize"]["sent"] == [1, 1]


@pytest.mark.asyncio
async def test_probe_transport_error_propagates():
    from unittest.mock import AsyncMock

    fetch = AsyncMock(side_effect=[[{"id": 0}], RuntimeError("upstream failure")])
    with pytest.raises(RuntimeError, match="upstream failure"):
        await collect_batch(fetch, requested=1, family="offset")
    assert fetch.await_count == 2


@pytest.mark.asyncio
async def test_explicit_native_offset_remains_one_page():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from unifi_fabric.shared_shapes._pagination import collect_offset

    client = SimpleNamespace(get=AsyncMock(return_value={"data": [{"id": 1}]}))
    result = await collect_offset(client, "/synthetic", offset=1, limit=1)
    assert result["items"] == [{"id": 1}]
    client.get.assert_awaited_once_with("/synthetic", key=None, params={"offset": 1, "limit": 1})


@pytest.mark.asyncio
@pytest.mark.parametrize("ignore_offset", [False, True])
async def test_nonzero_start_checks_boundary(ignore_offset):
    calls = []

    async def fetch(controls):
        calls.append(controls)
        index = 4 if ignore_offset else controls["offset"]
        return [{"id": index}]

    result = await collect_batch(fetch, requested=1, family="offset", start=4)
    assert result["items"] == [{"id": 4}]
    assert result["nextOffset"] == (None if ignore_offset else 5)
    assert result["incomplete"] is ignore_offset
    assert calls == [{"offset": 4, "limit": 1}, {"offset": 5, "limit": 1}]


@pytest.mark.asyncio
async def test_distinct_identity_free_witness_allows_continuation():
    calls = []

    async def fetch(controls):
        calls.append(controls)
        return [{"ordinal": controls.get("offset", 0)}]

    result = await collect_batch(fetch, requested=1, family="offset")
    assert result["items"] == [{"ordinal": 0}]
    assert result["nextOffset"] == 1
    assert result["incomplete"] is False
    assert calls == [{"limit": 1}, {"offset": 1, "limit": 1}]


@pytest.mark.asyncio
async def test_terminal_total_does_not_probe():
    from unittest.mock import AsyncMock

    fetch = AsyncMock(return_value={"data": [{"id": 0}], "totalCount": 1})
    result = await collect_batch(fetch, requested=1, family="offset")
    assert result["items"] == [{"id": 0}]
    assert result["nextOffset"] is None
    assert result["incomplete"] is False
    assert result["pages"] == 1
    assert result["_pageSize"]["sent"] == [1]
    fetch.assert_awaited_once_with({"limit": 1})


@pytest.mark.asyncio
async def test_two_page_cap_allows_and_accounts_for_probe():
    from unittest.mock import AsyncMock

    fetch = AsyncMock(side_effect=[[{"id": 0}], [{"id": 1}]])
    result = await collect_batch(fetch, requested=1, family="offset", max_pages=2)
    assert result["items"] == [{"id": 0}]
    assert result["nextOffset"] == 1
    assert result["incomplete"] is False
    assert result["pages"] == 2
    assert result["_pageSize"]["sent"] == [1, 1]
    assert [call.args[0] for call in fetch.await_args_list] == [
        {"limit": 1},
        {"offset": 1, "limit": 1},
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("start,requested,count", [(303, 101, 79), (50, 100, 80)])
@pytest.mark.parametrize("reordered", [False, True])
async def test_nonzero_requested_window_cannot_infer_repeated_unpaged_origin(
    start, requested, count, reordered
):
    calls = []
    rows = [{"id": i} for i in range(count)]

    async def fetch(controls):
        calls.append(controls)
        page = list(reversed(rows)) if reordered and len(calls) > 1 else rows
        return {"data": page, "marker": "first body"}

    result = await collect_batch(
        fetch, requested=requested, default_size=200, family="offset", start=start
    )
    assert calls == [
        {"offset": start, "limit": requested},
        {"offset": start + count, "limit": requested - count},
    ]
    assert result["items"] == rows
    assert result["envelope"]["marker"] == "first body"
    assert result["incomplete"] is True
    assert "origin" in result["incompleteReason"] and "ignores offset" in result["incompleteReason"]
    assert result["nextOffset"] is None
    assert result["nextPage"] is None
    assert result["nextToken"] is None
    assert result["nextCursor"] is None
    assert result["pages"] == 2
    assert result["_pageSize"]["sent"] == [requested, requested - count]
    assert result["_pageSize"]["returned"] == count
    assert result["_pageSize"]["effective"] == count


@pytest.mark.asyncio
async def test_zero_start_requested_repeat_retains_unpaged_complete_inference():
    calls = []
    rows = [{"id": i} for i in range(79)]

    async def fetch(controls):
        calls.append(controls)
        return {"data": rows}

    result = await collect_batch(fetch, requested=101, default_size=200, family="offset", start=0)
    assert calls == [{"limit": 101}, {"offset": 79, "limit": 22}]
    assert result["items"] == rows
    assert result["incomplete"] is False
    assert result["nextOffset"] is None
    assert result["pages"] == 2
    assert result["_pageSize"]["sent"] == [101, 22]
    assert result["_pageSize"]["returned"] == 79
    assert result["_pageSize"]["effective"] == 79
