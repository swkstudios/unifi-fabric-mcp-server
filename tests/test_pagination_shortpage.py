"""Completion requires evidence beyond an unreported console page-size clamp."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import PaginationAbortedError, UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.tools._pagination import collect_batch, collect_offset

NETWORK = "/v1/connector/consoles/synthetic/proxy/network/integration/v1/sites/site/networks"


@pytest.mark.parametrize("envelope", [False, True])
@pytest.mark.parametrize("requested", [None, 8])
async def test_get_only_network_unknown_clamp_returns_all_records(envelope, requested):
    calls = []

    async def fetch(path, *, key, params):
        calls.append(dict(params))
        start = params.get("offset", 0)
        records = [{"id": str(i)} for i in range(start, min(start + 3, 8))]
        return {"data": records} if envelope else records

    client = SimpleNamespace(get=fetch, paginate_max_pages=None)
    result = await collect_offset(client, NETWORK, limit=requested)
    assert result["items"] == [{"id": str(i)} for i in range(8)]
    assert not result["incomplete"]
    assert [call.get("offset", 0) for call in calls] == (
        [0, 3, 6, 8] if requested is None else [0, 3, 6]
    )


@pytest.mark.parametrize("envelope", [False, True])
async def test_get_only_network_unknown_clamp_stall_is_incomplete(envelope):
    page = [{"id": str(i)} for i in range(3)]
    fetch = AsyncMock(return_value={"data": page} if envelope else page)
    result = await collect_offset(SimpleNamespace(get=fetch, paginate_max_pages=None), NETWORK)
    assert result["items"] == page
    assert result["incomplete"]
    assert "same page again" in result["incompleteReason"]
    assert fetch.await_count == 2


@pytest.mark.parametrize("helper", ["collect", "client"])
@pytest.mark.parametrize("envelope", [False, True, "echo"])
async def test_offset_oversized_page_without_terminal_evidence_continues(helper, envelope):
    calls = []

    async def fetch(path, *, key, params):
        calls.append(dict(params))
        start = params.get("offset", 0)
        records = [{"id": str(i)} for i in range(start, min(start + 3, 8))]
        if envelope == "echo":
            return {"data": records, "limit": 2}
        return {"data": records} if envelope else records

    if helper == "collect":
        client = SimpleNamespace(get=fetch, paginate_max_pages=None)
        result = await collect_offset(client, NETWORK, page_size=2)
        records = result["items"]
        assert not result["incomplete"]
    else:
        client = UniFiClient(Settings(api_key="synthetic-shortpage"))
        client.get = fetch
        records = await client.paginate_offset(NETWORK, page_size=2)
    assert records == [{"id": str(i)} for i in range(8)]
    assert [call["offset"] for call in calls] == [0, 3, 6, 8]


async def test_number_short_page_without_echo_keeps_fetching():
    calls = []
    pages = [list(range(3)), list(range(3, 5)), list(range(5, 8)), []]

    async def fetch(controls):
        calls.append(dict(controls))
        return {"data": pages[controls["pageNumber"]]}

    result = await collect_batch(fetch, requested=None, default_size=200, family="number")
    assert result["items"] == list(range(8))
    assert not result["incomplete"]
    assert [call["pageNumber"] for call in calls] == [0, 1, 2, 3]


@pytest.mark.parametrize("envelope", [False, True])
@pytest.mark.parametrize("row_count", [1, 2, 3])
async def test_client_repeated_page_completion_depends_on_sent_size(envelope, row_count):
    rows = [{"id": str(i)} for i in range(row_count)]
    fetch = AsyncMock(return_value={"data": rows} if envelope else rows)
    client = UniFiClient(Settings(api_key="synthetic-shortpage"))
    client.get = fetch
    if row_count > 2:
        assert await client.paginate_offset(NETWORK, page_size=2) == rows
    else:
        with pytest.raises(PaginationAbortedError, match="same page again") as error:
            await client.paginate_offset(NETWORK, page_size=2)
        assert error.value.items == rows
    assert fetch.await_count == 2
    assert fetch.await_args_list[1].kwargs["params"] == {"offset": row_count, "limit": 2}


@pytest.mark.parametrize("family", ["offset", "number"])
@pytest.mark.parametrize("envelope", [False, True])
@pytest.mark.parametrize("row_count", [1, 2, 3])
async def test_batch_repeated_page_completion_depends_on_sent_size(family, envelope, row_count):
    rows = [{"id": str(i)} for i in range(row_count)]
    fetch = AsyncMock(return_value={"data": rows} if envelope else rows)
    result = await collect_batch(fetch, requested=None, default_size=2, family=family)
    assert result["items"] == rows
    assert result["incomplete"] is (row_count <= 2)
    if row_count <= 2:
        assert "same page again" in result["incompleteReason"]
    else:
        assert result["incompleteReason"] is None
    assert fetch.await_count == 2
    size_key = "limit" if family == "offset" else "pageSize"
    assert fetch.await_args_list[1].args[0][size_key] == (min(2, row_count) if envelope else 2)
