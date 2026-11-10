"""System-log paging validation and bare-array regressions from the ultra review."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from unifi_fabric import refusals
from unifi_fabric.families.statistics import system_log


@pytest.fixture()
def client():
    value = AsyncMock()
    value.paginate_max_pages = None
    return value


@pytest.fixture()
def registry():
    value = AsyncMock()
    value.resolve_key_for_host.return_value = None
    value.resolve_host_id.return_value = "host-001"
    value.resolve_site_slug.return_value = "default"
    return value


@pytest.mark.parametrize(
    "paging",
    [
        {"page_size": 2},
        {"query": {"pageSize": 2}},
    ],
)
async def test_critical_bare_array_with_requested_total(client, registry, paging):
    records = [{"id": number} for number in range(4)]
    client.post.return_value = records
    query = paging.get("query")
    kwargs = {key: value for key, value in paging.items() if key != "query"}
    result = await system_log._read_system_log(
        client, registry, "h", "Default", "critical", query, **kwargs
    )
    # page_size alone is window 0, as page=0 with page_size is: the first two entries,
    # trimmed and marked, with _nextPage so the other two are not silently dropped.
    assert result["data"] == records[:2]
    assert result["_nextPage"] == 1
    assert result["_pageSize"] == {"requested": 2, "sent": [2], "effective": 4, "returned": 2}
    assert not result.get("incomplete")
    assert records == [{"id": number} for number in range(4)]
    client.post.assert_awaited_once()


@pytest.mark.parametrize(
    "paging",
    [
        {"page": 1, "page_size": 2},
        {"query": {"pageNumber": 1, "pageSize": 2}},
    ],
)
async def test_critical_explicit_page_and_size_return_the_logical_window(client, registry, paging):
    # The upstream ignores pageSize and answers 4 records per page as a bare array.
    records = [{"id": number} for number in range(12)]

    async def post(
        _path: str, *, key: Any = None, json: dict[str, Any], always_write: bool = False
    ) -> Any:
        number = json["pageNumber"]
        return records[number * 4 : number * 4 + 4]

    client.post.side_effect = post
    query = paging.get("query")
    kwargs = {key: value for key, value in paging.items() if key != "query"}
    result = await system_log._read_system_log(
        client, registry, "h", "Default", "critical", query, **kwargs
    )
    assert result["data"] == records[2:4]
    assert result["_nextPage"] == 2
    assert result["_pageSize"] == {"requested": 2, "sent": [2, 2], "effective": 4, "returned": 2}
    assert [call.args[0] for call in client.post.await_args_list] == [
        "/v1/connector/consoles/host-001/proxy/network/v2/api/site/default/system-log/critical"
    ] * 2
    # The probe of page 1, then page 0 to learn the console page size (it holds the window).
    assert [call.kwargs["json"] for call in client.post.await_args_list] == [
        {"pageNumber": 1, "pageSize": 2},
        {"pageNumber": 0, "pageSize": 2},
    ]
    client.post.reset_mock()
    if query is None:
        resumed = await system_log._read_system_log(
            client, registry, "h", "Default", "critical", None, page=2, page_size=2
        )
    else:
        resumed = await system_log._read_system_log(
            client, registry, "h", "Default", "critical", {"pageNumber": 2, "pageSize": 2}
        )
    assert resumed["data"] == records[4:6]
    assert resumed["_nextPage"] == 3
    assert [call.kwargs["json"] for call in client.post.await_args_list] == [
        {"pageNumber": 2, "pageSize": 2},
        {"pageNumber": 0, "pageSize": 2},
        {"pageNumber": 1, "pageSize": 4},
    ]
    assert records == [{"id": number} for number in range(12)]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        *[("pageSize", value) for value in ("2", 2.0, 0, -1, True, None)],
        *[("pageNumber", value) for value in ("2", 2.0, -1, True, None)],
    ],
)
async def test_query_paging_rejected_before_any_upstream_request(client, registry, field, value):
    with pytest.raises(ValueError) as exc:
        await system_log._read_system_log(
            client, registry, "h", "Default", "critical", {field: value}
        )
    # PAGING-VALIDATION-A1 rules 1 and 3 (note 2): the system log converges on the
    # shared templates, naming the query field the caller sent.
    name = f"query_body.{field}"
    assert str(exc.value) == (
        f"{name} must be a positive integer (1 or more); got {value}. "
        f"Omit {name} to read the whole collection."
        if field == "pageSize"
        else f"{name} is zero-based and must be 0 or more; got {value}."
    )
    client.post.assert_not_awaited()
    client.get.assert_not_awaited()
    registry.resolve_key_for_host.assert_not_awaited()
    assert any(rule.matches(str(exc.value)) for rule in refusals.REFUSALS)


@pytest.mark.parametrize("value", [0, -1, "2", 2.0, True])
async def test_typed_page_size_rejected_before_any_upstream_request(client, registry, value):
    # PAGING-VALIDATION-A1 rule 3: the count template naming page_size.
    with pytest.raises(ValueError) as exc:
        await system_log._read_system_log(
            client, registry, "h", "Default", "critical", None, page_size=value
        )
    assert str(exc.value) == (
        f"page_size must be a positive integer (1 or more); got {value}. "
        "Omit page_size to read the whole collection."
    )
    client.post.assert_not_awaited()
    client.get.assert_not_awaited()
    registry.resolve_key_for_host.assert_not_awaited()


async def test_query_paging_is_validated_even_if_explicit_arguments_override(client, registry):
    with pytest.raises(ValueError, match="query_body.pageSize"):
        await system_log._read_system_log(
            client, registry, "h", "Default", "critical", {"pageSize": 0}, page_size=2
        )
    client.post.assert_not_awaited()


async def test_valid_query_page_zero_and_size_are_preserved(client, registry):
    # SHORTPAGE-EXPECTATIONS T10 and note N4: the short bare page 0 is not final evidence,
    # so the window reads page 1 at the console size 1; its empty answer ends the window and
    # the one bare page is returned as the console sent it.
    client.post.side_effect = [[{"id": 1}], []]
    result = await system_log._read_system_log(
        client,
        registry,
        "h",
        "Default",
        "critical",
        {"pageNumber": 0, "pageSize": 2, "other": "keep"},
    )
    assert result == [{"id": 1}]
    assert [call.kwargs["json"] for call in client.post.await_args_list] == [
        {"pageNumber": 0, "pageSize": 2, "other": "keep"},
        {"pageNumber": 1, "pageSize": 1, "other": "keep"},
    ]
