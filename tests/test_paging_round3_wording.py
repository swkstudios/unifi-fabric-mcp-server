"""Paging reason wording, final review follow-up (P6, PF-F7, PF-F9 of the Opus final review)."""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from unifi_fabric import _paging_identity
from unifi_fabric.tools import _pagination
from unifi_fabric.tools._pagination import collect_batch


@pytest.mark.parametrize(
    ("family", "field", "clause"),
    [
        ("number", {"total_page_count": 8}, "its total_page_count 8 still has outstanding pages"),
        ("number", {"has_next": True}, "its continuation has_next is still non-terminal"),
        ("cursor", {"nextToken": "more"}, "its continuation nextToken is still non-terminal"),
        (
            "links",
            {"links": {"next": "/synthetic?page=3&pageSize=2"}},
            "its continuation links.next is still non-terminal",
        ),
    ],
)
async def test_p6_repeat_reason_reads_although_its_continuation(family, field, clause):
    rows = [{"id": i} for i in range(3)]

    async def fetch(controls: dict[str, Any]) -> Any:
        return {"data": rows, **field}

    result = await collect_batch(fetch, requested=None, default_size=2, family=family)
    assert result["incomplete"]
    assert result["incompleteReason"].endswith(f" although {clause}")
    assert "although it its" not in result["incompleteReason"]
    assert "although it total_page_count" not in result["incompleteReason"]


async def test_pf_f7_number_oversized_pages_name_page_number_and_page_size():
    # Records without an identity: two different oversized pages cannot be told apart from
    # a console that ignores pageNumber.
    pages = [[{"v": "a"}, {"v": "b"}, {"v": "c"}], [{"v": "d"}, {"v": "e"}, {"v": "f"}]]
    calls: list[dict[str, Any]] = []

    async def fetch(controls: dict[str, Any]) -> Any:
        calls.append(dict(controls))
        return {"data": pages[controls["pageNumber"]]}

    result = await collect_batch(fetch, requested=None, default_size=2, family="number")
    assert result["incomplete"]
    assert result["incompleteReason"].startswith(
        "page 2 (pageNumber 1, record offset 3) returned 3 rows for a sent pageSize of 2, "
        "after page 1 also exceeded its sent pageSize; "
    )
    assert "limit" not in result["incompleteReason"]
    assert calls == [{"pageNumber": 0, "pageSize": 2}, {"pageNumber": 1, "pageSize": 2}]


async def test_pf_f7_offset_oversized_pages_keep_the_offset_wording():
    pages = {0: [{"v": "a"}, {"v": "b"}, {"v": "c"}], 3: [{"v": "d"}, {"v": "e"}, {"v": "f"}]}

    async def fetch(controls: dict[str, Any]) -> Any:
        return pages[controls.get("offset", 0)]

    result = await collect_batch(fetch, requested=None, default_size=2, family="offset")
    assert result["incomplete"]
    assert result["incompleteReason"].startswith(
        "page 2 at offset 3 returned 3 rows for a sent limit of 2, "
        "after page 1 also exceeded its sent limit; "
    )


@pytest.mark.parametrize("module", [_pagination, _paging_identity])
def test_pf_f9_no_word_is_split_across_a_line_break(module):
    source = inspect.getsource(module)
    assert "non-\n" not in source
    assert "non- " not in source
