"""Count-envelope assertions must detect corruption beyond the first page."""

from types import SimpleNamespace

import pytest

from tests.test_explicit_page_catalog import _assert_count_envelope


@pytest.mark.parametrize("tail", [[], [{"id": "1"}], [{"id": "changed"}]])
def test_later_page_corruption_is_rejected(tail):
    pages = [SimpleNamespace(body=[{"id": "0"}, {"id": "1"}]), SimpleNamespace(body=[{"id": "2"}])]
    rows = pages[0].body + tail
    payload = {
        "data": rows,
        "_count": len(rows),
        "_pageSize": {"requested": 7, "returned": len(rows)},
    }
    with pytest.raises(AssertionError):
        _assert_count_envelope(payload, pages, 7)


@pytest.mark.parametrize(
    "change",
    [
        {"_count": 2},
        {"_pageSize": {"requested": 7, "returned": 2}},
        {"incomplete": True, "incompleteReason": "unproved"},
        {"incompleteReason": "unproved"},
        {"_nextPage": 2},
        {"_continuation": "unproved"},
    ],
)
def test_count_and_continuation_corruption_is_rejected(change):
    pages = [SimpleNamespace(body=[{"id": "0"}, {"id": "1"}]), SimpleNamespace(body=[{"id": "2"}])]
    payload = {
        "data": pages[0].body + pages[1].body,
        "_count": 3,
        "_pageSize": {"requested": 7, "returned": 3},
    }
    _assert_count_envelope(payload, pages, 7)
    with pytest.raises(AssertionError):
        _assert_count_envelope({**payload, **change}, pages, 7)


def test_repeated_served_page_requires_actionable_incomplete_reason():
    page = SimpleNamespace(body=[{"id": "0"}, {"id": "1"}])
    payload = {
        "data": page.body,
        "_count": 2,
        "_pageSize": {"requested": 7, "returned": 2},
        "incomplete": True,
        "incompleteReason": "repeated page 1",
    }
    _assert_count_envelope(payload, [page, page], 7)
    with pytest.raises(AssertionError):
        _assert_count_envelope({**payload, "incomplete": False}, [page, page], 7)
