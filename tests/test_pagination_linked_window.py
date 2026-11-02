"""Exact linked-page windows and the ruling's minimal-request oracle."""

from types import SimpleNamespace

import pytest

from unifi_fabric.config import APIKeyConfig
from unifi_fabric.tools._pagination import collect_links


def console(total, clamp, *, echo=None, cap=None):
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append(dict(params))
        size = min(clamp, params["pageSize"])
        number = params["page"]
        start = (number - 1) * size
        rows = list(range(start, min(start + size, total)))
        links = {}
        if start + size < total:
            links["next"] = f"?page={number + 1}"
            if echo == "next":
                links["next"] += f"&pageSize={size}"
        if echo == "prev" and number > 1:
            links["prev"] = f"?page={number - 1}&pageSize={size}"
        return {"data": rows, "links": links}

    return SimpleNamespace(get=get, paginate_max_pages=cap), calls


def request_oracle(total, clamp, page, requested):
    """Count probe, optional discovery, and intersecting physical pages."""
    left = (page - 1) * requested
    wire = min(requested, 100)
    effective = min(clamp, wire)
    probe = left // wire + 1
    probe_end = min(probe * effective, total)
    count = max(0, probe_end - (probe - 1) * effective)
    if not count:
        return 1
    terminal = probe * effective >= total
    discovery = terminal and count < wire and probe > 1
    if terminal and total <= left:
        return 1 + discovery
    first = left // effective + 1
    last = (min(left + requested, total) - 1) // effective + 1
    return 1 + discovery + max(1, last - first + 1) - (first == probe)


@pytest.mark.parametrize("total", [0, 1, 59, 60, 61, 299, 300])
@pytest.mark.parametrize("clamp", [1, 60, 100, 500])
@pytest.mark.parametrize("page", [1, 2, 5])
@pytest.mark.parametrize("requested", [1, 60, 275, 425, 250])
async def test_linked_window_matrix_and_minimal_request_oracle(total, clamp, page, requested):
    client, calls = console(total, clamp)
    result = await collect_links(client, "/synthetic", "data", page=page, page_size=requested)
    left = (page - 1) * requested
    assert result["items"] == list(range(left, min(left + requested, total)))
    assert len(result["items"]) <= requested
    assert result["incomplete"] is False
    assert result["incompleteReason"] is None
    assert result["pages"] == len(calls) == request_oracle(total, clamp, page, requested)
    assert result["_pageSize"]["sent"] == [call["pageSize"] for call in calls]
    assert result["_pageSize"]["returned"] == len(result["items"])
    assert result["nextPage"] == (page + 1 if left + requested < total else None)


@pytest.mark.parametrize("total", [0, 1, 59, 60, 61, 299, 300])
@pytest.mark.parametrize("clamp", [1, 60, 100, 500])
async def test_size_250_consecutive_windows_are_disjoint_and_contiguous(total, clamp):
    client, _ = console(total, clamp)
    combined = []
    for page in range(1, 4):
        result = await collect_links(client, "/synthetic", "data", page=page, page_size=250)
        assert not set(combined).intersection(result["items"])
        combined.extend(result["items"])
        assert combined == list(range(min(total, page * 250)))
        assert result["incomplete"] is False


@pytest.mark.parametrize(
    ("total", "clamp", "requested", "expected", "calls"),
    [
        (300, 60, 425, [], [{"page": 5, "pageSize": 100}, {"page": 1, "pageSize": 100}]),
        (
            299,
            100,
            275,
            list(range(275, 299)),
            [{"page": 3, "pageSize": 100}, {"page": 1, "pageSize": 100}],
        ),
    ],
)
async def test_terminal_probe_discovers_total_without_unnecessary_pages(
    total, clamp, requested, expected, calls
):
    client, actual = console(total, clamp)
    result = await collect_links(client, "/synthetic", "data", page=2, page_size=requested)
    assert result["items"] == expected
    assert result["incomplete"] is False
    assert result["totalCount"] == total
    assert result["pages"] == 2
    assert actual == calls


@pytest.mark.parametrize("cap", [1, 2, 3])
async def test_corrective_pages_share_probe_budget(cap):
    client, calls = console(900, 60, cap=cap)
    result = await collect_links(client, "/synthetic", "data", page=2, page_size=275)
    assert result["incomplete"] is True
    assert "UNIFI_PAGINATE_MAX_PAGES page cap" in result["incompleteReason"]
    assert result["pages"] == len(calls) == cap
    assert result["items"] == list(range(275, max(275, 240 + (cap - 1) * 60)))
    assert result["nextPage"] is None


@pytest.mark.parametrize("echo", ["next", "prev"])
async def test_terminal_probe_reads_size_echo_before_discovery(echo):
    client, calls = console(299, 100, echo=echo)
    result = await collect_links(client, "/synthetic", "data", page=2, page_size=275)
    assert result["items"] == list(range(275, 299))
    assert result["incomplete"] is False
    assert result["pages"] == (1 if echo == "prev" else 2)
    assert len(calls) == result["pages"]


async def test_discovery_cap_stops_before_second_request():
    client, calls = console(299, 100, cap=1)
    result = await collect_links(client, "/synthetic", "data", page=2, page_size=275)
    assert result["items"] == []
    assert result["incomplete"] is True
    assert "UNIFI_PAGINATE_MAX_PAGES" in result["incompleteReason"]
    assert result["pages"] == len(calls) == 1


async def test_ambiguous_terminal_probe_fallback_has_native_resume():
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append(dict(params))
        return {"data": [1], "links": {}}

    client = SimpleNamespace(get=get, paginate_max_pages=None)
    result = await collect_links(client, "/synthetic", "data", page=2, page_size=275)
    assert result["items"] == []
    assert result["incomplete"] is True
    assert "page 3 with 1 rows" in result["incompleteReason"]
    assert "resume with page=3 and no page_size" in result["incompleteReason"]
    assert calls == [{"page": 3, "pageSize": 100}, {"page": 1, "pageSize": 100}]


@pytest.mark.parametrize("later", [{"unexpected": []}, {"data": [0], "links": {"next": "?page=3"}}])
async def test_later_malformed_or_repeated_page_is_incomplete_and_counted(later):
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append(dict(params))
        return {"data": [0], "links": {"next": "?page=2"}} if len(calls) == 1 else later

    client = SimpleNamespace(get=get, paginate_max_pages=None)
    result = await collect_links(client, "/synthetic", "data", page_size=3)
    assert result["items"] == [0]
    assert result["incomplete"] is True
    assert result["pages"] == len(calls) == 2
    assert any(word in result["incompleteReason"] for word in ("records array", "repeated"))


# --------------------------------------------------------------------------------------
# A console that clamps the page size and ignores ``page`` repeats the same records on
# every request, but a live (non-identity) field changes on each answer. The repeat is
# recognised by record identity, never by whole-body equality.
# --------------------------------------------------------------------------------------
def repeating_console(clamp, *, ignore=True, field="data"):
    calls = []

    async def get(path, *, key=None, params=None):
        calls.append((dict(params), key))
        number = 1 if ignore else params["page"]
        size = min(clamp, params["pageSize"])
        first = (number - 1) * size
        rows = [
            {"id": f"synthetic-{i}", "client_count": len(calls)} for i in range(first, first + size)
        ]
        return {field: rows, "links": {"next": f"?page={number + 1}&pageSize={size}"}}

    return SimpleNamespace(get=get, paginate_max_pages=None), calls


async def test_linked_window_rejects_a_repeat_whose_live_fields_changed():
    client, calls = repeating_console(2)
    beta = APIKeyConfig(key="sk-b", label="beta")
    result = await collect_links(client, "/synthetic", "data", key=beta, page=1, page_size=4)
    assert result["incomplete"] is True
    assert "repeated" in result["incompleteReason"]
    assert result["nextPage"] is None
    ids = [row["id"] for row in result["items"]]
    assert len(ids) == len(set(ids))  # no duplicated identity counts toward the window
    assert all(key is beta for _, key in calls)


async def test_linked_window_control_distinct_identities_with_changing_fields_complete():
    client, calls = repeating_console(2, ignore=False)
    result = await collect_links(client, "/synthetic", "data", page=2, page_size=4)
    assert result["incomplete"] is False
    assert [row["id"] for row in result["items"]] == [f"synthetic-{i}" for i in range(4, 8)]
    assert result["nextPage"] == 3


@pytest.mark.parametrize("ignore", [True, False], ids=["ignores-page", "pages"])
async def test_recognition_groups_window_with_changing_fields_and_beta_key_routing(ignore):
    from unittest.mock import AsyncMock

    from unifi_fabric.tools import recognition

    client, calls = repeating_console(2, ignore=ignore, field="groups")
    beta = APIKeyConfig(key="sk-b", label="beta")
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = beta
    registry.resolve_host_id.return_value = "console"
    result = await recognition.list_recognition_groups(
        client, registry, "console", "face", page=1, page_size=4
    )
    assert all(key is beta for _, key in calls)
    ids = [row["id"] for row in result["groups"]]
    if ignore:
        assert result["incomplete"] is True
        assert "repeated" in result["incompleteReason"]
        assert len(ids) == len(set(ids))
        assert "_nextPage" not in result
    else:
        assert not result.get("incomplete")
        assert ids == [f"synthetic-{i}" for i in range(4)]
        assert result["_nextPage"] == 2
