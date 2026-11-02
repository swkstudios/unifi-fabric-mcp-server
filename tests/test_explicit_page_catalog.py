"""Explicit-page mode across every paging helper and every list tool.

1. An explicit position returns the upstream page; a count requests that many records
   and can return a metadata envelope. Explicit position pages preserve bare arrays.
2. No optional query parameter is sent unless the caller gave it: a page fetched with one
   paging argument sends that one paging parameter upstream, never a default for another
   (no ``offset=0`` beside a lone ``limit``, no ``pageSize`` beside a lone ``page_token``).

Both properties are parametrized over every registered tool that takes a paging argument,
so a list tool added with any of the paging helpers (``collect_offset``,
``collect_cursor``, ``collect_links``, or its own) is covered at once.
"""

from __future__ import annotations

import copy
import functools
import json
import logging
from typing import Any

import httpx
import pytest

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import lazy_parametrize

TOOLS = cti.TOOLS

#: Every explicit-paging argument a tool can take, with a value unique on the wire.
PAGING_ARGS: dict[str, Any] = {
    "offset": 5,
    "limit": 7,
    "page_token": "probe-page-token",
    "page": 3,
    "page_number": 4,
    "page_size": 9,
    "cursor": "probe-cursor",
}
#: Upstream query names a paging argument can travel as.
PAGING_QUERY = frozenset(
    {
        "offset",
        "limit",
        "nextToken",
        "pageToken",
        "page",
        "pageNumber",
        "pageSize",
        "cursor",
        "page_size",
    }
)


def _props(name: str) -> set[str]:
    return set((TOOLS[name].parameters or {}).get("properties", {}))


def _explicit_args(name: str) -> list[str]:
    """The paging arguments that each select ONE page on their own. A page-number tool's
    ``page_size`` alone is the size of a full drain (its single page is ``page`` or
    ``page_number``)."""
    args = _props(name) & set(PAGING_ARGS)
    if {"page", "page_number"} & args:
        args.discard("page_size")
    return sorted(args)


@functools.cache
def _lz_PAGED_TOOLS():
    return sorted(n for n in TOOLS if _props(n) & set(PAGING_ARGS))


@functools.cache
def _lz_CASES():
    return [(name, arg) for name in _lz_PAGED_TOOLS() for arg in _explicit_args(name)]


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def test_the_sweep_is_non_trivial():
    assert len(_lz_PAGED_TOOLS()) >= 30, _lz_PAGED_TOOLS()
    styles = {arg for _n, arg in _lz_CASES()}
    assert styles == set(PAGING_ARGS), styles  # every paging style is exercised


def _payload(res: Any) -> Any:
    body = uh.result_payload(res)
    if isinstance(body, dict) and set(body) == {"result"}:
        return body["result"]
    return body


def _strip_additive(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: _strip_additive(v) for k, v in node.items() if not k.startswith("_")}
    if isinstance(node, list):
        return [_strip_additive(v) for v in node]
    return node


def _own_read(name: str, s: uh.Served) -> bool:
    """A read of the tool's own list: a GET (its resolution route, for a tool listing one),
    or the query POST whose page travels in the JSON body (the Network v2 system log, the
    sites overview, the Teleport invitation history). Those query POSTs are not on the
    read-POST allowlist, so the write classifier calls them writes (READ_NAMED_POST_WRITES
    in tests/test_read_only.py); a paged list tool sends no other POST."""
    own = cti.PRIMARY_RESOLUTION.get(name)
    if s.method == "POST":
        return True
    return s.method == "GET" and (not s.resolution or bool(own and s.path.endswith(own)))


def _sent_paging(s: uh.Served) -> dict[str, str]:
    """The request's query parameters plus the scalar top-level keys of its JSON body (a
    read-POST carries its page there), as strings."""
    sent = dict(uh.parse_query(s.query))
    if isinstance(s.sent_json, dict):
        sent.update({k: str(v) for k, v in s.sent_json.items() if not isinstance(v, (dict, list))})
    return sent


def _page_reads(name: str, up: uh.FakeUpstream) -> list[uh.Served]:
    return [
        s
        for s in up.served
        if _own_read(name, s) and 200 <= s.status < 300 and isinstance(s.body, list)
    ]


async def _one_page(monkeypatch, name: str, arg: str) -> tuple[Any, uh.FakeUpstream]:
    own = cti.PRIMARY_RESOLUTION.get(name)
    up = uh.FakeUpstream(
        replay_recordings=False, bare_pages=True, bare_resolution=(own,) if own else ()
    )
    args = {**tool_args.generated_args(TOOLS[name]), arg: PAGING_ARGS[arg]}
    res = await cti._call(monkeypatch, name, up, args)
    return _payload(res), up


def _assert_count_envelope(payload, pages, requested):
    # A bare-array source carries no continuation. Accept every distinct served
    # page in order, stopping only at the repeated-page guard or the requested total.
    expected = []
    seen = []
    repeated = False
    for served in pages:
        if served.body and served.body in seen:
            repeated = True
            break
        expected.extend(served.body)
        seen.append(served.body)
        if len(expected) >= requested:
            expected = expected[:requested]
            break
    assert _strip_additive(payload["data"]) == _strip_additive(expected)
    assert len(payload["data"]) == len(expected)
    assert payload["_pageSize"]["requested"] == requested
    assert payload["_pageSize"]["returned"] == len(expected)
    if "_count" in payload:
        assert payload["_count"] == len(expected)
    assert bool(payload.get("incomplete")) == repeated
    if repeated:
        assert "repeated page" in payload["incompleteReason"]
    else:
        assert not payload.get("incompleteReason")
    for marker in (
        "nextToken",
        "nextCursor",
        "nextPage",
        "_nextOffset",
        "_nextPage",
        "_nextCursor",
        "_continuation",
    ):
        assert payload.get(marker) is None, (marker, payload.get(marker))


@lazy_parametrize(("name", "arg"), lambda: _lz_CASES())
async def test_explicit_bare_array_page_is_returned_unchanged(monkeypatch, name, arg):
    payload, up = await _one_page(monkeypatch, name, arg)
    pages = _page_reads(name, up)
    assert pages, f"{name}({arg}): no bare-array page was served: {[s.path for s in up.served]}"
    page = pages[0].body if arg in {"limit", "page_size"} else pages[-1].body
    assert page, f"{name}({arg}): the served page is empty (vacuous)"
    if arg in {"limit", "page_size"} and isinstance(payload, dict):
        _assert_count_envelope(payload, pages, PAGING_ARGS[arg])
    else:
        assert isinstance(payload, list), (
            f"{name}({arg}): the bare-array page came back wrapped: {type(payload).__name__} "
            f"with keys {sorted(payload)[:8] if isinstance(payload, dict) else '-'}"
        )
        assert _strip_additive(payload) == _strip_additive(page), f"{name}({arg}): page altered"


@lazy_parametrize(("name", "arg"), lambda: _lz_CASES())
async def test_only_the_given_paging_parameter_is_sent(monkeypatch, name, arg):
    up = uh.FakeUpstream(replay_recordings=False)
    args = {**tool_args.generated_args(TOOLS[name]), arg: PAGING_ARGS[arg]}
    await cti._call(monkeypatch, name, up, args)
    wanted = str(PAGING_ARGS[arg])
    reads = [s for s in up.served if _own_read(name, s) and wanted in _sent_paging(s).values()]
    assert reads, f"{name}({arg}): {wanted!r} never reached the upstream"
    for s in reads:
        sent = _sent_paging(s)
        extra = sorted(k for k in sent if k in PAGING_QUERY and sent[k] != wanted)
        assert extra == [], (
            f"{name}({arg}): {s.method} {s.path} also sent {extra} the caller never gave"
        )


# A page-number tool given page_size requests that many records, starting at page zero.
#: Page-number tools whose pages travel in a query POST body, by route suffix.
PAGE_SIZE_DRAINS = {"query_teleport_invitations": "/teleport/invitation-history"}
_DRAIN_PAGE_SIZE = 9
#: Fixed synthetic pages: two full pages, a short page, then an empty page.
_DRAIN_PAGES = [
    [{"id": f"probe-invitation-{page}-{row}"} for row in range(rows)]
    for page, rows in enumerate((_DRAIN_PAGE_SIZE, _DRAIN_PAGE_SIZE, 4, 0))
]


class _FixedPages(uh.FakeUpstream):
    """Serves ``_DRAIN_PAGES`` (``{"data": [...]}``) on one query POST route by the body's
    ``pageNumber``; every other request is the normal synthetic upstream."""

    route = ""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.method == "POST" and req.url.path.endswith(self.route):
            number = json.loads(req.content)["pageNumber"]
            rows = _DRAIN_PAGES[number] if number < len(_DRAIN_PAGES) else []
            body = {"data": copy.deepcopy(rows)}
            self._record(req, 200, body, False)
            return httpx.Response(200, json=body)
        return super().__call__(req)


def test_page_size_drain_tools_take_page_size_and_a_page_number():
    assert "query_teleport_invitations" in PAGE_SIZE_DRAINS
    for name in PAGE_SIZE_DRAINS:
        assert "page_size" in _props(name) and {"page", "page_number"} & _props(name), name
        assert "page_size" not in _explicit_args(name), name


@pytest.mark.parametrize("name", sorted(PAGE_SIZE_DRAINS))
async def test_page_size_alone_drains_every_page_at_that_length(monkeypatch, name):
    up = _FixedPages(replay_recordings=False)
    up.route = PAGE_SIZE_DRAINS[name]
    args = {**tool_args.generated_args(TOOLS[name]), "page_size": _DRAIN_PAGE_SIZE}
    args.pop("page_number", None)
    args.pop("page", None)
    payload = uh.result_payload(await cti._call(monkeypatch, name, up, args))
    posts = [s.sent_json for s in up.served if s.method == "POST"]
    # The requested count is met by the first physical page.
    assert posts == [{"pageNumber": 0, "pageSize": _DRAIN_PAGE_SIZE}]
    assert payload["data"] == _DRAIN_PAGES[0], payload
    assert payload["_count"] == _DRAIN_PAGE_SIZE and payload["_pages"] == 1, payload
    assert payload["_pageSize"]["requested"] == _DRAIN_PAGE_SIZE
    assert "incomplete" not in payload, payload
