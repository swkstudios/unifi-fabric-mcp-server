"""Shared list-drain helpers so list tools return *complete* result sets.

Background — the bug these fix
------------------------------
Every list tool used to issue a single ``client.get()`` and return page one.
For a cursor endpoint it surfaced the ``nextToken``; for an offset endpoint it
surfaced ``totalCount``. Either way the *caller* was expected to notice and
follow up. On a single-console estate that never crossed a page boundary this
looked complete forever — and silently truncated the moment it pointed at a
large estate, which is the whole reason this server exists.

These helpers make ``list_*`` tools drain *all* pages by default while keeping
manual paging available and never masking a capped drain as complete.

Two pagination families, one contract
-------------------------------------
* ``collect_cursor`` — Site Manager ``/ea/*`` (+ ``/v1``) endpoints that page
  with an opaque ``nextToken`` cursor. Drains via ``UniFiClient.paginate``.
* ``collect_offset`` — Network *Integration* proxy endpoints that page with
  ``offset``/``limit`` and report ``totalCount``. Drains via
  ``UniFiClient.paginate_offset``.

Explicit-paging contract (deliberate, documented in every wired tool)
---------------------------------------------------------------------
* Default (no paging arg): auto-drain every page and return the complete set.
* Explicit paging — ``page_token`` for cursor tools, ``offset``/``limit`` for
  offset tools — returns exactly ONE page starting at that position and surfaces
  the continuation marker (``nextToken`` / ``totalCount``). This preserves the
  pre-existing manual-pagination contract for callers that page deliberately.

Incomplete results are never disguised
--------------------------------------
If a drain hits ``UNIFI_PAGINATE_MAX_PAGES`` (or a cursor stall), the pages
gathered so far are returned *with* ``incomplete=True`` and a human-readable
``incompleteReason``. A truncated result that looks complete is exactly the bug
being fixed, so truncation is always surfaced, never silent.
"""

from __future__ import annotations

from typing import Any

from ..client import PaginationAbortedError, UniFiClient
from ..config import APIKeyConfig

# API max page size; also the drain page size. Integration ``_page_params``
# validates limit in [0, 200], and larger pages mean fewer round-trips for a
# full drain, so 200 is both valid and efficient.
DRAIN_PAGE_SIZE = 200


async def collect_cursor(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None = None,
    params: dict[str, Any] | None = None,
    page_token: str | None = None,
    page_size: int = DRAIN_PAGE_SIZE,
) -> dict[str, Any]:
    """Fetch a cursor-paginated list, draining all pages unless ``page_token`` is given.

    Returns ``{items, nextToken, incomplete, incompleteReason}``. ``nextToken``
    is populated only in explicit-paging mode (single page); a full drain sets
    it to ``None`` because there is no next page to hand back.
    """
    if page_token is not None:
        req = dict(params or {})
        req["limit"] = page_size
        req["nextToken"] = page_token
        data = await client.get(path, key=key, params=req)
        return {
            "items": data.get("data", []),
            "nextToken": data.get("nextToken"),
            "incomplete": False,
            "incompleteReason": None,
        }
    try:
        items = await client.paginate(path, key=key, params=params, page_size=page_size)
        return {"items": items, "nextToken": None, "incomplete": False, "incompleteReason": None}
    except PaginationAbortedError as exc:
        return {
            "items": exc.items,
            "nextToken": None,
            "incomplete": True,
            "incompleteReason": exc.reason,
        }


async def collect_offset(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None = None,
    params: dict[str, Any] | None = None,
    offset: int | None = None,
    limit: int | None = None,
    page_size: int = DRAIN_PAGE_SIZE,
) -> dict[str, Any]:
    """Fetch an offset-paginated list, draining all pages unless ``offset``/``limit`` given.

    Returns ``{items, totalCount, incomplete, incompleteReason}``. Passing
    either ``offset`` or ``limit`` selects explicit-paging mode: exactly one page
    is fetched at that position and the API's ``totalCount`` is surfaced so the
    caller can page manually. A full drain reports ``totalCount`` as the number
    of records actually gathered.
    """
    base = dict(params or {})
    if offset is not None or limit is not None:
        req = dict(base)
        req["offset"] = offset if offset is not None else 0
        if limit is not None:
            req["limit"] = limit
        data = await client.get(path, key=key, params=req)
        if isinstance(data, list):
            return {
                "items": data,
                "totalCount": None,
                "incomplete": False,
                "incompleteReason": None,
            }
        return {
            "items": data.get("data", []),
            "totalCount": data.get("totalCount"),
            "incomplete": False,
            "incompleteReason": None,
        }
    try:
        items = await client.paginate_offset(
            path, key=key, params=base or None, page_size=page_size
        )
        return {
            "items": items,
            "totalCount": len(items),
            "incomplete": False,
            "incompleteReason": None,
        }
    except PaginationAbortedError as exc:
        return {
            "items": exc.items,
            "totalCount": None,
            "incomplete": True,
            "incompleteReason": exc.reason,
        }


async def collect_links(
    client: UniFiClient,
    path: str,
    array_field: str,
    *,
    key: APIKeyConfig | None = None,
    params: dict[str, Any] | None = None,
    page: int | None = None,
    page_size: int = DRAIN_PAGE_SIZE,
) -> dict[str, Any]:
    """Fetch a ``links.next`` / page-number list, draining all pages unless ``page`` given.

    The private Protect recognition endpoints (``/recognition/{type}/groups`` and
    ``.../{id}/detections``) return a ``{<array_field>, links:{prev,next}}`` envelope and
    page via an explicit ``page=N`` query parameter — a third pagination family alongside
    cursor (``nextToken``) and offset/limit. Drains via ``UniFiClient.paginate_links``.

    Returns ``{items, nextPage, incomplete, incompleteReason}``. Passing ``page`` selects
    explicit-paging mode: exactly one page is fetched and ``nextPage`` (the next page
    number, or ``None`` on the last page) is surfaced so the caller can page manually.
    A full drain reports ``nextPage`` as ``None`` because there is no next page to hand
    back.
    """
    base = dict(params or {})
    if page is not None:
        req = dict(base)
        req["pageSize"] = page_size
        req["page"] = page
        data = await client.get(path, key=key, params=req)
        if isinstance(data, list):
            items = data
            has_next = False
        else:
            items = data.get(array_field, [])
            has_next = bool((data.get("links") or {}).get("next"))
        return {
            "items": items,
            "nextPage": (page + 1) if has_next else None,
            "incomplete": False,
            "incompleteReason": None,
        }
    try:
        items = await client.paginate_links(
            path, array_field, key=key, params=base or None, page_size=page_size
        )
        return {"items": items, "nextPage": None, "incomplete": False, "incompleteReason": None}
    except PaginationAbortedError as exc:
        return {
            "items": exc.items,
            "nextPage": None,
            "incomplete": True,
            "incompleteReason": exc.reason,
        }


def mark_incomplete(result: dict[str, Any], collected: dict[str, Any]) -> dict[str, Any]:
    """Copy the incomplete markers from a ``collect_*`` result onto a tool result.

    Adds ``incomplete=True`` + ``incompleteReason`` only when the drain was
    actually capped/stalled, so a complete result stays free of noise keys.
    """
    if collected.get("incomplete"):
        result["incomplete"] = True
        result["incompleteReason"] = collected.get("incompleteReason")
    return result
