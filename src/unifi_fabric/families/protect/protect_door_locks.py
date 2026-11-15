"""Protect 7.x door-lock reads: one lock, and a lock's remote unlock requests.

Routes (private Protect API, the Protect 7.x Thread lock model; the official Integration API
has no door-lock route). Both are served by the Protect 7.3.74 console route table (the
service.js route table mined by ``scripts/private_api``): ``GET /locks/:id`` and
``GET /locks/:id/unlock/events``. The unlock-events handler takes the query ``limit``
(integer 1 to 100, default 50) and ``offset`` (integer 0 to 10000, default 0), no other
keys, and answers a bare array of unlock requests, newest first.

No door lock is available for live testing, so these tools are hermetic-only (docs/COVERAGE.md).

Every id is checked against ``GET /locks`` before the per-lock request: an id the console
does not list fails with the valid locks named. Every response is passed through verbatim.
"""

from __future__ import annotations

import json
from typing import Any, cast

from ...client import UniFiClient, UniFiConnectionError, path_segment, upstream_error_value
from ...config import APIKeyConfig
from ...matching import same_id
from ...registry import Registry
from ...shared_shapes._keys import with_context
from ...shared_shapes._pagination import (
    PageSizeBatch,
    bare_page,
    collect_offset,
    mark_incomplete,
    validate_pagination,
)
from ...shared_shapes._payload import with_upstream_hint
from .protect import _as_list, _private, _require_object, _resolve
from .schemas import (  # the family's shapes (family-owned layout)
    _LOCKS_HINT,
    UNLOCK_EVENTS_MAX_OFFSET,
    UNLOCK_EVENTS_PAGE_SIZE,
)


async def _require_known_lock(
    client: UniFiClient, host_id: str, key: APIKeyConfig | None, host: str, lock_id: str
) -> str:
    """Resolve ``lock_id`` against ``GET /locks``; return the id as the console lists it.

    An id the console does not list fails here, before the per-lock request, with the
    valid locks named (id and name), so the caller can correct the argument.
    """
    body = await with_upstream_hint(client.get(_private(host_id, "/locks"), key=key), _LOCKS_HINT)
    locks = [_require_object(lock, "door lock") for lock in _as_list(body, "door locks")]
    for lock in locks:
        if same_id(lock_id, lock.get("id")):
            return cast(str, lock["id"])
    if locks:
        listed = ", ".join(
            f"{upstream_error_value(lock.get('id'))} ({upstream_error_value(lock.get('name'))})"
            if lock.get("name")
            else str(upstream_error_value(lock.get("id")))
            for lock in locks
        )
    else:
        listed = "none (GET /locks returned an empty list)"
    raise ValueError(f"Unknown door lock {lock_id!r} on {host!r}; valid choices: {listed}")


async def get_door_lock(
    client: UniFiClient, registry: Registry, host: str, lock_id: str
) -> dict[str, Any]:
    """Read one door lock (``GET /locks/{id}``), verbatim."""
    path_segment(lock_id, "lock_id")
    key, host_id = await _resolve(registry, host)
    listed_id = await _require_known_lock(client, host_id, key, host, lock_id)
    path = _private(host_id, f"/locks/{path_segment(listed_id, 'lock_id')}")
    body = await with_upstream_hint(client.get(path, key=key), _LOCKS_HINT)
    return _require_object(body, f"GET {path}")


def _request_identity(item: Any) -> str:
    """The identity of one unlock request: its ``requestId``, else ``eventId``, else its body."""
    if isinstance(item, dict):
        for field in ("requestId", "eventId"):
            if isinstance(item.get(field), str) and item[field]:
                return f"{field}:{item[field]}"
    return "body:" + json.dumps(item, sort_keys=True, default=str)


async def _gather_unlock_events(
    client: UniFiClient,
    path: str,
    key: APIKeyConfig | None,
    total: int | None,
    policy: PageSizeBatch | None = None,
) -> tuple[list[Any], str | None]:
    """Gather unlock requests page by page: all of them, or ``total`` of them.

    Pages are requested at the route maximum and end on an empty page (a short page is not
    proof of the end). Paging does not use the shared drain: an unlock request has no ``id``,
    ``_id`` or ``uuid`` (the drain's identities) and every request of one lock carries that
    lock's ``mac``, so a request is identified here by its ``requestId``. Returns the
    requests and, when the
    gathering stopped before the end (the operator's page cap, the console's offset limit
    or a repeated page), the reason. ``policy`` (a requested count) records each size sent,
    and its first request sends no ``offset`` (the console's default is 0).
    """
    rows: list[Any] = []
    seen: set[Any] = set()
    max_pages = client.paginate_max_pages
    pages = 0
    while total is None or len(rows) < total:
        if len(rows) > UNLOCK_EVENTS_MAX_OFFSET:
            return rows, (
                f"the console serves unlock requests only up to offset {UNLOCK_EVENTS_MAX_OFFSET}; "
                f"{len(rows)} were gathered"
            )
        size = UNLOCK_EVENTS_PAGE_SIZE
        if total is not None:
            size = min(size, total - len(rows))
        params: dict[str, Any] = {"offset": len(rows), "limit": size}
        if policy is not None and not rows:
            del params["offset"]  # a requested count sends only what the caller gave
        if policy is not None:
            policy.record_sent(size)
        page = await client.get(path, key=key, params=params)
        pages += 1
        items = _as_list(page, "door lock unlock events")
        if not items:
            return rows, None
        ids = [_request_identity(item) for item in items]
        if all(identity in seen for identity in ids):
            return rows, (
                f"page {pages} at offset {len(rows)} was a repeated page (only unlock requests "
                "already returned): the console ignores offset, so later requests cannot be "
                "reached by paging"
            )
        seen.update(ids)
        rows.extend(items)
        if max_pages is not None and pages >= max_pages and (total is None or len(rows) < total):
            return rows, f"page cap of {max_pages} reached (UNIFI_PAGINATE_MAX_PAGES)"
    return rows, None


async def list_door_lock_unlock_events(
    client: UniFiClient,
    registry: Registry,
    host: str,
    lock_id: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
) -> Any:
    """List a door lock's remote unlock requests, newest first (``.../unlock/events``).

    With neither offset nor limit, the lock id is checked against GET /locks first and
    every page is drained ({result, _count}). An offset selects one native page through the
    shared offset collector (the bare array as sent). A limit gathers that many requests in
    pages of at most the route maximum, sending no ``offset`` on the first request, and
    returns {data, _count, _pageSize}. With an offset or a limit the id is checked only when
    the read fails or returns no requests, so a good read sends nothing else and an
    unlisted id still fails naming the valid locks.
    """
    validate_pagination(page_size=limit, offset=offset, names={"page_size": "limit"})
    path_segment(lock_id, "lock_id")
    key, host_id = await _resolve(registry, host)
    if offset is None and limit is None:
        listed_id = await _require_known_lock(client, host_id, key, host, lock_id)
        path = _private(host_id, f"/locks/{path_segment(listed_id, 'lock_id')}/unlock/events")
        events, stopped = await with_upstream_hint(
            _gather_unlock_events(client, path, key, None), _LOCKS_HINT
        )
        drained: dict[str, Any] = {"result": events, "_count": len(events)}
        if stopped is None:
            return drained
        return mark_incomplete(drained, {"incomplete": True, "incompleteReason": stopped})

    async def read(listed: str) -> tuple[Any, list[Any], str | None]:
        path = _private(host_id, f"/locks/{path_segment(listed, 'lock_id')}/unlock/events")
        if offset is not None:
            collected = await collect_offset(client, path, key=key, offset=offset, limit=limit)
            items = _as_list(collected["items"], "door lock unlock events")
            return bare_page(collected) or collected.get("raw"), items, None
        policy = PageSizeBatch(limit, UNLOCK_EVENTS_PAGE_SIZE, UNLOCK_EVENTS_PAGE_SIZE)
        rows, stopped = await _gather_unlock_events(client, path, key, limit, policy)
        return policy, rows, stopped

    error: UniFiConnectionError | None = None
    page: Any = None
    events = []
    stopped = None
    try:
        page, events, stopped = await with_upstream_hint(read(lock_id), _LOCKS_HINT)
    except UniFiConnectionError as exc:
        error = exc
    if error is not None or not events:
        # Check the id against GET /locks: an unlisted id fails naming the valid locks. A
        # listed id the caller spelled differently (letter case) is read again under the
        # console's own spelling, as the unpaged path reads it.
        listed_id = await _require_known_lock(client, host_id, key, host, lock_id)
        if listed_id != lock_id:
            page, events, stopped = await with_upstream_hint(read(listed_id), _LOCKS_HINT)
        elif error is not None:
            raise error
    if offset is not None:
        # One native page, exactly as the console sent it.
        return page
    gathered: dict[str, Any] = {"data": events, "_count": len(events)}
    gathered = with_context(gathered, cast(PageSizeBatch, page).context(returned=len(events)))
    if stopped is None:
        return gathered
    return mark_incomplete(gathered, {"incomplete": True, "incompleteReason": stopped})


# Module-level aliases: the registered tools below shadow these names inside register().
_get_door_lock = get_door_lock
_list_door_lock_unlock_events = list_door_lock_unlock_events
