"""Logical windows for page-number lists asked for both ``page`` and ``page_size``.

The Network v2 query POSTs (the system log, the sites overview, the Teleport invitation
history) page with a zero-based ``pageNumber`` and a ``pageSize`` in the JSON body. A
console may clamp ``pageSize`` or ignore it, so its own page size ``e`` need not equal the
size asked for. With ``page_size = N``, ``page`` is a zero-based window index counted in
units of N: the call returns the records ``[page*N, page*N + N)`` of the ordered result,
gathered across as many console pages as needed and trimmed at record level, never one
console page as the console sent it.

How a window is gathered:

1. Request console page ``page`` at ``pageSize = N`` (the probe). Page 0 needs nothing
   else: its records start at record 0. A page is final only on affirmative evidence (a
   page count or declared total reached, or an empty page), never because it is shorter
   than the size sent: a short page 0 without that evidence means the console clamps
   ``pageSize``, so the window continues at ``e = k`` until it is full or an empty page
   ends the collection, as the page-number drain does. When page 1 then repeats the short
   page 0 (the console ignores ``pageNumber``), the repeat is no larger than the size sent
   for it, so it is an abort that keeps the records of page 0: a console that clamps
   ``pageSize`` at ``k`` and ignores ``pageNumber`` answers exactly so for a longer
   collection, and a short page that equals the console clamp is not evidence of the end.
   A repeat after a full page 0 is an abort too.
2. Establish ``e`` from the probe: a page that is not the last one (``total_page_count``
   says more follow) holds exactly ``e`` records; a last page with a known
   ``total_element_count`` fixes ``e = (total - k) / page``. An empty probe whose total
   proves the window lies past the end returns an empty window at once.
3. Otherwise, request console page 0 once (the discovery request): when the probe held
   records, page 0 is full, so ``e`` is its record count. When the probe was empty, a
   page 0 of at most N records proves the window empty, and a longer one gives ``e``.
4. Gather console pages ``page*N // e`` onwards at ``pageSize = e``, reusing the probe and
   discovery pages, stop once the window is full or the last page is reached, and never
   request a page the window does not intersect.

A console that ignores ``pageNumber`` answers page 0 with the probe's records again. When
that repeated page is larger than the size sent and nothing shows more records exist (no
declared total above it, no page count or continuation beyond it), the endpoint is unpaged:
the page is the whole collection and the window is selected from it, complete. Otherwise
the repeat is reported incomplete.

Every request (probe, discovery, gather) counts against one ``max_pages`` budget. A call
that cannot establish ``e`` or prove its window, reaches the budget before the window is
full, or meets a repeated page, an early empty page, a page answered under another number
or a later page without a records array is marked ``incomplete`` with the reason; it never
returns a window of the wrong size or at the wrong offset. ``nextPage`` is ``page + 1``
when records exist past the window, or when the total is unknown and the window came back
full; calling again with it and the same ``page_size`` returns the next contiguous window.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from .._paging_identity import page_is_repeat, repeat_paging_evidence
from ..client import is_dry_run_preview, page_envelope

#: Console paging fields of a number-family page. A logical window is not one console
#: page, so the window result drops them; ``total_element_count`` is the upstream total
#: of the whole collection and stays.
CONSOLE_PAGE_KEYS = frozenset({"page_number", "total_page_count"})


def _count(value: Any) -> int | None:
    """A non-negative JSON integer, else None (a boolean is not a count)."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


@dataclass
class _Page:
    """One console page: its records and the paging facts its envelope declares."""

    number: int
    rows: list[Any]
    declared_pages: int | None
    total: int | None
    answered: Any

    def terminal(self, size: int | None) -> bool | None:
        """Whether this is the last console page (None when nothing proves either)."""
        if self.declared_pages is not None:
            return self.number + 1 >= self.declared_pages
        if self.total is not None and (size is not None or self.number == 0):
            return self.number * (size or 0) + len(self.rows) >= self.total
        if not self.rows:
            return True
        # A page shorter than the size sent is not final: the console may clamp pageSize.
        return None


def _records(response: Any, array_field: str) -> list[Any] | None:
    if isinstance(response, list):
        return response
    rows = response.get(array_field) if isinstance(response, dict) else None
    return rows if isinstance(rows, list) else None


def _page(response: Any, number: int, rows: list[Any]) -> _Page:
    if not isinstance(response, dict):
        return _Page(number, rows, None, None, None)
    total = next(
        (
            found
            for field in ("total_element_count", "totalCount", "total")
            if (found := _count(response.get(field))) is not None
        ),
        None,
    )
    return _Page(
        number,
        rows,
        _count(response.get("total_page_count")),
        total,
        response.get("page_number"),
    )


async def collect_number_window(
    fetch: Callable[[dict[str, Any]], Awaitable[Any]],
    *,
    page: int,
    page_size: int,
    max_pages: int | None,
    array_field: str = "data",
    keep_console_keys: bool = False,
) -> dict[str, Any]:
    """The records ``[page*page_size, page*page_size + page_size)`` of a page-number list.

    ``fetch`` sends one request with the given ``{"pageNumber", "pageSize"}`` controls.
    Returns ``{"raw": response}`` when the probe is a dry-run preview, not a JSON object or
    array, or an object without the records array (the caller decides how to report it),
    and when one bare array is the whole window.
    Otherwise returns ``{items, envelope, totalCount, pages, trimmed, nextPage, incomplete,
    incompleteReason, _pageSize}`` for :func:`~._pagination.mark_incomplete`, where
    ``_pageSize`` is ``{requested, sent, effective, returned}``, ``sent`` lists every wire
    size in request order and ``effective`` is the console page size, or None when the call
    did not need to establish it. ``keep_console_keys`` keeps the probe's
    :data:`CONSOLE_PAGE_KEYS` in the envelope, as a drain from page 0 returns its first
    page's envelope.
    """
    size, start = page_size, page * page_size
    sent: list[int] = []
    reason: str | None = None
    seen: list[list[Any]] = []

    def capped() -> bool:
        nonlocal reason
        if max_pages is not None and len(sent) >= max_pages:
            reason = f"UNIFI_PAGINATE_MAX_PAGES page cap of {max_pages} reached"
            return True
        return False

    async def request(
        number: int, wire: int, *, discovery: bool = False
    ) -> tuple[Any, _Page | None]:
        """One console page; on a fault sets ``reason`` and returns no page.

        The discovery request of page 0 returns a repeat of the probe as a page, so the
        caller can test it for an unpaged endpoint.
        """
        nonlocal reason
        sent.append(wire)
        response = await fetch({"pageNumber": number, "pageSize": wire})
        rows = None if is_dry_run_preview(response) else _records(response, array_field)
        if rows is None:
            return response, None
        found = _page(response, number, rows)
        if found.answered is not None and found.answered != number:
            reason = (
                f"page {number} was answered as page {found.answered!r}; the window cannot "
                "be located"
            )
            return response, None
        if (
            rows
            and not discovery
            and any(
                page_is_repeat(rows, earlier) and page_is_repeat(earlier, rows) for earlier in seen
            )
        ):
            reason = (
                f"page {number} repeated the entries of an earlier page; the controller did "
                "not page by pageNumber, so the window cannot be located"
            )
            return response, None
        if rows:
            seen.append(rows)
        return response, found

    def result(
        items: list[Any],
        effective: int | None,
        total: int | None,
        more: bool,
        trimmed: bool,
    ) -> dict[str, Any]:
        return {
            "items": items,
            "envelope": envelope,
            "array_key": array_field,
            "totalCount": total,
            "pages": len(sent),
            "trimmed": trimmed,
            # A window that stopped short is resumed with the same page, not the next one.
            "nextPage": page + 1 if more and reason is None else None,
            "incomplete": reason is not None,
            "incompleteReason": reason,
            "_pageSize": {
                "requested": size,
                "sent": sent,
                "effective": effective,
                "returned": len(items),
            },
        }

    envelope: dict[str, Any] = {}
    if capped():
        return result([], None, None, False, False)
    response, probe = await request(page, size)
    if probe is None and reason is None:
        return {"raw": response}
    envelope = page_envelope(
        response, array_field, extra=frozenset() if keep_console_keys else CONSOLE_PAGE_KEYS
    )
    if probe is None:
        return result([], None, None, False, False)
    cache = {page: probe}
    total = probe.total
    k = len(probe.rows)
    effective: int | None = None
    empty_from: int | None = None
    if page == 0:
        # Page 0 starts at record 0 whatever the console page size. A page that is not
        # proven last, short or not, gives the console page size: continue at that size.
        if probe.terminal(size) is True:
            total = k if total is None else total
        elif k:
            effective = k
    elif k and probe.terminal(None) is False:
        effective = k
    elif k and total is not None and probe.declared_pages is not None:
        # The last page at console size e: total = page*e + k, with k <= e.
        e, remainder = divmod(total - k, page)
        if not remainder and e >= k:
            effective = e
    elif not k and total is not None and total <= start:
        return result([], None, total, False, False)

    if page and effective is None and reason is None:
        if capped():
            return result([], None, total, False, False)
        discovered, first = await request(0, size, discovery=True)
        if first is None:
            reason = reason or "page 0 came back without a records array"
            return result([], None, total, False, False)
        cache[0] = first
        total = first.total if total is None else total
        k0 = len(first.rows)
        if k and page_is_repeat(probe.rows, first.rows) and page_is_repeat(first.rows, probe.rows):
            evidence = repeat_paging_evidence(
                discovered, total=total, gathered=k0, answered_page=0
            ) or repeat_paging_evidence(response, total=total, gathered=k0, answered_page=page)
            if k > size and evidence is None:
                # The same oversized page for page 0 and the probe, with nothing declaring
                # more, is the whole unpaged collection: select the window from it.
                items = first.rows[start : start + size]
                trimmed = k0 > start + size
                return result(items, k0, k0, trimmed, trimmed)
            reason = (
                "page 0 repeated the entries of an earlier page; the controller did not page "
                "by pageNumber, so the window cannot be located"
            )
            return result([], None, total, False, False)
        if k:
            if not k0:
                reason = f"page 0 came back empty while page {page} held {k} entries"
                return result([], None, total, False, False)
            # A later page holds records, so page 0 is a full console page.
            effective = k0
        elif k0 <= size:
            # A console page of at most N records puts page `page` at or before record
            # page*N; it came back empty, so no record exists at or past the window start.
            return result([], k0 or None, total if total is not None else k0, False, False)
        else:
            # The console ignores pageSize; pages at and past the empty probe hold nothing.
            effective, empty_from = k0, page

    if k and effective is not None and probe.terminal(effective) is True and total is None:
        total = page * effective + k
    if total is not None and start >= total:
        if len(sent) == 1 and isinstance(response, list):
            return {"raw": response}
        return result([], effective, total, False, False)
    number, skip = divmod(start, effective) if effective else (0, start)
    rows: list[Any] = []
    last: bool | None = None
    while True:
        current = cache.get(number)
        if current is None and empty_from is not None and number >= empty_from:
            last = True
            break
        if current is None:
            if effective is None:
                reason = f"the console page size is unknown, so page {number} cannot be located"
                break
            if capped():
                break
            # Page 1 after a short page 0 may repeat it by record identity: tested below.
            short_zero = page == 0 and number == 1 and 0 < k < size
            _, current = await request(number, effective, discovery=short_zero)
            if current is None:
                reason = reason or f"page {number} came back without a records array"
                break
            total = current.total if total is None else total
            if (
                short_zero
                and page_is_repeat(current.rows, probe.rows)
                and page_is_repeat(probe.rows, current.rows)
            ):
                # The repeat is no larger than the size sent for it: a console that clamps
                # pageSize at k and ignores pageNumber answers exactly so for a longer
                # collection, so the short page 0 is not evidence of the end.
                reason = (
                    f"page {number} repeated the entries of an earlier page; the controller "
                    "did not page by pageNumber, so the window cannot be located"
                )
                break
        rows.extend(current.rows)
        last = current.terminal(effective)
        if last is True:
            break
        if len(rows) >= skip + size:
            break
        if not current.rows:
            reason = f"the controller returned an empty page {number} before declared completion"
            break
        number += 1
    items = rows[skip : skip + size]
    trimmed = len(rows) > skip + size
    more = trimmed or last is False or (last is None and len(items) == size)
    if total is not None and start + size >= total:
        # A declared total at or inside the window end leaves no record past it, whatever
        # a page count says.
        more = False
    if (
        reason is None
        and page == 0
        and isinstance(response, list)
        and not more
        and rows == response
    ):
        # One bare page that is the whole window (any later page fetched came back
        # empty): returned as the console sent it.
        return {"raw": response}
    return result(items, effective, total, more, trimmed)
