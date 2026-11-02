"""Record identity, repeat comparison and paging stop decisions shared by pagination adapters.

``client.paginate_offset`` and the shared ``tools/_pagination`` loop both call
:func:`page_stop` for every page, so the two drains cannot disagree on when a repeated,
already-returned or misplaced page ends the drain.
"""

from dataclasses import dataclass
from typing import Any


def record_identity(record: Any) -> tuple[str, str | int] | None:
    """Read the first usable upstream identity without changing the record."""
    if isinstance(record, dict):
        for key in ("id", "_id", "uuid", "mac"):
            value = record.get(key)
            if (isinstance(value, str) and value) or (
                isinstance(value, int) and not isinstance(value, bool)
            ):
                return key, value
    return None


def identified_page(rows: list[Any]) -> bool:
    """Whether every row has a usable identity."""
    return bool(rows) and all(record_identity(row) is not None for row in rows)


def page_is_repeat(rows: list[Any], previous: list[Any]) -> bool:
    """Recognize equal and prefix pages, even when live fields have changed."""
    if not rows or len(rows) > len(previous):
        return False
    if identified_page(rows) and identified_page(previous):
        return [record_identity(row) for row in rows] == [
            record_identity(row) for row in previous[: len(rows)]
        ]
    return rows == previous[: len(rows)]


def unique_page_rows(
    rows: list[Any], gathered: list[Any], seen: set[tuple[str, str | int] | None] | None = None
) -> list[Any]:
    """Drop the rows of an identified page that an EARLIER page already returned.

    ``seen`` holds the identities of earlier pages and gains this page's identities only
    after the page is compared, so two rows of the same page are never dropped as
    duplicates of each other: the upstream page passes through verbatim.
    """
    if seen is None:
        seen = {record_identity(row) for row in gathered}
    identities = [record_identity(row) for row in rows]
    result = (
        [row for row, identity in zip(rows, identities, strict=True) if identity not in seen]
        if identified_page(rows)
        else rows
    )
    seen.update(identities)
    return result


def nothing_new(rows: list[Any], seen: set[tuple[str, str | int] | None]) -> bool:
    """Whether an identified, nonempty page holds only identities earlier pages returned."""
    return identified_page(rows) and all(record_identity(row) in seen for row in rows)


class PageHistory:
    """Index identified candidates; preserve exact equality for unidentified pages."""

    def __init__(self) -> None:
        self.pages: list[list[Any]] = []
        self.offsets: list[int | None] = []
        self._identified: dict[tuple[str, str | int] | None, list[int]] = {}
        self._unidentified: list[int] = []

    def match(self, rows: list[Any]) -> int | None:
        """Index of the earliest gathered page that ``rows`` equals or prefixes."""
        if not rows:
            return None
        if not identified_page(rows):
            candidates: list[int] = list(range(len(self.pages)))
        else:
            candidates = sorted(
                self._identified.get(record_identity(rows[0]), []) + self._unidentified
            )
        return next(
            (index for index in candidates if page_is_repeat(rows, self.pages[index])), None
        )

    def repeated(self, rows: list[Any]) -> bool:
        """Compare only possible identities, or exact body equality without IDs."""
        return self.match(rows) is not None

    def add(self, rows: list[Any], offset: int | None = None) -> None:
        """Retain each physical page verbatim for prefix and identity comparisons."""
        index = len(self.pages)
        self.pages.append(rows)
        self.offsets.append(offset)
        if identified_page(rows):
            self._identified.setdefault(record_identity(rows[0]), []).append(index)
        else:
            self._unidentified.append(index)


def repeat_paging_evidence(
    response: Any, *, total: int | None, gathered: int, answered_page: int
) -> str | None:
    """Read all affirmative outstanding evidence before inferring an unpaged endpoint.

    Returns a clause with its own subject ("it declared ...", "its continuation ... is still
    non-terminal"), so a reason reads "... although <clause>"
    (REPEATED-OVERSIZED-TOTAL wording), or None when nothing declares more records.
    """
    if total is not None and gathered < total:
        field = "total"
        for name in ("totalCount", "total", "total_element_count"):
            # Names the envelope field that declared the total; no record is filtered.
            if isinstance(response, dict) and response.get(name) == total:
                field = name
                break
        return f"it declared {field} {total} ({gathered} of {total} records gathered)"
    if not isinstance(response, dict):
        return None
    answered = response.get("page_number")
    if isinstance(answered, int) and not isinstance(answered, bool) and answered >= 0:
        answered_page = answered
    pages = response.get("total_page_count")
    if isinstance(pages, int) and not isinstance(pages, bool) and pages > answered_page + 1:
        return f"its total_page_count {pages} still has outstanding pages"
    if response.get("has_next") is True:
        return "its continuation has_next is still non-terminal"
    if response.get("nextToken") not in (None, ""):
        return "its continuation nextToken is still non-terminal"
    meta = response.get("meta")
    if isinstance(meta, dict) and (
        meta.get("hasMore") is True or meta.get("nextCursor") not in (None, "")
    ):
        return "its continuation meta.hasMore/nextCursor is still non-terminal"
    links = response.get("links")
    if isinstance(links, dict) and links.get("next") not in (None, ""):
        return "its continuation links.next is still non-terminal"
    return None


@dataclass(frozen=True)
class PageStop:
    """A page that ends the drain: complete (``reason`` None) or aborted with ``reason``."""

    reason: str | None


def page_stop(
    rows: list[Any],
    response: Any,
    *,
    family: str,
    history: PageHistory,
    seen: set[tuple[str, str | int] | None],
    page: int,
    position: int,
    sent: int | None,
    total: int | None,
    supplied: int,
    kept: int,
    first_oversized: bool,
    record_offset: int | None = None,
    requested: int | None = None,
) -> PageStop | None:
    """Decide whether one fetched page ends the drain, before any of it is appended.

    ``page`` is the 1-based count of pages answered (this one included), ``position`` the
    wire position sent (``offset`` for the offset family, ``pageNumber`` for the number
    family), ``supplied`` the start offset plus the records gathered once, and ``kept``
    the records gathered once. ``seen`` holds the identities of earlier pages and
    ``record_offset`` the record offset of this page for the number family. Returns None
    when the page is appended. A repeated page, or an identified page that returns only
    records earlier pages returned, is complete only when it exceeded the sent size and
    nothing shows more records exist (the endpoint is unpaged); otherwise it aborts with a
    reason naming the evidence. Only the offset and number families can stop on a page
    of already-returned records or on a second oversized page without identities.
    """
    matched = history.match(rows)
    stale = matched is None and family in {"offset", "number"} and nothing_new(rows, seen)
    if matched is not None or stale:
        evidence = repeat_paging_evidence(
            response,
            total=total,
            gathered=supplied,
            answered_page=position if family == "number" else page - 1,
        )
        oversized = (sent is not None and len(rows) > sent) or (
            family == "number" and first_oversized
        )
        if oversized and evidence is None:
            return PageStop(None)
        if family == "offset" and matched is not None:
            origin = history.offsets[matched] or 0
            reason = (
                f"page {page} at offset {position} returned the records already returned "
                f"at offsets {origin}-{origin + len(rows) - 1}: the upstream ignores offset, "
                "so records past the first page cannot be reached by paging"
            )
        elif family == "offset":
            reason = (
                f"page {page} at offset {position} returned only records already returned "
                "on earlier pages: the upstream ignores offset, so records past the first "
                "page cannot be reached by paging"
            )
        elif matched is not None:
            reason = (
                f"repeated page {position - 1}: the upstream answered the same page again; "
                f"the controller returned the same entries again on page {position}"
            )
        else:
            reason = (
                f"page {position} returned only entries earlier pages already returned: "
                "the controller did not page by pageNumber"
            )
        if family == "offset" and requested is not None:
            reason += f" ({kept} of {requested} requested records gathered)"
        if family == "offset" and matched is not None and len(rows) == len(history.pages[matched]):
            reason += "; repeated page: the server returned the same page again"
        if evidence is not None:
            reason += f" although {evidence}"
        elif total is not None:
            reason += f" ({kept} of {total} records gathered)"
        return PageStop(reason)
    if (
        rows
        and len(history.pages) == 1
        and family in {"offset", "number"}
        and first_oversized
        and sent is not None
        and len(rows) > sent
        and (not identified_page(history.pages[0]) or not identified_page(rows))
    ):
        # The number family sends pageNumber and pageSize: name the page number, the record
        # offset it starts at and the size control actually sent.
        where = (
            f"at offset {position}"
            if family == "offset"
            else f"(pageNumber {position}, record offset {record_offset})"
        )
        control = "limit" if family == "offset" else "pageSize"
        return PageStop(
            f"page {page} {where} returned {len(rows)} rows for a sent {control} "
            f"of {sent}, after page 1 also exceeded its sent {control}; "
            "these records carry no id, _id, uuid or mac field, so a server that ignores "
            "offset cannot be told apart from new records; "
            f"returned page 1 ({kept} records) only"
        )
    if (
        family == "offset"
        and rows
        and position > 0
        and isinstance(total, int)
        and not isinstance(total, bool)
        and position + len(rows) > total
    ):
        # No more than total - offset records can follow an offset; a larger page
        # proves the upstream ignores offset, so its records cannot be placed.
        return PageStop(
            f"page {page} at offset {position} returned {len(rows)} rows although the "
            f"upstream declared totalCount {total}, so at most {max(0, total - position)} "
            f"records follow offset {position}: the upstream ignores offset, so records "
            f"cannot be placed by offset ({kept} records gathered)"
        )
    return None
