"""Shared list-drain helpers so list tools return *complete* result sets.

Background — the bug these fix
------------------------------
Every list tool used to issue a single ``client.get()`` and return page one.
For a cursor endpoint it surfaced the ``nextToken``; for an offset endpoint it
surfaced ``totalCount``. Either way the *caller* was expected to notice and
follow up. On a single-console deployment that never crossed a page boundary this
looked complete forever — and silently truncated the moment it pointed at a
large deployment, which is the whole reason this server exists.

These helpers make ``list_*`` tools drain *all* pages by default while keeping
manual paging available and never masking a capped drain as complete.

Two pagination families, one contract
-------------------------------------
* ``collect_cursor`` — Site Manager ``/v1/*`` endpoints that page
  with an opaque ``nextToken`` cursor.
* ``collect_offset`` — Network *Integration* proxy endpoints that page with
  ``offset``/``limit`` and report ``totalCount``.
* Default drains delegate to the client paging adapters; requested totals use
  ``collect_batch`` across every pagination family.
* Requested sizes are totals gathered in effective-size batches; defaults drain all.

Explicit-paging contract (deliberate, documented in every wired tool)
---------------------------------------------------------------------
* Default (no paging arg): auto-drain every page and return the complete set.
* Native manual paging — a raw ``page_token`` for cursor tools, an ``offset`` for
  offset tools, or ``page`` without a size for page-number tools — returns ONE page starting
  at that position and surfaces the continuation marker (``nextToken`` /
  ``totalCount`` / ``nextPage``). Only the paging parameters the caller gave are
  sent. A page the upstream sent as a bare JSON array is returned as that array,
  unchanged, by every helper (:func:`bare_page`).

Incomplete results are never disguised
--------------------------------------
If a drain hits ``UNIFI_PAGINATE_MAX_PAGES`` (or a cursor stall), the pages
gathered so far are returned *with* ``incomplete=True`` and a human-readable
``incompleteReason``. A truncated result that looks complete is exactly the bug
being fixed, so truncation is always surfaced, never silent.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from inspect import getattr_static
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .._paging_identity import (
    PageHistory,
    page_is_repeat,
    page_stop,
    record_identity,
    unique_page_rows,
)
from ..client import (
    PaginationAbortedError,
    UniFiClient,
    UniFiConnectionError,
    describe_shape,
    is_dry_run_preview,
    page_envelope,
    page_has_more,
    page_has_next_link,
    page_total,
    read_page_token,
)
from ..config import APIKeyConfig
from ._continuation import decode_continuation, encode_continuation
from ._keys import with_context

# Drain page size: the published Network spec allows limit up to 200 on most offset
# lists (1000 on a few), and larger pages mean fewer round-trips for a full drain, so
# 200 is efficient for default drains. Requested totals are gathered across pages
# whose wire size is bounded by the route maximum and read back from the console.
DRAIN_PAGE_SIZE = 200


# Measured 2026-10-26: page-size-evidence-2026-10-26.json (Network 11.0.97).
NETWORK_INTEGRATION_MAX_LIMIT = 200
HOTSPOT_VOUCHERS_MAX_LIMIT = 1000
RECOGNITION_MAX_PAGE_SIZE = 100
# tests/fixtures/openapi/carrier-fabric-1.0.0.json:54 (/subscribers limit).
CARRIER_SUBSCRIBERS_MAX_LIMIT = 500
# tests/fixtures/openapi/mobility-1.0.0.json:77 (list limit).
MOBILITY_MAX_LIMIT = 200


def followed_page_width(response: Any, number: int, sent: Any, rows: int) -> int | None:
    """The native width proven by numbered page ``number`` when another page follows it.

    A followed page is full: at least the sent size proves its own width. A shorter one
    is a downward clamp unless it can also be the final data page at some wider width that
    a stale continuation still follows (at most one more, empty, page); a page count
    beyond that, or a declared total that no wider width ends on this page, proves it.
    """
    if rows < 1 or not isinstance(sent, int) or isinstance(sent, bool) or sent < 1:
        return None
    if rows >= sent:
        return rows
    pages = response.get("total_page_count") if isinstance(response, dict) else None
    if isinstance(pages, int) and not isinstance(pages, bool) and pages > number + 2:
        return rows
    total = response.get("total_element_count") if isinstance(response, dict) else None
    if total is None:
        total = page_total(response, "pagination")
    if not isinstance(total, int) or isinstance(total, bool):
        return None
    rest = total - rows
    if number < 1 or rest < 0 or rest % number or rest // number <= rows:
        return rows
    return None


def validate_pagination(
    *,
    page: Any = None,
    page_size: Any = None,
    offset: Any = None,
    zero_page: Any = None,
    names: Mapping[str, str] | None = None,
) -> None:
    """Reject meaningless positions and sizes before any upstream request.

    ``page_size`` is a count (1 or more), ``page`` a one-based page, ``zero_page`` a
    zero-based page and ``offset`` a record offset (0 or more). ``names`` maps each of
    those keywords to the argument the caller actually passed (``{"page_size": "limit"}``),
    so every message names an argument the caller can fix. There is no upper bound.
    """
    named = {"page_size": "page_size", "page": "page", "offset": "offset", "zero_page": "page"}
    named.update(names or {})

    def invalid(value: Any, minimum: int) -> bool:
        return value is not None and (
            not isinstance(value, int) or isinstance(value, bool) or value < minimum
        )

    if invalid(page_size, 1):
        name = named["page_size"]
        raise ValueError(
            f"{name} must be a positive integer (1 or more); got {page_size}. "
            f"Omit {name} to read the whole collection."
        )
    if invalid(page, 1):
        raise ValueError(f"{named['page']} is 1-based and must be 1 or more; got {page}.")
    if invalid(zero_page, 0):
        raise ValueError(
            f"{named['zero_page']} is zero-based and must be 0 or more; got {zero_page}."
        )
    if invalid(offset, 0):
        raise ValueError(f"{named['offset']} must be 0 or more; got {offset}.")


@dataclass
class PageSizeBatch:
    """Requested total, bounded wire size, and console effective-size read-back."""

    requested: int | None
    known_max: int | None = None
    default_size: int | None = DRAIN_PAGE_SIZE
    sent: int | None = None
    effective: int | None = None
    sent_sizes: list[int | None] = field(default_factory=list)

    def __post_init__(self) -> None:
        size = self.requested if self.requested is not None else self.default_size
        self.sent = min(size, self.known_max) if size is not None and self.known_max else size
        self.effective = self.sent

    def record_sent(self, size: int | None) -> None:
        """Record the actual wire size, separately from the observed console size."""
        self.sent_sizes.append(size)

    def observe(
        self, response: Any, rows: list[Any], family: str, *, first: bool, requested_page: int = 0
    ) -> None:
        effective = None
        if isinstance(response, dict):
            effective = response.get("limit")
            if family == "carrier":
                meta = response.get("meta")
                if meta is not None and not isinstance(meta, dict):
                    raise UniFiConnectionError(
                        "Unexpected response shape: 'meta' must be an object"
                    )
                effective = (meta or {}).get("limit")
            if family == "links" and page_has_next_link(response, "pagination"):
                values = parse_qs(urlsplit(response["links"]["next"]).query).get("pageSize", [])
                if values and values[0].isdigit():
                    effective = int(values[0])
        if isinstance(effective, int) and not isinstance(effective, bool) and effective > 0:
            self.effective = effective
        elif first and rows:
            more = False
            if isinstance(response, dict):
                if family == "cursor":
                    more = bool(read_page_token(response, "nextToken", "pagination"))
                elif family == "carrier":
                    more = page_has_more(response.get("meta") or {}, "pagination")
                elif family == "links":
                    more = page_has_next_link(response, "pagination")
                elif family == "number":
                    # Only a page zero followed by another measures the native size:
                    # a short terminal page proves nothing, and an oversized body can
                    # instead be unpaged. Without any continuation evidence a page no
                    # larger than the sent size still measures a downward clamp.
                    pages = response.get("total_page_count")
                    total = response.get("total_element_count")
                    if total is None:
                        total = page_total(response, "pagination")
                    has_next = response.get("has_next")
                    if isinstance(has_next, bool):
                        followed: bool | None = has_next
                    elif isinstance(pages, int) and not isinstance(pages, bool):
                        followed = pages > 1
                    elif total is not None:
                        followed = total > len(rows)
                    else:
                        followed = None
                    more = requested_page == 0 and (
                        len(rows) <= (self.sent or len(rows)) if followed is None else followed
                    )
                else:
                    total = page_total(response, "pagination")
                    more = total is None or total > len(rows)
            if more:
                self.effective = (
                    len(rows)
                    if family == "number"
                    else min(self.effective, len(rows))
                    if self.effective is not None
                    else len(rows)
                )

    def done(self, count: int) -> bool:
        return self.requested is not None and count >= self.requested

    def context(self, returned: int | None = None) -> dict[str, Any]:
        if self.requested is None:
            return {}
        metadata: dict[str, Any] = {
            "requested": self.requested,
            "sent": list(self.sent_sizes),
            "effective": self.effective,
        }
        if returned is not None:
            metadata["returned"] = returned
        return {"_pageSize": metadata}


def cursor_continuation(value: str | None, family: str) -> tuple[str | None, int | None]:
    """Decode our additive resume value without altering a native cursor string."""
    decoded = decode_continuation(value)
    if decoded is None or isinstance(decoded, str):
        return decoded, None
    token_key, size_key = ("cursor", "limit") if family == "carrier" else ("pageToken", "pageSize")
    argument = "cursor" if family == "carrier" else "page_token"
    if set(decoded) != {token_key, size_key}:
        raise ValueError(
            f"Use the returned opaque _continuation string for {argument} "
            f"with {token_key!r} and {size_key!r}, "
            "or a native cursor string for a manual page"
        )
    token, size = decoded[token_key], decoded[size_key]
    if (
        not isinstance(token, str)
        or not token
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
    ):
        raise ValueError(
            f"_continuation token {token_key} must be a nonempty string and "
            f"continuation {size_key} a positive integer; reuse the returned string "
            f"for {argument}"
        )
    return token, size


def physical_end(page: list[Any], kept: list[Any]) -> int:
    """The position in ``page`` just past its last row in ``kept`` (an ordered subsequence)."""
    index = 0
    for position, row in enumerate(page):
        if index < len(kept) and row is kept[index]:
            index += 1
            if index == len(kept):
                return position + 1
    return len(page)


async def collect_batch(
    fetch: Callable[[dict[str, Any]], Awaitable[Any]],
    *,
    requested: int | None,
    known_max: int | None = None,
    default_size: int | None = DRAIN_PAGE_SIZE,
    family: str = "number",
    array_field: str = "data",
    start: int = 0,
    token: str | None = None,
    max_pages: int | None = None,
    strict_total: bool = False,
    allow_unpaged: bool = False,
    path: str = "pagination",
    omit_initial_offset: bool = True,
    bare_single_page: bool = False,
    preserve_bare: bool = False,
) -> dict[str, Any]:
    """Gather requested records using echoed limits, links, totals and cursors.

    Offset advances by rows returned and exposes the first unreturned offset.
    Opaque-cursor requests keep their original wire size, including the final
    page: a native token may encode a page index tied to that size. Page-number and links
    APIs keep their effective size and return the whole final page, since their
    continuation cannot represent a position within it. Encoded cursor resumes
    retain the original wire size even when the logical requested count changes.
    Requested totals have no implicit cap, timeout or retry.
    """
    validate_pagination(page_size=requested, names={"page_size": "page_size"})
    validate_pagination(page_size=default_size, names={"page_size": "page_size"})
    validate_pagination(offset=start, names={"offset": "offset"})
    token, stored_size = cursor_continuation(token, family)
    batch = PageSizeBatch(requested, known_max, default_size)
    if stored_size is not None:
        batch.sent = batch.effective = stored_size
    rows: list[Any] = []
    gathered_identities: set[tuple[str, str | int] | None] = set()
    history = PageHistory()
    seen_rows = history.pages
    seen_tokens: set[str] = {token} if token is not None else set()
    number, pages = start, 0
    envelope: dict[str, Any] = {}
    array_key: str | None = array_field
    reason = None
    total = None
    last_meta = None
    trimmed = False
    first_oversized = False
    number_origin = start if family == "offset" else None
    number_wire_size = batch.sent
    consumed = 0
    while True:
        controls: dict[str, Any] = {}
        size_key = "limit" if family in {"offset", "carrier"} else "pageSize"
        size = (
            number_wire_size
            if family == "number"
            else batch.sent
            if family in {"cursor", "carrier"}
            else batch.effective
        )
        if size is not None:
            controls[size_key] = (
                min(size, requested - len(rows))
                if requested is not None and family == "offset"
                else size
            )
        if family in {"offset", "number", "links"}:
            controls[{"offset": "offset", "number": "pageNumber", "links": "page"}[family]] = number
        elif token is not None:
            controls["cursor" if family == "carrier" else "nextToken"] = token
        if (
            family == "offset"
            and requested is not None
            and pages == 0
            and start == 0
            and omit_initial_offset
        ):
            controls.pop("offset", None)
        batch.record_sent(controls.get(size_key))
        response = await fetch(controls)
        if is_dry_run_preview(response) or not isinstance(response, (dict, list)):
            if pages:
                reason = (
                    f"page {number} came back without a records array ({describe_shape(response)})"
                )
                break
            if family != "number" and not is_dry_run_preview(response):
                _page_items(response, array_field, path)
            return {"raw": response}
        if allow_unpaged and isinstance(response, list) and (requested is None or strict_total):
            return {"raw": response[:requested] if requested is not None else response}
        if (
            isinstance(response, dict)
            and not isinstance(response.get(array_field), list)
            and not strict_total
        ):
            if pages:
                reason = f"page {number} came back without a records array"
                break
            if family == "number":
                return {"raw": response}
            _page_items(response, array_field, path)
        if (
            not response
            and isinstance(response, list)
            and pages == 0
            and requested is None
            and family == "number"
        ):
            return {"raw": response}
        got = _page_items(response, array_field, path)
        pages += 1
        if pages == 1:
            if requested is None and isinstance(response, list):
                array_key = None
            envelope = (
                _single_page_envelope(response, array_field)
                if requested is not None
                else page_envelope(
                    response,
                    array_field,
                    extra=frozenset({"meta"}) if family == "carrier" else frozenset(),
                )
            )
        if pages == 2 and requested is not None:
            # A requested total can span physical pages. First-page controls no
            # longer describe the aggregate; retain only its non-paging envelope.
            extra = frozenset({"meta"}) if family == "carrier" else frozenset()
            envelope = page_envelope(envelope, array_field, extra=extra)
        if isinstance(response, dict):
            observed_total = (
                response.get("total_element_count")
                if response.get("total_element_count") is not None
                else page_total(response, "pagination")
            )
            if observed_total is not None:
                total = observed_total
            declared_pages = response.get("total_page_count")
        else:
            declared_pages = None
        if strict_total:
            if total is not None and (
                not isinstance(total, int) or isinstance(total, bool) or total < 0
            ):
                raise UniFiConnectionError(
                    "Invalid total_element_count; cannot prove pagination completeness"
                )
            if declared_pages is None and total is not None and total <= len(got):
                declared_pages = 1
            if (
                not isinstance(declared_pages, int)
                or isinstance(declared_pages, bool)
                or declared_pages < 0
            ):
                raise UniFiConnectionError(
                    "Missing or invalid total_page_count; cannot prove pagination completeness"
                )
        answered = response.get("page_number") if isinstance(response, dict) else None
        if family == "number" and answered is not None and answered != number:
            reason = (
                f"page {number} was answered as page {answered!r}; "
                f"the controller answered page {answered!r} when asked for page {number}"
            )
            break
        stop = page_stop(
            got,
            response,
            family=family,
            history=history,
            seen=gathered_identities,
            page=pages,
            position=number,
            sent=controls.get(size_key),
            total=total,
            supplied=(start if family == "offset" else number_origin or 0) + len(rows),
            kept=len(rows),
            first_oversized=first_oversized,
            record_offset=(number_origin or 0) + sum(len(page) for page in seen_rows[:1]),
            requested=requested,
        )
        if stop is not None:
            reason = stop.reason
            if reason is None and family == "offset" and requested is not None and start > 0:
                # An oversized repeated page can establish an unpaged collection only
                # from offset zero. At a nonzero origin the server may have ignored
                # the original offset too, so these rows cannot establish the window.
                reason = (
                    f"page {pages} at offset {number} returned only records already returned; "
                    f"the upstream ignores offset, so requested origin {start} cannot be "
                    f"established ({len(rows)} of {requested} requested records gathered)"
                )
            break
        if pages == 1:
            first_oversized = controls.get(size_key) is not None and len(got) > controls[size_key]
        previous_size = batch.effective
        batch.observe(response, got, family, first=pages == 1, requested_page=number)
        if family == "number" and number_origin is None and start and not got:
            # An empty resumed page lies past the end whatever the physical width.
            number_origin = total if isinstance(total, int) and not isinstance(total, bool) else 0
        elif family == "number" and number_origin is None:
            echoed = response.get("limit") if isinstance(response, dict) else None
            positive_echo = isinstance(echoed, int) and not isinstance(echoed, bool) and echoed > 0
            followed = isinstance(response, dict) and (
                response.get("has_next") is True
                or (
                    response.get("has_next") is None
                    and isinstance(declared_pages, int)
                    and not isinstance(declared_pages, bool)
                    and number + 1 < declared_pages
                )
            )
            proven = (
                followed_page_width(response, number, controls.get("pageSize"), len(got))
                if followed
                else None
            )
            if start and not positive_echo and proven is not None:
                batch.effective = proven
            elif start and not positive_echo and len(got) != controls.get("pageSize"):
                terminal = isinstance(response, dict) and (
                    response.get("has_next") is False
                    or (
                        isinstance(declared_pages, int)
                        and not isinstance(declared_pages, bool)
                        and number + 1 >= declared_pages
                    )
                )
                tail_width = (
                    (total - len(got)) // start
                    if terminal
                    and got
                    and isinstance(total, int)
                    and not isinstance(total, bool)
                    and (total - len(got)) % start == 0
                    else None
                )
                if tail_width is not None and tail_width >= len(got) and tail_width > 0:
                    batch.effective = tail_width
                elif max_pages is not None and pages >= max_pages:
                    # The discovery request shares the drain's page budget.
                    rows.extend(unique_page_rows(got, rows, gathered_identities))
                    reason = (
                        f"UNIFI_PAGINATE_MAX_PAGES page cap of {max_pages} reached before "
                        f"page 0 could establish the page-{start} origin; returned the "
                        "original page only"
                    )
                    more = False
                    break
                else:
                    discovery_controls = {"pageNumber": 0}
                    if batch.sent is not None:
                        discovery_controls["pageSize"] = batch.sent
                    discovery = await fetch(discovery_controls)
                    discovery_rows = _page_items(discovery, array_field, path)
                    pages += 1
                    batch.record_sent(discovery_controls.get("pageSize"))
                    batch.observe(discovery, discovery_rows, family, first=True, requested_page=0)
                    discovery_echo = discovery.get("limit") if isinstance(discovery, dict) else None
                    discovery_total = (
                        discovery.get("total_element_count")
                        if isinstance(discovery, dict)
                        else None
                    )
                    if discovery_total is None:
                        discovery_total = page_total(discovery, path)
                    discovery_pages = (
                        discovery.get("total_page_count") if isinstance(discovery, dict) else None
                    )
                    discovery_more = isinstance(discovery, dict) and (
                        discovery.get("has_next") is True
                        or (
                            isinstance(discovery_pages, int)
                            and not isinstance(discovery_pages, bool)
                            and discovery_pages > 1
                        )
                        or (discovery_total is not None and discovery_total > len(discovery_rows))
                    )
                    positive_discovery_echo = (
                        isinstance(discovery_echo, int)
                        and not isinstance(discovery_echo, bool)
                        and discovery_echo > 0
                    )
                    ambiguous_width = (
                        batch.sent is not None
                        and len(discovery_rows) > batch.sent
                        and not positive_discovery_echo
                        and not discovery_more
                    )
                    if (
                        ambiguous_width
                        and discovery_rows
                        and not page_is_repeat(got, discovery_rows)
                    ):
                        # Distinct records on the resumed page prove that page zero
                        # was followed by another, so it was a full native page.
                        batch.effective = len(discovery_rows)
                        ambiguous_width = False
                    unresolved = (got and not discovery_rows) or ambiguous_width
                    if unresolved:
                        rows.extend(unique_page_rows(got, rows, gathered_identities))
                        batch.effective = None
                        reason = (
                            f"page 0 returned {len(discovery_rows)} records for sent size "
                            f"{batch.sent} without size or continuation evidence; physical "
                            f"width and page-{start} origin cannot be established; "
                            "returned the original page only; retry from page 0 "
                            "without a requested total and follow native pages"
                        )
                        more = False
                        break
            number_origin = start * (batch.effective or 0)
            number_wire_size = batch.effective
        # A deliberately smaller offset tail is not a new endpoint ceiling.
        if (
            family == "offset"
            and previous_size is not None
            and batch.effective == controls.get(size_key)
            and batch.effective is not None
            and batch.effective < previous_size
        ):
            batch.effective = previous_size
        # Never discard records behind an opaque cursor or page-only continuation.
        # Offset APIs alone can resume at an arbitrary returned-record boundary.
        fresh = unique_page_rows(got, rows, gathered_identities)
        consumed = len(got)
        need = requested - len(rows) if requested is not None and family == "offset" else None
        trimmed = need is not None and len(fresh) > need
        if need is not None and trimmed:
            fresh = fresh[:need]
            consumed = physical_end(got, fresh)
        rows.extend(fresh)
        if family == "cursor":
            nxt = read_page_token(response, "nextToken", "pagination")
            more = nxt is not None
        elif family == "carrier":
            meta = response.get("meta") if isinstance(response, dict) else None
            if meta is not None and not isinstance(meta, dict):
                raise UniFiConnectionError("meta must be an object")
            last_meta = meta
            more = page_has_more(meta or {}, "pagination")
            nxt = read_page_token(meta or {}, "nextCursor", "pagination")
            if more and nxt is None and not batch.done(len(rows)):
                reason = (
                    "meta.hasMore is true but meta.nextCursor is None; "
                    "the next page cannot be requested"
                )
                break
        elif family == "links":
            more = page_has_next_link(response, "pagination")
        elif (
            family == "number"
            and isinstance(response, dict)
            and isinstance(response.get("has_next"), bool)
        ):
            more = response["has_next"]
        elif (
            family == "number"
            and isinstance(declared_pages, int)
            and not isinstance(declared_pages, bool)
        ):
            more = number + 1 < declared_pages
        elif total is not None:
            supplied = number + len(got) if family == "offset" else len(rows) + (number_origin or 0)
            more = supplied < total
        elif family == "offset":
            echoed_size = response.get("limit") if isinstance(response, dict) else None
            if (
                isinstance(echoed_size, int)
                and not isinstance(echoed_size, bool)
                and echoed_size > 0
            ):
                more = bool(got) and len(got) >= echoed_size
            else:
                # Bare feeds without a size echo can silently clamp the requested
                # size. Only an empty page proves they are exhausted.
                more = bool(got)
            if bare_single_page and isinstance(response, list):
                more = False
        else:
            # A measured/requested size alone cannot prove the final page.
            # Without a total or explicit continuation, only an echoed limit
            # makes a nonempty short page affirmative completion evidence.
            echoed_size = response.get("limit") if isinstance(response, dict) else None
            more = bool(got) and (
                not isinstance(echoed_size, int)
                or isinstance(echoed_size, bool)
                or echoed_size <= 0
                or len(got) >= echoed_size
            )
        if trimmed:
            more = True  # The native page itself proves there are unreturned records.
        if family in {"cursor", "carrier"} and more and nxt in seen_tokens:
            reason = f"cursor cycle detected: {nxt!r} was already followed"
            break
        if batch.done(len(rows)):
            if family == "offset" and pages == 1 and more:
                # A single page cannot establish that the upstream honors offset.
                # Verify the next physical boundary without exposing the probe.
                candidate = number + consumed
                if max_pages is not None and pages >= max_pages:
                    reason = (
                        f"UNIFI_PAGINATE_MAX_PAGES page cap of {max_pages} reached "
                        "before offset verification; raise or unset UNIFI_PAGINATE_MAX_PAGES "
                        "and retry the same window"
                    )
                    more = False
                else:
                    batch.record_sent(1)
                    probe = await fetch({"offset": candidate, "limit": 1})
                    pages += 1
                    if is_dry_run_preview(probe) or not isinstance(probe, (dict, list)):
                        reason = (
                            f"page {candidate} came back without a records array "
                            f"({describe_shape(probe)})"
                        )
                        more = False
                    elif isinstance(probe, dict) and not isinstance(probe.get(array_field), list):
                        reason = f"page {candidate} came back without a records array"
                        more = False
                    else:
                        witness = _page_items(probe, array_field, path)[:1]
                        if not witness:
                            probe_total = (
                                page_total(probe, path) if isinstance(probe, dict) else None
                            )
                            if (
                                trimmed
                                or (total is not None and total > candidate)
                                or (probe_total is not None and probe_total > candidate)
                            ):
                                reason = (
                                    f"offset verification at {candidate} returned no records "
                                    "despite evidence of remaining records"
                                )
                            more = False
                        else:
                            delivered = got[:consumed]
                            verification_history = PageHistory()
                            verification_history.add(delivered, number)
                            stop = page_stop(
                                witness,
                                probe,
                                family=family,
                                history=verification_history,
                                seen={record_identity(row) for row in delivered},
                                page=pages,
                                position=candidate,
                                sent=1,
                                total=total,
                                supplied=start + len(rows),
                                kept=len(rows),
                                first_oversized=False,
                                requested=requested,
                            )
                            if stop is not None:
                                reason = stop.reason
                                more = False
            break
        if not more:
            expected = (
                min(requested, max(0, total - start))
                if requested is not None and total is not None
                else None
            )
            offset_shortfall = (
                family == "offset"
                and total is not None
                and len(rows) < (expected if expected is not None else max(0, total - start))
            )
            if offset_shortfall or (
                strict_total and total is not None and len(rows) + (number_origin or 0) < total
            ):
                reason = (
                    f"the controller declared {total} entries but supplied only "
                    f"{len(rows)} across {pages} pages"
                )
            break
        if not got and family not in {"cursor", "carrier", "links"}:
            reason = f"the controller returned an empty page {number} before declared completion"
            if total is not None:
                reason += f" (totalCount {total}; {len(rows)} records gathered)"
            break
        if family in {"cursor", "carrier"}:
            if nxt in seen_tokens:
                reason = f"cursor cycle detected: {nxt!r} was already followed"
                break
            if nxt is not None:
                seen_tokens.add(nxt)
            token = nxt
        if max_pages is not None and pages >= max_pages:
            reason = f"UNIFI_PAGINATE_MAX_PAGES page cap of {max_pages} reached"
            if declared_pages is None and total is None:
                reason += " (total unknown)"
            break
        if got:
            history.add(got, number)
        number += len(got) if family == "offset" else 1
    abort_continuation = reason is not None and not reason.startswith("UNIFI_PAGINATE_MAX_PAGES")
    continuation_token = (
        read_page_token(response, "nextToken", path)
        if family == "cursor" and batch.done(len(rows)) and not abort_continuation
        else nxt
        if family == "carrier" and batch.done(len(rows)) and more and not abort_continuation
        else None
    )
    continuation = None
    if continuation_token is not None:
        token_key, continuation_size = (
            ("cursor", "limit") if family == "carrier" else ("pageToken", "pageSize")
        )
        continuation = encode_continuation(
            {token_key: continuation_token, continuation_size: controls.get(size_key)}
        )
    return {
        "items": rows,
        "envelope": envelope,
        "array_key": array_key,
        "totalCount": total,
        "pages": pages,
        "trimmed": trimmed,
        "nextToken": (
            read_page_token(response, "nextToken", path)
            if family == "cursor" and batch.done(len(rows)) and not abort_continuation
            else None
        ),
        "nextCursor": (
            nxt
            if family == "carrier" and batch.done(len(rows)) and more and not abort_continuation
            else None
        ),
        "meta": last_meta,
        "nextOffset": (
            # The physical position reached: rows dropped as already returned still
            # occupied offsets, so the record count kept would resume too early.
            number + consumed
            if family == "offset" and batch.done(len(rows)) and more and not abort_continuation
            else None
        ),
        "nextPage": (
            number + 1
            if family in {"links", "number"}
            and batch.done(len(rows))
            and more
            and not abort_continuation
            else None
        ),
        "incomplete": reason is not None,
        "incompleteReason": reason,
        **({"_continuation": continuation} if continuation is not None else {}),
        **batch.context(returned=len(rows)),
        **(
            {"raw": response}
            if preserve_bare and bare_single_page and isinstance(response, list)
            else {}
        ),
    }


def _client_drainer(client: UniFiClient, name: str) -> Callable[..., Awaitable[list[Any]]] | None:
    """Bind declared class or instance adapters, without fabricating dynamic ones.

    Lightweight clients can implement only ``get``. A dynamic ``__getattr__``
    placeholder is not a declared drain adapter, whereas an explicit instance
    override must take precedence over the client's normal class method.
    """
    if getattr_static(client, name, None) is None:
        return None
    adapter = getattr(client, name)
    return adapter if callable(adapter) else None


async def _collect_drain(drain: Awaitable[list[Any]]) -> dict[str, Any] | None:
    """Translate a client default drain without bypassing its established adapter.

    Client drainers carry the first upstream envelope and total on their result
    list. An aborted drain carries the same metadata and every record gathered
    before stopping, so default helpers preserve their incomplete-result contract.
    Plain lists remain supported for callers supplying a custom client adapter.
    A non-list completed result means a legacy duck-typed adapter does not provide
    this drain protocol; the caller uses its get-only path. Empty lists are valid
    completed drains. Transport and upstream response errors are never retried.
    """
    try:
        items = await drain
    except PaginationAbortedError as exc:
        return {
            "items": exc.items,
            "totalCount": exc.total_count,
            "envelope": dict(exc.envelope),
            "array_key": exc.array_key,
            "nextToken": None,
            "nextOffset": None,
            "nextPage": None,
            "pages": exc.page_count,
            "incomplete": True,
            "incompleteReason": exc.reason,
        }
    if not isinstance(items, list):
        return None
    return {
        "items": items,
        "totalCount": getattr(items, "total_count", None),
        "envelope": _envelope_of(items),
        "array_key": getattr(items, "array_key", None),
        "nextToken": None,
        "nextOffset": None,
        "nextPage": None,
        "incomplete": False,
        "incompleteReason": None,
    }


async def collect_cursor(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None = None,
    params: dict[str, Any] | None = None,
    page_token: str | None = None,
    page_size: int | None = DRAIN_PAGE_SIZE,
    one_page: bool = False,
) -> dict[str, Any]:
    """Fetch a cursor-paginated list, draining all pages unless a page is asked for.

    A size alone or an encoded continuation gathers the requested total through
    nextToken. A native token string fetches one verbatim page. An encoded
    continuation without a logical size fetches one page at its stored physical size.
    ``page_size=None`` sends no pageSize. Default drains use 200 per request.

    Returns ``{items, nextToken, incomplete, incompleteReason}``. ``nextToken``
    is populated only in explicit-paging mode (single page); a full drain sets
    it to ``None`` because there is no next page to hand back.
    """
    validate_pagination(page_size=page_size, names={"page_size": "page_size"})
    native_token, stored_size = cursor_continuation(page_token, "cursor")
    if page_size is not None and one_page and (page_token is None or stored_size is not None):
        return await collect_batch(
            lambda controls: client.get(path, key=key, params={**(params or {}), **controls}),
            requested=page_size,
            family="cursor",
            token=page_token,
            max_pages=client.paginate_max_pages,
        )
    if page_token is not None or one_page:
        req = dict(params or {})
        if page_size is not None or stored_size is not None:
            req["pageSize"] = stored_size if stored_size is not None else page_size
        if native_token is not None:
            req["nextToken"] = native_token
        data = await client.get(path, key=key, params=req)
        if isinstance(data, list):
            return _bare_page(data)
        continuation = read_page_token(data, "nextToken", path)
        return {
            "items": _page_items(data, "data", path),
            **(
                {
                    "_continuation": encode_continuation(
                        {"pageToken": continuation, "pageSize": stored_size}
                    )
                }
                if stored_size is not None and continuation is not None
                else {}
            ),
            "nextToken": read_page_token(data, "nextToken", path),
            "incomplete": False,
            "incompleteReason": None,
            "envelope": _single_page_envelope(data, "data"),
        }
    paginate = _client_drainer(client, "paginate")
    if callable(paginate):
        collected = await _collect_drain(
            paginate(path, key=key, params=params, page_size=page_size)
        )
        if collected is not None:
            return collected
    return await collect_batch(
        lambda controls: client.get(path, key=key, params={**(params or {}), **controls}),
        requested=None,
        family="cursor",
        default_size=page_size,
        max_pages=client.paginate_max_pages,
    )


async def collect_offset(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None = None,
    params: dict[str, Any] | None = None,
    offset: int | None = None,
    limit: int | None = None,
    page_size: int = DRAIN_PAGE_SIZE,
    preserve_bare: bool = False,
) -> dict[str, Any]:
    """Gather ``limit`` records in effective-size batches, or drain every page by default.

    Returns ``{items, totalCount, incomplete, incompleteReason}`` (plus ``raw``, the
    native upstream page when only ``offset`` is given). ``limit`` is a requested
    total when no native offset is supplied, gathered from zero across bounded pages.
    An explicit offset selects one verbatim page, including with a limit. Actual
    sent sizes and the separate effective size are returned under ``_pageSize``.
    Private Protect bare feeds without a measured clamp keep a sized request as one page.
    Object envelopes use their totals and echoed sizes to gather the requested total. A drain
    reports the upstream ``totalCount`` when the API gave one and ``None`` when it did
    not (the count is never invented from the records gathered); a drain that stops
    short is ``incomplete`` with the reason and still carries the upstream total.

    A page is final only on affirmative evidence: the declared total is reached, an echoed limit or
    size (`limit`, `meta.limit`, `links` pageSize) is larger than the rows returned, the page is
    empty, or the continuation (`nextToken`, `meta.hasMore`/`nextCursor`, `links.next`,
    `total_page_count`) is absent or terminal. The response shape is never evidence: an object
    envelope with neither a total nor a size echo is drained until an empty page exactly like a
    bare array; a page larger than the sent size is not terminal, and a repeated page is an abort
    unless the repeated page exceeded the sent size and nothing shows more records exist (no
    declared total above the records gathered and no continuation that is present and
    non-terminal), in which case the endpoint is unpaged and the drain is complete; otherwise
    the repeat stays an abort that keeps the records gathered once, the upstream total verbatim,
    and a reason naming the evidence.
    """
    validate_pagination(page_size=page_size, offset=offset, names={"page_size": "page_size"})
    # A limit below 1 is refused with or without an offset; any other limit is sent as given.
    validate_pagination(page_size=limit, names={"page_size": "limit"})
    base = dict(params or {})
    private_protect = "/proxy/protect/api/" in path
    if offset is not None:
        # A native position selects exactly one upstream page.
        req = dict(base)
        if offset is not None:
            req["offset"] = offset
        if limit is not None:
            req["limit"] = limit
        data = await client.get(path, key=key, params=req)
        items = _page_items(data, "data", path)
        if isinstance(data, dict) and limit is not None:
            policy = PageSizeBatch(limit)
            policy.record_sent(limit)
            policy.observe(data, items, "offset", first=True)
            data = with_context(data, policy.context(returned=len(items)))
        return {
            "items": items,
            "raw": data,
            "totalCount": page_total(data, path) if isinstance(data, dict) else None,
            "incomplete": False,
            "incompleteReason": None,
        }
    if limit is not None:
        maximum = (
            HOTSPOT_VOUCHERS_MAX_LIMIT
            if "/hotspot/vouchers" in path
            else None
            if "/proxy/protect/api/" in path
            else NETWORK_INTEGRATION_MAX_LIMIT
        )
        return await collect_batch(
            lambda controls: client.get(path, key=key, params={**base, **controls}),
            requested=limit,
            known_max=maximum,
            max_pages=client.paginate_max_pages,
            family="offset",
            start=offset or 0,
            omit_initial_offset=offset is None,
            path=path,
            bare_single_page=private_protect,
            preserve_bare=preserve_bare,
        )
    paginate = _client_drainer(client, "paginate_offset")
    if callable(paginate):
        collected = await _collect_drain(
            paginate(path, key=key, params=params, page_size=page_size)
        )
        if collected is not None:
            return collected
    maximum = (
        HOTSPOT_VOUCHERS_MAX_LIMIT
        if "/hotspot/vouchers" in path
        else None
        if private_protect
        else NETWORK_INTEGRATION_MAX_LIMIT
    )
    # Get-only adapters need the same completion evidence as client drainers:
    # a short bare page may reflect an unreported console clamp.
    return await collect_batch(
        lambda controls: client.get(path, key=key, params={**base, **controls}),
        requested=None,
        known_max=maximum,
        family="offset",
        default_size=page_size,
        max_pages=client.paginate_max_pages,
        path=path,
    )


async def collect_links(
    client: UniFiClient,
    path: str,
    array_field: str,
    *,
    key: APIKeyConfig | None = None,
    params: dict[str, Any] | None = None,
    page: int | None = None,
    page_size: int | None = None,
) -> dict[str, Any]:
    """Fetch a ``links.next`` / page-number list, draining all pages unless ``page`` given.

    The private Protect recognition endpoints (``/recognition/{type}/groups`` and
    ``.../{id}/detections``) return a ``{<array_field>, links:{prev,next}}`` envelope and
    page via an explicit ``page=N`` query parameter — a third pagination family alongside
    cursor (``nextToken``) and offset/limit. Default drains and requested totals use
    ``collect_batch``.

    Returns ``{items, nextPage, incomplete, incompleteReason}``. Passing ``page`` alone selects
    explicit-paging mode: exactly one page is fetched and ``nextPage`` (the next page
    number, or ``None`` on the last page) is surfaced so the caller can page manually.
    A full drain reports ``nextPage`` as ``None`` because there is no next page to hand
    back.

    ``page_size=N`` selects the logical window ``[(page-1)*N, page*N)``
    (default page 1), gathered across console pages of at most
    :data:`RECOGNITION_MAX_PAGE_SIZE`. Request the starting page to learn the
    effective size, discovering it from page 1 only for an ambiguous terminal
    probe. Every request shares one page budget. ``_pageSize`` reports all wire
    sizes and the effective size. Resume from ``nextPage`` with the same
    ``page_size`` to concatenate contiguous, disjoint logical windows. Without
    a size, a page selects one native page and a default drain follows every link.
    """
    validate_pagination(
        page=page, page_size=page_size, names={"page": "page", "page_size": "page_size"}
    )
    base = dict(params or {})
    if page is not None and page_size is None:
        req = dict(base)
        req["page"] = page
        data = await client.get(path, key=key, params=req)
        if isinstance(data, list):
            return {**_bare_page(data), "nextPage": None}
        items = _page_items(data, array_field, path)
        has_next = page_has_next_link(data, path)
        return {
            "items": items,
            "nextPage": (page + 1) if has_next else None,
            "incomplete": False,
            "incompleteReason": None,
            "envelope": _single_page_envelope(data, array_field),
        }

    if page_size is None:
        return await collect_batch(
            lambda controls: client.get(path, key=key, params={**base, **controls}),
            requested=None,
            known_max=RECOGNITION_MAX_PAGE_SIZE,
            default_size=RECOGNITION_MAX_PAGE_SIZE,
            family="links",
            array_field=array_field,
            start=1,
            max_pages=client.paginate_max_pages,
        )

    logical_page = page if page is not None else 1
    logical_start = (logical_page - 1) * page_size
    wire_size = min(page_size, RECOGNITION_MAX_PAGE_SIZE)
    probe_page = logical_start // wire_size + 1
    sent: list[int] = []
    effective: int | None = None
    rows: list[Any] = []
    envelope: dict[str, Any] = {}
    total: int | None = None
    reason: str | None = None
    declared: int | None = None
    unpaged = False
    more = False
    skip = 0

    def capped() -> bool:
        nonlocal reason
        cap = client.paginate_max_pages
        if cap is not None and len(sent) >= cap:
            gathered = min(page_size, max(0, len(rows) - skip))
            reason = (
                f"UNIFI_PAGINATE_MAX_PAGES page cap of {cap} reached after "
                f"{gathered} of {page_size} records of window page={logical_page}, "
                f"page_size={page_size}; this window needs more requests than the cap allows: "
                "raise or unset UNIFI_PAGINATE_MAX_PAGES and call again with "
                f"page={logical_page}, page_size={page_size}"
            )
            return True
        return False

    async def fetch(number: int, size: int) -> Any:
        sent.append(size)
        return await client.get(path, key=key, params={**base, "page": number, "pageSize": size})

    def empty_nonterminal_reason(number: int, size: int) -> str:
        return (
            f"page {number} (pageSize {size}) returned no records but links.next is still "
            "present, so record positions cannot be computed from page numbers on this "
            f"endpoint; read it natively with page={number + 1} and no page_size, "
            "following _nextPage"
        )

    def observed_size(response: Any, got: list[Any], has_next: bool) -> int | None:
        if isinstance(response, dict):
            links = response.get("links") or {}
            for direction in ("next", "prev"):
                link = links.get(direction)
                if isinstance(link, str):
                    values = parse_qs(urlsplit(link).query).get("pageSize", [])
                    if values and values[0].isdigit() and int(values[0]) > 0:
                        return int(values[0])
        if got and has_next:
            return len(got)
        if len(got) == wire_size:
            return wire_size
        return None

    if not capped():
        probe = await fetch(probe_page, wire_size)
        if is_dry_run_preview(probe):
            return {"raw": probe}
        probe_rows = _page_items(probe, array_field, path)
        envelope = _single_page_envelope(probe, array_field)
        probe_more = page_has_next_link(probe, path)
        if isinstance(probe, dict):
            declared = page_total(probe, path)
        effective = observed_size(probe, probe_rows, probe_more)
        if not probe_rows and probe_more:
            reason = empty_nonterminal_reason(probe_page, wire_size)
        # An echoed expansion can place an empty native probe beyond the
        # requested logical window; reposition using that positive evidence.
        # The A1 one-request empty control remains unchanged when e <= wire.
        if probe_rows or (
            not probe_more
            and effective is not None
            and effective > wire_size
            and (probe_page - 1) * effective > logical_start
        ):
            more = probe_more
            if effective is None and probe_page > 1:
                if not capped():
                    discovery = await fetch(1, wire_size)
                    if not isinstance(discovery, (dict, list)) or (
                        isinstance(discovery, dict)
                        and not isinstance(discovery.get(array_field), list)
                    ):
                        reason = "page 1 came back without a records array"
                    else:
                        discovery_rows = _page_items(discovery, array_field, path)
                        discovery_more = page_has_next_link(discovery, path)
                        if not discovery_rows and discovery_more:
                            reason = empty_nonterminal_reason(1, wire_size)
                        elif discovery_more:
                            effective = observed_size(discovery, discovery_rows, discovery_more)
                        elif (
                            len(probe_rows) > wire_size
                            and page_is_repeat(probe_rows, discovery_rows)
                            and page_is_repeat(discovery_rows, probe_rows)
                            and (declared is None or declared <= len(discovery_rows))
                        ):
                            # The same oversized terminal page for page 1 and the
                            # probe, with nothing declaring more, is the whole
                            # unpaged collection: select the window from it.
                            unpaged = True
                            rows, skip = list(discovery_rows), logical_start
                            total = len(rows)
                        if effective is None and reason is None and not unpaged:
                            reason = (
                                f"terminal probe page {probe_page} with {len(probe_rows)} rows "
                                f"has ambiguous page size; resume with page={probe_page} "
                                "and no page_size"
                            )
            # A short terminal first page needs no discovery: its complete list
            # is already the requested window, even without a size echo.
            if effective is None and probe_page == 1:
                effective = wire_size
            if effective is not None and reason is None and not unpaged:
                if not probe_more:
                    total = (probe_page - 1) * effective + len(probe_rows)
                if total is None or logical_start < total:
                    number, skip = divmod(logical_start, effective)
                    number += 1
                    seen: list[list[Any]] = []
                    while True:
                        if number == probe_page:
                            response, got, more = probe, probe_rows, probe_more
                        else:
                            if capped():
                                break
                            response = await fetch(number, effective)
                            if not isinstance(response, (dict, list)) or (
                                isinstance(response, dict)
                                and not isinstance(response.get(array_field), list)
                            ):
                                reason = f"page {number} came back without a records array"
                                break
                            got = _page_items(response, array_field, path)
                            more = page_has_next_link(response, path)
                        if not got and more:
                            reason = empty_nonterminal_reason(number, effective)
                            break
                        if got and any(
                            page_is_repeat(got, previous) and page_is_repeat(previous, got)
                            for previous in seen
                        ):
                            reason = f"page {number} repeated a previously returned page"
                            break
                        rows.extend(got)
                        if not more:
                            total = (number - 1) * effective + len(got)
                            break
                        if len(rows) >= skip + page_size:
                            break
                        if got:
                            seen.append(got)
                        number += 1
        # An empty terminal probe proves this window empty without discovery.

    items = rows[skip : skip + page_size]
    trimmed = len(rows) > skip + page_size
    if reason is None and declared is not None:
        held = max(0, min(logical_start + page_size, declared) - logical_start)
        if len(items) != held:
            # A declared total is affirmative evidence; page-number placement
            # that contradicts it cannot be returned as the window.
            reason = (
                f"the upstream declared totalCount {declared}, so window page={logical_page}, "
                f"page_size={page_size} holds {held} records, but page-number positions "
                f"placed {len(items)}; record positions cannot be computed from page "
                "numbers on this endpoint; read it natively without page_size, following "
                "_nextPage"
            )
            items, trimmed = [], False
    # A reached declared total is final even when a stale next link remains.
    beyond = trimmed or (more if declared is None else declared > logical_start + page_size)
    if len(sent) > 1:
        envelope = page_envelope(envelope, array_field)
    return {
        "items": items,
        "envelope": envelope,
        "array_key": array_field,
        "totalCount": total,
        "pages": len(sent),
        "trimmed": trimmed,
        "nextPage": logical_page + 1 if reason is None and beyond else None,
        "incomplete": reason is not None,
        "incompleteReason": reason,
        "_pageSize": {
            "requested": page_size,
            "sent": sent,
            "effective": effective,
            "returned": len(items),
        },
    }


def _bare_page(page: list[Any]) -> dict[str, Any]:
    """The ``collect_*`` result for ONE explicitly requested page the upstream sent as a
    bare JSON array: its records, no continuation marker (a bare array carries none), and
    the page itself under ``raw`` so the tool returns it unchanged (:func:`bare_page`)."""
    return {
        "items": page,
        "nextToken": None,
        "incomplete": False,
        "incompleteReason": None,
        "envelope": {},
        "raw": page,
    }


def bare_page(collected: dict[str, Any]) -> list[Any] | None:
    """The explicitly requested page when the upstream sent it as a bare JSON array, else
    ``None``. Every list tool returns such a page as that array, unchanged: never wrapped
    in an invented ``{"data": ...}`` (or ``groups`` / ``result`` ...) object."""
    raw = collected.get("raw")
    return raw if isinstance(raw, list) else None


def _single_page_envelope(page: Any, records_key: str) -> dict[str, Any]:
    """Every top-level key of ONE explicitly requested page except its records: a single
    page is the upstream body, so its paging controls (``nextToken``, ``links``) stay."""
    if not isinstance(page, dict):
        return {}
    return {k: v for k, v in page.items() if k != records_key}


def _envelope_of(items: Any) -> dict[str, Any]:
    """The first-page envelope a drained list carries (``{}`` for a plain list)."""
    envelope = getattr(items, "envelope", None)
    return dict(envelope) if isinstance(envelope, dict) else {}


def with_envelope(result: dict[str, Any], collected: dict[str, Any]) -> dict[str, Any]:
    """``result`` with the drained list's upstream envelope fields beside it.

    Every top-level key of the (first) upstream page that is neither the records array
    nor a per-page paging control (``offset``, ``limit``, ``count``, ``nextToken``,
    ``links``) is kept: ``traceId``, ``httpStatusCode``, ``totalCount`` and any field the
    API adds. Colliding server context is preserved through ``with_context`` instead
    of replacing upstream values.
    """
    envelope = collected.get("envelope")
    if not isinstance(envelope, dict) or not envelope:
        return result
    # The drained array is assembled across pages; every other envelope field,
    # including additive keys, retains the upstream value.
    base = {**envelope, **{k: v for k, v in result.items() if k in {"data", "result"}}}
    return with_context(base, {k: v for k, v in result.items() if k not in {"data", "result"}})


def _page_items(data: Any, field: str, path: str) -> list[Any]:
    """The item array of one page; an unexpected shape raises with the shape received."""
    if isinstance(data, list):
        return data
    items = data.get(field) if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from GET {path}: expected an object with a "
            f"{field!r} array, got {describe_shape(data)}"
        )
    return items


def offset_list_result(collected: dict[str, Any]) -> Any:
    """The tool result for a ``collect_offset`` call.

    An explicit offset returns one native upstream page: the object envelope
    (``offset``, ``limit``, ``count``, ``totalCount``, ``data``), possibly with
    ``_pageSize`` accounting, or a bare array returned without an invented wrapper.
    A limit without offset requests a total gathered in batches;
    the default drains all pages. Either gathered result returns ``{data, totalCount}``
    plus the first page's other envelope fields (:func:`with_envelope`), with incomplete
    markers when it stopped short. ``totalCount`` is the upstream total, or ``None``
    when the upstream reported none; it is never computed from ``data``.
    """
    if "raw" in collected:
        return collected["raw"]
    drained: dict[str, Any] = {
        "data": collected["items"],
        "totalCount": collected["totalCount"],
    }
    return mark_incomplete(with_envelope(drained, collected), collected)


def mark_incomplete(result: dict[str, Any], collected: dict[str, Any]) -> dict[str, Any]:
    """Copy the incomplete markers from a ``collect_*`` result onto a tool result.

    Adds ``incomplete=True`` + ``incompleteReason`` only when the drain was
    actually capped/stalled, so a complete result stays free of noise keys.
    """
    if "_continuation" in collected:
        result = with_context(result, {"_continuation": collected["_continuation"]})
    if "_pageSize" in collected:
        result = with_context(result, {"_pageSize": collected["_pageSize"]})
    for source, target in (
        ("nextOffset", "_nextOffset"),
        ("nextPage", "_nextPage"),
        ("nextCursor", "_nextCursor"),
    ):
        if collected.get(source) is not None and (
            source not in {"nextOffset", "nextCursor"}
            or collected.get("pages", 0) > 1
            or collected.get("trimmed")
        ):
            result = with_context(result, {target: collected[source]})
    if collected.get("incomplete"):
        return with_context(
            result,
            {"incomplete": True, "incompleteReason": collected.get("incompleteReason")},
        )
    return result


def upstream_total(body: Any, path: str) -> int | None:
    """The collection size an upstream body reports (``totalCount`` / ``total``), or None.

    The ONE total reader: :func:`~unifi_fabric.client.page_total`, strict -- a
    total that is not a non-negative integer (a string, a boolean, a float, a negative
    number) is a shape error naming the field and ``GET <path>``, never silently ignored.
    """
    return page_total(body, path)


def verbatim_list_result(raw: Any, records: list[Any], path: str) -> dict[str, Any]:
    """The tool result of a single-GET list: the upstream body verbatim plus ``_count``.

    Every top-level key the upstream sent is kept unchanged (``data`` / the named array,
    ``total``, ``offset``, ``limit``, ``httpStatusCode``, ``traceId`` and any field the API
    adds); only additive ``_``-prefixed keys are added. When the upstream reports a total
    larger than the records it returned, the result is marked ``incomplete: true`` with
    an ``incompleteReason`` (one GET returned part of the collection); nothing is invented.
    ``path`` names the request in a wrong-typed total's error.
    """
    body: dict[str, Any] = dict(raw) if isinstance(raw, dict) else {}
    result = with_context(body, {"_count": len(records)})
    total = upstream_total(body, path)
    if total is not None and total > len(records):
        result = with_context(
            result,
            {
                "incomplete": True,
                "incompleteReason": (
                    f"the upstream reported a total of {total} "
                    f"but returned {len(records)} record(s)"
                ),
            },
        )
    return result
