"""The offset-map searches of the scrubber before the galloping replacement, verbatim.

Side-by-side reference for the replacement in :mod:`unifi_fabric.secret_scrub`
(``_child_breaks`` and ``_Closure.source``): the same maps and source offsets, found
by one binary search over the rest of the map per query. Tests compare the two
implementations and show that the operation counter rejects this one. Not imported by
the product.
"""

from __future__ import annotations

from array import array
from bisect import bisect_left, bisect_right
from itertools import chain
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unifi_fabric.secret_scrub import _Breaks, _Units


def break_start(breaks: _Breaks, pos: int) -> int:
    """Source offset where character ``pos`` of a view starts."""
    at, starts, ends = breaks
    k = bisect_right(at, pos) - 1
    if k < 0:
        return pos
    return starts[k] if at[k] == pos else ends[k] + pos - at[k] - 1


def break_end(breaks: _Breaks, pos: int) -> int:
    """Source offset where character ``pos`` of a view ends."""
    at, _starts, ends = breaks
    k = bisect_right(at, pos) - 1
    if k < 0:
        return pos + 1
    return ends[k] + pos - at[k]


def child_breaks(size: int, parent: _Breaks, units: _Units) -> _Breaks:
    """The breaks of a layer of a view of ``size`` characters (breaks ``parent``) that
    decodes ``units`` (token start, end, characters; in order): a copied character
    keeps its span, a decoded one spans its whole token, a token decoding to nothing
    leaves no character."""
    p_at, p_starts, p_ends = parent
    at: array[int] | list[int]
    starts: array[int] | list[int]
    ends: array[int] | list[int]
    if isinstance(p_at, array):
        code = p_at.typecode
        at, starts, ends = array(code), array(code), array(code)
    else:
        at, starts, ends = [], [], []
    count = len(p_at)
    if not count:
        # The parent maps every character to itself (the raw view): a decoded character
        # spans its token; a copied one breaks only right after a token that decoded to
        # nothing (it does not start where the character before it ends).
        child = 0
        previous = 0
        pos = 0
        for token_start, token_end, char in units:
            child += token_start - pos
            if token_start > pos and pos != previous:
                at.append(child - (token_start - pos))
                starts.append(pos)
                ends.append(pos + 1)
            for _ in char:
                at.append(child)
                starts.append(token_start)
                ends.append(token_end)
                child += 1
            previous = token_end if char else (previous if token_start == pos else token_start)
            pos = token_end
        if size > pos and pos != previous:
            at.append(child)
            starts.append(pos)
            ends.append(pos + 1)
        return at, starts, ends
    previous = child = pos = k = 0
    # Source spans of parent characters, as break_start/break_end, inlined: the queried
    # positions only grow, so each search starts at the last break found (``low``).
    low = 0
    for token_start, token_end, char in chain(units, ((size, size, ""),)):
        if token_start > pos:  # characters [pos, token_start) are copied
            j = bisect_right(p_at, pos, low) - 1
            if j < 0:
                start, end = pos, pos + 1
            else:
                low = j
                offset = pos - p_at[j]
                if offset:
                    end = p_ends[j] + offset
                    start = end - 1
                else:
                    start, end = p_starts[j], p_ends[j]
            if start != previous or end != start + 1:
                at.append(child)
                starts.append(start)
                ends.append(end)
            # The parent's breaks after ``pos`` and before the token, shifted.
            k = bisect_right(p_at, pos, k)
            stop = bisect_left(p_at, token_start, k)
            if stop > k:
                shift = child - pos
                at.extend([value + shift for value in p_at[k:stop]])
                starts.extend(p_starts[k:stop])
                ends.extend(p_ends[k:stop])
                k = stop
            last = token_start - 1
            j = bisect_right(p_at, last, low) - 1
            if j < 0:
                previous = last + 1
            else:
                low = j
                previous = p_ends[j] + last - p_at[j]
            child += token_start - pos
        if token_start == size:
            break
        j = bisect_right(p_at, token_start, low) - 1
        if j < 0:
            start = token_start
        else:
            low = j
            offset = token_start - p_at[j]
            start = p_ends[j] + offset - 1 if offset else p_starts[j]
        last = token_end - 1
        j = bisect_right(p_at, last, low) - 1
        if j < 0:
            end = last + 1
        else:
            low = j
            end = p_ends[j] + last - p_at[j]
        for _ in char:
            at.append(child)
            starts.append(start)
            ends.append(end)
            child += 1
        if char:
            previous = end
        pos = token_end
    return at, starts, ends
