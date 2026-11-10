"""The scrubber's offset-map construction before it was split into short functions,
verbatim: ``_forward`` and ``_child_breaks`` as one function with both loops inline.

The product now builds the same breaks with each allocation-heavy loop in a code object
of its own (:func:`unifi_fabric.secret_scrub._child_breaks`). This copy is the
differential reference: tests run both over the same layers and compare every map and
every scrub result. Not imported by the product.
"""

from __future__ import annotations

from array import array
from bisect import bisect_left, bisect_right
from itertools import chain
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unifi_fabric.secret_scrub import _Breaks, _Search, _Units


def _forward(search: _Search, at: array[int] | list[int], x: int, low: int) -> int:
    """``search(at, x, low, len(at))`` (``bisect_left`` or ``bisect_right``) when the
    answer is at least ``low``, galloping up from ``low``: O(log(answer - low)) element
    reads, not O(log(len(at) - low)). A run of nondecreasing queries that each start at
    the previous answer therefore reads O(queries + len(at)) elements in total -- linear
    -- where a bisect to the end of the map reads O(queries * log(len(at)))."""
    count = len(at)
    width = 2
    while True:
        high = low + width
        if high >= count:
            return search(at, x, low, count)
        found = search(at, x, low, high)
        if found < high:
            return found
        low = high
        width <<= 1


def _child_breaks(size: int, parent: _Breaks, units: _Units) -> _Breaks:
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
    # Source spans of parent characters, as _Closure.source, inlined: the queried
    # positions only grow, so each search gallops up from the last break found
    # (``low``), and the whole layer reads each parent break a bounded number of times.
    low = 0
    for token_start, token_end, char in chain(units, ((size, size, ""),)):
        if token_start > pos:  # characters [pos, token_start) are copied
            j = _forward(bisect_right, p_at, pos, low) - 1
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
            k = _forward(bisect_right, p_at, pos, k)
            stop = _forward(bisect_left, p_at, token_start, k)
            if stop > k:
                shift = child - pos
                at.extend([value + shift for value in p_at[k:stop]])
                starts.extend(p_starts[k:stop])
                ends.extend(p_ends[k:stop])
                k = stop
            last = token_start - 1
            j = _forward(bisect_right, p_at, last, low) - 1
            if j < 0:
                previous = last + 1
            else:
                low = j
                previous = p_ends[j] + last - p_at[j]
            child += token_start - pos
        if token_start == size:
            break
        j = _forward(bisect_right, p_at, token_start, low) - 1
        if j < 0:
            start = token_start
        else:
            low = j
            offset = token_start - p_at[j]
            start = p_ends[j] + offset - 1 if offset else p_starts[j]
        last = token_end - 1
        j = _forward(bisect_right, p_at, last, low) - 1
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
