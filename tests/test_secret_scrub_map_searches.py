"""Offset-map searches stay linear: a deterministic probe count, no clock.

Every decoded match and every decoded token is mapped to source offsets through a view's
compact offset map (``_child_breaks`` and ``_Closure.source``). One binary search over
the rest of the map per query reads O(log n) map entries, so mapping a saturated mixed
region costs O(n log n) reads; each read of a typed offset array also allocates a Python
integer, which an allocation tracer charges per read. Galloping from the previous answer
reads O(1) entries per query, amortized.

The counter charges each binary search over an offset map with the worst case of its
range, ``(hi - lo).bit_length()`` reads, through the module's own ``bisect`` functions.
The work it is compared with is implementation-independent: the parent breaks and units
consumed by each map construction (the AT4 ``map_entries``) plus the ``source`` queries.
The side-by-side reference (:mod:`tests.scrub_map_reference`, the bisect searches this
replaced) is rejected by the same counter, and produces the same maps, offsets and
scrubbed text.
"""

from __future__ import annotations

import itertools
import random
from array import array
from bisect import bisect_left, bisect_right

import pytest

import unifi_fabric.secret_scrub as product
from tests import scrub_map_reference as reference
from tests import test_secret_scrub_timing as at4

#: Reads charged per map query: galloping reads a constant number per query, amortized
#: (largest measured: 2.55); the replaced search measured 4.74 to 10.03 on these classes.
PROBES_PER_QUERY = 4.0
#: A logarithmic search adds reads per query as the input doubles: across the two 4x
#: steps the replaced search grew by 2.5 to 4.2 reads per query, galloping by at most
#: 0.23 (converging).
MAX_GROWTH = 0.5
RUNGS = (1024, 4096, 16384)
FAMILY_TOKENS = ("backslash", "percent", "ampersand")
#: Every non-empty combination of the token families (the three single families, the
#: three pairs, and all three: AT4 "mixed"), plus the AT4 stall families.
CLASSES = tuple(
    "+".join(combo)
    for size in range(1, len(FAMILY_TOKENS) + 1)
    for combo in itertools.combinations(FAMILY_TOKENS, size)
) + ("stall-128X", "stall-16Z")


def class_text(name: str, size: int) -> tuple[str, tuple[str, ...]]:
    """The AT4 ladder construction for any token class: a seeded 1024-character base of
    whole tokens padded with "a", self-concatenated; stall classes repeat their unit."""
    if name.startswith("stall-"):
        unit, secrets = at4.FAMILIES[name]
        assert unit is not None
        return (unit * (size // len(unit) + 1))[:size], secrets
    if name == "+".join(FAMILY_TOKENS):  # the AT4 mixed corpus itself
        return at4.base_text("mixed") * (size // at4.BASE_SIZE), at4.COMMON_SECRETS
    tokens = tuple(itertools.chain.from_iterable(at4.TOKENS[f] for f in name.split("+")))
    rng = random.Random(f"{name}-{at4.BASE_SIZE}")  # noqa: S311 - deterministic test data
    parts: list[str] = []
    length = 0
    while True:
        token = rng.choice(tokens)
        if length + len(token) > at4.BASE_SIZE - 1:
            break
        parts.append(token)
        length += len(token)
    base = "".join(parts) + "a" * (at4.BASE_SIZE - length)
    return base * (size // at4.BASE_SIZE), at4.COMMON_SECRETS


def _reference_source(self: product._Closure, index: int, pos: int, end: bool) -> int:
    held = self.breaks(index)
    return reference.break_end(held, pos) if end else reference.break_start(held, pos)


def search_profile(text, secrets, monkeypatch, *, replaced=False):
    """Scrub ``text`` counting offset-map search reads; ``replaced`` swaps in the
    reference searches. Returns the counts and the scrubbed text."""
    counts = dict.fromkeys(("probes", "map_entries", "source_calls"), 0)

    def counting(search):
        def counted(seq, x, lo=0, hi=None):
            if hi is None:
                hi = len(seq)
            if isinstance(seq, array):  # an offset map (window and span lists are lists)
                counts["probes"] += (hi - lo).bit_length()
            return search(seq, x, lo, hi)

        return counted

    map_impl = reference.child_breaks if replaced else product._child_breaks
    source_impl = _reference_source if replaced else product._Closure.source

    def mapped(size, parent, units):
        counts["map_entries"] += len(parent[0]) + len(units)
        return map_impl(size, parent, units)

    def source(self, index, pos, end):
        counts["source_calls"] += 1
        return source_impl(self, index, pos, end)

    product._memo_clear()
    with monkeypatch.context() as patch:
        for module in (product, reference):
            patch.setattr(module, "bisect_right", counting(bisect_right))
            patch.setattr(module, "bisect_left", counting(bisect_left))
        patch.setattr(product, "_child_breaks", mapped)
        patch.setattr(product._Closure, "source", source)
        result = product.scrub(text, secrets)
    product._memo_clear()
    queries = counts["map_entries"] + counts["source_calls"]
    counts["per_query"] = counts["probes"] / queries if queries else 0.0
    return counts, result


def search_violations(rows: dict[int, dict]) -> list[str]:
    failures = [
        f"{size}: {row['per_query']:.3f} map reads per query > {PROBES_PER_QUERY}"
        for size, row in rows.items()
        if row["per_query"] > PROBES_PER_QUERY
    ]
    first, last = rows[min(rows)]["per_query"], rows[max(rows)]["per_query"]
    if last - first > MAX_GROWTH:
        failures.append(f"reads per query grew {first:.3f} -> {last:.3f} across the ladder")
    return failures


@pytest.mark.parametrize("name", CLASSES)
def test_map_searches_are_linear(name, monkeypatch):
    rows = {}
    for size in RUNGS:
        text, secrets = class_text(name, size)
        rows[size], _ = search_profile(text, secrets, monkeypatch)
    assert not search_violations(rows), (name, rows)


def test_counter_rejects_the_replaced_searches(monkeypatch):
    """The bisect-per-query searches fail the same clauses on the mixed class."""
    rows = {}
    for size in RUNGS[:2]:
        text, secrets = class_text("+".join(FAMILY_TOKENS), size)
        rows[size], _ = search_profile(text, secrets, monkeypatch, replaced=True)
    assert all(row["per_query"] > PROBES_PER_QUERY for row in rows.values()), rows
    assert search_violations(rows), rows


@pytest.mark.parametrize("name", CLASSES)
def test_replacement_matches_reference(name, monkeypatch):
    """Same maps, same source offsets in any query order, same scrubbed text."""
    text, secrets = class_text(name, 1024)
    current, ours = search_profile(text, secrets, monkeypatch)
    replaced, theirs = search_profile(text, secrets, monkeypatch, replaced=True)
    assert ours == theirs
    assert current["map_entries"] == replaced["map_entries"]
    assert current["source_calls"] == replaced["source_calls"]

    closure = product._Closure(text)
    with monkeypatch.context() as patch:
        patch.setattr(product, "_child_breaks", reference.child_breaks)
        expected = product._Closure(text)
        expected_maps = [expected.breaks(index) for index in range(len(expected.views))]
    assert closure.views == expected.views
    rng = random.Random(f"order-{name}")  # noqa: S311 - deterministic test data
    for index, view in enumerate(closure.views):
        assert [list(part) for part in closure.breaks(index)] == [
            list(part) for part in expected_maps[index]
        ]
        positions = list(range(len(view)))
        orders = (positions, positions[::-1], rng.sample(positions, len(positions)))
        for order in orders:
            for pos in order:
                for end in (False, True):
                    want = (reference.break_end if end else reference.break_start)(
                        expected_maps[index], pos
                    )
                    assert closure.source(index, pos, end) == want, (index, pos, end)


def test_gallops_equal_bisect():
    rng = random.Random("gallop")  # noqa: S311 - deterministic test data
    for count in (0, 1, 2, 3, 5, 8, 17, 64):
        values = array("I", sorted(rng.randrange(0, 4 * count + 2) for _ in range(count)))
        for x in range(-1, 4 * count + 3):
            for search in (bisect_left, bisect_right):
                answer = search(values, x)
                for low in range(answer + 1):
                    assert product._forward(search, values, x, low) == answer
            answer = bisect_right(values, x)
            for high in range(answer, count):
                if values[high] > x:
                    assert product._backward(values, x, high) == answer
