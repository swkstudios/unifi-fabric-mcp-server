"""Allocation and exact-offset regressions for the scrubber and its count oracle.

The tracemalloc peak measurements run in an untraced child interpreter
(tests/_untraced.py) with the same inputs and bounds, so they do not also pay for the
coverage tracer of the test run.
"""

from __future__ import annotations

import random
import struct
import tracemalloc

import pytest

from tests import _untraced as untraced
from tests import scrub_oracle
from tests.test_secret_scrub_timing import TOKENS, family_text
from unifi_fabric import secret_scrub


@pytest.mark.parametrize(
    "text",
    [
        "",
        "unchanged",
        r"a%255c%78%34%31z",
        r"\6&#55;",
        "a&#x7f;b&#x7f;c",
        "&#x7f;&#x7f;%41&#x7f;",
        "a&NotEqualTilde;b",
        r"%26NotEqualTilde%3b\x41&#x7f;z",
        *[family_text(family, 1024) for family in TOKENS],
    ],
)
@pytest.mark.parametrize("limit", [1, 3, 128])
def test_packed_count_oracle_retains_every_view_and_source_span(text, limit):
    expected_bound, expected = scrub_oracle.closure(text, limit)
    actual_bound, packed = scrub_oracle.closure(text, limit, packed=True)
    actual = [(view, tuple(struct.iter_unpack("=II", spans))) for view, spans in packed]
    assert actual_bound == expected_bound
    assert actual == expected
    assert scrub_oracle.view_count(text, limit) == len(expected)


def test_packed_count_oracle_agrees_on_random_mixed_tokens():
    rng = random.Random(361070)  # noqa: S311 - deterministic test data
    for _ in range(200):
        text = "".join(rng.choices(TOKENS["mixed"], k=rng.randrange(1, 40)))
        expected_bound, expected = scrub_oracle.closure(text)
        actual_bound, packed = scrub_oracle.closure(text, packed=True)
        assert actual_bound == expected_bound
        assert [
            (view, tuple(struct.iter_unpack("=II", spans))) for view, spans in packed
        ] == expected


def count_oracle_peak():
    """Run in the untraced child (tests/_untraced.py): views and peak bytes at 64 KiB."""
    text = family_text("mixed", 65536)
    tracemalloc.start()
    try:
        count = scrub_oracle.view_count(text)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return count, peak


def test_count_oracle_has_bounded_allocation():
    count, peak = untraced.run("tests.test_secret_scrub_memory:count_oracle_peak")
    assert count == 128
    assert peak < 40 * 1024 * 1024, peak


@pytest.mark.parametrize(
    "spans",
    [
        [],
        [(0, 3)],
        [(0, 3)] * 100,
        [(0, 3), (3, 5)],
        [(0, 10), (2, 8)],
        [(8, 10), (0, 2), (1, 9)],
        [(4, 6), (2, 4), (6, 8)],
        [(4, 6), (0, 2), (1, 5), (8, 10)],
    ],
)
def test_span_union_preserves_duplicate_overlap_and_adjacency(spans):
    found = secret_scrub._SpanUnion(10)
    for span in spans:
        found.append(span)
    assert found.merged() == secret_scrub._merged(spans.copy())


def one_megabyte_mixed_peak():
    """Run in the untraced child (tests/_untraced.py): result type and peak bytes."""
    unit = family_text("mixed", 1024) + " "
    text = (unit * (1024 * 1024 // len(unit) + 1))[: 1024 * 1024]
    secret_scrub._memo_clear()
    tracemalloc.start()
    try:
        result = secret_scrub.scrub(text, ("A", "Key0123456789012345"))
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return type(result).__name__, peak


def test_one_megabyte_mixed_body_has_bounded_allocation():
    result_type, peak = untraced.run("tests.test_secret_scrub_memory:one_megabyte_mixed_peak")
    assert result_type == "str"
    # Includes all bounded decoded views and whole-window search batches, but
    # excludes a tuple object graph for every match in every decoded view.
    assert peak < 160 * 1024 * 1024, peak


def decoded_token_offsets_peak():
    """Run in the untraced child (tests/_untraced.py): views, offsets and peak bytes."""
    text = r"\x41" * 131072
    tracemalloc.start()
    try:
        closure = secret_scrub._Closure(text)
        views_ok = closure.views == [text, "A" * 131072]
        start = closure.source(1, 131071, end=False)
        end = closure.source(1, 131071, end=True)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return views_ok, start, end, len(text), peak


def test_decoded_token_offsets_have_bounded_allocation():
    views_ok, start, end, length, peak = untraced.run(
        "tests.test_secret_scrub_memory:decoded_token_offsets_peak"
    )
    assert views_ok
    assert start == 524284
    assert end == length
    # Includes decoding and exact source-map construction, with room for allocator
    # variation; retaining a tuple plus two Python integers per token exceeds this.
    assert peak < 8 * 1024 * 1024, peak


@pytest.mark.parametrize(
    "units",
    [
        [],
        [(0, 2, "a"), (2, 4, "a"), (4, 6, "a")],
        [(0, 2, "a"), (2, 5, "a"), (5, 8, "a")],
        [(0, 2, "a"), (3, 5, "a"), (5, 7, "b")],
        [(0, 2, "a"), (2, 4, "b"), (4, 6, "b"), (6, 8, "a")],
        [(0, 2, ""), (2, 4, ""), (4, 6, "ab"), (6, 8, "ab")],
    ],
)
@pytest.mark.parametrize("size", [256, 257])
def test_token_runs_retain_every_decoded_unit(units, size):
    packed = secret_scrub._Units(size)
    for unit in units:
        packed.append(*unit)
    assert list(packed) == units
    assert len(packed) == len(units)
    assert bool(packed) == bool(units)


def one_megabyte_backslash_peak():
    """Same pathological body through all four entry points, each with a cold memo."""
    text = "\\" * 1_000_000
    raw = text.encode("ascii")
    secrets = ("Key0123456789012345", "OtherConfiguredSecret6789")
    results = []
    peaks = []
    for operation, data in (
        (secret_scrub.scrub, text),
        (secret_scrub.scrub_bytes, raw),
        (secret_scrub.contains_secret, text),
        (secret_scrub.contains_secret, raw),
    ):
        secret_scrub._memo_clear()
        tracemalloc.start()
        try:
            result = operation(data, secrets)
            results.append(result.decode("ascii") if isinstance(result, bytes) else result)
            peaks.append(tracemalloc.get_traced_memory()[1])
        finally:
            tracemalloc.stop()
    secret_scrub._memo_clear()
    return results, peaks


def test_one_megabyte_backslash_body_has_bounded_allocation():
    results, peaks = untraced.run("tests.test_secret_scrub_memory:one_megabyte_backslash_peak")
    # Nine distinct layers exceed D=8, so G5 withholds the entire escape component.
    assert results == ["***", "***", True, True]
    # Measured at 15.47 MB across the four entry points on CPython 3.12 (including
    # decoded text, exact source maps and byte-to-text conversion). 20 MB leaves
    # allocator headroom while rejecting the previous 25.20 MB representation.
    assert max(peaks) < 20 * 1_000_000, peaks
