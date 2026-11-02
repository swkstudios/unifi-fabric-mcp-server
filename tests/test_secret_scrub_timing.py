"""AT4 deterministic work and memory gates.

For fixed corpus shape, at most two scrub rounds inspect at most 2*n characters.
Each region closure holds at most N views and attempts three decode families per
view. Map construction processes at most one stored map plus three candidate maps
per view, each consuming at most n parent entries and n token units. These give
independent, weighted work ceilings of 3*N*closure_chars decoded characters,
8*N*closure_chars map entries, and N*closure_chars materialized view characters.
The self-concatenating ladder also gates deterministic work growth at every 4x step.
The existing 256 MB / 4.4x memory clauses remain blocking on every host and CI event.
There are no elapsed-time clauses, host-load skips, or opt-in AT4 markers.
The measured ladder runs in an untraced child interpreter (tests/_untraced.py), so the
tracemalloc rungs no longer also pay for the coverage tracer of the test run.
"""

from __future__ import annotations

import contextlib
import functools
import gc
import json
import os
import platform
import random
import socket
import tracemalloc
from pathlib import Path

import pytest

import unifi_fabric.secret_scrub as product
from tests import _untraced as untraced
from tests import scrub_oracle

_EVIDENCE_DIR = os.environ.get("UNIFI_SCRUB_CORPUS_EVIDENCE")
BASE_SIZE = 1024
SIZES = (1024, 4096, 16384, 65536, 262144)
LONG = BASE_SIZE * 98
LADDER = (*SIZES, LONG)
MAX_RATIO = 5.0
PEAK_64K_MB = 256.0
PEAK_256K_FACTOR = 4.4
N_BOUND = 128
INVARIANT_FAMILIES = ("backslash", "percent", "ampersand", "mixed")
STALL_SECRET = "\\" * 16 + "Z"
COMMON_SECRETS = ("A", "Key0123456789012345")
TOKENS = {
    "backslash": ("\\x41", "\\101", "\\\\", "\\u0041", "\\n", "\\x5c", "\\134", "\\1", "a"),
    "percent": ("%41", "%25", "%2541", "%u0041", "%5c", "%2525", "%3", "a"),
    "ampersand": ("&amp;", "&#65;", "&#x41;", "&lt;", "&amp;#65;", "&#38;", "&#", "a"),
}
TOKENS["mixed"] = TOKENS["backslash"] + TOKENS["percent"] + TOKENS["ampersand"]
#: family -> (repeating unit or None for the random-token ladder, secrets)
FAMILIES = {
    "backslash": (None, COMMON_SECRETS),
    "percent": (None, COMMON_SECRETS),
    "ampersand": (None, COMMON_SECRETS),
    "mixed": (None, COMMON_SECRETS),
    "stall-128X": ("\\" * 128 + "X", (STALL_SECRET,)),
    "stall-16Z": ("\\" * 16 + "Z", (STALL_SECRET,)),
}


@functools.cache
def base_text(family: str) -> str:
    """text(1k): seeded random WHOLE tokens, padded with >= 1 trailing "a" to 1024."""
    rng = random.Random(f"{family}-{BASE_SIZE}")  # noqa: S311 - deterministic test data
    parts: list[str] = []
    length = 0
    while True:
        token = rng.choice(TOKENS[family])
        if length + len(token) > BASE_SIZE - 1:  # keep room for at least one "a"
            break
        parts.append(token)
        length += len(token)
    return "".join(parts) + "a" * (BASE_SIZE - length)


@functools.cache
def family_text(family: str, size: int) -> str:
    unit, _ = FAMILIES[family]
    if unit is not None:  # stall families: unchanged construction
        return (unit * (size // len(unit) + 1))[:size]
    if size == LONG:
        return base_text(family) * 98
    if size not in SIZES:
        raise ValueError(f"{size} is not on the AT4 ladder")
    text = base_text(family)
    while len(text) < size:
        text = text * 4  # text(4n) = text(n) * 4
    return text


def view_counts(family: str) -> dict[int, int]:
    """N per ladder size, counted by the oracle's own bounded BFS."""
    return {size: scrub_oracle.view_count(family_text(family, size)) for size in LADDER}


def generator_defects(family: str, views: dict[int, int]) -> list[str]:
    """V5 preconditions: a failure here is a corpus defect, never a ratio violation."""
    defects = []
    if family in INVARIANT_FAMILIES and len(set(views.values())) != 1:
        defects.append(f"N not invariant across the ladder: {views}")
    if family == "mixed" and any(n != N_BOUND for n in views.values()):
        defects.append(f"mixed does not saturate N = {N_BOUND} at every size: {views}")
    return defects


@contextlib.contextmanager
def _patched(target, **attributes):
    """Set module attributes for the block and restore them, in or out of pytest."""
    saved = {name: getattr(target, name) for name in attributes}
    try:
        for name, value in attributes.items():
            setattr(target, name, value)
        yield
    finally:
        for name, value in saved.items():
            setattr(target, name, value)


def operation_profile(text, secrets, *, memory=False):
    counts = dict.fromkeys(
        ("rounds", "scan_chars", "closure_chars", "view_chars", "decode_chars", "map_entries"), 0
    )
    original_closure = product._Closure
    original_spans = product._spans
    original_map = product._child_breaks
    original_families = product._FAMILIES

    class CountingClosure(original_closure):
        __slots__ = ()

        def __init__(self, data):
            counts["closure_chars"] += len(data)
            super().__init__(data)
            counts["view_chars"] += sum(map(len, self.views))

    def spans(data, *args, **kwargs):
        counts["rounds"] += 1
        counts["scan_chars"] += len(data)
        return original_spans(data, *args, **kwargs)

    def mapped(size, parent, units):
        counts["map_entries"] += len(parent[0]) + len(units)
        return original_map(size, parent, units)

    def counted(layer):
        def decode(capture, data):
            counts["decode_chars"] += len(data)
            return layer(capture, data)

        return decode

    product._memo_clear()
    gc.collect()
    with _patched(
        product,
        _Closure=CountingClosure,
        _spans=spans,
        _child_breaks=mapped,
        _FAMILIES=tuple((intro, counted(fn)) for intro, fn in original_families),
    ):
        if memory:
            tracemalloc.start()
        try:
            result = product.scrub(text, secrets)
            peak = tracemalloc.get_traced_memory()[1] if memory else 0
        finally:
            if memory:
                tracemalloc.stop()
    assert isinstance(result, str)
    assert len(result) <= len(text)
    counts["work"] = sum(
        counts[key] for key in ("scan_chars", "view_chars", "decode_chars", "map_entries")
    )
    return counts, peak


def work_violations(size, views, counts):
    failures = []
    ceilings = {
        "rounds": 2,
        "scan_chars": 2 * size,
        "closure_chars": 2 * size,
        "view_chars": views * counts["closure_chars"],
        "decode_chars": 3 * views * counts["closure_chars"],
        "map_entries": 8 * views * counts["closure_chars"],
    }
    for key, ceiling in ceilings.items():
        if counts[key] > ceiling:
            failures.append(f"{size} {key}: {counts[key]} > {ceiling}")
    return failures


def measure(family, views):
    profiles = {}
    peaks = {}
    for size in LADDER:
        profiles[str(size)], peak = operation_profile(
            family_text(family, size),
            FAMILIES[family][1],
            memory=size in (65536, 262144),
        )
        peaks[size] = peak
    return {
        "family": family,
        "host": {"hostname": socket.gethostname(), "python": platform.python_version()},
        "views": {str(size): views[size] for size in LADDER},
        "operations": profiles,
        "steps_4x": [
            {
                "step": f"{small}->{large}",
                "ratio": profiles[str(large)]["work"] / profiles[str(small)]["work"],
            }
            for small, large in zip(SIZES, SIZES[1:], strict=False)
        ],
        "peak_mb_64k": peaks[65536] / 2**20,
        "peak_mb_256k": peaks[262144] / 2**20,
        "peak_ratio_256k_64k": peaks[262144] / peaks[65536] if peaks[65536] else 0,
    }


def violations(row):
    failures = []
    for size, counts in row["operations"].items():
        failures.extend(work_violations(int(size), row["views"][size], counts))
    failures.extend(
        f"4x operation step {step['step']}: {step['ratio']} > {MAX_RATIO}"
        for step in row["steps_4x"]
        if step["ratio"] > MAX_RATIO
    )
    if row["peak_mb_64k"] > PEAK_64K_MB:
        failures.append("64k memory ceiling exceeded")
    if row["peak_ratio_256k_64k"] > PEAK_256K_FACTOR:
        failures.append("256k/64k memory linearity exceeded")
    return failures


def _write_evidence(family, row):
    if _EVIDENCE_DIR:
        destination = Path(_EVIDENCE_DIR)
        destination.mkdir(exist_ok=True)
        (destination / f"at4-{family}.json").write_text(json.dumps(row, indent=1))


def test_at4_clause_checker_fails_on_injected_violations():
    counts = {
        "rounds": 2,
        "scan_chars": 2048,
        "closure_chars": 1024,
        "view_chars": 1024,
        "decode_chars": 3072,
        "map_entries": 8192,
        "work": 14336,
    }
    base = {
        "operations": {"1024": counts},
        "views": {"1024": 1},
        "steps_4x": [{"step": "a->b", "ratio": 4}],
        "peak_mb_64k": 100,
        "peak_ratio_256k_64k": 4,
    }
    assert violations(base) == []
    for field in (
        "rounds",
        "scan_chars",
        "closure_chars",
        "view_chars",
        "decode_chars",
        "map_entries",
    ):
        assert violations({**base, "operations": {"1024": {**counts, field: 999999}}})
    assert violations({**base, "steps_4x": [{"step": "a->b", "ratio": 5.1}]})
    assert violations({**base, "peak_mb_64k": 256.1})
    assert violations({**base, "peak_ratio_256k_64k": 4.5})


def test_at4_generator_precondition_checker():
    """The V5 precondition checker rejects a varying N and an unsaturated mixed family."""
    flat = dict.fromkeys(LADDER, 7)
    assert generator_defects("percent", flat) == []
    assert generator_defects("percent", {**flat, 262144: 13})
    assert generator_defects("mixed", dict.fromkeys(LADDER, N_BOUND)) == []
    assert generator_defects("mixed", flat)  # invariant but not saturated
    assert generator_defects("mixed", {**dict.fromkeys(LADDER, N_BOUND), 1024: 127})
    # stall families are reported, not asserted
    assert generator_defects("stall-16Z", {**flat, 262144: 9}) == []


@pytest.mark.parametrize("family", list(INVARIANT_FAMILIES))
def test_at4_ladder_is_self_concatenating(family):
    """V5 construction: a 1024-character whole-token base, every rung four of the last."""
    base = base_text(family)
    assert len(base) == BASE_SIZE
    assert base.endswith("a")
    for small, large in zip(SIZES, SIZES[1:], strict=False):
        assert family_text(family, large) == family_text(family, small) * 4
        assert len(family_text(family, large)) == large
    assert family_text(family, LONG) == base * 98
    assert len(family_text(family, LONG)) == 100_352
    # N invariance on the cheap rungs; the full ladder is asserted by the ordinary AT4 case.
    views = {size: scrub_oracle.view_count(family_text(family, size)) for size in SIZES[:2]}
    assert len(set(views.values())) == 1, views
    if family == "mixed":
        assert set(views.values()) == {N_BOUND}, views


def at4_row(family):
    """The AT4 corpus check and measurement, run in the untraced child (tests/_untraced.py)."""
    views = view_counts(family)
    defects = generator_defects(family, views)
    if defects:
        return {"family": family, "defects": defects}
    return {**measure(family, views), "defects": []}


@pytest.mark.parametrize("family", list(FAMILIES))
def test_at4_operation_count_and_memory(family):
    # Same corpus, ladder, counters, tracemalloc rungs and ceilings as in-process; the
    # child only removes the coverage tracer from the measured run.
    row = untraced.run("tests.test_secret_scrub_timing:at4_row", family)
    assert not (defects := row.pop("defects")), (family, defects)
    failures = violations(row)
    row["violations"] = failures
    _write_evidence(family, row)
    assert not failures, ("AT4 deterministic work/memory", row, failures)
