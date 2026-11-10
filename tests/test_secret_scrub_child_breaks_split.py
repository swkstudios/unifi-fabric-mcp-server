"""The offset-map construction split into short functions gives the same maps and the
same scrub results as the single function it replaced.

:func:`unifi_fabric.secret_scrub._child_breaks` keeps each allocation-heavy loop in a
code object of its own, because tracemalloc on CPython 3.12 pays, for every traced
allocation, a line-table scan from the start of the running function. The previous
implementation is vendored verbatim in ``tests/scrub_child_breaks_previous.py``. Every
case here runs the scrubber twice with a cold memo: once with each layer built by both
implementations and compared (array type, typecode and every entry), once with the
previous implementation alone; the two results must be equal. The corpus is the oracle
suite's fixtures and its fast and shallow fuzz corpora, plus 10,240 seeded random
inputs (mixed, backslash, unicode, escape soup) and a set of 16-128 KiB bodies. Most of
it is ``-m slow``; the default run keeps a sample of each part.
"""

from __future__ import annotations

import contextlib
import dis
import json
import random
from array import array
from pathlib import Path

import pytest

import unifi_fabric.secret_scrub as product
from tests import scrub_child_breaks_previous as previous
from tests import scrub_fuzz
from tests.test_secret_scrub_oracle import (
    CHAIN_REGRESSIONS,
    CORPORA,
    PRESERVED,
    REGRESSIONS,
)
from tests.test_secret_scrub_timing import COMMON_SECRETS, TOKENS, family_text

_CASES = json.loads((Path(__file__).parent / "scrub_spec_v2_cases.json").read_text())
_CURRENT = product._child_breaks
#: Seeded random inputs: CHUNKS items of PER_CHUNK cases each (10,240 in total).
CHUNKS = 16
PER_CHUNK = 640
#: The default run keeps one random chunk, one oracle corpus seed and the large bodies
#: that take seconds (about 30 s in all); the rest is ``-m slow`` (about 400 s).
SLOW = (pytest.mark.slow,)
DEFAULT_CORPUS = ("shallow", 36200)
UNICODE_TOKENS = (
    "\\u00e9",
    "\\U0001F600",
    "\\ud83d\\ude00",
    "%C3%A9",
    "%F0%9F%98%80",
    "%u00e9",
    "&#x1F600;",
    "&#233;",
    "&eacute;",
    "&amp;eacute;",
    "\u00e9",
    "\U0001f600",
    "\u2028",
    "e\u0301",
    "\\x41",
    "%41",
    "a",
    " ",
)
BACKSLASH_TOKENS = ("\\", "\\\\", "\\x5c", "\\134", "\\x41", "\\u0041", "\\1", "x41", "Z", "a")


def _assert_same_map(new, old, where):
    assert len(new) == len(old) == 3, where
    for part, (mine, theirs) in enumerate(zip(new, old, strict=True)):
        assert type(mine) is type(theirs), (where, part)
        if isinstance(mine, array):
            assert mine.typecode == theirs.typecode, (where, part)
        assert list(mine) == list(theirs), (where, part)


class _Counter:
    __slots__ = ("layers",)

    def __init__(self) -> None:
        self.layers = 0


@contextlib.contextmanager
def _child_breaks(implementation):
    saved = product._child_breaks
    product._child_breaks = implementation
    try:
        yield
    finally:
        product._child_breaks = saved


def _both(counter: _Counter):
    def compared(size, parent, units):
        new = _CURRENT(size, parent, units)
        old = previous._child_breaks(size, parent, units)
        _assert_same_map(new, old, (size, len(parent[0]), len(units)))
        counter.layers += 1
        return new

    return compared


def _results(text: str, secrets: list[str] | tuple[str, ...]) -> tuple[object, ...]:
    product._memo_clear()
    try:
        out: list[object] = [product.scrub(text, secrets), product.contains_secret(text, secrets)]
        try:
            raw = text.encode("utf-8")
        except UnicodeEncodeError:  # a lone surrogate: text-only case
            raw = None
        if raw is not None:
            out.append(product.scrub_bytes(raw, secrets))
        return tuple(out)
    finally:
        product._memo_clear()


def differential(text: str, secrets: list[str] | tuple[str, ...], counter: _Counter) -> None:
    with _child_breaks(_both(counter)):
        current = _results(text, secrets)
    with _child_breaks(previous._child_breaks):
        before = _results(text, secrets)
    assert current == before, (text[:200], secrets)
    for mine, theirs in zip(current, before, strict=True):
        assert type(mine) is type(theirs)


def _oracle_cases() -> list[tuple[str, list[str]]]:
    cases = [(case["text"], case["secrets"]) for case in _CASES["captured"]]
    cases += [(case["text"], case["secrets"]) for case in _CASES["at2_bound"]]
    cases += [(case["text"], case["secrets"]) for case in _CASES["at1_exact128"]]
    cases += [(text, list(secrets)) for text, secrets in PRESERVED]
    cases += [(text, [secret]) for text, secret in REGRESSIONS + CHAIN_REGRESSIONS]
    cases += [(text, [secret]) for text, secret in scrub_fuzz.REPORTED]
    return cases


def test_oracle_fixtures_match_previous_maps_and_results():
    counter = _Counter()
    cases = _oracle_cases()
    for text, secrets in cases:
        differential(text, secrets, counter)
    assert len(cases) >= 40
    assert counter.layers > 0


@pytest.mark.parametrize(
    ("corpus", "seed"),
    [
        pytest.param(name, seed, marks=() if (name, seed) == DEFAULT_CORPUS else SLOW)
        for name in ("fast", "shallow")
        for seed in CORPORA[name][0]
    ],
)
def test_oracle_corpus_matches_previous_maps_and_results(corpus, seed):
    _, count, generator, _ = CORPORA[corpus]
    rng = random.Random(seed)  # noqa: S311 - the oracle suite's deterministic corpus
    counter = _Counter()
    for _ in range(count):
        text, secrets = scrub_fuzz.case(rng, **generator)
        differential(text, secrets, counter)
    assert counter.layers > count


def _secrets(rng: random.Random) -> list[str]:
    pick = rng.random()
    if pick < 0.3:
        return list(COMMON_SECRETS)
    if pick < 0.5:
        return [rng.choice(("A", "K", "K!", "\u00e9", "\U0001f600", "\\A", " K", "a1"))]
    return [scrub_fuzz.secret(rng) for _ in range(rng.choice((1, 1, 2)))]


def _random_case(rng: random.Random) -> tuple[str, list[str]]:
    kind = rng.randrange(5)
    if kind == 0:
        text = "".join(rng.choices(TOKENS["mixed"], k=rng.randrange(1, 300)))
    elif kind == 1:
        text = "".join(rng.choices(BACKSLASH_TOKENS, k=rng.randrange(1, 300)))
    elif kind == 2:
        text = "".join(rng.choices(UNICODE_TOKENS + TOKENS["mixed"], k=rng.randrange(1, 200)))
    elif kind == 3:
        text = scrub_fuzz.soup(rng)
    else:
        text, secrets = scrub_fuzz.case(rng)
        return text, secrets
    secrets = _secrets(rng)
    if rng.random() < 0.3:  # a secret, plain or encoded, inside the escapes
        value = rng.choice(secrets)
        cut = rng.randrange(len(text) + 1)
        piece = scrub_fuzz.encode(rng, value, 3) if rng.random() < 0.5 else value
        text = text[:cut] + piece + text[cut:]
    return text, secrets


@pytest.mark.parametrize(
    "chunk", [pytest.param(chunk, marks=() if chunk == 0 else SLOW) for chunk in range(CHUNKS)]
)
def test_seeded_random_inputs_match_previous_maps_and_results(chunk):
    rng = random.Random(f"child-breaks-split-{chunk}")  # noqa: S311 - deterministic test data
    counter = _Counter()
    for _ in range(PER_CHUNK):
        text, secrets = _random_case(rng)
        differential(text, secrets, counter)
    assert counter.layers > PER_CHUNK


HUGE = {
    "mixed-64k": lambda: family_text("mixed", 65536),
    "backslash-64k": lambda: family_text("backslash", 65536),
    "percent-64k": lambda: family_text("percent", 65536),
    "ampersand-64k": lambda: family_text("ampersand", 65536),
    "mixed-spaced-128k": lambda: (family_text("mixed", 1024) + " ") * 128,
    "decoded-x41-128k": lambda: "\\x41" * 32768,
    "backslash-run-64k": lambda: "\\" * 65536,
    "percent-chain-16k": lambda: ("%" + "25" * 7 + "41a") * 1024,
    "unicode-64k": lambda: "".join(
        random.Random("unicode-64k").choices(UNICODE_TOKENS + TOKENS["mixed"], k=16384)  # noqa: S311
    ),
}


#: The two bodies of the AT4 [mixed] and one-megabyte mixed shape take 12-16 s each.
SLOW_HUGE = frozenset({"mixed-64k", "mixed-spaced-128k"})


@pytest.mark.parametrize(
    "name", [pytest.param(name, marks=SLOW if name in SLOW_HUGE else ()) for name in HUGE]
)
def test_large_bodies_match_previous_maps_and_results(name):
    counter = _Counter()
    differential(HUGE[name](), COMMON_SECRETS, counter)
    assert counter.layers > 0


def _has_loop(function) -> bool:
    return any(
        instruction.opname in {"FOR_ITER", "JUMP_BACKWARD"}
        for instruction in dis.get_instructions(function)
    )


def test_layer_loops_start_code_objects_of_their_own():
    """The structure the tracemalloc cost depends on: ``_child_breaks`` itself has no
    loop, the raw and mapped layer loops are functions of their own, the per-token loop
    hands the copied characters to a function, and the shifted copy of parent breaks is
    a function too. The single previous function holds all of it."""
    assert _has_loop(previous._child_breaks)
    assert not _has_loop(product._child_breaks)
    for loop in (product._raw_child_breaks, product._mapped_child_breaks):
        assert _has_loop(loop), loop
    size = len(previous._child_breaks.__code__.co_code)
    assert len(product._mapped_child_breaks.__code__.co_code) * 2 < size
    assert len(product._raw_child_breaks.__code__.co_code) * 2 < size
    calls = {
        instruction.argval
        for instruction in dis.get_instructions(product._mapped_child_breaks)
        if instruction.opname == "LOAD_GLOBAL"
    }
    assert "_copied_breaks" in calls
    shifted = {
        instruction.argval
        for instruction in dis.get_instructions(product._copied_breaks)
        if instruction.opname == "LOAD_GLOBAL"
    }
    assert "_extend_shifted" in shifted
