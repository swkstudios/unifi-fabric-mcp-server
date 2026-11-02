"""SCRUBBER-SPEC-V2 acceptance as amended by V2-A1, V3 and V4: independent reference
equality (AT1), the bound predicate (V3-1), per-round AT2 (A1), and aggregate coverage
floors with the bound-hit rate reported, never gated (V3-2)."""

from __future__ import annotations

import json
import os
import random
from pathlib import Path

import pytest

import unifi_fabric.secret_scrub as product
from tests import scrub_fuzz, scrub_oracle

_CASES = json.loads((Path(__file__).parent / "scrub_spec_v2_cases.json").read_text())
CAPTURED = _CASES["captured"]
AT2_BOUND = _CASES["at2_bound"]
EXACT_128 = _CASES["at1_exact128"]
#: Read at import: the autouse hermetic-env fixture deletes UNIFI_* before each test.
_SLOW_REQUESTED = os.environ.get("UNIFI_SCRUB_ORACLE_SLOW") == "1"
_EVIDENCE_DIR = os.environ.get("UNIFI_SCRUB_CORPUS_EVIDENCE")
_AGGREGATE_REQUESTED = os.environ.get("UNIFI_SCRUB_CORPUS_AGGREGATE") == "1"
#: corpus -> (seeds, cases per chunk, generator arguments, non-bound floors (rate, count)).
#: V3-2: these AGGREGATE coverage floors are the only gates derived from bound hits.
CORPORA = {
    "fast": (range(36100, 36104), 600, {"max_depth": 7}, (0.50, 1000)),
    "shallow": (range(36200, 36204), 600, {"max_depth": 3, "chain_units": 5}, (0.90, 2160)),
    "slow": (range(72000, 72050), 4200, {"max_depth": 7}, (0.50, 0)),
}

PRESERVED = [(r"e\1\x301K!", ["K!"])]
#: R-433 L-1 / ruling (c): the corpus cases judged by AT2 because a LATER G4 round (not
#: the input) hits a bound, per (corpus, seed): the exact index list each chunk must
#: produce. Empty under the per-region bounds (fast, shallow and the 210k slow corpus); a
#: new case fails its chunk until it is reviewed and pinned here, so the class cannot
#: widen silently.
LATER_ROUND_PINNED: dict[tuple[str, int], tuple[int, ...]] = {}
REGRESSIONS = [
    (r"Qk\61\62", "Qk12"),
    (r"Qk\61\x32", "Qk12"),
    (r"Qk\612", "Qk" + chr(0o612)),
    (r"Qk\62\061", "Qk21"),
    (r"Qk9z1\x5c\x&#55;832", "Qk9z12"),
    (r"\6&#55;", "7"),
    ("%4B%45%59", "KEY"),
    ("&#x4b;\\x45&amp;#89;", "KEY"),
    ("%25%34%62%25%34%35%25%35%39", "KEY"),
    (r"\x5c\x41", r"\A"),
    ("%5c%5c%78%34%31", r"\x41"),
    ("&#38;#37;4B%45&#x59;", "KEY"),
    ("%C3%A9t%C3%A9", "été"),
    ("administrator", "admin"),
    ("x%4Bey", "Key"),
    ("ab%63d", "bc"),
    ("&#0049", "1"),
    ("x" + "Key0123456789012345" * 2 + "y", "Key0123456789012345"),
    # R-433: a whole-token secret right after a region; its left boundary is the
    # view's last (decoded) character, "&" (shallow seed 36202 index 337).
    (r"\x5cU00000026!", "!"),
    ("_\\u0%3037'!%u007e~\n", "~"),
]

#: The long (>= 12 chars, substring-matched) synthetic secret of the chain cases.
_LONG_SYNTHETIC = "Key" + "0123456789012345"
#: r16y-A1 (a long percent chain right before the secret: 20 layers, a depth bound hit)
#: and F2 (mixed multi-layer chains), through the same AT1/AT2 check as every corpus case.
CHAIN_REGRESSIONS = [
    ("%" + "25" * 19 + "20" + "K!", "K"),
    ("%" + "25" * 19 + "20" + _LONG_SYNTHETIC, _LONG_SYNTHETIC),
    ("e&#38;&#35;37;09K!", "K"),
    ("%2526%252337%253B5CnK!", "K"),
]


@pytest.mark.parametrize("case", CAPTURED, ids=[f"captured-{i}" for i in range(8)])
def test_captured_preserved(case):
    text, secrets = case["text"], case["secrets"]
    assert scrub_oracle.reference_scrub(text, secrets) == text, ("G1/G3", case)
    assert product.scrub(text, secrets) == text, ("G1/G3", case)
    assert product.scrub_bytes(text.encode(), secrets) == text.encode()


@pytest.mark.parametrize(("text", "secrets"), PRESERVED)
def test_reported_preserved(text, secrets):
    assert scrub_oracle.reference_scrub(text, secrets) == text
    assert product.scrub(text, secrets) == text, ("G1/G3", text, secrets)


def only_masked_within(text, out, permitted):
    """AT2 (ii): ``out`` is ``text`` with disjoint source spans each replaced by ``***`` and
    every replaced span inside the ``permitted`` union; every other byte is unchanged.

    Exact alignment by dynamic programming over (consumed text, consumed out); the set of
    reachable text positions for each out position is a bitset."""
    size = len(text)
    runs = []
    for start, end in scrub_oracle.merge(list(permitted)):
        start, end = max(start, 0), min(end, size)
        if start < end:
            runs.append((end, ((1 << end) - 1) ^ ((1 << start) - 1)))
    where: dict[str, int] = {}
    for index, char in enumerate(text):
        where[char] = where.get(char, 0) | (1 << index)
    reach = [0] * (len(out) + 1)
    reach[0] = 1
    for j in range(len(out) + 1):
        here = reach[j]
        if not here:
            continue
        if j < len(out):
            reach[j + 1] |= (here & where.get(out[j], 0)) << 1
        if out.startswith("***", j):
            for end, bits in runs:
                inside = here & bits
                if inside:
                    low = (inside & -inside).bit_length() - 1
                    reach[j + 3] |= ((1 << (end + 1)) - 1) ^ ((1 << (low + 1)) - 1)
    return bool((reach[len(out)] >> size) & 1)


def at2_violations(text, secrets, out):
    """AT2 for a bound-hit input (SPEC-V2 AT2/G5 with V2-A1 A1), exactly:

    (i) no reference occurrence or form in any view (depth 8) of ``out``;
    (ii) PER ROUND: with v0 = ``text`` and v(r+1) = one product G4 round on v(r), every
    byte of v(r) outside reference_spans(v(r)) UNION the G5 components of v(r) is unchanged
    in v(r+1); the rounds end where the product's do, and the last one equals ``out``.

    The G5 components are the oracle's (every escape component of every view a bounded
    enumeration holds), so the check does not trust the product's own claim."""
    found = []
    if scrub_oracle.reference_spans(out, secrets):
        found.append("AT2(i) reference occurrence in output")
    values = tuple(sorted(set(secrets)))
    view = text
    for index in range(len(text) + 2):
        following = product._scrub_round(view, values)
        if following == view:
            break
        permitted = scrub_oracle.reference_spans(view, secrets) + scrub_oracle.regional_components(
            view, secrets
        )
        if not only_masked_within(view, following, permitted):
            found.append(
                f"AT2(ii) G4 pass {index}: byte changed outside reference spans UNION G5 components"
            )
            break
        kept = len(view) - view.count("*")
        view = following
        if len(view) - view.count("*") == kept:
            break
    if view != out:
        found.append("G4 fixed point: the output is not the last round")
    return found


def _later_round_bound(text, secrets):
    """Whether a G4 round after the first works on a text that hits a bound.

    Masking changes the text, and with it the closure: an input inside the bounds can
    become, after its first round, a text past them. G5 applies per round (AT2(ii) is
    checked round by round), so such a case is judged by AT2, not by AT1 equality with
    the unbounded reference (found by the 210k corpus: seed 72037, index 2654)."""
    values = tuple(sorted(set(secrets)))
    view = text
    for _ in range(len(text) + 2):
        following = product._scrub_round(view, values)
        if following == view:
            return False
        kept = len(view) - view.count("*")
        view = following
        if scrub_oracle.regional_bound(view, secrets):
            return True
        if len(view) - view.count("*") == kept:
            return False
    return False


def check(text, secrets):
    """One corpus case: V3-1 bound predicate, then AT1 (no bound) or AT2 (bound), then
    bytes parity. Returns (any reference occurrence in the input, bound hit, judged by
    AT2 only because a later round hits a bound)."""
    declared = bool(product._security_bound_spans(text, secrets))
    bound = scrub_oracle.regional_bound(text, secrets)
    assert declared == bound, ("V3-1 bound predicate", text, secrets, declared, bound)
    out = product.scrub(text, secrets)
    later = not bound and _later_round_bound(text, secrets)
    if not bound and not later:
        expected = scrub_oracle.reference_scrub(text, secrets)
        assert out == expected, ("G1-G4/AT1", text, secrets, expected, out)
    else:
        violations = at2_violations(text, secrets, out)
        assert not violations, ("G5/AT2", violations, text, secrets, out)
    encoded = text.encode("utf-8", "surrogatepass")
    bytes_out = product.scrub_bytes(encoded, secrets)
    if text.isascii():
        assert bytes_out == out.encode(), ("AT1 bytes parity", text, secrets)
    assert not scrub_oracle.reference_spans(bytes_out.decode("latin-1"), secrets), (
        "AT1 bytes leak",
        text,
        secrets,
        bytes_out,
    )
    return bool(scrub_oracle.reference_spans(text, secrets)), bound, later


def _case_id(case):
    return f"{case['seed']}-{case['index']}"


@pytest.mark.parametrize("case", AT2_BOUND, ids=_case_id)
def test_at2_bound_cases_pass(case):
    """The 4 attempt-1 bound hits (N > 128) meet AT2 (i) and per-round (ii). G2 bounds
    are per region (R-433): each case still has a region past the bound, and the
    product's G5 spans are exactly the oracle's components of that region's views at the
    bound. ``product_out`` is the regional output, re-pinned after AT2 passed on it."""
    text, secrets = case["text"], case["secrets"]
    assert scrub_oracle.bound(text), case["root_cause"]
    assert scrub_oracle.regional_bound(text, secrets), case["root_cause"]
    assert product._security_bound_spans(text, secrets), case["root_cause"]
    assert scrub_oracle.merge(product._security_bound_spans(text, secrets)) == (
        scrub_oracle.regional_components(text, secrets)
    ), "G5: the product masks exactly the components of the views at the bound, per region"
    out = product.scrub(text, secrets)
    assert out == case["product_out"]
    assert at2_violations(text, secrets, out) == [], case["root_cause"]
    check(text, secrets)


@pytest.mark.parametrize("case", AT2_BOUND, ids=_case_id)
def test_at2_checker_fails_on_injected_leak(case, monkeypatch):
    """Non-vacuity (i): an output that keeps a reference occurrence is rejected."""
    text, secrets = case["text"], case["secrets"]
    assert scrub_oracle.reference_spans(text, secrets)
    assert "AT2(i) reference occurrence in output" in at2_violations(text, secrets, text)
    monkeypatch.setattr(product, "scrub", lambda value, values=None: value)
    with pytest.raises(AssertionError, match=r"AT2\(i\)"):
        check(text, secrets)


@pytest.mark.parametrize("case", AT2_BOUND, ids=_case_id)
def test_at2_checker_fails_on_injected_overmask(case, monkeypatch):
    """Non-vacuity (ii): a round that masks one byte outside reference spans UNION G5
    components is rejected, while masking exactly that union is accepted."""
    text, secrets = case["text"], case["secrets"]
    permitted = scrub_oracle.merge(
        scrub_oracle.reference_spans(text, secrets)
        + scrub_oracle.regional_components(text, secrets)
    )
    covered = {i for start, end in permitted for i in range(start, end)}
    free = [i for i in range(len(text)) if i not in covered and text[i] != "*"]
    if not free:
        # Every byte is permitted to change: append a plain word (no escape, no secret, a
        # space keeps it out of every component) so there is a byte (ii) must protect.
        text += " zz"
        assert scrub_oracle.regional_bound(text, secrets)
        permitted = scrub_oracle.merge(
            scrub_oracle.reference_spans(text, secrets)
            + scrub_oracle.regional_components(text, secrets)
        )
        covered = {i for start, end in permitted for i in range(start, end)}
        free = [i for i in range(len(text)) if i not in covered and text[i] != "*"]
    outside = free[0]
    assert only_masked_within(text, scrub_oracle.mask(text, permitted), permitted)
    over = scrub_oracle.mask(text, [*permitted, (outside, outside + 1)])
    assert not only_masked_within(text, over, permitted)
    real_round = product._scrub_round

    def injected(view, values, as_bytes=False):
        return over if view == text else real_round(view, values, as_bytes)

    monkeypatch.setattr(product, "_scrub_round", injected)
    with pytest.raises(AssertionError, match=r"AT2\(ii\) G4 pass 0"):
        check(text, secrets)


@pytest.mark.parametrize("case", EXACT_128, ids=_case_id)
def test_exactly_128_views_is_not_a_bound(case):
    """V3-1/V3-3: |C_8| == 128 with C_9 == C_8 is the full closure, not a bound hit, and
    satisfies AT1 equality. Per region (R-433): the product's regions are the oracle's,
    each holds its full closure (the oracle's |C_8|, no bound), and a fixture that is one
    region holds exactly 128 views."""
    text, secrets = case["text"], case["secrets"]
    assert scrub_oracle.closure_size(text) == (128, True)
    assert not scrub_oracle.bound(text)
    regions = product._regions(text, tuple(sorted(set(secrets))), False, {})
    assert [(start, end) for start, end, _ in regions] == scrub_oracle.regions(text, secrets)
    for start, end, closure in regions:
        assert closure.bound == []
        assert scrub_oracle.closure_size(text[start:end]) == (len(closure.views), True)
    if len(regions) == 1:
        assert len(regions[0][2].views) == 128
    assert not product._security_bound_spans(text, secrets)
    assert product.scrub(text, secrets) == scrub_oracle.reference_scrub(text, secrets)
    check(text, secrets)


def test_exactly_128_fixtures_hold_single_region_cases():
    """Non-vacuity of the exact-N case per region: at least two fixtures are ONE region
    whose closure is exactly 128 views (so N is reached and not exceeded in a region)."""
    single = [
        case
        for case in EXACT_128
        if len(scrub_oracle.regions(case["text"], case["secrets"])) == 1
        and scrub_oracle.closure_size(case["text"]) == (128, True)
    ]
    assert len(single) >= 2


@pytest.mark.parametrize("case", EXACT_128, ids=_case_id)
def test_bound_predicate_checker_fails_on_overdeclared_bound(case, monkeypatch):
    """Non-vacuity of V3-1: declaring a bound at exactly 128 views is rejected."""
    monkeypatch.setattr(product, "_security_bound_spans", lambda text, secrets: [(0, 1)])
    with pytest.raises(AssertionError, match="V3-1 bound predicate"):
        check(case["text"], case["secrets"])


@pytest.mark.parametrize("case", AT2_BOUND, ids=_case_id)
def test_bound_predicate_checker_fails_on_undeclared_bound(case, monkeypatch):
    """Non-vacuity of V3-1: missing a bound past 128 views is rejected."""
    monkeypatch.setattr(product, "_security_bound_spans", lambda text, secrets: [])
    with pytest.raises(AssertionError, match="V3-1 bound predicate"):
        check(case["text"], case["secrets"])


@pytest.mark.parametrize(
    ("text", "bound"),
    [
        ("%" + "25" * 7 + "41", False),  # 8 layers: views of depth <= 8 are inside the bound
        ("%" + "25" * 8 + "41", True),  # a depth-8 view decodes to a new view: C_9 != C_8
    ],
)
def test_depth_bound_is_inclusive(text, bound):
    """V3-1 D bound: inclusive at depth 8, hit iff a depth-8 view decodes to a new view."""
    assert scrub_oracle.closure_size(text) == (9, not bound)
    assert scrub_oracle.bound(text) is bound
    assert bool(product._security_bound_spans(text, ["A"])) is bound
    check(text, ["A"])


@pytest.mark.parametrize(("text", "secret"), REGRESSIONS + CHAIN_REGRESSIONS + scrub_fuzz.REPORTED)
def test_regressions(text, secret):
    check(text, [secret])


@pytest.mark.parametrize(
    ("text", "secret"), CHAIN_REGRESSIONS[:2], ids=["r16y-A1-K!", "r16y-A1-long"]
)
def test_r16y_a1_over_mask_is_a_declared_bound(text, secret):
    """SPEC-V4 A2: both r16y-A1 outputs differ from the reference (G5 over-mask), which is
    accepted ONLY under a declared bound; a non-bound case would be an unaccepted FP class."""
    assert scrub_oracle.bound(text) is True, ("V4-A2 non-bound r16y-A1 case", text)
    assert product._security_bound_spans(text, [secret]), ("V4-A2 product declares no bound", text)
    check(text, [secret])


def test_token_decode_stdlib_equality():
    rng = random.Random(361)  # noqa: S311
    tokens = [
        r"\612",
        r"\777",
        r"\0",
        r"\/",
        "&#0;",
        "&#128;",
        "&NotEqualTilde;",
        "&notanentity;",
        r"\U00110000",
    ]
    for char in "abfnrtv\\'\"/":
        tokens.append("\\" + char)
    for _ in range(3000):
        value = rng.randrange(0x110000)
        tokens.extend(
            (
                f"%{value % 256:02x}",
                f"%u{value % 65536:04x}",
                f"\\x{value % 256:02x}",
                f"\\u{value % 65536:04x}",
                f"\\U{value:08x}",
                f"\\{value % 512:o}",
                f"&#{value};",
                f"&#x{value:x};",
            )
        )
    for token in tokens:
        assert product._unit_char(token) == scrub_oracle.token_decode(token), ("G1", token)


def run_chunk(corpus, seed):
    """Every case of one chunk through :func:`check`; the bound-hit rate is REPORTED in the
    evidence JSON (per chunk), never gated here (V3-2). The later-round-bound exemptions
    (ruling (c)) are reported AND gated: the chunk's index list must equal
    :data:`LATER_ROUND_PINNED`."""
    _, count, generator, _ = CORPORA[corpus]
    rng = random.Random(seed)  # noqa: S311
    positive = bounds = 0
    later: list[int] = []
    for index in range(count):
        text, secrets = scrub_fuzz.case(rng, **generator)
        try:
            hit, bound, exempt = check(text, secrets)
        except AssertionError as exc:
            pytest.fail(f"{corpus} seed={seed} index={index} {exc}", pytrace=False)
        positive += hit
        bounds += bound
        if exempt:
            later.append(index)
    evidence = {
        "corpus": corpus,
        "seed": seed,
        "cases": count,
        "positive": positive,
        "bounds": bounds,
        "non_bound": count - bounds,
        "bound_rate": round(bounds / count, 4),
        "later_round_bound": later,
    }
    if directory := _EVIDENCE_DIR:
        destination = Path(directory)
        destination.mkdir(exist_ok=True)
        (destination / f"{corpus}-{seed}.json").write_text(json.dumps(evidence))
    pinned = list(LATER_ROUND_PINNED.get((corpus, seed), ()))
    assert later == pinned, ("ruling (c): unpinned later-round-bound exemptions", evidence)
    return evidence


def gate_coverage(corpus, chunks):
    """V3-2 aggregate coverage floor over a whole corpus; the summary (per-chunk and
    aggregate bound-hit rates) goes to the evidence directory."""
    rate, floor = CORPORA[corpus][3]
    cases = sum(chunk["cases"] for chunk in chunks)
    bounds = sum(chunk["bounds"] for chunk in chunks)
    summary = {
        "corpus": corpus,
        "cases": cases,
        "bounds": bounds,
        "non_bound": cases - bounds,
        "bound_rate": round(bounds / cases, 4),
        "non_bound_rate": round((cases - bounds) / cases, 4),
        "floor": {"non_bound_rate": rate, "non_bound": floor},
        "later_round_bound": sum(len(c.get("later_round_bound", ())) for c in chunks),
        "chunks": [
            {
                "seed": c["seed"],
                "bounds": c["bounds"],
                "bound_rate": round(c["bounds"] / c["cases"], 4),
            }
            for c in chunks
        ],
    }
    if directory := _EVIDENCE_DIR:
        destination = Path(directory)
        destination.mkdir(exist_ok=True)
        (destination / f"{corpus}-aggregate.json").write_text(json.dumps(summary, indent=1))
    assert cases - bounds >= rate * cases, ("V3-2 coverage floor (rate)", summary)
    assert cases - bounds >= floor, ("V3-2 coverage floor (count)", summary)
    return summary


@pytest.mark.parametrize("corpus", ["fast", "shallow"])
def test_coverage_floor(corpus):
    """V3-2 for the default corpora: the oracle's WHOLE-TEXT bound predicate over every
    case. A region's bound implies the whole text's (its views are the whole text's
    views of that region), so this counts at least the regional bounds the chunk tests
    see (where the product must declare exactly the oracle's regional bounds): the floor
    on non-bound cases is the stricter one."""
    seeds, count, generator, _ = CORPORA[corpus]
    chunks = []
    for seed in seeds:
        rng = random.Random(seed)  # noqa: S311
        bounds = sum(scrub_oracle.bound(scrub_fuzz.case(rng, **generator)[0]) for _ in range(count))
        chunks.append({"seed": seed, "cases": count, "bounds": bounds})
    gate_coverage(corpus, chunks)


@pytest.mark.parametrize("chunk", range(4))
def test_fast(chunk):
    run_chunk("fast", 36100 + chunk)


@pytest.mark.parametrize("chunk", range(4))
def test_shallow(chunk):
    """SPEC-V2-A1 A3 shallow sub-corpus (max_depth 3, CHAINS units capped at 5)."""
    run_chunk("shallow", 36200 + chunk)


@pytest.mark.slow
@pytest.mark.parametrize("chunk", range(50))
def test_slow(chunk, request):
    if not _SLOW_REQUESTED and "slow" not in (request.config.getoption("-m") or ""):
        pytest.skip("210,000-case acceptance is explicitly selected")
    run_chunk("slow", 72000 + chunk)


@pytest.mark.slow
def test_slow_coverage_floor():
    """V3-2 for the 210,000-case corpus, aggregated from the 50 chunk evidence files: run
    after the chunks with UNIFI_SCRUB_CORPUS_AGGREGATE=1 and the same
    UNIFI_SCRUB_CORPUS_EVIDENCE directory."""
    if not _AGGREGATE_REQUESTED:
        pytest.skip("aggregate step: UNIFI_SCRUB_CORPUS_AGGREGATE=1 after the 50 slow chunks")
    assert _EVIDENCE_DIR, "UNIFI_SCRUB_CORPUS_EVIDENCE names the chunk evidence directory"
    directory = Path(_EVIDENCE_DIR)
    chunks = [
        json.loads((directory / f"slow-{seed}.json").read_text()) for seed in CORPORA["slow"][0]
    ]
    gate_coverage("slow", chunks)


def _seed_72037_case_2654():
    rng = random.Random(72037)  # noqa: S311 - reproducible synthetic fuzz, no credentials
    for _ in range(2655):
        text, secrets = scrub_fuzz.case(rng, **CORPORA["slow"][2])
    return text, secrets


def test_former_later_round_bound_case_now_equals_the_reference():
    """210k corpus seed 72037 index 2654 was the one later-round-bound case under the
    whole-text bounds (its second G4 round's text was past them). Under the per-region
    bounds no round of it hits a bound, so it is held to AT1: equality with the
    unbounded reference."""
    text, secrets = _seed_72037_case_2654()
    assert not scrub_oracle.bound(text)
    assert not scrub_oracle.regional_bound(text, secrets)
    assert not _later_round_bound(text, secrets)
    assert product.scrub(text, secrets) == scrub_oracle.reference_scrub(text, secrets)
    assert check(text, secrets)[2] is False


def test_later_round_bound_is_judged_by_at2(monkeypatch):
    """Ruling (c) routing, non-vacuous: when a round after the first hits a bound (here
    the oracle is made to report one for every text but the input), :func:`check` judges
    the case by AT2 (whose per-round (ii) non-vacuity is
    ``test_at2_checker_fails_on_injected_overmask``) and reports it as an exemption."""
    text, secrets = _seed_72037_case_2654()
    real_bound = scrub_oracle.regional_bound
    monkeypatch.setattr(
        scrub_oracle,
        "regional_bound",
        lambda view, values: True if view != text else real_bound(view, values),
    )
    assert _later_round_bound(text, secrets)
    assert check(text, secrets)[2] is True
