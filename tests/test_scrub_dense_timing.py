"""Deterministic operation-count guards for dense scrub inputs.

The dense cases exercise the view and closure bounds without depending on host speed,
load, subprocess timing, or historical git objects. Decoder calls are counted at the
family boundary; every distinct region closure is counted once, including closures made
while deciding whether adjacent regions join.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from collections.abc import Iterable
from pathlib import Path

import pytest

import unifi_fabric.secret_scrub as candidate
from tests.test_secret_leak_invariant import CONFIGURED, _closed_echo_body, _echo_body

_PREAUTH_SECRETS = ("Sh1eldSentinelAAAA/BBBBcccc0123", "Q7x")
_MAX_DENSE_DECODES = {"echo": 5_000, "closed": 2_500}
_ORIGINAL_CLOSURE = candidate._Closure
_ORIGINAL_FAMILIES = candidate._FAMILIES
_BASELINE_PATH = Path(__file__).parent / "fixtures" / "scrub_baseline.py"
_BASELINE_SHA256 = "ac02ee7c3d260f784f007e4abbbc66f722ba79c7073f519f483c3bc7eedc63d7"
_spec = importlib.util.spec_from_file_location("scrub_baseline", _BASELINE_PATH)
assert _spec and _spec.loader
baseline = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = baseline
_spec.loader.exec_module(baseline)


def test_scrubber_baseline_is_pinned_and_matches_closed_error_corpus() -> None:
    """The restored public baseline keeps closed-body scrub behavior reproducible."""
    assert hashlib.sha256(_BASELINE_PATH.read_bytes()).hexdigest() == _BASELINE_SHA256
    body = _closed_echo_body(403)
    for operation in ("scrub", "scrub_bytes"):
        data = body if operation == "scrub" else body.encode()
        assert getattr(candidate, operation)(data, CONFIGURED) == getattr(baseline, operation)(
            data, CONFIGURED
        )


def _operation_profile(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    body: str,
    secrets: Iterable[str],
) -> tuple[str | bytes, dict[str, int]]:
    counts = {"closures": 0, "views": 0, "decode_calls": 0, "decode_chars": 0}

    class CountingClosure(_ORIGINAL_CLOSURE):  # type: ignore[misc, valid-type]
        __slots__ = ()

        def __init__(self, text: str) -> None:
            counts["closures"] += 1
            super().__init__(text)
            counts["views"] += len(self.views)

    def counted(layer):
        def decode(*args, **kwargs):
            counts["decode_calls"] += 1
            counts["decode_chars"] += len(args[1])
            return layer(*args, **kwargs)

        return decode

    monkeypatch.setattr(candidate, "_Closure", CountingClosure)
    monkeypatch.setattr(
        candidate,
        "_FAMILIES",
        tuple((intro, counted(layer)) for intro, layer in _ORIGINAL_FAMILIES),
    )
    candidate._memo_clear()
    data = body if operation == "scrub" else body.encode()
    result = getattr(candidate, operation)(data, tuple(secrets))
    # A closure can hold at most _MAX_VIEWS and tries at most one decoder per family
    # per view. This structural ceiling is independent of machine speed.
    assert counts["closures"] > 0
    assert counts["views"] <= counts["closures"] * candidate._MAX_VIEWS
    assert counts["decode_calls"] <= (
        counts["closures"] * candidate._MAX_VIEWS * len(candidate._FAMILIES)
    )
    return result, counts


@pytest.mark.parametrize("operation", ["scrub", "scrub_bytes"])
@pytest.mark.parametrize("body_name", sorted(("closed", "echo")))
def test_dense_body_operation_count_guard(body_name, operation, monkeypatch):
    build = _echo_body if body_name == "echo" else _closed_echo_body
    body = build(403)
    assert len(body) == (51_438 if body_name == "echo" else 30_567)
    assert bool(candidate._security_bound_spans(body, CONFIGURED)) is (body_name == "echo")

    result, counts = _operation_profile(monkeypatch, operation, body, CONFIGURED)
    assert counts["decode_calls"] <= _MAX_DENSE_DECODES[body_name], counts
    text = result if isinstance(result, str) else result.decode("latin-1")
    assert text


def _fit(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


PREAUTH_TARGETS = {
    "mixed_chain": "/" + _fit("%26%2523%5Cx41&#37;3\\u0025&#x5c;x", 1023),
    "mixed_dense": "/" + _fit("%41&#66;\\x43%u0044&amp;\\105", 1023),
    "short_dense": "/" + _fit("Q7x %51%37x &#81;7x \\x517x ", 1023),
    "pct25": "/" + _fit("%25", 1020) + "41",
}


# The fixed whole-token corpus reaches 16/8 views in its one mixed region;
# each view can attempt at most three families. Percent-only has three views
# (plus one boundary-view slack). Short secrets create at most five single-family
# regions across the ladder (plus one boundary-region slack). These bounds do not
# grow with the record length, unlike the removed 3*len(record) call ceiling.
_MAX_PREAUTH_DECODES = {
    "mixed_chain": 16 * 3,
    "mixed_dense": 8 * 3,
    "pct25": 3 + 1,
    "short_dense": 5 + 1,
}


@pytest.mark.parametrize("target", sorted(PREAUTH_TARGETS))
def test_preauth_access_record_operation_bound(target, monkeypatch):
    profiles = []
    for scale in (1, 4, 16):
        payload = "/" + PREAUTH_TARGETS[target][1:] * scale
        record = f'203.0.113.9:5555 - "GET {payload} HTTP/1.1" 401'
        result, counts = _operation_profile(monkeypatch, "scrub", record, _PREAUTH_SECRETS)
        assert isinstance(result, str)
        assert result
        assert counts["decode_calls"] <= _MAX_PREAUTH_DECODES[target], counts
        # Every bounded decoder call consumes at most the input record once.
        assert counts["decode_chars"] <= _MAX_PREAUTH_DECODES[target] * len(record), counts
        profiles.append(counts)
    for small, large in zip(profiles, profiles[1:], strict=False):
        # The shared AT4 model permits <=5x work at each 4x whole-token growth
        # step, covering fixed record and region-boundary overhead deterministically.
        assert large["decode_chars"] <= 5 * small["decode_chars"], profiles


@pytest.mark.parametrize("operation", ["scrub", "scrub_bytes"])
def test_dense_count_repeats_after_memo_clear(operation, monkeypatch):
    body = _echo_body(403)
    _, first = _operation_profile(monkeypatch, operation, body, CONFIGURED)
    _, second = _operation_profile(monkeypatch, operation, body, CONFIGURED)
    assert first == second
