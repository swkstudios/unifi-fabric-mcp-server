"""``mask_error_text`` runs in time linear in its input, without weakening the mask.

Every tool error passes through it (twice) under ``UNIFI_REDACT_SECRETS``, and an error
can echo a caller's argument in full, so one oversized bracket- or key-heavy string must
not hold the event loop for seconds. Shapes that defeat the linear scans are bounded by
a work budget: past it the text is withheld (fail closed), never returned unmasked.
"""

from __future__ import annotations

import json
import time

import pytest

from unifi_fabric.redaction import REDACTION_MASK, mask_error_text

#: Generous for a loaded CI runner; the unbounded masker took 16 s on 8,000 brackets.
LIMIT_SECONDS = 2.0
SECRET = "synthetic-secret-value-0001"


def _timed(text: str) -> tuple[str, float]:
    start = time.perf_counter()
    out = mask_error_text(text)
    return out, time.perf_counter() - start


@pytest.mark.parametrize(
    "text",
    [
        "(" * 8000,
        "{" * 8000,
        "[" * 8000,
        "[" * 4000 + "x" + "]" * 4000,
        "Invalid 'host' '" + "(" * 6000 + "\n'",
        "a=" * 8000,
        "a." * 8000 + "=v",
        'k=\\\\\\"' * 3000 + 'k=\\"' * 3000,
        "{'a': (" * 3000,
    ],
    ids=[
        "parens",
        "braces",
        "brackets",
        "balanced-invalid",
        "selector-echo",
        "bare-pairs",
        "dotted-key",
        "mixed-escape-quotes",
        "repr-openers",
    ],
)
def test_adversarial_error_text_is_masked_in_bounded_time(text: str) -> None:
    out, seconds = _timed(text)
    assert seconds < LIMIT_SECONDS, f"{seconds:.2f} s for {len(text)} chars"
    assert isinstance(out, str)


def test_the_time_grows_linearly() -> None:
    _, small = _timed("(" * 10000)
    _, large = _timed("(" * 40000)
    # Quadratic work would be 16x; allow noise well short of that.
    assert large < max(small, 0.05) * 8


def test_a_large_structured_error_is_still_masked_not_withheld() -> None:
    body = {"data": [{"name": f"row-{i}", "note": "x" * 40} for i in range(400)]}
    body["data"][200]["password"] = SECRET
    text = "HTTP 400 from PUT /v1/x: " + json.dumps(body)
    out, seconds = _timed(text)
    assert seconds < LIMIT_SECONDS
    assert SECRET not in out
    assert REDACTION_MASK in out
    assert "row-399" in out  # the diagnostics around the credential survive


def test_a_credential_after_an_unclosed_bracket_is_still_masked() -> None:
    out, _ = _timed("(" * 8000 + f" password={SECRET}")
    assert SECRET not in out


def _cpu(text: str) -> tuple[str, float]:
    start = time.process_time()
    out = mask_error_text(text)
    return out, time.process_time() - start


def test_many_short_pairs_scale_linearly_and_stay_unmasked() -> None:
    # Every key=value token of the fallback scan once copied the whole rest of the text:
    # 160,000 pairs took seconds and came back unchanged, never reaching the work bound.
    timings = {}
    for n in (10_000, 40_000, 160_000):
        text = "a=v " * n
        out, seconds = _cpu(text)
        assert out == text  # nothing credential-named: returned whole, not withheld
        timings[n] = seconds
    assert timings[160_000] < 2 * LIMIT_SECONDS  # CPU seconds; quadratic took 3 s here
    # 4x the pairs: linear work grows about 4x (measured 4.0); the quadratic copy grew
    # about 10x (2.94 s / 0.30 s).
    assert timings[160_000] < max(timings[40_000], 0.01) * 7


def test_a_credential_after_many_short_pairs_is_still_masked() -> None:
    out, _ = _cpu("a=v " * 160_000 + f"password={SECRET}")
    assert SECRET not in out
