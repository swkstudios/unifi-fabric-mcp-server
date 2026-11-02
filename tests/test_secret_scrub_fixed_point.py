"""G2 gap reuse and the conservative G4 fixed-point shortcut."""

from __future__ import annotations

import pytest

from unifi_fabric import secret_scrub as product


def test_repeated_gap_keeps_each_decoded_endpoint_decision(monkeypatch):
    # Same gap, but only the first pair of decoded endpoints can form the secret.
    text, values = "%41 %42 %43 %44", ("A B",)
    calls = []
    original = product._join_pairs

    def counted(forms, gap):
        calls.append(gap)
        return original(forms, gap)

    monkeypatch.setattr(product, "_join_pairs", counted)
    with product.secret_scope(values):
        assert product.scrub(text, values) == "*** %43 %44"
    # One region pass per G4 round; every identical gap shares its candidate scan.
    assert calls == [" ", " "]


@pytest.mark.parametrize("entries,gap_chars", [(1, 256), (256, 0)])
def test_join_memo_eviction_and_nonadmission_preserve_masking(monkeypatch, entries, gap_chars):
    monkeypatch.setattr(product, "_JOIN_CACHE_ENTRIES", entries)
    monkeypatch.setattr(product, "_JOIN_CACHE_GAP_CHARS", gap_chars)
    values = ("A B", "C:D")
    text = "%41 %42|%43:%44|%45 %46|%47:%48"
    with product.secret_scope(values):
        assert product.scrub(text, values) == "***|***|%45 %46|%47:%48"


LONG = "LongSyntheticSecret42"
ENCODED = "".join(f"%{ord(char):02X}" for char in LONG)


@pytest.mark.parametrize(
    "text,values,expected,rounds",
    [
        (f"prefix {LONG} suffix %41 %42", (LONG,), "prefix *** suffix %41 %42", 1),
        (f"%41|{ENCODED}|%42", (LONG,), "%41|***|%42", 1),
        (f"{LONG}%41", (LONG,), "***%41", 2),
        (f"%4{LONG}1", (LONG,), "%4***1", 2),
        ("%41 KEY", ("KEY",), "%41 ***", 2),
        ("Long*SyntheticSecret42 %41", ("Long*SyntheticSecret42",), "*** %41", 2),
    ],
)
def test_fixed_point_shortcut_and_fallback(text, values, expected, rounds, monkeypatch):
    original = product._spans
    calls = []

    def counted(*args, **kwargs):
        calls.append(None)
        return original(*args, **kwargs)

    monkeypatch.setattr(product, "_spans", counted)
    with product.secret_scope(values):
        assert product.scrub(text, values) == expected
    assert len(calls) == rounds

    # Exercise the complete loop independently of the optimized result/memo.
    monkeypatch.setattr(product, "_mask_stable_forms", lambda *_: False)
    for fn, body, result in (
        (product.scrub, text, expected),
        (product.scrub_bytes, text.encode(), expected.encode()),
        (product.contains_secret, text, True),
        (product.contains_secret, text.encode(), True),
    ):
        with product.secret_scope(values):
            assert fn(body, values) == result
