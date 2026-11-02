"""Whole-window batch bounds, source unions, and exact first-match precedence."""

from __future__ import annotations

import pytest

from unifi_fabric import secret_scrub as scrubber


def _forms(monkeypatch, forms, fragments=()):
    monkeypatch.setattr(scrubber, "_raw_forms", lambda *_: forms)
    monkeypatch.setattr(scrubber, "_long_forms", lambda *_: frozenset(forms))
    monkeypatch.setattr(scrubber, "_fragments", lambda *_: fragments)
    chars = frozenset("".join(forms))
    width = max(map(len, forms), default=0)
    shortest = min(map(len, (*forms, *fragments)), default=0)
    monkeypatch.setattr(scrubber, "_join_tables", lambda *_: ((), (), chars, width, shortest))


@pytest.mark.parametrize("chars,windows", [(1024, 1), (3, 1024), (3, 1)])
def test_batches_preserve_every_source_span_and_form_priority(monkeypatch, chars, windows):
    _forms(monkeypatch, ("B", "A"))
    monkeypatch.setattr(scrubber, "_DECODED_BATCH_CHARS", chars)
    monkeypatch.setattr(scrubber, "_DECODED_BATCH_WINDOWS", windows)
    text = "|".join(["%41", "%42"] * 8)
    values = ("controlled-batch-forms",)
    regions = scrubber._regions(text, values, False, {})
    batches = list(scrubber._decoded_batches(text, regions, values, False, []))
    assert len(batches) == 16
    assert all(len(corpus) <= chars and len(batch) == 1 for corpus, batch, _ in batches)
    expected = [(start, start + 3) for start in range(0, len(text), 4)]
    assert scrubber._decoded_spans(text, regions, values, False, False, []) == expected
    # Form B wins even though form A occurs in the first batch.
    assert scrubber._decoded_spans(text, regions, values, False, True, []) == [(4, 7)]


def test_batches_preserve_fragment_priority_across_windows(monkeypatch):
    _forms(monkeypatch, (), ("BB", "AA"))
    monkeypatch.setattr(scrubber, "_DECODED_BATCH_WINDOWS", 1)
    text = "%41%41 %42%42"
    values = ("controlled-batch-fragments",)
    regions = scrubber._regions(text, values, False, {})
    assert scrubber._decoded_spans(text, regions, values, False, False, []) == [
        (0, 6),
        (7, 13),
    ]
    assert scrubber._decoded_spans(text, regions, values, False, True, []) == [(7, 13)]


def test_oversized_window_is_kept_whole_and_alone(monkeypatch):
    _forms(monkeypatch, ("A",))
    monkeypatch.setattr(scrubber, "_DECODED_BATCH_CHARS", 8)
    text = "%41" * 100 + "|%41"
    values = ("controlled-batch-oversize",)
    regions = scrubber._regions(text, values, False, {})
    batches = list(scrubber._decoded_batches(text, regions, values, False, []))
    assert [len(batch) for _, batch, _ in batches] == [1, 1]
    assert len(batches[0][0]) > 8
    assert all(len(corpus) <= 8 or len(batch) == 1 for corpus, batch, _ in batches)
    assert scrubber._decoded_spans(text, regions, values, False, False, []) == [
        (0, 300),
        (301, 304),
    ]
