"""Every decoded character keeps the independent oracle's exact source span."""

import pytest

from tests import scrub_oracle
from tests.test_secret_scrub_timing import family_text
from unifi_fabric.secret_scrub import _Closure, scrub, scrub_bytes


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
        "a" * 248 + r"%2541xyz",
        "a" * 249 + r"%2541xyz",
        family_text("mixed", 1024),
    ],
    ids=[
        "empty",
        "literal",
        "nested",
        "cross-family",
        "deleted",
        "adjacent-deleted",
        "multi-character",
        "mixed-width",
        "small-map-boundary",
        "typed-map-boundary",
        "saturated",
    ],
)
def test_all_view_source_spans_equal_independent_oracle(text):
    _, expected = scrub_oracle.closure(text)
    closure = _Closure(text)
    actual = [
        (
            view,
            tuple(
                (closure.source(index, pos, False), closure.source(index, pos, True))
                for pos in range(len(view))
            ),
        )
        for index, view in enumerate(closure.views)
    ]
    assert actual == expected


def test_leading_form_can_use_decoded_character_after_literal_gap():
    text = r"\x26!%41"
    expected = r"\x26***"
    assert scrub_oracle.reference_scrub(text, ("!A",)) == expected
    assert scrub(text, ("!A",)) == expected
    assert scrub_bytes(text.encode(), ("!A",)) == expected.encode()


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("hello %41", "hello A"),
        ("%41 hello", "A hello"),
        ("prefixprefix %41", "prefixprefix A"),
        ("%41 suffixsuffix", "A suffixsuffix"),
    ],
)
def test_already_masked_region_can_extend_mask_into_literal_context(text, secret):
    values = ("A", secret)
    assert scrub_oracle.reference_scrub(text, values) == "***"
    assert scrub(text, values) == "***"
    assert scrub_bytes(text.encode(), values) == b"***"
