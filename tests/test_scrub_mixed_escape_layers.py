import itertools

import pytest

from unifi_fabric.secret_scrub import scrub, scrub_bytes


def _layer(text, kind):
    # Keep alphanumerics literal: the final boundary must depend on decoding every layer.
    return "".join(
        c
        if c.isalnum()
        else {"%": f"%{ord(c):02x}", "&": f"&#{ord(c)};", "\\": f"\\u{ord(c):04x}"}[kind]
        for c in text
    )


def test_mixed_layers_every_secret_position():
    for order in itertools.product("%&\\", repeat=5):
        prefix = "\\n"
        for kind in order:
            prefix = _layer(prefix, kind)
        for position in range(3):
            parts = [prefix + "safe!"] * 3
            parts[position] = prefix + "K!"
            text = " ".join(parts)
            expected = text.replace("K!", "***!")
            assert scrub(text, ["K"]) == expected, order
            assert scrub_bytes(text.encode(), ["K"]) == expected.encode(), order


@pytest.mark.parametrize("prefix", ["e&#38;&#35;37;09", "%2526%252337%253B5Cn"])
def test_reported_mixed_chain(prefix):
    assert scrub(prefix + "K!", ["K"]) == prefix + "***!"
