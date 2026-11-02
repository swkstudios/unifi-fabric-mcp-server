"""Random inputs for the scrubber property: secrets hidden under per-character escape
nesting, plus the escape-boundary cases reviewers reported."""

from __future__ import annotations

import html.entities
import random

SECRET_CHARS = "abcKXYZq0123456789-_.!~:@"
RARE_SECRET_CHARS = "%&\\\"'/ +=;#\u00e9\U0001f600"
FILLER = "abxuU0123456789fF%&\\#;:!-_ \"'/=.,\n"
#: Named entities that stand for one character, by that character.
NAMED_FOR = {}
for _name, _value in sorted(html.entities.html5.items(), key=lambda item: len(item[0])):
    if _name.endswith(";") and len(_value) == 1:
        NAMED_FOR.setdefault(_value, []).append(_name[:-1])
SINGLE_FOR = {"\a": "a", "\b": "b", "\f": "f", "\n": "n", "\r": "r", "\t": "t", "\v": "v"}
SINGLE_FOR.update({"\\": "\\", "'": "'", '"': '"', "/": "/"})

#: The reviewer's octal/encoded-digit leaks, and the same shape over every scheme.
REPORTED = [
    ("e\\1%301K!", "K!"),
    ("e\\1&#48;1K!", "K!"),
    ("%5c1&#0048;1K!", "K!"),
    ("&#92;1&#48;1K!", "K!"),
]


def _case(rng: random.Random, text: str) -> str:
    return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in text)


def encodings(rng: random.Random, char: str) -> list[str]:
    """Every escape this model decodes back to ``char``."""
    code = ord(char)
    out = []
    if code < 256:
        out.append("%" + _case(rng, f"{code:02x}"))
        out.append("\\x" + _case(rng, f"{code:02x}"))
    if code > 0xFFFF:  # an astral character: a UTF-16 surrogate pair (JSON, %u)
        high, low = 0xD800 + ((code - 0x10000) >> 10), 0xDC00 + ((code - 0x10000) & 0x3FF)
        out.append(f"\\u{high:04x}\\u{low:04x}")
        out.append(f"%u{high:04X}%u{low:04X}")
    else:
        out.append("%u" + _case(rng, f"{code:04x}"))
        out.append("\\u" + _case(rng, f"{code:04x}"))
    out.append("\\U" + _case(rng, f"{code:08x}"))
    if code < 512:
        out.append(f"\\{code:03o}")
        out.append(f"\\{code:o}")  # short octal: may wait for or swallow what follows
    if char in SINGLE_FOR:
        out.append("\\" + SINGLE_FOR[char])
    out.append("&#" + "0" * rng.randrange(3) + f"{code};")
    out.append("&#" + rng.choice("xX") + "0" * rng.randrange(3) + _case(rng, f"{code:x}") + ";")
    if char in NAMED_FOR:
        out.append("&" + rng.choice(NAMED_FOR[char]) + ";")
    return out


def nest(rng: random.Random, char: str, depth: int) -> str:
    """``char`` under ``depth`` layers of escapes: each layer re-escapes one character of
    the previous layer's text (its introducer, or any other: letters and digits too)."""
    text = rng.choice(encodings(rng, char))
    for _ in range(depth - 1):
        if rng.random() < 0.15:  # sometimes a whole layer over every character
            text = "".join(rng.choice(encodings(rng, c)) if rng.random() < 0.5 else c for c in text)
            if len(text) > 400:
                break
            continue
        index = 0 if rng.random() < 0.5 else rng.randrange(len(text))
        text = text[:index] + rng.choice(encodings(rng, text[index])) + text[index + 1 :]
    return text


def secret(rng: random.Random) -> str:
    size = rng.choice((1, 1, 2, 3, 4, 5, 6, 8))
    chars = [
        rng.choice(RARE_SECRET_CHARS) if rng.random() < 0.12 else rng.choice(SECRET_CHARS)
        for _ in range(size)
    ]
    value = "".join(chars)
    return value if value.strip() else value + "k"


def filler(rng: random.Random, size: int) -> str:
    return "".join(rng.choice(FILLER) for _ in range(size))


def plain_text(rng: random.Random, secrets: list[str]) -> str:
    """Random text holding the secrets (or not), next to random neighbours."""
    parts = [filler(rng, rng.randrange(6))]
    for _ in range(rng.randrange(4)):
        if secrets and rng.random() < 0.8:
            parts.append(rng.choice(secrets))
        parts.append(filler(rng, rng.randrange(5)))
    return "".join(parts)


def encode(rng: random.Random, text: str, max_depth: int) -> str:
    out = []
    for char in text:
        roll = rng.random()
        if roll < 0.35:
            out.append(char)
        else:
            out.append(nest(rng, char, rng.randrange(1, max_depth + 1)))
    return "".join(out)


#: Escape shapes the decoder treats specially: chains of one introducer decoding to
#: itself, backslash runs, long entity digit runs, octal escapes waiting on what follows.
CHAINS = {
    "%": ("%", "25"),
    "&": ("&", "amp;"),
    "\\": ("\\u005c", "u005c"),
    "\\134": ("\\134", "134"),
    "&#37;": ("&#37;", "25"),
}
CLOSERS = ("41", "20", "5c", "u0041", "x41", "134", "n", "#65;", "#x41;", "amp;", "1", "00", "%31")


def structured(rng: random.Random, chain_units: int = 39) -> str:
    """A run of the shapes above, mixed with escapes, digits and backslashes.

    ``chain_units`` caps the repeated units of a CHAINS run (39 for the reference
    corpus; the shallow corpus of SPEC-V2-A1 A3 uses 5)."""
    parts = []
    for _ in range(rng.randrange(1, 5)):
        roll = rng.random()
        if roll < 0.3:
            head, unit = rng.choice(list(CHAINS.values()))
            parts.append(head + unit * rng.randrange(0, chain_units + 1) + rng.choice(CLOSERS))
        elif roll < 0.5:
            parts.append("\\" * rng.randrange(1, 12) + rng.choice(CLOSERS + ("%5c", "&#92;")))
        elif roll < 0.65:
            # a long entity digit run, its introducer decoded or not, ended by a digit
            # or ";" that some later pass decodes
            digits = "0" * rng.randrange(10, 45) + rng.choice(
                ("", "3", "%33", "&#51;", "\\063", "%2533", "&#37;33", "%25%33", "&amp;#51;")
            )
            head = rng.choice(("&#", "&#", "&amp;#", "%26#", "&#38;#", "%26%23", "&"))
            parts.append(
                head
                + rng.choice(("", "x"))
                + digits
                + rng.choice(("7;", "%3b", "&#59;", "%253b", ""))
            )
        elif roll < 0.8:
            parts.append(
                "\\" + rng.choice("0123") + rng.choice(("%30", "&#48;", "\\x30", "%5c", ""))
            )
        else:
            parts.append(filler(rng, rng.randrange(1, 6)))
    return "".join(parts)


#: Escape fragments: concatenated at random they form escapes across their joins.
SOUP = (
    "%",
    "25",
    "5c",
    "5C",
    "\\",
    "u005c",
    "x5c",
    "134",
    "&",
    "amp;",
    "#",
    "92;",
    "37;",
    "x",
    "41",
    "0",
    "1",
    "3",
    ";",
    "u",
    "00",
    "30",
    "%3",
    "&#",
    "\\1",
    "K",
    "!",
    "a",
    " ",
)


def soup(rng: random.Random) -> str:
    return "".join(rng.choice(SOUP) for _ in range(rng.randrange(3, 40)))


def case(rng: random.Random, max_depth: int = 7, chain_units: int = 39) -> tuple[str, list[str]]:
    """One random input: ``(text, secrets)``.

    ``max_depth`` bounds :func:`nest` only; :func:`structured` and :func:`soup` emit
    chains deeper than that by design (SPEC-V2-A1 A4)."""
    roll = rng.random()
    if roll < 0.1:
        secrets = [rng.choice(("K", "K!", "a", "1K", "A", "!", "\\A", "%", "a1", "0a", " K"))]
        return soup(rng), secrets
    if roll < 0.25:
        secrets = [secret(rng) for _ in range(rng.choice((1, 1, 2)))]
        pieces = [structured(rng, chain_units)]
        for _ in range(rng.randrange(3)):
            piece = rng.choice(secrets)
            pieces.append(encode(rng, piece, 3) if rng.random() < 0.5 else piece)
            pieces.append(structured(rng, chain_units) if rng.random() < 0.6 else filler(rng, 2))
        return "".join(pieces), secrets
    roll = rng.random()
    if roll < 0.06:
        text, value = rng.choice(REPORTED)
        return encode(rng, text, 2) if rng.random() < 0.5 else text, [value]
    secrets = [secret(rng) for _ in range(rng.choice((1, 1, 1, 2)))]
    if roll < 0.12:
        # secrets split by an escape chain: one character deep, its neighbours plain
        target = rng.choice(secrets)
        split = rng.randrange(len(target))
        hidden = target[:split] + nest(rng, target[split], max_depth) + target[split + 1 :]
        return filler(rng, 3) + hidden + filler(rng, 3), secrets
    return encode(rng, plain_text(rng, secrets), max_depth), secrets
