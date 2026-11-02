"""The scrubber's bounds are per region, so
neither a leak nor a rewrite of secret-free data depends on the size of the text.

B-1 -- every byte of a matched secret is masked by ``scrub`` and ``scrub_bytes`` at any
body size. A secret holding separators (``/``, ``-``, ``+``) sits next to an escape
(JSON ``\\/``, octal, ``\\xNN``, ``%XX``, ``&#N;``, ``&amp;#N;``) inside an escape-dense
body, at sizes on both sides of the former 4,096-character view budget and of its
one-view floor (262,144 characters). Leak detection is partial: no 8-character window of
the secret, nor of its escaped text, may be left in the output.

B-2 -- a secret-free body comes back byte for byte, and ``contains_secret`` is False, at
every size and content type: binary (seeded random bytes, never decoded as text),
text/plain and JSON with escapes, through the core and through the client's 2xx path.

Synthetic sentinels only (a fresh random marker per run)."""

from __future__ import annotations

import json
import random
import secrets as token_source
import types

import httpx
import pytest

from unifi_fabric.client import UniFiClient
from unifi_fabric.secret_scrub import contains_secret, scrub, scrub_bytes

MARKER = "r" + token_source.token_hex(8)
SECRET = f"{MARKER}AAAA/BBBB-CCCC+DDDD"
OTHER = f"{MARKER}-other/key+9z"
CONFIGURED = (SECRET, OTHER)
WINDOW = 8

#: Across the former size-scaled budget: 4,096 (128 views), 131,072 (2 to 3 views),
#: 262,144 (one view, raw only) and beyond.
LEAK_SIZES = (2_000, 4_096, 4_097, 20_000, 150_000, 300_000, 700_000)
#: Escape-dense, secret-free filler: every family, nested, quotes and separators.
FILLER = 'x%20y &amp; \\n z\\x41 %2541 &#38;#65; "q\\"" a/b+c-d \\\\x41 %u0041 '


def windows(value: str) -> set[str]:
    return {value[i : i + WINDOW] for i in range(len(value) - WINDOW + 1)}


def escaped(secret: str, family: str, separator: str) -> str:
    """``secret`` with the character after its first ``separator`` written in
    ``family`` (or, for ``json-slash``, every ``/`` written ``\\/``)."""
    if family == "json-slash":
        return secret.replace("/", "\\/")
    at = secret.index(separator) + 1
    code = ord(secret[at])
    unit = {
        "octal": f"\\{code:o}",
        "hex": f"\\x{code:02x}",
        "percent": f"%{code:02X}",
        "entity": f"&#{code};",
        "amp-entity": f"&amp;#{code};",
    }[family]
    return secret[:at] + unit + secret[at + 1 :]


CONTEXTS = (
    ("json-slash", "/"),
    ("octal", "/"),
    ("hex", "+"),
    ("percent", "-"),
    ("percent", "+"),
    ("entity", "/"),
    ("amp-entity", "-"),
)


def leak_body(size: int, encoded: str, where: str) -> str:
    """``encoded`` in an escape-dense body of ``size`` characters: spaced at the start,
    the middle or the end, or glued to the filler on both sides."""
    room = size - len(encoded) - 2
    pad = (FILLER * (room // len(FILLER) + 1))[:room]
    if where == "start":
        return " " + encoded + " " + pad
    if where == "end":
        return pad + " " + encoded + " "
    half = room // 2
    if where == "glued":
        return pad[:half] + "q" + encoded + "q" + pad[half:]
    return pad[:half] + " " + encoded + " " + pad[half:]


def assert_no_window(out: str, encoded: str, label: str) -> None:
    survivors = sorted(w for w in windows(SECRET) | windows(encoded) if w in out)
    assert not survivors, (label, survivors[:5])


@pytest.mark.parametrize("size", LEAK_SIZES)
@pytest.mark.parametrize(("family", "separator"), CONTEXTS, ids=[f"{f}-{s}" for f, s in CONTEXTS])
def test_separator_secret_next_to_an_escape_is_masked_at_any_size(size, family, separator):
    encoded = escaped(SECRET, family, separator)
    assert encoded != SECRET or family == "json-slash"
    for where in ("start", "middle", "end", "glued"):
        text = leak_body(size, encoded, where)
        assert len(text) == size
        label = (size, family, separator, where)
        assert_no_window(scrub(text, CONFIGURED), encoded, ("scrub", *label))
        out = scrub_bytes(text.encode(), CONFIGURED).decode("latin-1")
        assert_no_window(out, encoded, ("scrub_bytes", *label))
        assert contains_secret(text, CONFIGURED), ("contains_secret", *label)


def test_partial_window_check_is_not_vacuous():
    """The window check rejects an output that keeps 8 characters of the secret."""
    encoded = escaped(SECRET, "json-slash", "/")
    with pytest.raises(AssertionError):
        assert_no_window("***" + SECRET[5:13] + "***", encoded, "injected")
    with pytest.raises(AssertionError):
        assert_no_window("***" + encoded[-8:], encoded, "injected")
    assert_no_window("*** " + SECRET[:7] + " ***", encoded, "seven characters")


# ---------------------------------------------------------------------------- B-2
#: Across the former bound (175 KB was the first size rewritten) to over a megabyte.
CLEAN_SIZES = (4_096, 175_000, 300_000, 1_100_000)


def binary_body(size: int) -> bytes:
    return random.Random(f"b2-binary-{size}").randbytes(size)  # noqa: S311 - test data


def text_body(size: int) -> bytes:
    unit = b"line with \\n escape and %20 and &amp; ok \\x41 &#66; %2541 \\\\u0041 a/b\n"
    return (unit * (size // len(unit) + 1))[:size]


def json_body(size: int) -> bytes:
    item = 'café "q" a/b %20 &amp; \\n \\x41 &#38;#65; %2541'
    data = json.dumps({"d": [item] * (size // 40 + 1)}).encode()
    return data[: data.rfind(b",")] + b"]}"


BODIES = {"binary": binary_body, "text": text_body, "json": json_body}


@pytest.mark.parametrize("size", CLEAN_SIZES)
@pytest.mark.parametrize("kind", sorted(BODIES))
def test_secret_free_body_is_returned_byte_for_byte(kind, size):
    data = BODIES[kind](size)
    assert scrub_bytes(data, CONFIGURED) == data, (kind, size)
    assert contains_secret(data, CONFIGURED) is False, (kind, size)
    if kind != "binary":  # a binary body is never decoded as text
        text = data.decode()
        assert scrub(text, CONFIGURED) == text, (kind, size)
        assert contains_secret(text, CONFIGURED) is False, (kind, size)


@pytest.mark.parametrize(
    ("size", "content_type", "kind"),
    [
        (200_000, "image/jpeg", "binary"),
        (400_000, "image/jpeg", "binary"),
        (400_000, "text/plain", "text"),
        (440_000, "application/json", "json"),
        (1_100_000, "application/octet-stream", "binary"),
    ],
)
def test_secret_free_2xx_body_is_verbatim_through_the_client(size, content_type, kind):
    data = BODIES[kind](size)
    response = httpx.Response(
        200,
        content=data,
        headers={"content-type": content_type},
        request=httpx.Request("GET", "http://unifi.invalid/x"),
    )
    holder = types.SimpleNamespace(_settings=None)
    key = types.SimpleNamespace(key=SECRET)
    out = UniFiClient._scrubbed_response(holder, response, key)
    assert out.content == data, (content_type, size)


def test_secret_in_a_large_2xx_binary_body_is_still_masked():
    """The verbatim guarantee is for secret-free data: an echoed key is still masked."""
    data = bytearray(binary_body(400_000))
    data[200_000:200_000] = b" " + SECRET.encode() + b" "
    response = httpx.Response(
        200,
        content=bytes(data),
        headers={"content-type": "image/jpeg"},
        request=httpx.Request("GET", "http://unifi.invalid/x"),
    )
    holder = types.SimpleNamespace(_settings=None)
    out = UniFiClient._scrubbed_response(holder, response, types.SimpleNamespace(key=SECRET))
    assert SECRET.encode() not in out.content
    assert len(out.content) == len(data) - len(SECRET) + 3
