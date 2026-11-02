"""One central scrubber for configured server secrets in responses, errors and logs.

Every configured secret -- each UniFi API key (``UNIFI_API_KEY`` and every ``key`` in
``UNIFI_API_KEYS``), the transport bearer token (``MCP_BEARER_TOKEN``) and the TLS
private-key password (``MCP_TLS_KEY_PASSWORD``) -- is replaced by ``***`` in any text
this server raises, returns or logs: client transport errors, upstream response bodies
and headers (which may echo a request header back), tool errors,
audit-log lines, log records (message, arguments and exception text, for every handler)
and the placement-snapshot CLI.

A secret is matched in every form a message can carry it (see :func:`secret_forms`):

* raw, and with surrounding whitespace stripped;
* Python ``str`` and ``bytes`` repr escaping (``b'KEY\\n'`` in an httpx ``Illegal header
  value`` error), ``unicode_escape`` and JSON string escaping (ASCII and non-ASCII), and
  each of those escapings applied twice (a repr of a message that already holds one);
* URL percent-encoding: ``quote`` with no safe characters and with the default safe
  ``/``, and ``quote_plus``, each with upper- and lower-case hex digits;
* standard and URL-safe base64, padded or not, of the secret alone (``Bearer <b64>``)
  and of the secret embedded after any prefix (``Basic base64(user:secret)``: the whole
  base64 token holding it is masked);
* hexadecimal (upper- and lower-case) of its UTF-8 bytes;
* UTF-16 (little- and big-endian) code units, as text and as hexadecimal;
* and under ANY nesting of percent, backslash and HTML-entity escapes, character by
  character (``%4B%45%59``, ``&#x4b;\\x45&amp;#89;``, ``%2525...41`` at any depth): the
  text is decoded the way repeated unescaping would (the decoding model is described at
  :func:`_decode`) and the secret -- or its UTF-8 bytes read one byte per character --
  is matched in every partial decoding; the whole source span that decodes to it is
  masked.

Every configured secret is scrubbed, whatever its length (one character is enough).
Each match is a WHOLE TOKEN: no ASCII letter or
digit directly before or after it, EXCEPT that on the left a decoded escape, or a
complete escape sequence ending in a letter or digit -- ``%XX`` / ``%uXXXX``, ``\\xNN``,
``\\uNNNN``, ``\\UNNNNNNNN``, octal ``\\N`` (any one to three digits) and ``\\n``
``\\t`` ``\\r`` (and the other single-letter C escapes) -- is a boundary too, in the
text or in any partial decoding of it: a key after ``%20`` in a ``Location`` header,
after ``\\n`` in a JSON-escaped message or after ``\\x0a`` in a bytes repr is masked. An
escape that ends in punctuation (``\\\\``, ``\\"``, ``&#10;``, ``&amp;``) already ends
in a non-word character; after the secret, every escape starts with one (``%``, ``\\``,
``&``), so the right boundary needs no exception. A short secret therefore also masks
the same text where it stands alone as a word (``admin`` in ``user admin``): the price
of never leaking it. The embedded-base64 match (``Basic base64(user:secret)``) needs at
least four base64 characters that depend on the secret alone, so it applies to secrets
of three bytes or more; the plain base64 form of a shorter secret is still matched.
Masking can make the text next to a mask a whole token, so the result is scrubbed again
until nothing is left to mask.

No configured value makes the scrubber raise: a value that is not encodable as
UTF-8 (a lone surrogate) is matched in every form that can carry it, and a form that
cannot be built for it is skipped. Settings reject such a credential at load, naming the
variable.

Upstream response bodies and headers are scrubbed only for configured server-secret
values, in every status including 2xx. Scrubbing also covers exception messages,
log records and the audit log. JSON string values and keys are scrubbed without
changing scalar types or syntax. Binary bodies use :func:`scrub_bytes` and are never
decoded or re-encoded.

This applies only to the server's OWN configured credentials. Unrelated upstream data is never
filtered here: credential fields of a response or an error body are masked only by the
opt-in ``UNIFI_REDACT_SECRETS`` (see :mod:`unifi_fabric.redaction`).
"""

from __future__ import annotations

import base64
import hashlib
import html.entities
import json
import logging
import os
import re
import sys
import threading
import weakref
from bisect import bisect_left, bisect_right
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import lru_cache
from heapq import heappop, heappush
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, quote_plus

if TYPE_CHECKING:
    from .config import MCPTransportSettings, Settings

MASK = "***"

#: Environment variables that each hold one secret value.
SECRET_ENV_VARS = ("UNIFI_API_KEY", "MCP_BEARER_TOKEN", "MCP_TLS_KEY_PASSWORD")
#: Environment variable holding a JSON list of ``{"key": ...}`` objects.
KEYS_ENV_VAR = "UNIFI_API_KEYS"

#: The shortest base64 fragment of an embedded secret that is matched (shorter
#: fragments carry too few bits of the secret and would match unrelated text).
_MIN_FRAGMENT = 4

_PERCENT_HEX = re.compile(r"%[0-9A-F]{2}")


def _env_secrets() -> list[str]:
    values = [os.environ.get(name, "") for name in SECRET_ENV_VARS]
    raw = os.environ.get(KEYS_ENV_VAR, "")
    if raw.strip():
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            values.extend(
                item["key"]
                for item in parsed
                if isinstance(item, dict) and isinstance(item.get("key"), str)
            )
    return values


# Per-call secrets: credential values that belong to ONE tool call rather than to the
# server's configuration -- a caller-supplied secret argument (a Matter setup code, a
# SIM PIN, a device password) or a value a registered route sends or returns (see
# ``route_secrets``). They live in a call scope, never in settings or on disk, and every
# free-text channel of that call (errors, hints, validation messages, logs, audit
# lines) and the result of a failed or partial write is scrubbed of them. Structured
# data of a successful call follows the opt-in ``UNIFI_REDACT_SECRETS`` instead.
#
# This is the one per-call mechanism:
# * the server's outermost tool-call middleware opens a scope with :func:`secret_scope`
#   (the registered and credential-named arguments, bound before validation can echo
#   them);
# * the client chokepoint and tool helpers use :func:`request_secret_scope`, which adds
#   to the enclosing call scope, or opens one for a standalone request;
# * :func:`add_call_secrets` adds a value discovered mid-call (a response secret) to the
#   enclosing scope;
# * :func:`configured_secrets` (``include_call=True``, the default) and the log scrubber
#   read the scope, so every scrubbing sink sees the bound values.
#
# The scope holder is mutable and shared by child tasks (``asyncio.gather``): a value a
# child binds reaches its parent's error scrubbing; a nested scope restores the
# enclosing one on exit. Every bound value is scrubbed whatever its length, like a
# configured secret (a 4-digit PIN is a secret). Matching is case-sensitive.
@dataclass
class _CallSecrets:
    values: tuple[str, ...] = ()
    text_cache: dict[tuple[str, tuple[str, ...]], str] = field(default_factory=dict)


_call_secrets: ContextVar[_CallSecrets | None] = ContextVar("unifi_call_secrets", default=None)


def call_secret_values() -> tuple[str, ...]:
    """The secrets bound to the current call scope (empty outside a scope)."""
    state = _call_secrets.get()
    return state.values if state is not None else ()


def _bound_values(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({v for v in values if isinstance(v, str) and v.strip()}))


@contextmanager
def secret_scope(values: Iterable[str] = ()) -> Iterator[None]:
    """Bind error/log secrets for this scope and its inherited child task contexts.

    Children share the holder, so additions discovered under gather reach the parent.
    Reset only this context on exit: surviving children still need their inherited
    secrets. Nested explicit scopes restore the enclosing scope on exit.
    """
    state = _CallSecrets(_bound_values((*call_secret_values(), *values)))
    binding = _call_secrets.set(state)
    try:
        yield
    finally:
        _call_secrets.reset(binding)


@contextmanager
def request_secret_scope(values: Iterable[str] = ()) -> Iterator[None]:
    """Bind ``values`` into the enclosing call scope, or open one when there is none.

    Inside a tool call the values stay bound until the call ends, so an error raised
    after the request (in the tool or a middleware) is still scrubbed of them. A
    standalone request (no tool call) gets its own scope, dropped when it ends.
    """
    if _call_secrets.get() is not None:
        add_call_secrets(values)
        yield
    else:
        with secret_scope(values):
            yield


def add_call_secrets(values: Iterable[str]) -> None:
    """Add values to the active call scope; outside a scope this is a no-op.

    Client requests always open or reuse a scope. A mutable holder is deliberately
    shared by child tasks, unlike rebinding a ContextVar tuple. Duplicate additions
    preserve cached work; new values invalidate the bounded, per-scope text cache.
    """
    state = _call_secrets.get()
    if state is None:
        return
    combined = tuple(sorted(set(state.values) | set(_bound_values(values))))
    if combined != state.values:
        state.values = combined
        state.text_cache.clear()


def configured_secrets(
    settings: Settings | None = None,
    transport: MCPTransportSettings | None = None,
    extra: Iterable[str] = (),
    *,
    include_call: bool = True,
) -> tuple[str, ...]:
    """Every configured secret: the environment's, plus those of the given settings.

    ``include_call`` adds the secrets bound to the current call (:func:`secret_scope`).
    Message channels and failed (non-2xx) results include them; the structured data of
    a successful upstream response excludes them (opt-in ``UNIFI_REDACT_SECRETS``).
    """
    values: list[str] = _env_secrets()
    if settings is not None:
        values.append(settings.api_key)
        values.extend(cfg.key for cfg in settings.api_keys)
    if transport is not None:
        values.extend((transport.bearer_token, transport.tls_key_password))
    values.extend(extra)
    if include_call:
        values.extend(call_secret_values())
    return tuple(sorted({v for v in values if isinstance(v, str) and v.strip()}))


def _escapes(text: str) -> set[str]:
    """The ways one string can be escaped inside a message."""
    out = {text}
    out.add(repr(text)[1:-1])
    out.add(text.encode("unicode_escape").decode("ascii"))
    out.add(repr(text.encode("utf-8", "surrogatepass"))[2:-1])
    out.add(json.dumps(text)[1:-1])
    out.add(json.dumps(text, ensure_ascii=False)[1:-1])
    # A repr whose text holds both quote kinds escapes the one it is delimited by
    # (``'b"KEY\\'S"'``): the same escaping with each quote kind forced.
    for item in list(out):
        out.add(item.replace("'", "\\'"))
        out.add(item.replace('"', '\\"'))
        out.add(item.replace("'", "\\'").replace('"', '\\"'))
    return out


def _url_forms(text: str) -> set[str]:
    """Percent-encodings of ``text``: quote (no safe / default safe ``/``), quote_plus.

    ``surrogatepass`` so a lone surrogate (not encodable as UTF-8) never raises."""
    errors = "surrogatepass"
    encoded = {
        quote(text, safe="", errors=errors),
        quote(text, errors=errors),
        quote_plus(text, safe="", errors=errors),
        quote_plus(text, errors=errors),
    }
    lower = {_PERCENT_HEX.sub(lambda m: m.group(0).lower(), item) for item in encoded}
    return encoded | lower


def _base64_forms(raw: bytes) -> set[str]:
    """Standard and URL-safe base64 of ``raw`` alone, padded and unpadded."""
    forms: set[str] = set()
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        text = encode(raw).decode("ascii")
        forms |= {text, text.rstrip("=")}
    return forms


def _embedded_base64_fragments(raw: bytes) -> set[str]:
    """The base64 characters of ``raw`` embedded after a prefix of any length.

    An embedded secret (``base64(b"user:" + secret)``) shifts by the prefix length mod 3;
    for each shift, the characters that encode the secret's bits only (none of the
    prefix's or of what follows) are the same whatever surrounds it. The whole base64
    token holding such a fragment is masked.
    """
    forms: set[str] = set()
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        for shift in (0, 1, 2):
            encoded = encode(b"\x00" * shift + raw).decode("ascii").rstrip("=")
            first = -(-8 * shift // 6)  # first character holding no prefix bits
            last = (8 * (shift + len(raw))) // 6  # end of the characters holding no suffix
            fragment = encoded[first:last]
            if len(fragment) >= _MIN_FRAGMENT:
                forms.add(fragment)
    return forms


def _base_forms(base: str) -> set[str]:
    """Every form of one (unstripped or stripped) secret value. Each family is built on
    its own, so a family that cannot carry an unusual value is skipped while
    every other family -- and the raw value -- is still matched."""
    forms: set[str] = {base}
    raw = base.encode("utf-8", "surrogatepass")
    builders: tuple[Callable[[], set[str]], ...] = (
        lambda: {form for item in _escapes(base) for form in _escapes(item)},
        lambda: _base64_forms(raw),
        lambda: _url_forms(base),
        lambda: {raw.hex(), raw.hex().upper()},
        lambda: _utf16_forms(base),
    )
    for build in builders:
        try:
            forms |= build()
        except (ValueError, UnicodeError):  # pragma: no cover - every family is lossless
            continue
    return forms


def _utf16_forms(base: str) -> set[str]:
    forms: set[str] = set()
    for codec in ("utf-16-le", "utf-16-be"):
        units = base.encode(codec, "surrogatepass")
        forms |= {units.decode("latin-1"), units.hex(), units.hex().upper()}
    return forms


def secret_forms(secret: str) -> set[str]:
    """Every searchable form of one secret (see the module docstring for the list)."""
    forms: set[str] = set()
    for base in {secret, secret.strip()}:
        if base.strip():
            forms |= _base_forms(base)
    return {f for f in forms if f.strip()}


def scrubbable(secrets: Iterable[str]) -> tuple[str, ...]:
    """The secrets the scrubber matches: every configured string that is not blank,
    whatever its length."""
    return tuple(sorted({s for s in secrets if isinstance(s, str) and s.strip()}))


@lru_cache(maxsize=64)
def _forms(secrets: tuple[str, ...]) -> tuple[str, ...]:
    """Every searchable form of every scrubbable secret, longest first."""
    forms: set[str] = set()
    for secret in scrubbable(secrets):
        forms |= secret_forms(secret)
    return tuple(sorted(forms, key=lambda f: (-len(f), f)))


@lru_cache(maxsize=64)
def _fragments(secrets: tuple[str, ...]) -> tuple[str, ...]:
    """The prefix-independent base64 fragments of every scrubbable secret embedded after
    a prefix (``Basic base64(user:secret)``), matched inside a base64 token."""
    out: set[str] = set()
    for secret in scrubbable(secrets):
        for base in {secret, secret.strip()}:
            out |= _embedded_base64_fragments(base.encode("utf-8", "surrogatepass"))
    return tuple(sorted(out, key=lambda f: (-len(f), f)))


#: An ASCII letter or digit: the characters a whole-token match may not touch.
_WORD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

# Each pattern below is ONE character class repeated, matched at a known position: it
# runs in time linear in what it consumes (no alternation, no adjacent repeats).
_WORD_RUN = re.compile(r"[A-Za-z0-9]*")
#: The characters of a base64 token (standard and URL-safe alphabets), then padding.
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]*")
_PAD_RUN = re.compile(r"=*")


@lru_cache(maxsize=64)
def _bytes_forms(secrets: tuple[str, ...]) -> tuple[bytes, ...]:
    """Every form as UTF-8 bytes, and as Latin-1 where that differs (raw UTF-16 code
    units), so a body is searched without being decoded; longest first."""
    out: set[bytes] = set()
    for form in _forms(secrets):
        out.add(form.encode("utf-8", "surrogatepass"))
        try:
            out.add(form.encode("latin-1"))
        except UnicodeEncodeError:
            pass
    return tuple(sorted(out, key=lambda f: (-len(f), f)))


# ------------------------------------------------------------------ escape decoding
#: The characters that open an escape.
_INTRO = frozenset("%\\&")
_INTRODUCER = re.compile(r"[%\\&]")
_HEX = frozenset("0123456789abcdefABCDEF")
_OCT = frozenset("01234567")
_DEC = frozenset("0123456789")
_ALPHA = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
#: The characters an escape body continues through before its last character.
_BODY = _WORD | {"#"}
_SINGLE = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "/": "/",
}
_WIDTH = {"x": 2, "u": 4, "U": 8}
#: Characters other than letters and digits that can end an escape.
_CAN_END_ESCAPE = frozenset(";\\'\"/")
#: HTML5 named entities that stand for one character, by name (without ``;``).
_NAMED = {
    name[:-1]: value
    for name, value in html.entities.html5.items()
    if name.endswith(";") and len(value) == 1
}
_MAX_NAME = 31  # the longest name in _NAMED (checked at import below)
_MAX_CODE = 0x10FFFF
#: The most nodes from an introducer to the last character of its escape.
_REACH = _MAX_NAME + 2

#: One complete escape at a raw position (the first pass, over undecoded text).
_UNIT = re.compile(
    r"%(?:u[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2})"
    r"|\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{3}"
    r"|[0-7]{1,2}(?![0-7%\\&])|[abfnrtv\\'\"/])"
    r"|&(?:#[0-9]+;|#[xX][0-9A-Fa-f]+;|[A-Za-z][A-Za-z0-9]{0,30};)"
)
#: The body of one escape after a decoded introducer, over undecoded text.
_CHAIN_BODY = {
    "%": re.compile(r"u[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}"),
    "\\": re.compile(r"x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[abfnrtv'\"/]"),
    "&": re.compile(r"#[0-9]+;|#[xX][0-9A-Fa-f]+;|[A-Za-z][A-Za-z0-9]{0,30};"),
}
_DEC_RUN = re.compile(r"[0-9]*")
_LONG_NUMERIC = re.compile(r"&#[xX]?[0-9A-Fa-f]{16,}")
_HEX_RUN = re.compile(r"[0-9A-Fa-f]*")
#: A complete escape ending in a letter or digit, in the raw text: where one ends, a
#: whole-token match may start (an octal escape at each of its digits). None of them can
#: start inside another, so a plain scan finds them all.
_WORD_ESCAPE_FIXED = re.compile(
    r"%(?:u[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2})|\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|[abfnrtv])"
)
_WORD_ESCAPE_WIDE = re.compile(r"\\U([0-9A-Fa-f]{8})")
_OCTAL_ESCAPE = re.compile(r"\\[0-7]{1,3}")
_WORD_ESCAPE_FULL = re.compile(
    r"%(?:u[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2})"
    r"|\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[abfnrtv])"
)
assert max(map(len, _NAMED)) == _MAX_NAME  # noqa: S101 - the patterns above use 31


def _numeric(digits: str, base: int) -> str | None:
    digits = digits.lstrip("0")
    if len(digits) > 7:
        return None
    value = int(digits or "0", base)
    return chr(value) if value <= _MAX_CODE else None


def _unit_char(unit: str) -> str | None:
    """The character one complete escape stands for, or None when it is out of range."""
    intro, kind = unit[0], unit[1]
    if intro == "%":
        return chr(int(unit[2:] if kind == "u" else unit[1:], 16))
    if intro == "\\":
        if kind in _WIDTH:
            value = int(unit[2:], 16)
            return chr(value) if value <= _MAX_CODE else None
        if kind in _OCT:
            return chr(int(unit[1:], 8))
        return _SINGLE[kind]
    if kind == "#":
        if unit[2] in "xX":
            return _numeric(unit[3:-1], 16)
        return _numeric(unit[2:-1], 10)
    return _NAMED.get(unit[1:-1])


def _word_escape_ok(unit: str) -> bool:
    return not (unit.startswith("\\U") and int(unit[2:], 16) > _MAX_CODE)


class _Forest:
    """Every node of a text's decoding, and the whole-token boundary rule over them.

    ``starts`` / ``ends`` / ``chars`` list every decoded node (a single raw character is
    a node too, implicitly), in the order the passes made them; ``last_start[p]`` /
    ``last_end[p]`` is the last node starting / ending at ``p`` (-1: none) and
    ``same_start[i]`` / ``same_end[i]`` the node made before node ``i`` with the same
    start / end, so the nodes at a position are a chain, built as the passes run.
    """

    __slots__ = (
        "text",
        "size",
        "has_intro",
        "starts",
        "ends",
        "chars",
        "same_start",
        "same_end",
        "last_start",
        "last_end",
        "_starts_sorted",
        "_ends_sorted",
        "_escape_ends",
        "_escape_ends_sorted",
        "_chars_starting",
        "_runs",
    )

    def __init__(self, text: str) -> None:
        self.text = text
        self.size = len(text)
        self.has_intro = _INTRODUCER.search(text) is not None
        self.starts: list[int] = []
        self.ends: list[int] = []
        self.chars: list[str] = []
        self.same_start: list[int] = []
        self.same_end: list[int] = []
        self.last_start: list[int] = []
        self.last_end: list[int] = []
        self._starts_sorted: list[int] | None = None
        self._ends_sorted: list[int] | None = None
        self._escape_ends: set[int] | None = None
        self._escape_ends_sorted: list[int] = []
        self._chars_starting: dict[int, str] = {}
        self._runs: dict[int, int] = {}

    # -- indexes, built on first use
    def chars_starting(self, pos: int) -> str:
        """The distinct characters of the decoded nodes that start at ``pos``."""
        found = self._chars_starting.get(pos)
        if found is None:
            found = ""
            index = self.last_start[pos] if self.starts else -1
            while index >= 0:
                if self.chars[index] not in found:
                    found += self.chars[index]
                index = self.same_start[index]
            self._chars_starting[pos] = found
        return found

    def _raw_escape_ends(self) -> set[int]:
        if self._escape_ends is None:
            text = self.text
            ends = {match.end() for match in _WORD_ESCAPE_FIXED.finditer(text)}
            ends.update(
                match.end()
                for match in _WORD_ESCAPE_WIDE.finditer(text)
                if int(match.group(1), 16) <= _MAX_CODE
            )
            for match in _OCTAL_ESCAPE.finditer(text):
                ends.update(range(match.start() + 2, match.end() + 1))
            self._escape_ends = ends
            self._escape_ends_sorted = sorted(ends)
        return self._escape_ends

    # -- the boundary rule
    def left_ok(self, pos: int) -> bool:
        """True when a whole-token match may start at ``pos``: at the start, after a
        character that is not a letter or digit, after a decoded node, or after a
        complete escape (in any partial decoding) that ends in a letter or digit."""
        if pos == 0 or self.text[pos - 1] not in _WORD:
            return True
        if not self.has_intro:
            return False
        if self.starts and self.last_end[pos] >= 0:
            return True
        escapes = self._escape_ends
        if escapes is None:
            escapes = self._raw_escape_ends()
        if pos in escapes:
            return True
        return bool(self.starts) and self._mixed_escape_end(pos)

    def _mixed_escape_end(self, pos: int) -> bool:
        """A complete letter/digit-ending escape spelled by adjacent nodes, at least one
        of them decoded, ends at ``pos`` (``%5c10`` decodes to an octal prefix)."""
        text, starts, chars = self.text, self.starts, self.chars
        last_end, same_end = self.last_end, self.same_end
        stack: list[tuple[int, str, bool]] = [(pos, "", False)]
        while stack:
            end, suffix, decoded = stack.pop()
            if end == 0 or len(suffix) >= 10:
                continue
            options = [(end - 1, text[end - 1], False)]
            index = last_end[end]
            while index >= 0:
                options.append((starts[index], chars[index], True))
                index = same_end[index]
            for start, char, is_decoded in options:
                spelled = char + suffix
                has_decoded = decoded or is_decoded
                if char in "%\\":
                    if (
                        has_decoded
                        and _WORD_ESCAPE_FULL.fullmatch(spelled)
                        and _word_escape_ok(spelled)
                    ):
                        return True
                elif char in _WORD:
                    stack.append((start, spelled, has_decoded))
        return False

    def next_start(self, pos: int) -> int:
        """After a failed whole-token match at ``pos`` (inside a letter/digit run), the
        next position in that run where one could start, or the run's end."""
        run_end = self._runs.get(pos)
        if run_end is None:
            match = _WORD_RUN.match(self.text, pos)
            run_end = match.end() if match else pos + 1
        best = run_end
        if self.starts:
            if self._ends_sorted is None:
                self._ends_sorted = sorted(set(self.ends))
            ends = self._ends_sorted
            index = bisect_right(ends, pos - 9)
            if index < len(ends):
                best = min(best, pos + 1 if ends[index] <= pos else ends[index])
        if self.has_intro:
            self._raw_escape_ends()
            escape_ends = self._escape_ends_sorted
            index = bisect_right(escape_ends, pos)
            if index < len(escape_ends):
                best = min(best, escape_ends[index])
        target = max(best, pos + 1)
        if target < run_end:
            self._runs[target] = run_end
        return target

    # -- paths of nodes
    def paths(self, pos: int, rest: str) -> list[int]:
        """The ends of every run of adjacent nodes from ``pos`` spelling ``rest``."""
        if not rest:
            return [pos]
        text, size = self.text, self.size
        if self._starts_sorted is None:
            self._starts_sorted = sorted(set(self.starts))
        starts_sorted = self._starts_sorted
        count = len(starts_sorted)
        last_start, same_start, chars, ends = (
            self.last_start,
            self.same_start,
            self.chars,
            self.ends,
        )
        length = len(rest)
        out: list[int] = []
        stack = [(pos, 0)]
        while stack:
            at, index = stack.pop()
            if index == length:
                out.append(at)
                continue
            if at >= size:
                continue
            char = rest[index]
            node = last_start[at]
            if node >= 0:
                if text[at] == char:
                    stack.append((at + 1, index + 1))
                while node >= 0:
                    if chars[node] == char:
                        stack.append((ends[node], index + 1))
                    node = same_start[node]
                continue
            # raw characters up to the next node start
            following = bisect_left(starts_sorted, at)
            limit = starts_sorted[following] if following < count else size
            span = min(limit - at, length - index)
            if text.startswith(rest[index : index + span], at):
                stack.append((at + span, index + span))
        return out


def _decode_nodes(forest: _Forest) -> None:
    """Record every node of the forest's text's decoding in it, by the repeated-pass
    model, pass by pass but only where the previous pass changed something (see
    :func:`_decode`)."""
    text = forest.text
    size = len(text)
    starts, ends, chars = forest.starts, forest.ends, forest.chars
    same_start, same_end = forest.same_start, forest.same_end
    last_start = forest.last_start = [-1] * (size + 1)
    last_end = forest.last_end = [-1] * (size + 1)
    # The current pass's text: a decoded node starting at ``s`` ends at ``end_at[s]``
    # (0: a raw character) with ``char_at[s]``, made by pass ``birth_at[s]``;
    # ``start_of_end[e] - 1`` is the node ending at ``e``.
    end_at = [0] * (size + 1)
    char_at = [""] * (size + 1)
    birth_at = [0] * (size + 1)
    start_of_end = [0] * (size + 1)
    dead = bytearray(size + 1)
    # Failed escapes waiting on the escape at a position: when a node starts there,
    # they are tried again.
    watchers: dict[int, list[int]] = {}
    pending: dict[int, list[int]] = {}
    passes: list[int] = []
    runs: dict[tuple[int, bool], tuple[int, str | None]] = {}

    def add(start: int, end: int, char: str) -> None:
        index = len(starts)
        starts.append(start)
        ends.append(end)
        chars.append(char)
        same_start.append(last_start[start])
        last_start[start] = index
        same_end.append(last_end[end])
        last_end[end] = index

    def queue(number: int) -> list[int]:
        """The starts to try in pass ``number``."""
        found = pending.get(number)
        if found is None:
            found = pending[number] = []
            heappush(passes, number)
        return found

    def walk_back(start: int, number: int) -> int:
        """The nearest introducer before the node made at ``start`` in pass ``number``,
        through escape-body characters only: its escape may now reach (or wait on)
        that node. -1 when there is none, or when a node made in the same pass comes
        first (its own walk covers what lies before it)."""
        pos, steps = start, 0
        while pos > 0 and steps < _REACH:
            prev = start_of_end[pos]
            if prev:
                prev -= 1
                if birth_at[prev] == number:
                    return -1
                before = char_at[prev]
            else:
                prev = pos - 1
                before = text[prev]
            if before in _INTRO:
                return prev
            if before not in _BODY:
                return -1
            pos, steps = prev, steps + 1
        return -1

    def created(start: int, char: str, number: int, target: list[int]) -> None:
        """Queue (in ``target``, pass ``number + 1``) every escape the node just made at
        ``start`` can change: its own, those that stopped at it, the one before it."""
        if char in _INTRO:
            target.append(start)
        if watchers:
            waiting = watchers.pop(start, None)
            if waiting:
                target.extend(waiting)
        prev = start_of_end[start]
        if prev and birth_at[prev - 1] == number:
            return  # the node before was made this pass: its walk covers the rest
        before = walk_back(start, number)
        if before >= 0:
            target.append(before)

    def chain(start: int, char: str, number: int) -> int:
        """Follow a decoded introducer that decodes to itself again over plain escape
        text (``%2525...``, ``&amp;amp;...``), one pass per step, in one loop. Only
        this node's end and pass change meanwhile: whatever reads it from the left sees
        the same introducer, a queued try of this node for a pass it has already made
        is skipped, and the step that yields another character is left to its own pass.
        A backslash is followed only when nothing before it can become a backslash that
        pairs with it. Returns the pass of the last step."""
        if char == "\\" and start:
            prev = start_of_end[start]
            before = char_at[prev - 1] if prev else text[start - 1]
            if before in _WORD or before in _CAN_END_ESCAPE:
                return number
        body = _CHAIN_BODY[char]
        while True:
            end = end_at[start]
            match = body.match(text, end)
            if match is None:
                break
            unit = char + match.group()
            after = match.end()
            if char == "\\" and unit[1] in _OCT and len(unit) < 4 and after < size:
                follower = char_at[after] if end_at[after] else text[after]
                if follower in _INTRO or follower in _OCT:
                    break
            if _unit_char(unit) != char:
                break
            number += 1
            start_of_end[end] = 0
            end_at[start] = after
            birth_at[start] = number
            start_of_end[after] = start + 1
            index = len(starts)
            starts.append(start)
            ends.append(after)
            chars.append(char)
            same_start.append(last_start[start])
            last_start[start] = index
            same_end.append(last_end[after])
            last_end[after] = index
        queue(number + 1).append(start)
        return number

    def digit_run(pos: int, hexadecimal: bool) -> tuple[int, str | None]:
        """The raw digit run at ``pos``: its end and its digits without leading zeroes
        (None past seven significant digits, which no code point has)."""
        key = (pos, hexadecimal)
        found = runs.get(key)
        if found is None:
            match = (_HEX_RUN if hexadecimal else _DEC_RUN).match(text, pos)
            end = match.end() if match else pos
            digits = text[pos:end].lstrip("0")
            found = (end, digits if len(digits) <= 7 else None)
            runs[key] = found
        return found

    def attempt(pos: int, char: str) -> tuple[int, str, list[int]] | int:
        """The longest complete escape whose introducer node (``char``) ends at ``pos``,
        over the current pass's text: ``(end, character, nodes it takes)``; on failure,
        the position of the introducer whose own decoding it waits on, or -1 when
        nothing that follows can change."""
        if pos >= size:
            return -1
        kids: list[int] = []
        end = end_at[pos]
        found = char_at[pos] if end else text[pos]
        end = end or pos + 1
        if char == "%" or (char == "\\" and found in _WIDTH):
            if char == "%":
                width = 4 if found == "u" else 2
            else:
                width = _WIDTH[found]
            if char == "\\" or found == "u":
                kids.append(pos)
                pos = end
            digits = ""
            while len(digits) < width:
                if pos >= size:
                    return -1
                end = end_at[pos]
                found = char_at[pos] if end else text[pos]
                if found not in _HEX:
                    return pos if found in _INTRO else -1
                kids.append(pos)
                digits += found
                pos = end or pos + 1
            value = int(digits, 16)
            return (pos, chr(value), kids) if value <= _MAX_CODE else -1
        if char == "\\":
            if found in _OCT:
                digits = ""
                while len(digits) < 3 and pos < size:
                    end = end_at[pos]
                    found = char_at[pos] if end else text[pos]
                    if found not in _OCT:
                        break
                    kids.append(pos)
                    digits += found
                    pos = end or pos + 1
                if len(digits) < 3 and pos < size and found in _INTRO:
                    return pos  # waits for that escape's own decoding
                return pos, chr(int(digits, 8)), kids
            if found in _SINGLE:
                kids.append(pos)
                return end, _SINGLE[found], kids
            return pos if found in _INTRO else -1
        # "&"
        if found == "#":
            kids.append(pos)
            pos = end
            if pos >= size:
                return -1
            end = end_at[pos]
            found = char_at[pos] if end else text[pos]
            hexadecimal = found in ("x", "X")
            if hexadecimal:
                kids.append(pos)
                pos = end or pos + 1
            alphabet = _HEX if hexadecimal else _DEC
            significant, count = "", 0
            while True:
                if pos >= size:
                    return -1
                end = end_at[pos]
                if not end and text[pos] in alphabet:
                    run_end, run_digits = digit_run(pos, hexadecimal)
                    if run_digits is None:
                        return -1
                    if significant:
                        significant += text[pos:run_end]
                    else:
                        significant = run_digits
                    if len(significant) > 7:
                        return -1
                    count += run_end - pos
                    pos = run_end
                    continue
                found = char_at[pos] if end else text[pos]
                end = end or pos + 1
                if found in alphabet:
                    if significant or found != "0":
                        significant += found
                        if len(significant) > 7:
                            return -1
                    kids.append(pos)
                    count += 1
                    pos = end
                    continue
                if found == ";" and count:
                    kids.append(pos)
                    value = int(significant or "0", 16 if hexadecimal else 10)
                    return (end, chr(value), kids) if value <= _MAX_CODE else -1
                return pos if found in _INTRO else -1
        if found in _ALPHA:
            name = ""
            while len(name) <= _MAX_NAME:
                if found == ";":
                    named = _NAMED.get(name)
                    if named is None:
                        return -1
                    kids.append(pos)
                    return end, named, kids
                if found not in _WORD:
                    return pos if found in _INTRO else -1
                kids.append(pos)
                name += found
                pos = end
                if pos >= size:
                    return -1
                end = end_at[pos]
                found = char_at[pos] if end else text[pos]
                end = end or pos + 1
            return -1
        return pos if found in _INTRO else -1

    # Pass 1: one scan of the raw text (a unit that is out of range is not an escape:
    # the scan resumes right after its introducer).
    units: dict[str, str | None] = {}
    made: list[int] = []
    search = _UNIT.search
    pos = 0
    while True:
        match = search(text, pos)
        if match is None:
            break
        start, unit = match.start(), match.group()
        char = units.get(unit, "")
        if char == "":
            char = units[unit] = _unit_char(unit)
        if char is None:
            pos = start + 1
            continue
        pos = match.end()
        end_at[start] = pos
        char_at[start] = char
        birth_at[start] = 1
        start_of_end[pos] = start + 1
        made.append(start)
    for start in made:
        end = end_at[start]
        index = len(starts)
        starts.append(start)
        ends.append(end)
        chars.append(char_at[start])
        same_start.append(last_start[start])
        last_start[start] = index
        same_end.append(last_end[end])
        last_end[end] = index
    # A failed entity whose digit run is longer than the walk back reaches waits on
    # the escape that ends its digits (``&#000...%33``).
    for match in _LONG_NUMERIC.finditer(text):
        after = match.end()
        if after < size and text[after] in _INTRO and not end_at[match.start()]:
            watchers.setdefault(after, []).append(match.start())
    if made:
        second = queue(2)
        previous_end = -1
        for start in made:
            char = char_at[start]
            if char in _INTRO:
                second.append(start)
            if watchers:
                waiting = watchers.pop(start, None)
                if waiting:
                    second.extend(waiting)
            if start != previous_end:  # else the node before is new: its walk covers it
                before = walk_back(start, 1)
                if before >= 0:
                    second.append(before)
            previous_end = end_at[start]
    # Later passes: only what the previous one queued.
    while passes:
        number = heappop(passes)
        current = pending.pop(number)
        if len(current) > 1:
            current.sort()
        last = -1
        following_queue: list[int] | None = None
        for start in current:
            if start == last or dead[start] or birth_at[start] >= number:
                continue  # consumed, or already advanced past this pass by chain()
            last = start
            end = end_at[start]
            char = char_at[start] if end else text[start]
            if char not in _INTRO:
                continue
            following = end or start + 1
            if char == "\\" and following < size:
                # The commonest step, inline: two backslash nodes make one.
                next_end = end_at[following]
                if (char_at[following] if next_end else text[following]) == "\\":
                    if following_queue is None:
                        following_queue = queue(number + 1)
                    if next_end:
                        end_at[following] = 0
                        start_of_end[next_end] = 0
                    else:
                        next_end = following + 1
                    dead[following] = 1
                    if end:
                        start_of_end[end] = 0
                    end_at[start] = next_end
                    char_at[start] = "\\"
                    birth_at[start] = number
                    start_of_end[next_end] = start + 1
                    index = len(starts)
                    starts.append(start)
                    ends.append(next_end)
                    chars.append("\\")
                    same_start.append(last_start[start])
                    last_start[start] = index
                    same_end.append(last_end[next_end])
                    last_end[next_end] = index
                    if watchers:
                        waiting = watchers.pop(following, None)
                        if waiting:
                            following_queue.extend(waiting)
                    prev = start_of_end[start]
                    left = char_at[prev - 1] if prev else (text[start - 1] if start else "")
                    if start and (left in _WORD or left in _CAN_END_ESCAPE):
                        # no chain() (a backslash before may pair with it): queue as
                        # created() would
                        following_queue.append(start)
                        if watchers:
                            waiting = watchers.pop(start, None)
                            if waiting:
                                following_queue.extend(waiting)
                        if not (prev and birth_at[prev - 1] == number):
                            found_before = walk_back(start, number)
                            if found_before >= 0:
                                following_queue.append(found_before)
                        continue
                    made_in = chain(start, "\\", number)
                    created(
                        start,
                        "\\",
                        made_in,
                        following_queue if made_in == number else queue(made_in + 1),
                    )
                    continue
            result: tuple[int, str, list[int]] | int
            if following < size and not end_at[following]:
                # an escape body of plain characters, over raw text (no node can start
                # inside one); an octal escape needs what follows it settled
                match = _CHAIN_BODY[char].match(text, following)
                value = None
                if match is not None:
                    unit = char + match.group()
                    after = match.end()
                    if char == "\\" and unit[1] in _OCT and len(unit) < 4 and after < size:
                        follower = char_at[after] if end_at[after] else text[after]
                        if not (follower in _INTRO or follower in _OCT):
                            value = units.get(unit, "")
                            if value == "":
                                value = units[unit] = _unit_char(unit)
                    else:
                        value = units.get(unit, "")
                        if value == "":
                            value = units[unit] = _unit_char(unit)
                result = (after, value, []) if value is not None else attempt(following, char)
            else:
                result = attempt(following, char)
            if isinstance(result, int):
                if result >= 0:
                    watchers.setdefault(result, []).append(start)
                continue
            end, value, kids = result
            if following_queue is None:
                following_queue = pending.get(number + 1)
                if following_queue is None:
                    following_queue = pending[number + 1] = []
                    heappush(passes, number + 1)
            for kid in kids:
                kid_end = end_at[kid]
                if kid_end:
                    end_at[kid] = 0
                    start_of_end[kid_end] = 0
                dead[kid] = 1
                if watchers:
                    waiting = watchers.pop(kid, None)
                    if waiting:
                        following_queue.extend(waiting)
            old = end_at[start]
            if old:
                start_of_end[old] = 0
            end_at[start] = end
            char_at[start] = value
            birth_at[start] = number
            start_of_end[end] = start + 1
            index = len(starts)
            starts.append(start)
            ends.append(end)
            chars.append(value)
            same_start.append(last_start[start])
            last_start[start] = index
            same_end.append(last_end[end])
            last_end[end] = index
            if value in _INTRO:
                made_in = chain(start, value, number)
                if made_in != number:
                    created(start, value, made_in, queue(made_in + 1))
                    continue
                following_queue.append(start)
            if watchers:
                waiting = watchers.pop(start, None)
                if waiting:
                    following_queue.extend(waiting)
            prev = start_of_end[start]
            if not (prev and birth_at[prev - 1] == number):
                found_before = walk_back(start, number)
                if found_before >= 0:
                    following_queue.append(found_before)


def _decode(text: str) -> _Forest:
    """Every escape node of ``text``'s decoding (none when it holds no introducer).

    The decoding model, the scrubber's contract (checked against an independent
    reference in the tests): a pass reads the text left to right and decodes, at each
    position, the longest complete escape that starts there -- ``%XX`` / ``%uXXXX``;
    ``\\xXX`` / ``\\uXXXX`` / ``\\UXXXXXXXX``; octal ``\\N`` (one to three digits; a
    shorter octal escape directly followed by ``%`` / ``\\`` / ``&`` waits for that
    escape's own decoding: ``\\1%301`` decodes to ``\\101``, then ``A``); the single
    character escapes ``\\a \\b \\f \\n \\r \\t \\v \\\\ \\' \\" \\/``; HTML numeric
    entities (any number of leading zeroes) and every single-character HTML5 named
    entity, ``;`` terminated -- then continues after it. Passes repeat until one changes
    nothing. Each decoded character is a node spanning the source text it came from; a
    secret is matched in every partial decoding (any run of adjacent nodes, decoded or
    raw), which includes the text of every pass, and the source span under a match is
    masked.

    It runs in time linear in the text: after the first pass (one regex scan), a pass
    re-tries only the escapes the previous pass can have changed -- a new node's own
    introducer, the nearest introducer before it whose escape body reaches it, and any
    escape that stopped at it -- and a decoded introducer that decodes to itself again
    over plain escape text (``%2525...``) is followed in one loop.
    """
    forest = _Forest(text)
    if forest.has_intro:
        _decode_nodes(forest)
    return forest


# --------------------------------------------------------------------------- matching
@lru_cache(maxsize=64)
def _variants(secrets: tuple[str, ...]) -> tuple[str, ...]:
    """Each secret (and stripped) as decoding yields it: as text, as its UTF-8 bytes
    read one byte per character (``%C3%A9`` decodes to the two characters of ``é``'s
    bytes), and as UTF-16 code units (``\\ud83d\\ude00`` decodes to two surrogates)."""
    out: set[str] = set()
    for secret in scrubbable(secrets):
        for base in {secret, secret.strip()}:
            if base.strip():
                out.add(base)
                out.add(base.encode("utf-8", "surrogatepass").decode("latin-1"))
                units = base.encode("utf-16-le", "surrogatepass")
                out.add(
                    "".join(
                        chr(int.from_bytes(units[i : i + 2], "little"))
                        for i in range(0, len(units), 2)
                    )
                )
    return tuple(sorted(out, key=lambda f: (-len(f), f)))


#: Where a decoded node can sit in a variant: the rest of the variant after it, and
#: whether its first / last characters are a letter or digit (the whole-token rule
#: applies on that side) -- grouped under the variant's text before it (raw text there).
_Anchor = tuple[str, bool, bool]
_Anchors = dict[str, tuple[_Anchor, ...]]
_END = ""  # the "next character" of a variant's last character


@lru_cache(maxsize=64)
def _anchor_index(
    secrets: tuple[str, ...],
) -> tuple[dict[tuple[str, str], dict[str, _Anchors]], dict[str, frozenset[str]]]:
    """Every place a decoded node can sit in a variant, by ``(its character, the next
    character)`` (``""`` at a variant's end), then by the raw character before it
    (``""`` at a variant's start), then by the variant's text before it -- so a node is
    checked only where its neighbours already fit, each distinct prefix once; and the
    characters that can follow each character in a variant."""
    index: dict[tuple[str, str], dict[str, dict[str, list[_Anchor]]]] = {}
    for variant in _variants(secrets):
        head, tail = variant[0] in _WORD, variant[-1] in _WORD
        for offset, char in enumerate(variant):
            before = variant[offset - 1] if offset else ""
            after = variant[offset + 1] if offset + 1 < len(variant) else _END
            by_before = index.setdefault((char, after), {})
            by_prefix = by_before.setdefault(before, {})
            by_prefix.setdefault(variant[:offset], []).append((variant[offset + 1 :], head, tail))
    nexts_for: dict[str, set[str]] = {}
    for char, after in index:
        if after != _END:
            nexts_for.setdefault(char, set()).add(after)
    return (
        {
            key: {
                before: {prefix: tuple(items) for prefix, items in by_prefix.items()}
                for before, by_prefix in by_before.items()
            }
            for key, by_before in index.items()
        },
        {char: frozenset(afters) for char, afters in nexts_for.items()},
    )


@lru_cache(maxsize=128)
def _raw_forms(secrets: tuple[str, ...], as_bytes: bool) -> tuple[str, ...]:
    """Every form searched in the undecoded text (bytes read one byte per character)."""
    forms = set(_variants(secrets))
    if as_bytes:
        forms.update(form.decode("latin-1") for form in _bytes_forms(secrets))
    else:
        forms.update(_forms(secrets))
    return tuple(sorted(forms, key=lambda f: (-len(f), f)))


def _raw_spans(forest: _Forest, form: str, found: list[tuple[int, int]], first_only: bool) -> None:
    """Every whole-token occurrence of ``form`` in the undecoded text. A failed
    candidate inside a letter/digit run skips to the next place one could start."""
    text, size, length = forest.text, forest.size, len(form)
    head = form[0] in _WORD
    tail = form[-1] in _WORD
    all_word = head and tail and all(char in _WORD for char in form)
    pos = 0
    while True:
        idx = text.find(form, pos)
        if idx < 0:
            return
        stop = idx + length
        left = not head or forest.left_ok(idx)
        if left and (not tail or stop == size or text[stop] not in _WORD):
            found.append((idx, stop))
            if first_only:
                return
            pos = stop
        elif all_word and not left:
            pos = forest.next_start(idx)
        else:
            pos = idx + 1


def _decoded_spans(
    forest: _Forest,
    secrets: tuple[str, ...],
    found: list[tuple[int, int]],
    first_only: bool,
) -> None:
    """Every whole-token run of adjacent nodes, at least one decoded, spelling a
    variant: anchored at its first decoded node (raw characters before it). A node is
    looked at only where its own and its neighbours' characters fit a variant."""
    index, nexts_for = _anchor_index(secrets)
    get = index.get
    text, size = forest.text, forest.size
    chars, last_start, same_start = forest.chars, forest.last_start, forest.same_start
    for start, end, char in zip(forest.starts, forest.ends, chars, strict=True):
        at_end = get((char, _END))
        after_set = nexts_for.get(char)
        if not (at_end or after_set):
            continue  # its character ends no variant and continues none
        keys: list[dict[str, _Anchors] | None] = [at_end] if at_end else []
        if after_set and end < size:
            if text[end] in after_set:
                keys.append(get((char, text[end])))
            node, steps = last_start[end], 0
            while node >= 0 and steps < 8:  # the decoded nodes starting at ``end``
                if chars[node] in after_set:
                    keys.append(get((char, chars[node])))
                node, steps = same_start[node], steps + 1
            if node >= 0:  # a long chain of them: its distinct characters
                keys.extend(
                    get((char, after)) for after in forest.chars_starting(end) if after in after_set
                )
        if not keys:
            continue
        before = text[start - 1] if start else ""
        for by_before in keys:
            if not by_before:
                continue
            for left in (before, "") if before else ("",):
                by_prefix = by_before.get(left)
                if not by_prefix:
                    continue
                for prefix, anchors in by_prefix.items():
                    begin = start - len(prefix)
                    if begin < 0 or (prefix and not text.startswith(prefix, begin)):
                        continue
                    for rest, head, tail in anchors:
                        for stop in forest.paths(end, rest):
                            if tail and stop < size and text[stop] in _WORD:
                                continue
                            if head and not forest.left_ok(begin):
                                break
                            found.append((begin, stop))
                            if first_only:
                                return


def _spans(
    data: str, values: tuple[str, ...], as_bytes: bool = False, first_only: bool = False
) -> list[tuple[int, int]]:
    """The merged, sorted spans of ``data`` (bytes read one byte per character) that
    hold a form of a secret, in the text or in any partial decoding of it."""
    forest = _decode(data)
    found: list[tuple[int, int]] = []
    for form in _raw_forms(values, as_bytes):
        _raw_spans(forest, form, found, first_only)
        if first_only and found:
            return found
    if forest.starts:
        _decoded_spans(forest, values, found, first_only)
        if first_only and found:
            return found
    fragments = _fragments(values)
    if fragments:
        found.extend(_fragment_spans(data, fragments, _B64_RUN, _PAD_RUN))
    found.sort()
    merged: list[tuple[int, int]] = []
    for start, end in found:
        if merged and start < merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def _fragment_spans(
    data: Any,
    fragments: tuple[Any, ...],
    b64_run: re.Pattern[Any],
    pad_run: re.Pattern[Any],
) -> list[tuple[int, int]]:
    """The whole base64 token (with its ``=`` padding) around every embedded-secret
    fragment: each fragment is found by substring search, then the token is expanded
    outward over the base64 alphabet, left and right, and the search resumes after it
    -- linear in ``len(data)`` (no regex with an unbounded leading repeat)."""
    runs: list[tuple[int, int]] = []
    reversed_data = None
    size = len(data)
    for fragment in fragments:
        pos = 0
        while True:
            idx = data.find(fragment, pos)
            if idx < 0:
                break
            if reversed_data is None:
                reversed_data = data[::-1]
            left = b64_run.match(reversed_data, size - idx)
            start = idx - (left.end() - left.start() if left else 0)
            right = b64_run.match(data, idx)
            end = right.end() if right else idx + len(fragment)
            pad = pad_run.match(data, end)
            end = pad.end() if pad else end
            runs.append((start, end))
            pos = max(end, idx + 1)
    return runs


def _masked(data: Any, spans: list[tuple[int, int]], mask: Any) -> Any:
    parts: list[Any] = []
    pos = 0
    for start, end in spans:
        parts.append(data[pos:start])
        parts.append(mask)
        pos = end
    parts.append(data[pos:])
    return data[:0].join(parts)


def _scrub_rounds(view: str, values: tuple[str, ...], as_bytes: bool) -> tuple[str, bool, bool]:
    """``view`` masked until no form of a secret is left in it or in any partial
    decoding of it. Masking can turn a neighbour of a mask into a whole token (the
    letter before it is gone), so the result is checked again; each round masks at
    least one more character that is not ``*`` (a round that only rewrites runs of
    ``*`` is the last), so this ends.

    Returns ``(result, found, clean)``: whether the first round found a form of a
    secret (what :func:`contains_secret` answers), and whether the last round found
    none in the result (so scrubbing the result again returns it unchanged)."""
    found = False
    while True:
        spans = _spans(view, values, as_bytes)
        if not spans:
            return view, found, True
        found = True
        masked = _masked(view, spans, MASK)
        if masked == view:
            return view, found, False
        stars = len(view) - view.count("*")
        view = masked
        if len(view) - view.count("*") == stars:
            return view, found, False


# ---------------------------------------------------------------- repeat-scrub memo
# One text is scrubbed many times on its way out: a log record's completed message by
# the record factory, then the formatter's and the handler's output and the emitted
# line; an exception's text when its chain is checked and again when its stand-in is
# built; a response body by contains_secret, then by scrub_bytes. Each is a full decode
# of the text (on a large escape-dense error body, most of the scrubbing time), so the
# outcome of scrubbing a large text is remembered by the SHA-256 digest of the text --
# never the text itself, which may hold a secret -- with the configured secrets (already
# held by the form caches above) and the str/bytes mode: whether it holds a secret, and
# its scrubbed result (what the caller is returned anyway, never the input). A result
# that is a fixed point is remembered as clean too, so scrubbing it again is free.
# Bounded in entries and in the characters of the results kept.
#: Shorter texts are scrubbed again rather than hashed (their decode costs less).
_MEMO_MIN_CHARS = 4096
_MEMO_MAX_ENTRIES = 64
_MEMO_MAX_CHARS = 4_000_000
_MemoKey = tuple[tuple[str, ...], bool, bytes]
#: digest key -> (whether the text holds a form of a secret, its scrubbed result;
#: None when the result is the text itself)
_memo: OrderedDict[_MemoKey, tuple[bool, str | None]] = OrderedDict()
_memo_chars = 0
_memo_lock = threading.Lock()


def _memo_key(view: str, values: tuple[str, ...], as_bytes: bool) -> _MemoKey:
    digest = hashlib.sha256(view.encode("utf-8", "surrogatepass")).digest()
    return values, as_bytes, digest


def _memo_get(key: _MemoKey) -> tuple[bool, str | None] | None:
    with _memo_lock:
        hit = _memo.get(key)
        if hit is not None:
            _memo.move_to_end(key)
        return hit


def _memo_put(key: _MemoKey, found: bool, result: str | None) -> None:
    global _memo_chars
    with _memo_lock:
        old = _memo.pop(key, None)
        if old is not None and old[1] is not None:
            _memo_chars -= len(old[1])
        _memo[key] = (found, result)
        _memo_chars += len(result) if result is not None else 0
        while len(_memo) > _MEMO_MAX_ENTRIES or _memo_chars > _MEMO_MAX_CHARS:
            _, (_, dropped) = _memo.popitem(last=False)
            _memo_chars -= len(dropped) if dropped is not None else 0


def _memo_clear() -> None:
    """Forget every remembered outcome (timing tests measure the scrub itself)."""
    global _memo_chars
    with _memo_lock:
        _memo.clear()
        _memo_chars = 0


def _scrub_outcome(view: str, values: tuple[str, ...], as_bytes: bool) -> tuple[bool, str]:
    """Whether ``view`` holds a form of a secret, and ``view`` scrubbed (see
    :func:`_scrub_rounds`); remembered for a large text."""
    if len(view) < _MEMO_MIN_CHARS:
        result, found, _clean = _scrub_rounds(view, values, as_bytes)
        return found, result
    key = _memo_key(view, values, as_bytes)
    hit = _memo_get(key)
    if hit is not None:
        found, kept = hit
        return found, view if kept is None else kept
    result, found, clean = _scrub_rounds(view, values, as_bytes)
    _memo_put(key, found, None if result == view else result)
    if found and clean and result != view and len(result) >= _MEMO_MIN_CHARS:
        _memo_put(_memo_key(result, values, as_bytes), False, None)
    return found, result


def _scrub_view(view: str, values: tuple[str, ...], as_bytes: bool) -> str:
    return _scrub_outcome(view, values, as_bytes)[1]


def _contains_view(view: str, values: tuple[str, ...], as_bytes: bool) -> bool:
    """True when ``view`` holds a form of a secret. A large text is scrubbed in full
    (decoding it is most of the work either way) and the outcome remembered, so the
    scrub that follows a positive answer costs nothing more."""
    if len(view) < _MEMO_MIN_CHARS:
        return bool(_spans(view, values, as_bytes, first_only=True))
    return _scrub_outcome(view, values, as_bytes)[0]


def scrub(text: str, secrets: Iterable[str] | None = None) -> str:
    """``text`` with every form of every configured secret replaced by ``***``.

    ``secrets`` defaults to the environment's configured secrets. Every secret is
    matched, whatever its length, as a whole token (no ASCII letter or digit directly
    before or after it; an escape sequence directly before it counts as a boundary), in
    the text and in every partial decoding of its escapes (the model is described at
    :func:`_decode`). Matching is substring search plus a decoder that revisits only what a pass
    changed, never a backtracking regex: the time is linear in the length of ``text``
    whatever it holds. Never raises on any configured value.
    """
    values = tuple(sorted(set(secrets))) if secrets is not None else configured_secrets()
    if not text or not values:
        return text
    state = _call_secrets.get()
    if state is None or not state.values or len(text) >= _MEMO_MIN_CHARS:
        # A large text is remembered by digest in the bounded global memo instead.
        return _scrub_view(text, values, False)
    # Factory/filter/formatter paths often render the same short text repeatedly. Keep
    # those results inside the call holder, never in a global cache of caller text.
    cache_key = (text, values)
    if cache_key not in state.text_cache:
        if len(state.text_cache) >= 128:
            state.text_cache.clear()
        state.text_cache[cache_key] = _scrub_view(text, values, False)
    return state.text_cache[cache_key]


def scrub_log_text(text: str, secrets: Iterable[str]) -> str:
    """Scrub log free text, including a secret embedded in a larger token.

    Structured tool data keeps the normal whole-token policy; log and error text has the
    stricter no-secret policy, so a route-building suffix cannot expose a configured key.
    The plain-replace pass does not cover escaped or encoded embedded forms.
    """
    values = tuple(
        sorted({secret for secret in secrets if secret}, key=lambda secret: (-len(secret), secret))
    )
    clean = scrub(text, values)
    for secret in values:
        clean = clean.replace(secret, MASK)
    return clean


def scrub_json_strings(obj: Any, secrets: Iterable[str]) -> Any:
    """Scrub configured credentials in JSON strings, preserving structure and types.

    JSON numbers, booleans, null and structural delimiters are upstream data, not
    credential strings. Scrubbing the serialized bytes could turn a numeric 1 into
    unquoted *** for a supported one-character credential, making the body invalid.
    """
    values = tuple(secrets)

    def visit(value: Any) -> Any:
        if isinstance(value, str):
            return scrub(value, values)
        if isinstance(value, dict):
            clean_keys = {key: scrub(key, values) for key in value}
            reserved = {key for key, clean in clean_keys.items() if key == clean}
            result = {}
            for key, child in value.items():
                clean_key = clean_keys[key]
                if clean_key != key:
                    while clean_key in reserved or clean_key in result:
                        clean_key += "*"
                result[clean_key] = visit(child)
            return result
        if isinstance(value, list):
            return [visit(child) for child in value]
        return value

    return visit(obj)


def scrub_bytes(data: bytes, secrets: Iterable[str]) -> bytes:
    """``data`` with every form of every configured secret replaced by ``***`` at the
    byte level: a body is never decoded or re-encoded (it is read one byte per
    character), so every other byte of a binary body is kept exactly as received."""
    values = tuple(sorted(set(secrets)))
    if not data or not values:
        return data
    view = bytes(data).decode("latin-1")
    out = _scrub_view(view, values, True)
    return data if out == view else out.encode("latin-1")


def contains_secret(data: bytes | str, secrets: Iterable[str]) -> bool:
    """True when ``data`` (a raw body or a header value) holds any form of a secret.

    Bytes are searched one byte per character, so a body is never decoded as text.
    """
    values = tuple(sorted(set(secrets)))
    if not data or not values:
        return False
    if isinstance(data, bytes | bytearray):
        return _contains_view(bytes(data).decode("latin-1"), values, True)
    return _contains_view(data, values, False)


# --------------------------------------------------------------------------- logging
_provider: Callable[[], Iterable[str]] = configured_secrets
_installed = False
#: Live objects carrying a ``_settings`` (every UniFiClient registers itself), so a log
#: record from a library (httpcore traces an illegal header value) is scrubbed of the
#: keys of settings built in code as well as from the environment.
_live_settings_holders: weakref.WeakSet[Any] = weakref.WeakSet()
#: Set on a record to the fields a scrub left, so the factory and filters never redo it.
_SCRUBBED_ATTR = "_unifi_secrets_scrubbed"


def track_settings_holder(holder: Any) -> None:
    """Scrub log records of ``holder._settings``'s secrets while ``holder`` is alive."""
    _live_settings_holders.add(holder)


def set_secret_provider(provider: Callable[[], Iterable[str]]) -> None:
    """Name the callable that returns the secrets log records are scrubbed of."""
    global _provider
    _provider = provider


def _log_secrets() -> tuple[str, ...]:
    values = [*_provider(), *call_secret_values()]
    for holder in list(_live_settings_holders):
        settings = getattr(holder, "_settings", None)
        if settings is not None:
            values.extend(configured_secrets(settings, include_call=False))
    return tuple(sorted({v for v in values if v.strip()}))


def _safe_text(render: Callable[[Any], str], value: Any) -> str:
    try:
        return render(value)
    except Exception:  # noqa: BLE001 - an object that cannot render has no text to leak
        return f"<unprintable {type(value).__name__}>"


class _ScrubbedArg(str):
    """A log argument whose ``str`` and ``repr`` held a secret, both scrubbed.

    A ``str`` subclass, so ``%s`` and ``%r`` format as the original would (minus the
    secret) and formatters that treat arguments as strings keep working.
    """

    __slots__ = ("_repr",)
    _repr: str

    def __new__(cls, text: str, rendered_repr: str) -> _ScrubbedArg:
        obj = super().__new__(cls, text)
        obj._repr = rendered_repr
        return obj

    def __repr__(self) -> str:
        return self._repr

    def __reduce__(self) -> tuple[Any, ...]:
        # pickle / copy rebuild it from both renderings (str's own reduce passes one).
        return (_ScrubbedArg, (str.__str__(self), self._repr))


def _scrub_value(value: Any, secrets: tuple[str, ...]) -> Any:
    """One log argument with its secrets scrubbed; its type is kept where possible.

    ``str`` stays ``str`` and numbers, booleans and ``None`` are returned as they are (a
    formatter such as uvicorn's access formatter reads the status code as an ``int``).
    Any other object is kept unless its ``str`` or ``repr`` holds a secret, in which case
    it becomes a :class:`_ScrubbedArg` carrying both renderings, scrubbed.
    """
    if isinstance(value, str):
        return scrub(value, secrets) if type(value) is str else _scrub_object(value, secrets)
    if value is None or isinstance(value, (int, float)):
        return value
    return _scrub_object(value, secrets)


def _scrub_object(value: Any, secrets: tuple[str, ...]) -> Any:
    text, rendered = _safe_text(str, value), _safe_text(repr, value)
    clean_text, clean_repr = scrub(text, secrets), scrub(rendered, secrets)
    if clean_text == text and clean_repr == rendered:
        return value
    return _ScrubbedArg(clean_text, clean_repr)


_FLAG_CHARS = frozenset("#0- +")
_LENGTH_CHARS = frozenset("hlL")
_CONVERSIONS = frozenset("diouxXeEfFgGcrsa%")


def _spec_end(msg: str, start: int) -> int:
    """The end of the ``%`` conversion specifier starting at ``msg[start]`` (``%s``,
    ``%(name)r``, ``%-08.3f``, ``%%``), or ``start`` when no valid specifier starts there.
    A hand-written scanner (no regex), linear in the specifier's length."""
    size = len(msg)
    pos = start + 1
    if pos < size and msg[pos] == "(":
        close = msg.find(")", pos)
        if close < 0:
            return start
        pos = close + 1
    while pos < size and msg[pos] in _FLAG_CHARS:
        pos += 1
    for _part in (0, 1):  # width, then precision after a "."
        if pos < size and msg[pos] == "*":
            pos += 1
        else:
            while pos < size and msg[pos].isdigit() and msg[pos].isascii():
                pos += 1
        if _part == 0 and pos < size and msg[pos] == ".":
            pos += 1
        else:
            break
    if pos < size and msg[pos] in _LENGTH_CHARS:
        pos += 1
    return pos + 1 if pos < size and msg[pos] in _CONVERSIONS else start


def _format_spec_spans(msg: str) -> list[tuple[int, int]]:
    """The spans of every ``%`` conversion specifier in a log format string."""
    spans: list[tuple[int, int]] = []
    pos = msg.find("%")
    while pos >= 0:
        end = _spec_end(msg, pos)
        if end > pos:
            spans.append((pos, end))
            pos = msg.find("%", end)
        else:
            pos = msg.find("%", pos + 1)
    return spans


def _scrub_format(msg: str, secrets: tuple[str, ...]) -> str:
    """A log record's ``%``-format string scrubbed WITHOUT touching its conversion
    specifiers: with secrets of any length a one-letter secret ``s`` must not
    turn ``%s`` into ``%***`` (the record would fail to format). A secret occurrence
    overlapping a specifier is the specifier, not the secret; every other one is masked."""
    values = tuple(sorted({s for s in secrets if isinstance(s, str)}))
    if not msg or not values:
        return msg
    spans = _spans(msg, values)
    if not spans:
        return msg
    specs = _format_spec_spans(msg)
    kept: list[tuple[int, int]] = []
    index = 0
    for start, end in spans:
        while index < len(specs) and specs[index][1] <= start:
            index += 1
        if index < len(specs) and specs[index][0] < end:
            continue  # overlaps a specifier
        kept.append((start, end))
    return _masked(msg, kept, MASK) if kept else msg


def _scrub_args(args: Any, secrets: tuple[str, ...]) -> Any:
    """Record arguments with the same structure (type and arity), each element scrubbed."""
    if isinstance(args, tuple):
        return tuple(_scrub_value(item, secrets) for item in args)
    if isinstance(args, Mapping):
        return {key: _scrub_value(item, secrets) for key, item in args.items()}
    return args


_SUBSTITUTE_TYPES: dict[type[BaseException], type[BaseException]] = {}


def _substitute_str(self: BaseException) -> str:
    return str(getattr(self, "_scrubbed_str", ""))


def _substitute_repr(self: BaseException) -> str:
    return str(getattr(self, "_scrubbed_repr", ""))


def _substitute_type(cls: type[BaseException]) -> type[BaseException]:
    """A stand-in exception class with ``cls``'s name, module and qualified name.

    Tracebacks (stdlib and rich) render the class name from it, so a scrubbed exception
    reads exactly like the original, minus the secret.
    """
    sub = _SUBSTITUTE_TYPES.get(cls)
    if sub is None:
        namespace: dict[str, Any] = {
            "__module__": cls.__module__,
            "__qualname__": cls.__qualname__,
            "__doc__": cls.__doc__,
        }
        base: type[BaseException]
        if issubclass(cls, BaseExceptionGroup):
            base = ExceptionGroup if issubclass(cls, Exception) else BaseExceptionGroup
        else:
            base = Exception if issubclass(cls, Exception) else BaseException
            namespace["__str__"] = _substitute_str
            namespace["__repr__"] = _substitute_repr
        sub = type(cls.__name__, (base,), namespace)
        _SUBSTITUTE_TYPES[cls] = sub
    return sub


def _exception_chain(exc: BaseException | None) -> list[BaseException]:
    """``exc`` and every exception reachable from it (cause, context, group members)."""
    seen: dict[int, BaseException] = {}
    pending = [exc]
    while pending:
        item = pending.pop()
        if item is None or id(item) in seen:
            continue
        seen[id(item)] = item
        pending.extend((item.__cause__, item.__context__))
        if isinstance(item, BaseExceptionGroup):
            pending.extend(item.exceptions)
    return list(seen.values())


def _exception_texts(exc: BaseException) -> list[str]:
    texts = [_safe_text(str, exc), _safe_text(repr, exc)]
    texts.extend(_safe_text(str, arg) for arg in getattr(exc, "args", ()))
    notes = getattr(exc, "__notes__", None)
    if isinstance(notes, list):
        texts.extend(_safe_text(str, note) for note in notes)
    return texts


def _substitute_exception(
    exc: BaseException | None, secrets: tuple[str, ...], memo: dict[int, BaseException]
) -> BaseException | None:
    """A scrubbed stand-in for ``exc`` and its whole chain (the original is untouched)."""
    if exc is None:
        return None
    if id(exc) in memo:
        return memo[id(exc)]
    cls = _substitute_type(type(exc))
    inst: BaseException
    if isinstance(exc, BaseExceptionGroup):
        members = [_substitute_exception(member, secrets, memo) for member in exc.exceptions]
        inst = cls(scrub(_safe_text(str, exc.message), secrets), members)  # type: ignore[call-arg]
    else:
        inst = cls(*(_scrub_value(arg, secrets) for arg in getattr(exc, "args", ())))
        inst._scrubbed_str = scrub(_safe_text(str, exc), secrets)  # type: ignore[attr-defined]
        inst._scrubbed_repr = scrub(_safe_text(repr, exc), secrets)  # type: ignore[attr-defined]
    memo[id(exc)] = inst
    inst.__traceback__ = exc.__traceback__
    inst.__cause__ = _substitute_exception(exc.__cause__, secrets, memo)
    inst.__context__ = _substitute_exception(exc.__context__, secrets, memo)
    inst.__suppress_context__ = exc.__suppress_context__
    notes = getattr(exc, "__notes__", None)
    if isinstance(notes, list):
        inst.__notes__ = [scrub(_safe_text(str, note), secrets) for note in notes]
    return inst


def scrub_exc_info(exc_info: Any, secrets: tuple[str, ...]) -> Any:
    """``exc_info`` with a scrubbed stand-in exception when any text in its chain holds
    a secret; otherwise ``exc_info`` unchanged.

    Every handler renders the exception from this tuple -- ``logging.Formatter`` through
    ``traceback`` and rich's ``RichHandler`` through ``Traceback.from_exception`` -- so
    the stand-in (same class name, scrubbed message, args, notes, cause and context, and
    the original traceback frames) makes every handler's exception text clean.
    """
    if not (isinstance(exc_info, tuple) and len(exc_info) == 3):
        return exc_info
    exc = exc_info[1]
    if not isinstance(exc, BaseException):
        return exc_info
    if not any(
        contains_secret(text, secrets)
        for item in _exception_chain(exc)
        for text in _exception_texts(item)
    ):
        return exc_info
    stand_in = _substitute_exception(exc, secrets, {})
    if stand_in is None:  # pragma: no cover - exc is an exception, so never None
        return exc_info
    return (type(stand_in), stand_in, exc_info[2])


def _record_state(record: logging.LogRecord) -> tuple[Any, ...]:
    return (record.msg, record.args, record.exc_info, record.exc_text, record.stack_info)


def _already_scrubbed(record: logging.LogRecord) -> bool:
    """True when the record's fields are the very objects a previous pass left.

    Identity, not a flag: ``logging.makeLogRecord`` builds a record through the factory
    and only then sets its fields, so a flag set by the factory would wrongly skip them.
    """
    state = getattr(record, _SCRUBBED_ATTR, None)
    return state is not None and all(
        a is b for a, b in zip(state, _record_state(record), strict=True)
    )


def _scrub_record(record: logging.LogRecord) -> None:
    """Scrub a record in place. Never raises: logging must not fail at the call site
    (the record factory runs inside every ``logger.info``)."""
    if _already_scrubbed(record):
        return
    try:
        _scrub_fields(record)
    except Exception as exc:  # noqa: BLE001 - withheld rather than raised or leaked
        record.msg = f"<log record withheld: scrubbing it failed ({type(exc).__name__})>"
        record.args = None
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
    setattr(record, _SCRUBBED_ATTR, _record_state(record))


def _message(record: logging.LogRecord) -> str | None:
    """The record's completed message, or None when its format string and arguments do
    not format (``logger.info("%d", "abc")``): stdlib raises that at emit time, inside
    the handler, which reports it through ``Handler.handleError`` -- so must we."""
    try:
        return logging.LogRecord.getMessage(record)
    except Exception:  # noqa: BLE001 - reported later by the handler, as stdlib does
        return None


class _CompletedLogMessage(str):
    """A record's scrubbed format string that formats to its scrubbed completed message.

    The arguments stay on the record, typed (a formatter such as uvicorn's access
    formatter reads them), while ``msg % args`` -- what ``getMessage`` does -- yields the
    completed message scrubbed as a whole (a secret split across arguments, or rebuilt
    by ``%d``, is masked there). Pickle and copy rebuild it from both strings.
    """

    def __new__(cls, template: str, completed: str) -> _CompletedLogMessage:
        obj = super().__new__(cls, template)
        obj.completed = completed
        return obj

    completed: str

    def __str__(self) -> str:
        return self

    def __mod__(self, args: Any) -> str:
        return self.completed

    def __reduce__(self) -> tuple[Any, ...]:
        return (_CompletedLogMessage, (str.__str__(self), self.completed))


def _scrub_fields(record: logging.LogRecord) -> None:
    secrets = _log_secrets()
    if not secrets:
        return
    message = _message(record)
    completed = None if message is None else scrub_log_text(message, secrets)
    if record.args and isinstance(record.msg, str):
        # A format string: its specifiers survive, so the record still formats.
        record.msg = _scrub_format(record.msg, secrets)
    else:
        record.msg = _scrub_value(record.msg, secrets)
    if record.args:
        record.args = _scrub_args(record.args, secrets)
    if record.args and completed is not None and completed != _message(record):
        record.msg = _CompletedLogMessage(str(record.msg), completed)
    if record.exc_info:
        record.exc_info = scrub_exc_info(record.exc_info, secrets)
    if record.exc_text:
        record.exc_text = scrub_log_text(record.exc_text, secrets)
    if record.stack_info:
        record.stack_info = scrub_log_text(record.stack_info, secrets)


class SecretScrubFilter(logging.Filter):
    """Scrubs a record that did not come through the record factory (``makeLogRecord``)."""

    def filter(self, record: logging.LogRecord) -> bool:
        _scrub_record(record)
        return True


_FILTER = SecretScrubFilter()


def _attach_filter(target: logging.Logger | logging.Handler) -> None:
    if _FILTER not in target.filters:
        target.addFilter(_FILTER)


def _memo_scrub_record(record: logging.LogRecord, text: str) -> str:
    """Deduplicate successful completed-text scrubs without changing the core."""
    from unifi_fabric.log_scrub_memo import scrub_record_text

    values = _log_secrets()
    withheld = isinstance(record.msg, str) and record.msg.startswith("<log record withheld:")
    return scrub_record_text(record, text, values, scrub_log_text, cacheable=not withheld)


_plain_formatter_format = logging.Formatter.format


def _format_scrubbed_record(formatter: logging.Formatter, record: logging.LogRecord) -> str:
    """Scrub fields reconstructed by formatters, including uvicorn's access fields."""
    return _memo_scrub_record(record, _plain_formatter_format(formatter, record))


_plain_handler_handle = logging.Handler.handle


def _handle_error_scrubbed(handler: logging.Handler, record: logging.LogRecord) -> None:
    """Render logging diagnostics as a whole, then scrub BEFORE writing anything.

    Replaces stdlib ``Handler.handleError``, whose ``Message:``/``Arguments:`` reprs
    (numeric arguments included) would otherwise bypass completed-text scrubbing.
    Typed arguments remain available to access formatters. A formatter, stream or
    secret-provider failure yields a static diagnostic, and this never raises.
    """
    import traceback

    try:
        secrets = _log_secrets()
        error = sys.exc_info()
        diagnostic = "--- Logging error ---\n" + "".join(traceback.format_exception(*error))
        diagnostic += "Message: " + _safe_text(repr, record.msg) + "\n"
        diagnostic += "Arguments: " + _safe_text(repr, record.args) + "\n"
        diagnostic = scrub_log_text(diagnostic, secrets)
    except Exception:  # noqa: BLE001 - static fallback contains no supplied value
        diagnostic = "--- Logging error: diagnostic withheld ---\n"
    try:
        if logging.raiseExceptions and sys.stderr is not None:
            sys.stderr.write(diagnostic)
    except Exception:  # noqa: BLE001, S110 - broken diagnostic stream must not raise
        pass


def _handle_scrubbed(handler: logging.Handler, record: logging.LogRecord) -> Any:
    """``Handler.handle`` with the record scrubbed first; a custom emitter or formatter
    that raises is reported through the scrubbed diagnostic, never raised."""
    try:
        _scrub_record(record)
        return _plain_handler_handle(handler, record)
    except Exception:  # noqa: BLE001 - custom formatters/emitters are contained too
        _handle_error_scrubbed(handler, record)
        return False


def _emit_scrubbed(handler: logging.StreamHandler[Any], record: logging.LogRecord) -> None:
    """``StreamHandler.emit`` writing only scrubbed completed output (custom formatters
    included); a failure is reported through the scrubbed diagnostic."""
    try:
        message = _memo_scrub_record(record, handler.format(record))
        handler.stream.write(message + handler.terminator)
        handler.flush()
    except Exception:  # noqa: BLE001 - stdlib's emit contract reports through handleError
        _handle_error_scrubbed(handler, record)


_plain_handler_format = logging.Handler.format


def _handler_format_scrubbed(handler: logging.Handler, record: logging.LogRecord) -> str:
    """``Handler.format`` returning only scrubbed completed output.

    Every handler that formats goes through here (SysLog, SMTP, NTEventLog, Queue, file,
    rotating file and any custom handler), so a formatter that renders the typed
    arguments itself (a numeric secret rebuilt from an ``int``), or a formatter object
    that is not a :class:`logging.Formatter` at all, never reaches a sink unscrubbed.
    """
    return _memo_scrub_record(record, _plain_handler_format(handler, record))


#: LogRecord schema keys are kept so receivers can rebuild records. Their string
#: values are caller-controlled (logger names, paths, thread names), and must be scrubbed.
_MACHINE_RECORD_FIELDS = frozenset(
    {
        "name",
        "levelno",
        "levelname",
        "pathname",
        "filename",
        "module",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "msg",
        "args",
        "exc_info",
        "exc_text",
        "stack_info",
        "message",
    }
)


_NUMERIC_RECORD_FIELDS = frozenset(
    {"levelno", "lineno", "created", "msecs", "relativeCreated", "thread", "process"}
)


def _wire_value(value: Any, secrets: tuple[str, ...], seen: frozenset[int] = frozenset()) -> Any:
    """Only primitive values and sanitized containers may cross the wire.

    An opaque object can hide secrets in pickle state even when its str/repr is clean.
    Convert those objects (including primitive/container subclasses with custom state)
    to scrubbed text instead of retaining their original serialization behavior.
    """
    if isinstance(value, str):
        return scrub(str.__str__(value), secrets)
    if type(value) in (type(None), bool, int, float, complex, bytes):
        text, rendered = _safe_text(str, value), _safe_text(repr, value)
        if scrub(text, secrets) == text and scrub(rendered, secrets) == rendered:
            return value
        return scrub(text, secrets)
    if type(value) in (dict, list, tuple, set, frozenset) and id(value) not in seen:
        seen = seen | {id(value)}
        if type(value) is dict:
            return {
                _wire_value(key, secrets, seen): _wire_value(item, secrets, seen)
                for key, item in value.items()
            }
        return type(value)(_wire_value(item, secrets, seen) for item in value)
    return scrub(_safe_text(str, value), secrets)


def _wire_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Sanitize record fields while preserving logging receivers' numeric types.

    Schema keys are plain strings. Numeric metadata is retained only when its
    rendered value is secret-free; otherwise a same-type zero crosses the wire.
    Scrub bookkeeping and custom serialization state never leave the process.
    """
    secrets = _log_secrets()
    cleaned: dict[str, Any] = {}
    for key, value in fields.items():
        plain_key = str.__str__(key) if isinstance(key, str) else _safe_text(str, key)
        if plain_key == _SCRUBBED_ATTR:
            continue
        wire_key = plain_key if plain_key in _MACHINE_RECORD_FIELDS else scrub(plain_key, secrets)
        wire_value = _wire_value(value, secrets)
        if plain_key in _NUMERIC_RECORD_FIELDS and type(value) in (int, float):
            wire_value = value if type(wire_value) is type(value) else type(value)(0)
        cleaned[wire_key] = wire_value
    return cleaned


def _make_pickle_scrubbed(handler: logging.Handler, record: logging.LogRecord) -> bytes:
    """``SocketHandler.makePickle`` (also DatagramHandler's) over scrubbed fields: the
    stdlib wire format (length prefix, pickled dict with ``msg`` completed and ``args``
    cleared), with nothing typed left to rebuild a secret on the receiving end."""
    import pickle
    import struct

    if record.exc_info:
        handler.format(record)  # fills record.exc_text, as stdlib does
    fields = dict(record.__dict__)
    fields["msg"] = record.getMessage()
    fields["args"] = None
    fields["exc_info"] = None
    fields.pop("message", None)
    payload = pickle.dumps(_wire_fields(fields), 1)
    return struct.pack(">L", len(payload)) + payload


def _scrubbed_wire_patches() -> None:
    """Patch the stdlib handlers that ship record fields rather than formatted text."""
    import logging.handlers as handlers

    plain_map = handlers.HTTPHandler.mapLogRecord
    plain_prepare = handlers.QueueHandler.prepare

    def map_log_record(handler: handlers.HTTPHandler, record: logging.LogRecord) -> Any:
        return _wire_fields(plain_map(handler, record))

    def prepare(handler: handlers.QueueHandler, record: logging.LogRecord) -> Any:
        prepared = plain_prepare(handler, record)
        if isinstance(prepared, logging.LogRecord):
            # A copied subclass can retain secret-bearing slots or pickle hooks.
            # Rebuild the plain stdlib record before a queue can serialize it.
            cleaned = _wire_fields(prepared.__dict__)
            prepared = logging.LogRecord("", 0, "", 0, "", (), None)
            prepared.__dict__.clear()
            prepared.__dict__.update(cleaned)
        return prepared

    setattr(handlers.HTTPHandler, "mapLogRecord", map_log_record)  # noqa: B010
    setattr(handlers.QueueHandler, "prepare", prepare)  # noqa: B010
    setattr(handlers.SocketHandler, "makePickle", _make_pickle_scrubbed)  # noqa: B010


def install_log_scrubber() -> None:
    """Scrub every log record, for all loggers and all handlers, of configured secrets.

    The record factory scrubs each record as it is created -- by any library (uvicorn,
    httpx, FastMCP) and for any handler, including ones added later (``basicConfig``,
    uvicorn's ``dictConfig``) -- before a handler sees it. The message and every
    argument are scrubbed in place with the argument structure kept (same type and
    arity), so formatters that unpack arguments (uvicorn's access formatter) keep
    working; exception info is replaced by a scrubbed stand-in (:func:`scrub_exc_info`),
    so tracebacks are clean in every handler, rich's ``RichHandler`` included.
    Completed messages are scrubbed after interpolation; the base formatter also
    scrubs its completed output, covering fields rebuilt from typed access-log args.
    Handler.handle, StreamHandler.emit and Handler.handleError are patched
    so every logging error path (malformed format, failing formatter, stream or custom
    emitter, lastResort) writes only a scrubbed diagnostic and never raises.
    Handler.format is patched so every handler's completed formatter output is
    scrubbed, whatever the formatter (SysLog, SMTP, NTEventLog, Queue and file sinks);
    the handlers that ship record fields instead of text (Socket, Datagram, HTTP, and
    the record a QueueHandler enqueues) send only scrubbed fields. Argument types on
    the record itself are never changed.

    A filter is also attached to the root logger and to every handler that exists when
    this runs, for records built without the factory. Call again after reconfiguring
    logging to cover new handlers; the factory is installed only once.
    """
    global _installed
    if not _installed:
        previous = logging.getLogRecordFactory()

        def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
            record = previous(*args, **kwargs)
            _scrub_record(record)
            return record

        logging.setLogRecordFactory(factory)
        # Intentional class patches: subclasses retain their formatMessage dispatch, and
        # a handler's own handleError override is left alone.
        setattr(logging.Formatter, "format", _format_scrubbed_record)  # noqa: B010
        setattr(logging.Handler, "handleError", _handle_error_scrubbed)  # noqa: B010
        setattr(logging.Handler, "handle", _handle_scrubbed)  # noqa: B010
        setattr(logging.StreamHandler, "emit", _emit_scrubbed)  # noqa: B010
        setattr(logging.Handler, "format", _handler_format_scrubbed)  # noqa: B010
        _scrubbed_wire_patches()
        _installed = True
    root = logging.getLogger()
    _attach_filter(root)
    loggers = [root] + [
        item
        for item in logging.Logger.manager.loggerDict.values()
        if isinstance(item, logging.Logger)
    ]
    for logger in loggers:
        for handler in list(logger.handlers):
            _attach_filter(handler)
