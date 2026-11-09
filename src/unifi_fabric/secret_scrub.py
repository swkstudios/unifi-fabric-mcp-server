r"""One central scrubber for configured server secrets in responses, errors and logs.

Every configured secret -- each UniFi API key (``UNIFI_API_KEY`` and every ``key`` in
``UNIFI_API_KEYS``), the transport bearer token (``MCP_BEARER_TOKEN``) and the TLS
private-key password (``MCP_TLS_KEY_PASSWORD``) -- is replaced by ``***`` in any text
this server raises, returns or logs: client transport errors, upstream response bodies
and headers (which may echo a request header back), tool errors,
audit-log lines, log records (message, arguments and exception text, for every handler)
and the placement-snapshot CLI. A dry-run preview is not an upstream response: it echoes
the request body as the caller wrote it.

G1 CLOSED decoder set, three token families, stdlib semantics per token:
P percent (%XX via unquote_to_bytes read as Latin-1, %uXXXX via chr);
H html (&#N; &#xN; &name; via html.unescape, unchanged token = not an escape);
B backslash (token regex \\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|
U[0-9a-fA-F]{8}|[0-7]{1,3}|[abfnrtv\\'"/]) via codecs.decode unicode_escape,
\/ -> /, greedy 1-3 digit octal with Python semantics so \612 -> chr(0o612)).
A layer = one family applied once left-to-right over the whole current view.
NO simultaneous/mixed layer, NO deferred octal, NO partial-token boundaries.
"e\1\x301K!" is NOT a leak of "K!"; "\6&#55;" IS a leak of "7" (H then B).

G2 Regions and views. A SEPARATOR is a character no token can hold and no base64 run
or padding can hold: anything outside [A-Za-z0-9%&#;\\'"/+_=-] (whitespace, most
punctuation, any non-ASCII character, a mask's "*"). Every view copies each separator
unchanged, so the views of the whole text under one family order are the views of the
REGIONS between separators under that order, side by side. A region is a maximal
separator-free run holding an introducer; two neighbouring regions are one region when
a form of a configured secret could cover the text between them together with a view
character of each side (that text inside the form, the character before it one a view
of the left region can end with and the one after it one a view of the right region
can start with), or, for a whole-token secret, could start at that text (its left
boundary is then a character of the left region). The views of a region: all distinct
results of <= D=8 layers in any family order (BFS, dedup on text+offsets), each view
char carrying its source span. Security bounds (documented as such, never size caps),
the SPEC-V3 numbers PER REGION: D=8 layers, N=128 views. Both bounds are inclusive
(SPEC-V3-1): with C_k the distinct views of a region reachable by <= k layers, the
region hits a bound iff |C_8| > N (an (N+1)th view exists) or C_9 != C_8 (a depth-8
view decodes to a new view). Exactly N views with C_9 == C_8 is the full closure. A
bound depends only on the region's own text, never on the size of the text around it.

G3 Match rule in every view incl. raw: literal forms secret_forms() (raw,
stripped, repr/JSON escaped once+twice, percent variants, base64 std/urlsafe
padded/unpadded, hex upper/lower, UTF-16 LE/BE text+hex, UTF-8-bytes-as-Latin-1
and UTF-16-code-unit variants) by substring search, plus embedded-base64
fragments over a base64 run. A decoded view is searched with the literal text around
its region (separators and undecoded text are the same in every view). Whole-token
boundary only for secrets with len(strip)<12: left OK iff at view start, or previous
view char not [A-Za-z0-9], or previous view char is a decoded unit (source span
length>1); right OK iff the SOURCE char after the match's source end is absent or not
[A-Za-z0-9]. Secrets >=12 chars match as substrings (A-3).

G4 Output: mask "***" over the union of source spans of all matches in all
views; every other byte unchanged; re-scrub until fixed point (bounded:
text shrinks).

G5 Bound behaviour (fail-closed): only for a REGION that hits D or N, additionally mask
every escape component of its views at the bound = maximal run of
[A-Za-z0-9#;%\\&] containing >=1 introducer, mapped to source. This is the
ONLY accepted over-masking class, and it stays inside that region; outside bound hits
the scrubber must EQUAL the reference. No other false-positive class is accepted. A
text with no region at a bound and no form of a secret is returned unchanged, whatever
its size (a binary body byte for byte).

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
filtered here. Credential fields a route registers in :mod:`unifi_fabric.route_secrets` are
bound there (on an error body, only the fields the route returns); any other credential
field of a response is masked only by the opt-in ``UNIFI_REDACT_SECRETS`` (see
:mod:`unifi_fabric.redaction`).
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import logging
import os
import re
import sys
import threading
import weakref
from array import array
from bisect import bisect_left, bisect_right
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import lru_cache, wraps
from itertools import chain, repeat, starmap
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote, quote_plus

if TYPE_CHECKING:
    from .config import MCPTransportSettings, Settings

MASK = "***"

#: Environment variables that each hold one secret value.
SECRET_ENV_VARS = (
    "UNIFI_API_KEY",
    "UNIFI_AUDIT_HMAC_KEY",
    "MCP_BEARER_TOKEN",
    "MCP_TLS_KEY_PASSWORD",
)
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
# log and audit channel of that call is scrubbed of them. Response and error data
# follow the opt-in ``UNIFI_REDACT_SECRETS`` setting, while configured server secrets
# are always scrubbed.
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
    log_values: tuple[str, ...] = ()
    text_cache: dict[tuple[str, tuple[str, ...]], str] = field(default_factory=dict)
    derived_cache: dict[tuple[Any, ...], Any] = field(default_factory=dict)
    outcomes: OrderedDict[Any, tuple[bool, str | None]] = field(default_factory=OrderedDict)
    outcome_chars: int = 0
    token_chars: dict[str, str | None] = field(default_factory=dict)


_call_secrets: ContextVar[_CallSecrets | None] = ContextVar("unifi_call_secrets", default=None)


def _secret_cache(maxsize: int) -> Callable[..., Any]:
    """Keep call-derived values with their inherited scope, never in global LRUs."""

    def decorate(fn: Callable[..., Any]) -> Any:
        configured = lru_cache(maxsize=maxsize)(fn)

        @wraps(fn)
        def cached(*args: Any) -> Any:
            state = _call_secrets.get()
            if state is None:
                return configured(*args)
            key = (fn, *args)
            if key not in state.derived_cache:
                state.derived_cache[key] = fn(*args)
            return state.derived_cache[key]

        cached.cache_clear = configured.cache_clear  # type: ignore[attr-defined]
        cached.cache_info = configured.cache_info  # type: ignore[attr-defined]
        return cached

    return decorate


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
    state = _CallSecrets(
        _bound_values((*call_secret_values(), *values)), log_values=log_secret_values()
    )
    token = _call_secrets.set(state)
    try:
        yield
    finally:
        _call_secrets.reset(token)


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


def add_log_secrets(values: Iterable[str]) -> None:
    """Bind values to logging only, preserving structured response data."""
    state = _call_secrets.get()
    if state is not None:
        state.log_values = _bound_values((*state.log_values, *values))


def log_secret_values() -> tuple[str, ...]:
    state = _call_secrets.get()
    return state.log_values if state is not None else ()


def configured_secrets(
    settings: Settings | None = None,
    transport: MCPTransportSettings | None = None,
    extra: Iterable[str] = (),
    *,
    include_call: bool = True,
) -> tuple[str, ...]:
    """Every configured secret: the environment's, plus those of the given settings.

    ``include_call`` adds the secrets bound to the current call (:func:`secret_scope`).
    Message and audit sinks include call-bound values; result and error-data paths
    pass an explicit opt-in policy. Configured server secrets are always included.
    """
    values: list[str] = _env_secrets()
    if settings is not None:
        values.append(settings.api_key)
        values.extend(cfg.key for cfg in settings.api_keys)
        if settings.audit_hmac_key is not None:
            values.append(settings.audit_hmac_key.get_secret_value())
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


@_secret_cache(maxsize=128)
def _secret_forms(secret: str) -> frozenset[str]:
    """Reuse one secret's encodings as a call grows, retaining call values in scope."""
    return frozenset(secret_forms(secret))


def scrubbable(secrets: Iterable[str]) -> tuple[str, ...]:
    """The secrets the scrubber matches: every configured string that is not blank,
    whatever its length."""
    return tuple(sorted({s for s in secrets if isinstance(s, str) and s.strip()}))


@_secret_cache(maxsize=64)
def _forms(secrets: tuple[str, ...]) -> tuple[str, ...]:
    """Every searchable form of every scrubbable secret, longest first."""
    forms: set[str] = set()
    for secret in scrubbable(secrets):
        forms |= _secret_forms(secret)
    return tuple(sorted(forms, key=lambda f: (-len(f), f)))


@_secret_cache(maxsize=64)
def _fragments(secrets: tuple[str, ...]) -> tuple[str, ...]:
    """The prefix-independent base64 fragments of every scrubbable secret embedded after
    a prefix (``Basic base64(user:secret)``), matched inside a base64 token."""
    out: set[str] = set()
    for secret in scrubbable(secrets):
        for base in {secret, secret.strip()}:
            out |= _embedded_base64_fragments(base.encode("utf-8", "surrogatepass"))
    return tuple(sorted(out, key=lambda f: (-len(f), f)))


_WORD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]*")
_PAD_RUN = re.compile(r"=*")
_INTRO = frozenset("%\\&")
_SINGLE = dict(zip("abfnrtv", "\a\b\f\n\r\t\v", strict=True))
_SINGLE.update({"\\": "\\", "'": "'", '"': '"', "/": "/"})
_PERCENT_PATTERN = re.compile(r"%(?:u[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2})")
_HTML_PATTERN = re.compile(r"&(?:#[0-9]+;|#[xX][0-9A-Fa-f]+;|[A-Za-z][A-Za-z0-9]{0,30};)")
_BACKSLASH_PATTERN = re.compile(
    r"\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[abfnrtv\\'\"/])"
)
_PATTERNS = (_PERCENT_PATTERN, _HTML_PATTERN, _BACKSLASH_PATTERN)
# Security bounds on ambiguity and depth, never text-size caps.
_MAX_DEPTH = 8
_MAX_VIEWS = 128


@_secret_cache(maxsize=64)
def _bytes_forms(secrets: tuple[str, ...]) -> tuple[bytes, ...]:
    out = set()
    for form in _forms(secrets):
        out.add(form.encode("utf-8", "surrogatepass"))
        try:
            out.add(form.encode("latin-1"))
        except UnicodeEncodeError:
            pass
    return tuple(sorted(out, key=lambda f: (-len(f), f)))


@_secret_cache(maxsize=64)
def _variants(secrets: tuple[str, ...]) -> tuple[str, ...]:
    out = set()
    for secret in scrubbable(secrets):
        for base in {secret, secret.strip()}:
            if not base.strip():
                continue
            out.add(base)
            out.add(base.encode("utf-8", "surrogatepass").decode("latin-1"))
            units = base.encode("utf-16-le", "surrogatepass")
            out.add(
                "".join(
                    chr(int.from_bytes(units[i : i + 2], "little")) for i in range(0, len(units), 2)
                )
            )
    return tuple(sorted(out, key=lambda f: (-len(f), f)))


@_secret_cache(maxsize=128)
def _raw_forms(secrets: tuple[str, ...], as_bytes: bool) -> tuple[str, ...]:
    forms = set(_variants(secrets))
    forms.update(f.decode("latin-1") for f in _bytes_forms(secrets)) if as_bytes else forms.update(
        _forms(secrets)
    )
    return tuple(sorted(forms, key=lambda f: (-len(f), f)))


def _numeric_charref(unit: str) -> str:
    """``&#...;`` with its leading zeros dropped, the same character reference for
    :func:`html.unescape` (so its result is the stdlib's), but never an integer
    conversion of thousands of digits (which raises past ``sys.get_int_max_str_digits``).
    More than 7 decimal or 6 hexadecimal significant digits is past U+10FFFF, which
    the stdlib decodes to U+FFFD."""
    hexadecimal = unit[2] in "xX"
    digits = unit[3:-1] if hexadecimal else unit[2:-1]
    digits = digits.lstrip("0") or "0"
    if len(digits) > (6 if hexadecimal else 7):
        digits = "110000" if hexadecimal else "1114112"
    return ("&#x" if hexadecimal else "&#") + digits + ";"


def _unit_char(unit: str) -> str | None:
    """G1 token semantics; integer conversions equal the stdlib decoders."""
    if unit[0] == "%":
        return chr(int(unit[2:] if unit[1] == "u" else unit[1:], 16))
    if unit[0] == "&":
        if unit[1] == "#":
            unit = _numeric_charref(unit)
        char = html.unescape(unit)
        return None if char == unit else char
    kind = unit[1]
    if kind in "xuU":
        value = int(unit[2:], 16)
    elif kind in "01234567":
        value = int(unit[1:], 8)
    else:
        return _SINGLE[kind]
    return chr(value) if value <= 0x10FFFF else None


#: Offset-array type codes: 4-byte unsigned where the source fits (memory only; the same
#: offsets either way, so this is output-neutral), 8-byte beyond 2**32 - 1 characters.
_NARROW_OFFSETS = next(code for code in "IL" if array(code).itemsize == 4)


#: A maximal run of [A-Za-z0-9#;%\\&] holding at least one introducer, matched only at
#: the start of a run (lookbehind) and with possessive repeats, so a long run without an
#: introducer is rejected in one pass (linear, no backtracking).
_COMPONENT = re.compile(r"(?<![A-Za-z0-9#;%\\&])[A-Za-z0-9#;]*+[%\\&][A-Za-z0-9#;%\\&]*+")

#: G2 regions. Every character a token of some family can hold (G1: each pattern is over
#: [A-Za-z0-9%&#;\\'"/]) or a base64 run or its padding can hold ([A-Za-z0-9+/_=-]). Any
#: other character -- a SEPARATOR: whitespace, most punctuation, every non-ASCII
#: character, a mask's ``*`` -- is in no token, so every view copies it unchanged.
_LINKED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%&#;\\'\"/+_=-")
#: A maximal run of linked characters holding at least one introducer (lookbehind and
#: possessive repeats: linear, no backtracking).
_SEGMENT = re.compile(
    r"(?<![A-Za-z0-9%&#;\\'\"/+_=\-])[A-Za-z0-9#;'\"/+_=\-]*+[%&\\][A-Za-z0-9%&#;\\'\"/+_=\-]*+"
)
#: Characters that can stand between two windows of the search corpus (none is linked).
_SEPARATORS = "\x00\x01\x02\x03\x04\x05\x06\x07\x0e\x0f\x10\x11"


#: Decoded short tokens (a body repeats a few); bounded, emptied when full. A token of
#: thousands of digits is decoded every time and never retained.
_TOKEN_CHARS: dict[str, str | None] = {}
_TOKEN_CACHE_SIZE = 8192
_UNKNOWN = object()


def _token_char(unit: str) -> str | None:
    """:func:`_unit_char`, remembered for short tokens."""
    state = _call_secrets.get()
    cache = _TOKEN_CHARS if state is None else state.token_chars
    char = cache.get(unit, _UNKNOWN)
    if char is _UNKNOWN:
        char = _unit_char(unit)
        if len(unit) <= 16:
            if len(cache) >= _TOKEN_CACHE_SIZE:
                cache.clear()
            cache[unit] = char
    return char  # type: ignore[return-value]


def _token_sub(match: re.Match[str]) -> str:
    unit = match.group()
    char = _token_char(unit)
    return unit if char is None else char  # "" is a decoding (html.unescape("&#3;"))


#: The introducer every token of a family starts with (a view without it decodes to
#: itself in that family).
_INTRODUCERS = ("%", "&", "\\")
#: Per family, in the fixed G2 order: its introducer and its layer (a regex substitution).
_FAMILIES = tuple(zip(_INTRODUCERS, (pattern.sub for pattern in _PATTERNS), strict=True))


#: A view's source-offset map, compressed: the view positions whose source span is NOT
#: the continuation of the character before (start == previous end, one character
#: long; before the first character the "previous end" is 0), with their spans. Every
#: other character continues the one before it. Lossless: the same text with the same
#: breaks is the same text with the same offsets (G2 dedup is exact), and the raw view
#: has none.
_Breaks = tuple["array[int] | list[int]", "array[int] | list[int]", "array[int] | list[int]"]
_Unit = tuple[int, int, str]


class _Units:
    # Lossless runs of adjacent, equal-width tokens with equal decoded characters.
    # Dense escape layers must not retain an entry per repeated token at every depth.
    __slots__ = ("chars", "counts", "ends", "starts")

    def __init__(self, size: int) -> None:
        self.starts: array[int] | list[int]
        self.ends: array[int] | list[int]
        if size <= 256:
            self.starts, self.ends = [], []
        else:
            code = _NARROW_OFFSETS if size <= 0xFFFFFFFF else "Q"
            self.starts, self.ends = array(code), array(code)
        self.chars: list[str] = []
        # Uncompressed layers keep the original two-offset-array representation.
        self.counts: array[int] | list[int] | None = None

    def append(self, start: int, end: int, char: str) -> None:
        if (
            self.chars
            and self.chars[-1] == char
            and self.ends[-1] == start
            and (end - start) * (self.counts[-1] if self.counts is not None else 1)
            == start - self.starts[-1]
        ):
            if self.counts is None:
                self.counts = (
                    array(self.starts.typecode, [1]) * len(self.chars)
                    if isinstance(self.starts, array)
                    else [1] * len(self.chars)
                )
            self.ends[-1] = end
            self.counts[-1] += 1
        else:
            self.starts.append(start)
            self.ends.append(end)
            if self.counts is not None:
                self.counts.append(1)
            self.chars.append(char)

    def __bool__(self) -> bool:
        return bool(self.chars)

    def __len__(self) -> int:
        return sum(self.counts) if self.counts is not None else len(self.chars)

    def __iter__(self) -> Iterator[_Unit]:
        if self.counts is None:
            return zip(self.starts, self.ends, self.chars, strict=True)
        # Each run's tokens come from C-level iterators: no Python frame per token.
        return chain.from_iterable(
            starmap(_run_units, zip(self.starts, self.ends, self.counts, self.chars, strict=True))
        )


def _run_units(start: int, end: int, count: int, char: str) -> Iterator[_Unit]:
    """The ``count`` adjacent tokens of width ``(end - start) // count`` from ``start``
    to ``end``, each decoding to ``char``."""
    width = (end - start) // count
    return zip(range(start, end, width), range(start + width, end + width, width), repeat(char))


#: The raw view's breaks (none), shared and never modified.
_NO_BREAKS: _Breaks = (array(_NARROW_OFFSETS), array(_NARROW_OFFSETS), array(_NARROW_OFFSETS))
_NO_BREAKS_WIDE: _Breaks = (array("Q"), array("Q"), array("Q"))
#: Short regions avoid the construction/append overhead of three typed arrays. The
#: representation is fixed by the raw region, so exact dedup always compares like
#: maps. Large regions retain compact typed storage, including under AT4 saturation.
_NO_BREAKS_SMALL: _Breaks = ([], [], [])


_Search = Callable[["array[int] | list[int]", int, int, int], int]


def _forward(search: _Search, at: array[int] | list[int], x: int, low: int) -> int:
    """``search(at, x, low, len(at))`` (``bisect_left`` or ``bisect_right``) when the
    answer is at least ``low``, galloping up from ``low``: O(log(answer - low)) element
    reads, not O(log(len(at) - low)). A run of nondecreasing queries that each start at
    the previous answer therefore reads O(queries + len(at)) elements in total -- linear
    -- where a bisect to the end of the map reads O(queries * log(len(at)))."""
    count = len(at)
    width = 2
    while True:
        high = low + width
        if high >= count:
            return search(at, x, low, count)
        found = search(at, x, low, high)
        if found < high:
            return found
        low = high
        width <<= 1


def _backward(at: array[int] | list[int], x: int, high: int) -> int:
    """``bisect_right(at, x, 0, high)`` when ``at[high]`` (if any) is past ``x``,
    galloping down from ``high``: O(log(high - answer)) element reads."""
    width = 2
    while True:
        low = high - width
        if low <= 0:
            return bisect_right(at, x, 0, high)
        found = bisect_right(at, x, low, high)
        if found > low:
            return found
        high = low
        width <<= 1


def _child_breaks(size: int, parent: _Breaks, units: _Units) -> _Breaks:
    """The breaks of a layer of a view of ``size`` characters (breaks ``parent``) that
    decodes ``units`` (token start, end, characters; in order): a copied character
    keeps its span, a decoded one spans its whole token, a token decoding to nothing
    leaves no character."""
    p_at, p_starts, p_ends = parent
    at: array[int] | list[int]
    starts: array[int] | list[int]
    ends: array[int] | list[int]
    if isinstance(p_at, array):
        code = p_at.typecode
        at, starts, ends = array(code), array(code), array(code)
    else:
        at, starts, ends = [], [], []
    count = len(p_at)
    if not count:
        # The parent maps every character to itself (the raw view): a decoded character
        # spans its token; a copied one breaks only right after a token that decoded to
        # nothing (it does not start where the character before it ends).
        child = 0
        previous = 0
        pos = 0
        for token_start, token_end, char in units:
            child += token_start - pos
            if token_start > pos and pos != previous:
                at.append(child - (token_start - pos))
                starts.append(pos)
                ends.append(pos + 1)
            for _ in char:
                at.append(child)
                starts.append(token_start)
                ends.append(token_end)
                child += 1
            previous = token_end if char else (previous if token_start == pos else token_start)
            pos = token_end
        if size > pos and pos != previous:
            at.append(child)
            starts.append(pos)
            ends.append(pos + 1)
        return at, starts, ends
    previous = child = pos = k = 0
    # Source spans of parent characters, as _Closure.source, inlined: the queried
    # positions only grow, so each search gallops up from the last break found
    # (``low``), and the whole layer reads each parent break a bounded number of times.
    low = 0
    for token_start, token_end, char in chain(units, ((size, size, ""),)):
        if token_start > pos:  # characters [pos, token_start) are copied
            j = _forward(bisect_right, p_at, pos, low) - 1
            if j < 0:
                start, end = pos, pos + 1
            else:
                low = j
                offset = pos - p_at[j]
                if offset:
                    end = p_ends[j] + offset
                    start = end - 1
                else:
                    start, end = p_starts[j], p_ends[j]
            if start != previous or end != start + 1:
                at.append(child)
                starts.append(start)
                ends.append(end)
            # The parent's breaks after ``pos`` and before the token, shifted.
            k = _forward(bisect_right, p_at, pos, k)
            stop = _forward(bisect_left, p_at, token_start, k)
            if stop > k:
                shift = child - pos
                at.extend([value + shift for value in p_at[k:stop]])
                starts.extend(p_starts[k:stop])
                ends.extend(p_ends[k:stop])
                k = stop
            last = token_start - 1
            j = _forward(bisect_right, p_at, last, low) - 1
            if j < 0:
                previous = last + 1
            else:
                low = j
                previous = p_ends[j] + last - p_at[j]
            child += token_start - pos
        if token_start == size:
            break
        j = _forward(bisect_right, p_at, token_start, low) - 1
        if j < 0:
            start = token_start
        else:
            low = j
            offset = token_start - p_at[j]
            start = p_ends[j] + offset - 1 if offset else p_starts[j]
        last = token_end - 1
        j = _forward(bisect_right, p_at, last, low) - 1
        if j < 0:
            end = last + 1
        else:
            low = j
            end = p_ends[j] + last - p_at[j]
        for _ in char:
            at.append(child)
            starts.append(start)
            ends.append(end)
            child += 1
        if char:
            previous = end
        pos = token_end
    return at, starts, ends


class _Closure:
    """The G2 views of one region (raw first, breadth-first, families in a fixed order,
    dedup on text+offsets) under D and N, and the views at a bound (G5).

    A view is held as its text, its parent and its layer's units (token start and end in
    the parent, decoded characters), captured while decoding. A view character is
    mapped to source by its compact breaks (:meth:`source`); those exact offset maps
    are built on demand for matching or comparing views of the same text (dedup).

    ``heads[i]`` / ``tails[i]``: how many leading characters of view ``i`` are the
    region's own leading characters, copied by every layer (character ``k`` is region
    character ``k``), and how many trailing ones are its trailing characters (aligned at
    the region's end). Exact by construction: a layer copies every character before its
    first token and after its last one."""

    __slots__ = (
        "_breaks",
        "_ends",
        "_hints",
        "bound",
        "heads",
        "layers",
        "parents",
        "tails",
        "views",
    )

    def __init__(self, text: str) -> None:
        views = self.views = [text]
        parents = self.parents = [0]
        layers: list[_Units | None] = [None]
        self.layers = layers
        self._breaks: dict[int, _Breaks] = {
            0: (
                _NO_BREAKS_SMALL
                if len(text) <= 256
                else _NO_BREAKS
                if len(text) <= 0xFFFFFFFF
                else _NO_BREAKS_WIDE
            )
        }
        self._ends: tuple[frozenset[str] | None, frozenset[str] | None] | None = None
        self.bound: list[int] = []
        heads = self.heads = [len(text)]
        tails = self.tails = [len(text)]
        depths = [0]
        held: dict[str, list[int]] = {text: [0]}
        units = _Units(len(text))
        state = _call_secrets.get()
        known = (_TOKEN_CHARS if state is None else state.token_chars).get

        def capture(match: re.Match[str]) -> str:
            unit = match.group()
            char = known(unit, _UNKNOWN)
            if char is _UNKNOWN:
                char = _token_char(unit)
            if char is None:
                return unit
            units.append(match.start(), match.end(), char)  # type: ignore[arg-type]
            return char  # type: ignore[return-value]

        count = 1
        cursor = 0
        while cursor < count:
            index = cursor
            cursor += 1
            view = views[index]
            for introducer, layer in _FAMILIES:
                if introducer not in view:
                    continue
                units = _Units(len(view))  # collected by ``capture``
                decoded = layer(capture, view)
                if not units:
                    continue  # decodes to itself: already held
                same = held.get(decoded)
                child = None
                if same is not None:
                    child = _child_breaks(len(view), self.breaks(index), units)
                    for other in same:
                        if self.breaks(other) == child:
                            break
                    else:
                        other = -1
                    if other >= 0:
                        continue  # the same text+offsets: already held
                if depths[index] == _MAX_DEPTH or count == _MAX_VIEWS:
                    self.bound.append(index)  # its components are withheld (G5)
                    break
                if child is not None:
                    self._breaks[count] = child
                if same is None:
                    held[decoded] = [count]
                else:
                    same.append(count)
                count += 1
                views.append(decoded)
                parents.append(index)
                layers.append(units if child is None else None)
                depths.append(depths[index] + 1)
                head, tail = heads[index], tails[index]
                first, last = units.starts[0], len(view) - units.ends[-1]
                heads.append(first if first < head else head)
                tails.append(last if last < tail else tail)
        self._hints = [0] * count  # per view: where its last source() search landed

    def breaks(self, index: int) -> _Breaks:
        held = self._breaks.get(index)
        if held is None:
            parent = self.parents[index]
            units = cast("_Units", self.layers[index])
            held = _child_breaks(len(self.views[parent]), self.breaks(parent), units)
            self._breaks[index] = held
            self.layers[index] = None  # the exact map replaces the token offsets
        return held

    def source(self, index: int, pos: int, end: bool) -> int:
        """The region offset where character ``pos`` of view ``index`` starts (or, with
        ``end``, ends), using the view's exact, compact offset map.

        Reuse the same map as closure deduplication. A dictionary entry per queried
        character retains tuple keys and Python integers for almost every position
        of every mixed-escape view; the compact map stores only offset breaks.

        The searches of one view gallop from where its previous query landed (one
        integer per view): the matches of one form are mapped in increasing order, so
        a view's queries read O(log gap) map entries each, linear in total, instead of
        a binary search over the whole map per query."""
        at, starts, ends = self.breaks(index)
        hints = self._hints
        k = hints[index]  # bisect_right(at, previous query)
        if k < len(at) and at[k] <= pos:
            k = _forward(bisect_right, at, pos, k + 1)
        elif k and at[k - 1] > pos:
            k = _backward(at, pos, k - 1)
        hints[index] = k
        k -= 1  # the last break at or before ``pos``
        if end:
            return pos + 1 if k < 0 else ends[k] + pos - at[k]
        if k < 0:
            return pos
        return starts[k] if at[k] == pos else ends[k] + pos - at[k] - 1

    def ends(self) -> tuple[frozenset[str] | None, frozenset[str] | None]:
        """The characters a view of this region can start and end with; they decide
        whether a form can cross to a neighbour. (None, None) -- any character -- when
        the closure is bounded, or when a view is empty (a token can decode to nothing,
        so the texts on both sides of the region meet in that view)."""
        if self._ends is None:
            if self.bound or not all(self.views):
                self._ends = None, None
            else:
                self._ends = (
                    frozenset(view[0] for view in self.views),
                    frozenset(view[-1] for view in self.views),
                )
        return self._ends

    def withheld(self) -> list[tuple[int, int]]:
        """G5: every escape component of every view at a bound, in region offsets."""
        spans = _SpanUnion(len(self.views[0]))
        for index in self.bound:
            for match in _COMPONENT.finditer(self.views[index]):
                start, stop = match.span()
                spans.append((self.source(index, start, False), self.source(index, stop - 1, True)))
        return spans.merged()


_JoinTables = tuple[tuple[str, ...], tuple[str, ...], frozenset[str], int, int]
_JoinCandidates = tuple[set[tuple[str, str]], tuple[str, ...]]

#: Per-region-pass memo only: no body text survives a scrub. Bound both entry count
#: and gap length so unique/large literal gaps cannot grow its retained text.
_JOIN_CACHE_ENTRIES = 256
_JOIN_CACHE_GAP_CHARS = 256


@_secret_cache(maxsize=128)
def _join_tables(values: tuple[str, ...], as_bytes: bool) -> _JoinTables:
    """What the region joins and the search windows need from the forms:

    * the forms with an interior separator (a form that can cross the text between
      two regions); their matching pieces are searched for the actual gap, without
      materializing every separator-bounded substring of every form;
    * the whole-token forms (G3, under 12 characters) that start with a separator (their
      left boundary is the character before that text, in the region before it);
    * every character of a form, and the longest form (a window's literal context);
    * the shortest form or embedded-base64 fragment (a shorter window holds no match)."""
    forms = _raw_forms(values, as_bytes)
    long_forms = _long_forms(values, as_bytes)
    inner = tuple(form for form in forms if any(char not in _LINKED for char in form[1:-1]))
    leading = tuple(form for form in forms if form not in long_forms and form[0] not in _LINKED)
    chars = frozenset(char for form in forms for char in form)
    width = max((len(form) for form in forms), default=0)
    shortest = min((len(item) for item in (*forms, *_fragments(values))), default=0)
    return inner, leading, chars, width, shortest


def _join_pairs(forms: tuple[str, ...], gap: str) -> set[tuple[str, str]]:
    """The neighbours of every interior occurrence of this separator-bounded gap."""
    pairs: set[tuple[str, str]] = set()
    if not gap or gap[0] in _LINKED or gap[-1] in _LINKED:
        return pairs
    size = len(gap)
    for form in forms:
        at = form.find(gap, 1)
        while 0 <= at < len(form) - size:
            pairs.add((form[at - 1], form[at + size]))
            at = form.find(gap, at + 1)
    return pairs


def _joined(
    data: str,
    before: tuple[int, int],
    after: tuple[int, int],
    tables: _JoinTables,
    closure: Callable[[int, int], _Closure],
    joins: dict[str, _JoinCandidates],
) -> bool:
    """Whether a match of some form could cover the gap between two segments
    (separator-bounded text, the same in every view) together with a view character of
    each neighbour, in a way a search of each on its own would not see: crossing the
    whole gap, or starting at its first character (a whole-token form, whose left
    boundary is then the last character of a view of the segment before).

    The raw view is a view of each segment, so its characters decide first; the
    segments' closures are built only when they do not."""
    gap = data[before[1] : after[0]]
    size = len(gap)
    candidates = joins.get(gap)
    if candidates is None:
        inner, leading, _chars, _width, _shortest = tables
        pairs = _join_pairs(inner, gap)
        # G2: every view copies the literal gap unchanged. Candidate pairs and
        # leading forms depend only on that gap and these constant tables, so
        # repeated gaps share this work. Actual endpoint checks stay per boundary.
        leading = tuple(
            form
            for form in leading
            if (gap.startswith(form) if len(form) <= size else form.startswith(gap))
        )
        candidates = pairs, leading
        if size <= _JOIN_CACHE_GAP_CHARS:
            if len(joins) >= _JOIN_CACHE_ENTRIES:
                joins.clear()
            joins[gap] = candidates
    pairs, leading = candidates
    if not pairs and not leading:
        return False
    raw_last, raw_first = data[before[1] - 1], data[after[0]]
    if pairs and (raw_last, raw_first) in pairs:
        return True
    if leading and raw_last in _WORD:
        for form in leading:
            if (
                gap.startswith(form)
                if len(form) <= size
                else (form.startswith(gap) and form[size] == raw_first)
            ):
                return True
    last, first = closure(*before).ends()[1], closure(*after).ends()[0]
    for left, right in pairs or ():
        if (last is None or left in last) and (first is None or right in first):
            return True
    if leading and (last is None or not last.isdisjoint(_WORD)):
        for form in leading:
            if len(form) <= size:
                if gap.startswith(form):
                    return True
            elif form.startswith(gap) and (first is None or form[size] in first):
                return True
    return False


_Region = tuple[int, int, _Closure]


def _regions(
    data: str, values: tuple[str, ...], as_bytes: bool, cache: dict[str, _Closure]
) -> list[_Region]:
    """The G2 regions of ``data`` with their closures (``cache``: region text -> closure,
    shared by the G4 rounds of one scrub)."""

    def closure(start: int, end: int) -> _Closure:
        text = data[start:end]
        held = cache.get(text)
        if held is None:
            held = cache[text] = _Closure(text)
        return held

    segments = [match.span() for match in _SEGMENT.finditer(data)]
    tables = _join_tables(values, as_bytes)
    if len(segments) > 1 and (tables[0] or tables[1]):
        joins: dict[str, _JoinCandidates] = {}
        spans = []
        start, end = segments[0]
        previous = segments[0]
        for segment in segments[1:]:
            if _joined(data, previous, segment, tables, closure, joins):
                end = segment[1]
            else:
                spans.append((start, end))
                start, end = segment
            previous = segment
        spans.append((start, end))
        segments = spans
    return [(start, end, closure(start, end)) for start, end in segments]


def _withheld_spans(regions: list[_Region]) -> list[tuple[int, int]]:
    return [
        (offset + start, offset + end)
        for offset, _end, closure in regions
        if closure.bound
        for start, end in closure.withheld()
    ]


def _security_bound_spans(data: str, secrets: Iterable[str]) -> list[tuple[int, int]]:
    """The G5 spans of ``data`` (empty unless a region hits a bound)."""
    values = scrubbable(secrets)
    if not values or ("%" not in data and "\\" not in data and "&" not in data):
        return []
    return _withheld_spans(_regions(data, values, False, {}))


def _merged(found: list[tuple[int, int]]) -> list[tuple[int, int]]:
    found.sort()
    merged: list[tuple[int, int]] = []
    for start, end in found:
        if merged and start <= merged[-1][1]:
            merged[-1] = merged[-1][0], max(end, merged[-1][1])
        else:
            merged.append((start, end))
    return merged


class _SpanUnion:
    """Union of source spans in O(input) space, independent of decoded-view count.

    A decoded match can occur at the same source offsets in every view. Retaining
    a tuple and boxed offsets for each occurrence amplifies memory by N. Signed
    endpoint counts retain every overlap and adjacency exactly, with eight bytes
    per source position; one final sweep emits the disjoint source intervals. Until
    a disjoint span arrives, keep the single interval directly: a whole-region mask
    must not allocate and scan an input-sized endpoint array.
    """

    __slots__ = ("_events", "_single", "_size")

    def __init__(self, size: int) -> None:
        self._size = size
        self._events: array[int] | None = None
        self._single: tuple[int, int] | None = None

    def append(self, span: tuple[int, int]) -> None:
        start, end = span
        if start == end:
            return
        if self._events is None:
            if self._single is None:
                self._single = span
                return
            left, right = self._single
            if start <= right and end >= left:
                self._single = min(left, start), max(right, end)
                return
            self._events = array("q", [0]) * (self._size + 1)
            self._events[left] += 1
            self._events[right] -= 1
            self._single = None
        self._events[start] += 1
        self._events[end] -= 1

    def merged(self) -> list[tuple[int, int]]:
        if self._events is None:
            return [] if self._single is None else [self._single]
        result = []
        depth = start = 0
        for position, change in enumerate(self._events):
            previous = depth
            depth += change
            if not previous and depth:
                start = position
            elif previous and not depth:
                result.append((start, position))
        return result


@_secret_cache(maxsize=128)
def _long_forms(values: tuple[str, ...], as_bytes: bool) -> frozenset[str]:
    """G3: the forms of a secret of 12 or more characters match without word bounds."""
    return frozenset(
        form
        for secret in values
        if len(secret.strip()) >= 12
        for form in _raw_forms((secret,), as_bytes)
    )


def _raw_spans(data: str, values: tuple[str, ...], as_bytes: bool) -> list[tuple[int, int]]:
    """G3 in the raw view: every form, and every embedded-base64 fragment's token."""
    long_forms = _long_forms(values, as_bytes)
    found = []
    for form in _raw_forms(values, as_bytes):
        pos = 0
        while (index := data.find(form, pos)) >= 0:
            end = index + len(form)
            if form in long_forms or (
                (index == 0 or data[index - 1] not in _WORD)
                and (end == len(data) or data[end] not in _WORD)
            ):
                found.append((index, end))
            pos = index + 1
    found.extend(_fragment_spans(data, _fragments(values), _B64_RUN, _PAD_RUN))
    return found


#: One decoded view in the search corpus: (corpus offset of the window, source offset
#: of the window, characters of literal text before the view, characters before the
#: text after it, source offset of that text, the region's closure, the view, the
#: source character before the window or None at a boundary, whether the whole source
#: region is already masked). A window is the view with
#: the literal text around its region that a match can reach (separators and undecoded
#: text are the same in every view).
_Window = tuple[int, int, int, int, int, _Closure, int, "str | None", bool]


# Search one bounded group of complete windows at a time. A single larger window
# is searched alone, retaining O(input) storage without splitting match context.
_DECODED_BATCH_CHARS = 256 * 1024
_DECODED_BATCH_WINDOWS = 1024


def _decoded_batches(
    data: str,
    regions: list[_Region],
    values: tuple[str, ...],
    as_bytes: bool,
    covered: list[tuple[int, int]],
) -> Iterator[tuple[str, list[_Window], list[int]]]:
    """Whole decoded windows in bounded search corpora; source context is unchanged."""
    _inner, _leading, chars, width, shortest = _join_tables(values, as_bytes)
    separator = next(char for char in _SEPARATORS if char not in chars)
    parts: list[str] = []
    windows: list[_Window] = []
    starts_at: list[int] = []
    covered_ends = [end for _start, end in covered]
    pos = previous = 0
    count = len(regions)
    for number in range(count):
        start, end, closure = regions[number]
        views = closure.views
        if len(views) > 1:
            cover = bisect_left(covered_ends, end)
            masked = cover < len(covered) and covered[cover][0] <= start
            following = regions[number + 1][0] if number + 1 < count else len(data)
            low, high = max(previous, start - width), min(following, end + width)
            head, tail = start, end
            while head > low and data[head - 1] in chars:
                head -= 1
            while tail < high and data[tail] in chars:
                tail += 1
            # Left boundary of a match at the window's first character: a literal source
            # character, or (None) the text start or the whole gap after the region
            # before (a whole-token form starting there joined the two regions).
            left = None if head in (0, previous) else data[head - 1]
            before, after = data[head:start], data[end:tail]
            size = start - head
            for index in range(1, len(views)):
                view = views[index]
                if size + len(view) + len(after) < shortest:
                    continue  # no form or fragment fits in this window
                length = size + len(view) + len(after) + 1
                if windows and (
                    pos + length > _DECODED_BATCH_CHARS or len(windows) >= _DECODED_BATCH_WINDOWS
                ):
                    yield "".join(parts), windows, starts_at
                    parts, windows, starts_at = [], [], []
                    pos = 0
                windows.append(
                    (pos, head, size, size + len(view), end, closure, index, left, masked)
                )
                starts_at.append(pos)
                parts += (before, view, after, separator)
                pos += size + len(view) + len(after) + 1
        previous = end
    if windows:
        yield "".join(parts), windows, starts_at


def _decoded_spans(
    data: str,
    regions: list[_Region],
    values: tuple[str, ...],
    as_bytes: bool,
    first_only: bool,
    covered: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    """G3 matches mapped to source, with bounded whole-window search batches."""
    forms = _raw_forms(values, as_bytes)
    long_forms = _long_forms(values, as_bytes)
    fragments = _fragments(values)
    found = _SpanUnion(len(data))
    best: tuple[int, int, int, tuple[int, int]] | None = None
    for batch_number, (corpus, windows, starts_at) in enumerate(
        _decoded_batches(data, regions, values, as_bytes, covered)
    ):
        for rank, form in enumerate(forms):
            if first_only and best is not None and rank >= best[0]:
                break
            long = form in long_forms
            length = len(form)
            at = corpus.find(form)
            while at >= 0:
                window = windows[bisect_right(starts_at, at) - 1]
                local = at - window[0]
                size, view_end = window[2], window[3]
                last = local + length - 1
                if window[8] and size <= local and last < view_end:
                    # Every source character of this match is already in the union.
                    # Matches crossing either edge still need their boundary checks and
                    # source mapping: they can extend the union into literal context.
                    at = corpus.find(form, at + 1)
                    continue
                # A match must touch the view (else the raw search has it), or, for a
                # whole-token form, start right after it: its left boundary is then the
                # view's last character, which may be a decoded one the raw view lacks.
                if (local < view_end or (local == view_end and not long)) and last >= size:
                    head, region_end, closure, index = window[1], window[4], window[5], window[6]
                    # A match inside the view's copied head or tail, with the character its
                    # left boundary reads, is the same text at the same source span as in the
                    # raw view, judged the same: the raw search has it.
                    if long or local > 0:
                        first_view = local - size if long else local - size - 1
                        if last - size < closure.heads[index] or first_view >= (
                            view_end - size - closure.tails[index]
                        ):
                            at = corpus.find(form, at + 1)
                            continue
                    region = head + size
                    if last < view_end:
                        end = region + closure.source(index, last - size, True)
                    else:
                        end = region_end + last - view_end + 1
                    ok = long or end == len(data) or data[end] not in _WORD
                    if ok and not long:
                        if local == 0:
                            ok = window[7] is None or window[7] not in _WORD
                        elif corpus[at - 1] in _WORD:
                            prior = local - 1 - size  # a decoded unit is a boundary
                            ok = (
                                0 <= prior < view_end - size
                                and closure.source(index, prior, True)
                                - closure.source(index, prior, False)
                                > 1
                            )
                    if ok:
                        if local < size:
                            first = head + local
                        elif local < view_end:
                            first = region + closure.source(index, local - size, False)
                        else:
                            first = region_end + local - view_end
                        if first_only:
                            if rank == 0:
                                return [(first, end)]
                            candidate = (rank, batch_number, at, (first, end))
                            if best is None or candidate[:3] < best[:3]:
                                best = candidate
                            break
                        found.append((first, end))
                at = corpus.find(form, at + 1)
        groups: Iterator[tuple[int, tuple[str, ...]]]
        if first_only:
            groups = (
                (len(forms) + number, (fragment,)) for number, fragment in enumerate(fragments)
            )
        else:
            groups = iter(((len(forms), fragments),))
        for rank, group in groups:
            if first_only and best is not None and rank >= best[0]:
                break
            runs = _fragment_spans(corpus, group, _B64_RUN, _PAD_RUN)
            for start, stop in runs:
                window = windows[bisect_right(starts_at, start) - 1]
                local, last = start - window[0], stop - 1 - window[0]
                size, view_end = window[2], window[3]
                if window[8] and size <= local and last < view_end:
                    continue
                if local < view_end and last >= size:
                    closure, index = window[5], window[6]
                    region = window[1] + size
                    if local < size:
                        first = window[1] + local
                    else:
                        first = region + closure.source(index, local - size, False)
                    if last < view_end:
                        end = region + closure.source(index, last - size, True)
                    else:
                        end = window[4] + last - view_end + 1
                    if first_only:
                        candidate = (rank, batch_number, start, (first, end))
                        if best is None or candidate[:3] < best[:3]:
                            best = candidate
                        break
                    found.append((first, end))
    if first_only:
        return [] if best is None else [best[3]]
    return found.merged()


def _spans(
    data: str,
    values: tuple[str, ...],
    as_bytes: bool = False,
    first_only: bool = False,
    cache: dict[str, _Closure] | None = None,
    regions_out: list[_Region] | None = None,
) -> list[tuple[int, int]]:
    """G3 matches in every view of ``data`` (raw, then every decoded view of every
    region) and the G5 spans of every region at a bound, merged, in source offsets."""
    found = _raw_spans(data, values, as_bytes)
    if (first_only and found) or ("%" not in data and "\\" not in data and "&" not in data):
        return found if first_only else _merged(found)
    regions = _regions(data, values, as_bytes, {} if cache is None else cache)
    if regions_out is not None:
        regions_out.extend(regions)
    found.extend(_withheld_spans(regions))
    if first_only and found:
        return found
    found = _merged(found)
    found.extend(_decoded_spans(data, regions, values, as_bytes, first_only, found))
    return found if first_only else _merged(found)


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


def _scrub_round(view: str, values: tuple[str, ...], as_bytes: bool = False) -> str:
    """One G4 round: ``view`` with the union of the source spans of every match in every
    G2 view (and, on a G5 bound hit, every escape component) replaced by ``***``.

    The single-round seam of :func:`_scrub_rounds`; the SPEC-V2-A1 AT2(ii) acceptance
    check walks it round by round."""
    spans = _spans(view, values, as_bytes)
    return _masked(view, spans, MASK) if spans else view


@_secret_cache(maxsize=128)
def _mask_stable_forms(values: tuple[str, ...], as_bytes: bool) -> bool:
    """G3 forms whose matches neither depend on word boundaries nor cross a mask."""
    long_forms = _long_forms(values, as_bytes)
    return all(form in long_forms and "*" not in form for form in _raw_forms(values, as_bytes))


def _masked_whole_regions(spans: list[tuple[int, int]], regions: list[_Region]) -> bool:
    """Whether each G2 region touched by the masks is completely removed.

    Both sequences are ordered and disjoint. An untouched region keeps its complete
    closure; a partially masked one must be decoded again (even G5 can change).
    """
    index = 0
    for start, end, _closure in regions:
        while index < len(spans) and spans[index][1] <= start:
            index += 1
        if index < len(spans):
            first, last = spans[index]
            if first < end and (first > start or last < end):
                return False
    return True


def _scrub_rounds(view: str, values: tuple[str, ...], as_bytes: bool) -> tuple[str, bool, bool]:
    """``view`` masked until no form of a secret is left in it or in any partial
    decoding of it. Masking can turn a neighbour of a mask into a whole token (the
    letter before it is gone), so the result is checked again; each round masks at
    least one more character that is not ``*`` (a round that only rewrites runs of
    ``*`` is the last), so this ends.

    Returns ``(result, found, clean)``: whether the first round found a form of a
    secret (what :func:`contains_secret` answers), and whether the last round found
    none in the result (so scrubbing the result again returns it unchanged).

    G2/G3/G4 fixed-point shortcut: if all forms match without word boundaries and
    contain no "*", and masks remove every region they touch in full, no new match
    is possible. Remaining regions have unchanged closures and bounds; "*" is a G2
    separator, so no new token or form can cross a mask. Embedded-base64 matches
    likewise cannot cross "*": its alphabet excludes it, and splitting a run cannot
    create a fragment. Other cases retain the full fixed-point loop."""
    found = False
    closures: dict[str, _Closure] = {}  # region text -> closure, across the rounds
    while True:
        regions: list[_Region] = []
        spans = _spans(view, values, as_bytes, cache=closures, regions_out=regions)
        if not spans:
            return view, found, True
        found = True
        masked = _masked(view, spans, MASK)
        if _mask_stable_forms(values, as_bytes) and _masked_whole_regions(spans, regions):
            return masked, found, True
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
# outcome of scrubbing a large text is remembered by a per-process keyed BLAKE2b digest --
# never the text itself, which may hold a secret -- with the configured secrets (already
# held by the form caches above) and the str/bytes mode: whether it holds a secret, and
# its scrubbed result (what the caller is returned anyway, never the input). A result
# that is a fixed point is remembered as clean too, so scrubbing it again is free.
# Bounded in entries and in the characters of the results kept.
#: Shorter texts are scrubbed again rather than hashed (their decode costs less).
_MEMO_HASH_KEY = os.urandom(32)
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
    digest = hashlib.blake2b(
        view.encode("utf-8", "surrogatepass"), key=_MEMO_HASH_KEY, digest_size=32
    ).digest()
    return values, as_bytes, digest


def _memo_get(key: _MemoKey) -> tuple[bool, str | None] | None:
    with _memo_lock:
        state = _call_secrets.get()
        memo = _memo if state is None else state.outcomes
        hit = memo.get(key)
        if hit is not None:
            memo.move_to_end(key)
        return hit


def _memo_put(key: _MemoKey, found: bool, result: str | None) -> None:
    global _memo_chars
    with _memo_lock:
        state = _call_secrets.get()
        memo = _memo if state is None else state.outcomes
        chars = _memo_chars if state is None else state.outcome_chars
        old = memo.pop(key, None)
        if old is not None and old[1] is not None:
            chars -= len(old[1])
        memo[key] = (found, result)
        chars += len(result) if result is not None else 0
        while len(memo) > _MEMO_MAX_ENTRIES or chars > _MEMO_MAX_CHARS:
            _, (_, dropped) = memo.popitem(last=False)
            chars -= len(dropped) if dropped is not None else 0
        if state is None:
            _memo_chars = chars
        else:
            state.outcome_chars = chars


def _memo_clear() -> None:
    """Forget every remembered outcome (timing tests measure the scrub itself)."""
    global _memo_chars
    with _memo_lock:
        _memo.clear()
        _memo_chars = 0
        state = _call_secrets.get()
        if state is not None:
            state.outcomes.clear()
            state.outcome_chars = 0


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
    """Mask configured secrets using bounded layered decoding with source offsets."""
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
    clean = text
    # Masking an embedded secret can join the text around it into a new encoded form of the
    # secret (the first pass is blind to what its own masks uncover), so run to a fixpoint:
    # the result is then idempotent, and a later pass over it (formatter, handler, emit)
    # can never mask more than this one did. Each changing pass shortens or keeps the
    # text, so the loop ends; the bound is a backstop, not a limit on what is scrubbed.
    for _ in range(len(text) + 1):
        step = scrub(clean, values)
        for secret in values:
            step = step.replace(secret, MASK)
        if step == clean:
            break
        clean = step
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
    values = [*_provider(), *call_secret_values(), *log_secret_values()]
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
    # A handler may retain the record after the call ends. Never let the global
    # memo retain caller values or call-derived text independently of its scope.
    cacheable = not withheld and _call_secrets.get() is None
    return scrub_record_text(record, text, values, scrub_log_text, cacheable=cacheable)


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
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    if not _installed:
        previous = logging.getLogRecordFactory()

        def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
            record = previous(*args, **kwargs)
            # Preserve the request line used by accounting but drop caller query values.
            if (
                record.name == "httpx"
                and isinstance(record.args, tuple)
                and len(record.args) == 5
                and str(record.msg).startswith("HTTP Request:")
            ):
                request_args = list(record.args)
                request_args[1] = str(request_args[1]).split("?", 1)[0]
                record.args = tuple(request_args)
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
