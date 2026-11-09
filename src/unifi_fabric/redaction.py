"""Opt-in credential redaction (public issue https://github.com/swkstudios/unifi-fabric-mcp-server/issues/26).

By default the server is a faithful pass-through: upstream responses are returned
verbatim and redaction is a no-op. When the operator sets ``UNIFI_REDACT_SECRETS``
to a truthy value, EVERY tool response has a DOCUMENTED, EXPLICIT set of credential
fields masked at one shared point before it leaves the server.

A key is a credential field when it matches one of three documented rules, all
case-insensitive and anchored (never a free substring search):

1. its exact name is in :data:`CREDENTIAL_FIELDS` (any value is masked, except null or
   the empty string, which hold nothing to mask), or in :data:`CREDENTIAL_STRING_FIELDS`
   and its value is a non-empty string;
2. it ends with a suffix in :data:`CREDENTIAL_SUFFIXES` (``google_maps_api_key``,
   ``wireguard_private_key``, ``utm_token``) and its value is a string;
3. it is a controller hidden ``x_`` field (not an ``x_has_`` presence flag) whose name
   ends with an ending in :data:`X_FIELD_CREDENTIAL_ENDINGS` (``x_authkey``,
   ``x_stripe_api_key``, ``x_ssh_sha512passwd``) and its value is a string.

A pagination cursor (:data:`CURSOR_FIELDS`: ``nextToken``, ``page_token`` ...) is
never a credential field, under any rule.

Rules 2 and 3 never mask a boolean, number, null, object or list (a flag such as
``radius_macacl_empty_password: false`` is a setting, not a credential); containers are
recursed into instead. Every non-credential field is left byte-identical to the
unmasked response.

Coverage is installed once, server-wide, by :func:`install_response_redaction`,
which wraps every registered tool's handler. The wrapper reads the flag at call
time: when redaction is disabled it returns the handler result unchanged (a
byte-identical pass-through with no transform), so the default output and the
pre-publish pass-through guard baseline are unaffected.

The reverse direction is handled in the client's single write path: a write body
field whose value is exactly :data:`REDACTION_MASK` is left out of the request only
when redaction is enabled (so a
redacted read fed back into an update never overwrites the stored secret with the
mask) and the dropped paths are reported on the tool result under
:data:`MASKED_FIELDS_KEY`. This is not a refusal; the rest of the write is sent.
"""

from __future__ import annotations

import ast
import functools
import inspect
import json
import re
import sys
import unicodedata
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .switches import env_flag

#: Replacement value substituted for a matched credential field.
REDACTION_MASK = "***REDACTED***"

#: Opt-in rule 1: documented explicit set of credential-class field names masked when
#: ``UNIFI_REDACT_SECRETS`` is enabled, whatever the value type. Matched
#: case-insensitively against the exact key name. Keep this list, the suffix and ``x_``
#: rules below and the docs/CONFIGURATION.md "Credential redaction" section in sync.
CREDENTIAL_FIELDS: frozenset[str] = frozenset(
    {
        # WLAN / wlanconf pre-shared keys and passwords
        "x_passphrase",
        "x_password",
        "x_iapp_key",
        "x_wep",
        "wpa_psk",
        "sae_psk",  # WPA3 SAE passwords (scalar or list), not an enable flag.
        "x_mesh_psk",
        # WPA-Enterprise / certificate key material
        "x_ca_crt",
        "x_ca_key",
        "x_certificate_crt",
        "x_certificate_key",
        "server_certificate_key",
        "x_private_key",
        "private_key",
        "privatekey",
        # RADIUS shared secrets
        "x_secret",
        "x_radius_secret",
        "radius_secret",
        # SSH / device management credentials (get_system_info, device settings)
        "x_ssh_password",
        "ssh_password",
        "x_ssh_sudopassword",
        "syslog_key",
        # VPN pre-shared keys / tunnel secrets (IPsec / L2TP / WireGuard)
        "x_ipsec_pre_shared_key",
        "ipsec_pre_shared_key",
        "pre_shared_key",
        "preshared_key",
        "presharedkey",
        "psk",
        "x_psk",
        # VPN client credentials (Classic networkconf vpn-client records: list_vpn_clients,
        # create_vpn_client / update_vpn_client bodies and dry-run previews)
        "x_wireguard_private_key",
        "x_openvpn_password",
        "openvpn_configuration",
        # API tokens / auth material / cloud access
        "api_token",
        "x_api_token",
        "api_key",
        "apikey",
        "device_auth",  # Cloud device authentication material, distinct from device_id.
        "auth_token",
        "x_auth_token",
        "access_token",
        "refresh_token",
        # Controller camelCase credential fields.
        "sharedsecret",
        "authserversecret",
        "wanpassword",
        "wireguardprivatekey",
        "clientsecret",
        "bearertoken",
        "apitoken",
        "accesstoken",
        "refreshtoken",
        "radiussecret",
        "pppoepassword",
        "sshpassword",
        # Controller x_ aliases for the documented camelCase fields.
        "x_shared_secret",
        "x_auth_server_secret",
        "x_wan_password",
        "x_client_secret",
        "x_bearer_token",
        "x_access_token",
        "x_refresh_token",
        "x_pppoe_password",
        # Generic named credential fields (WLAN, Dynamic DNS, hotspot operator,
        # RADIUS account, settings objects)
        "passphrase",
        "password",
        "secret",
        "token",
    }
)


#: Opt-in rule 1, string values only: exact credential names (matched
#: case-insensitively) whose value is masked when it is a non-empty string. A boolean,
#: number, null, object or list under one of these names is left as is.
CREDENTIAL_STRING_FIELDS: frozenset[str] = frozenset(
    {
        "acctserversecret",  # RADIUS accounting server secret (acctServerSecret)
        "authtoken",  # authToken
        "hashedpassword",  # hashedPassword
        "wpapsk",  # WLAN pre-shared key (wpaPsk)
    }
)

#: Pagination cursors: never credential fields, whatever the rules above would say
#: (``page_token`` / ``next_token`` end with the ``_token`` suffix). Matched
#: case-insensitively against the exact key name.
CURSOR_FIELDS: frozenset[str] = frozenset(
    {
        "nexttoken",
        "next_token",
        "pagetoken",
        "page_token",
        "continuationtoken",
        "continuation_token",
    }
)

#: Opt-in rule 2: a key ending with one of these snake_case suffixes (case-insensitive)
#: is a credential when its value is a string. The underscore is part of the suffix, so
#: camelCase identifiers such as Protect ``profileToken`` (a stream-profile id) and
#: ``digitalInputTokens`` are never matched, and neither are ``token_count`` / ``key_id``.
CREDENTIAL_SUFFIXES: tuple[str, ...] = (
    "_api_key",
    "_private_key",
    "_secret",
    "_token",
    "_password",
    "_passphrase",
)

#: Opt-in rule 3: the controller prefixes its hidden fields with ``x_``; such a key is a
#: credential when its name ends with one of these (case-insensitive) and its value is a
#: string. Derived from :data:`CREDENTIAL_FIELDS` and the ``x_`` keys in
#: ``tests/fixtures/recorded``. Matched there: ``x_iapp_key``, ``x_authkey``,
#: ``x_inform_authkey``, ``x_vwirekey``, ``x_mgmt_key``, ``x_private_key``,
#: ``x_wireguard_private_key``, ``x_pregenerated_dh_key``, ``x_stripe_api_key``,
#: ``x_quickpay_apikey``, ``x_merchantwarrior_apikey``, ``x_authorize_transactionkey``,
#: ``x_mesh_psk``, ``x_element_psk``, ``x_passphrase``,
#: ``x_merchantwarrior_apipassphrase``, ``x_password``, ``x_paypal_password``,
#: ``x_ssh_password``, ``x_ssh_sha512passwd``, ``x_secret``, ``x_api_token``,
#: ``x_sso_token``, ``x_paypal_signature``; VPN clients (r18 list_vpn_clients /
#: create_vpn_client) add ``x_wireguard_private_key`` and ``x_openvpn_password``.
#: Left verbatim: identifiers and flags (``x_ssh_username``, ``x_paypal_username``,
#: ``x_quickpay_merchantid``,
#: ``x_quickpay_agreementid``, ``x_authorize_loginid``, ``x_ippay_terminalid``,
#: ``x_merchantwarrior_merchantuuid``, ``x_mesh_essid``, ``x_element_essid``,
#: ``x_ssh_enabled``, ``x_ssh_bind_wildcard``, ``x_ssh_auth_password_enabled``,
#: ``x_aes_gcm``), public material (``x_certificate_pem``, ``x_certificate_arn``,
#: ``x_ssh_keys`` authorized public keys, ``x_ssh_hostkey_fingerprint``) and ``x_has_``
#: presence flags (``x_has_ssh_hostkey``).
X_FIELD_CREDENTIAL_ENDINGS: tuple[str, ...] = (
    "key",
    "psk",
    "passphrase",
    "password",
    "passwd",
    "secret",
    "token",
    "signature",
)


def _is_pattern_credential_key(lowered: str) -> bool:
    """Rules 2 and 3 on an already lower-cased key (value type checked by the caller)."""
    if lowered.endswith(CREDENTIAL_SUFFIXES):
        return True
    return (
        lowered.startswith("x_")
        and not lowered.startswith("x_has_")
        and lowered.endswith(X_FIELD_CREDENTIAL_ENDINGS)
    )


def is_credential_field(key: Any) -> bool:
    """Return True if ``key`` names a credential field under any documented rule.

    This classifies the key only. :func:`redact_credentials` masks a rule 2 or 3 match
    only when its value is a string; callers that inspect values apply the same gate.
    """
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    if lowered in CURSOR_FIELDS:
        return False
    return (
        lowered in CREDENTIAL_FIELDS
        or lowered in CREDENTIAL_STRING_FIELDS
        or _is_pattern_credential_key(lowered)
    )


def _is_empty(value: Any) -> bool:
    """True for a value that holds nothing to mask: null or the empty string."""
    return value is None or value == ""


def _should_mask(key: Any, value: Any) -> bool:
    """True when ``key: value`` is masked under ``UNIFI_REDACT_SECRETS``."""
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    if lowered in CURSOR_FIELDS:
        return False
    if lowered in CREDENTIAL_FIELDS or lowered in CREDENTIAL_STRING_FIELDS:
        # Rule 1 (exact names): a null or empty value holds nothing to mask.
        if _is_empty(value):
            return False
        return lowered in CREDENTIAL_FIELDS or isinstance(value, str)
    return isinstance(value, str) and _is_pattern_credential_key(lowered)


def redact_credentials(obj: Any) -> Any:
    """Return a deep copy of ``obj`` with every documented credential field masked.

    Recurses through dicts, lists and tuples. The value of any key in
    :data:`CREDENTIAL_FIELDS`, and the string value of any key matching
    :data:`CREDENTIAL_SUFFIXES` or the ``x_`` rule, is replaced with
    :data:`REDACTION_MASK`; all other keys and values are preserved unchanged. The
    input object is never mutated.
    """
    if isinstance(obj, dict):
        return {
            k: (REDACTION_MASK if _should_mask(k, v) else redact_credentials(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_credentials(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(redact_credentials(item) for item in obj)
    return obj


#: The longest quoted key read in error text (a key never spans a line either).
_ERROR_KEY_MAX = 1024
#: A JSON or Python escape written into a bare key (``pass\u0077ord=v``), at any depth.
_ERROR_KEY_ESCAPE = r"\\+(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2})"
#: Where a key in error text starts: the opening quote of a quoted key, as JSON or a
#: Python repr writes it at any escape depth (``"k"``, ``'k'``, ``\"k\"``, ``\\'k\\'``;
#: its complete content and the ``:`` or ``=`` after it are read by
#: :func:`_quoted_error_key`), or a bare key before ``=`` (``k=v``: a keyword argument, a
#: query or form parameter). A bare key is any run of word characters (Unicode, digits
#: first included), ``.:/@$+-`` and escapes, starting after a delimiter or a ``\n``,
#: ``\r`` or ``\t`` escape, at most a quarter of :data:`_ERROR_KEY_MAX` long.
_ERROR_KEY = re.compile(
    r"(?P<q>\\*[\"'])"
    r"|(?:(?<![\w\\\"'-])|(?<=\\[nrt]))"
    rf"(?P<bare>(?:[\w.:/@$+-]|{_ERROR_KEY_ESCAPE}){{1,{_ERROR_KEY_MAX // 4}}})"
    r"[ \t]?=(?!=)[ \t]?"
)
#: The separator between a quoted key and its value.
_ERROR_KEY_SEPARATOR = re.compile(r"\s*[:=]\s*")
#: How many escape layers a key is decoded through (a repr of JSON-encoded JSON is 3).
_ERROR_KEY_DEPTH = 6
#: Maximum fallback escape-decoding iterations; scan the result of every iteration.
_ERROR_ESCAPE_ITERATIONS = 128
_ERROR_WITHHELD = (
    "upstream error withheld: it contained credential-shaped content (UNIFI_REDACT_SECRETS)"
)
#: One JSON or Python string escape: ``\uXXXX``, ``\UXXXXXXXX``, ``\xXX``, ``\N{name}``,
#: an octal escape, or a backslash before any other character.
_KEY_ESCAPE = re.compile(
    r"\\(?:u(?P<u>[0-9A-Fa-f]{4})|U(?P<U>[0-9A-Fa-f]{8})|x(?P<x>[0-9A-Fa-f]{2})"
    r"|N\{(?P<name>[^}]*)\}|(?P<octal>[0-7]{1,3})|(?P<char>.))",
    re.DOTALL,
)
_KEY_SIMPLE_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
}
#: The opening quote of a quoted value, with the backslashes its escape depth adds.
_ERROR_QUOTE = re.compile(r"\\*[\"']")
#: An unquoted value: a JSON scalar, a repr'd number or a bare ``k=v`` value.
_ERROR_BARE_VALUE = re.compile(r"[^\s,;&)\]}]+")
_ERROR_PAIR_BARE_VALUE = re.compile(r"[^,;&\n\r)\]}]+")
_ERROR_LITERAL_PREFIX = re.compile(r"""(?i:br|rb|rf|fr|b|r|u|f)(?=["'])""")
_ERROR_SCALARS: dict[str, Any] = {
    "null": None,
    "None": None,
    "true": True,
    "True": True,
    "false": False,
    "False": False,
}


def _quoted_value_end(
    text: str,
    start: int,
    quote: str,
    stop: int | None = None,
    *,
    escape_scale: int | None = None,
) -> tuple[int, int]:
    """Find the closing quote at the enclosing representation's escape parity.

    Each enclosing string doubles the backslashes representing an escape. A closing
    quote can also follow any number of literal backslashes; only its delimiter's
    backslashes belong outside the masked content. Unclosed values run to ``stop``.
    """
    depth, char = len(quote) - 1, quote[-1]
    if escape_scale is None:
        escape_scale = max(1, depth + 1)
    limit = len(text) if stop is None else stop
    cursor = start
    while (found := text.find(char, cursor, limit)) >= 0:
        first = found
        while first > start and text[first - 1] == "\\":
            first -= 1
        if (found - first - depth) % (2 * escape_scale) == 0:
            return found - depth, found + 1
        cursor = found + 1
    return limit, limit


def _quoted_error_key(text: str, start: int, quote: str) -> tuple[str, int] | None:
    """``(raw key, value start)`` for a quoted key whose ``quote`` ends at ``start``.

    The key is the COMPLETE quoted content, any characters and escapes included, closed
    by the quote of the opening's depth (:func:`_quoted_value_end`) on the same line and
    followed by ``:`` or ``=``. ``None`` when the quote opens no key.
    """
    newline = text.find("\n", start)
    stop = min(len(text) if newline < 0 else newline, start + _ERROR_KEY_MAX)
    last, end = _quoted_value_end(text, start, quote, stop)
    if last == end:
        return None  # Unclosed on this line: not a key.
    separator = _ERROR_KEY_SEPARATOR.match(text, end)
    if separator is None:
        return None
    return text[start:last], separator.end()


def _unescape_key(key: str) -> str:
    """``key`` with one layer of JSON or Python string escapes decoded.

    Covers both grammars (``json.loads`` for a double-quoted key, a Python literal for a
    single-quoted one): ``\\uXXXX``, ``\\UXXXXXXXX``, ``\\xXX``, ``\\N{name}``, octal,
    the single-letter escapes and an escaped quote or backslash. Never evaluates code and
    never raises: an escape that does not decode is kept as written.
    """

    def decode(match: re.Match[str]) -> str:
        code = match.group("u") or match.group("U") or match.group("x")
        if code is not None:
            point = int(code, 16)
            return chr(point) if point <= sys.maxunicode else match.group()
        if (name := match.group("name")) is not None:
            try:
                return unicodedata.lookup(name)
            except KeyError:
                return match.group()
        if (octal := match.group("octal")) is not None:
            return chr(int(octal, 8))
        char = match.group("char")
        return _KEY_SIMPLE_ESCAPES.get(char, char)

    return _KEY_ESCAPE.sub(decode, key) if "\\" in key else key


def _error_key_forms(raw: str) -> list[str]:
    """``raw`` and each decoding of it, one escape layer at a time.

    An error key is written at the escape depth of the message around it (a key inside a
    repr of JSON carries ``pass\\\\u0077ord``), so every layer down to the plain key is
    tried against the credential rules: a key is a credential field when any form is.
    """
    forms = [raw]
    for _ in range(_ERROR_KEY_DEPTH):
        decoded = _unescape_key(forms[-1])
        if decoded == forms[-1]:
            break
        forms.append(decoded)
    return forms


def _structure_end(text: str, start: int) -> int:
    """Consume a complete credential container, or fail closed on ambiguity."""
    end = _literal_end(text, start)
    if end is not None:
        span = text[start:end]
        try:
            json.loads(span)
            return end
        except ValueError:
            try:
                ast.literal_eval(span)
                return end
            except (ValueError, TypeError, SyntaxError, RecursionError):
                pass
    # An invalid/unclosed representation cannot safely establish a delimiter.
    return len(text)


def _bare_value(token: str) -> Any:
    """An unquoted value as the type it spells (``null`` -> None, ``12`` -> 12)."""
    if token in _ERROR_SCALARS:
        return _ERROR_SCALARS[token]
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        return token


def _literal_end(text: str, start: int) -> int | None:
    """Scan one balanced literal with local quote and backslash state.

    Prose apostrophes never establish representation depth. Only completely
    parsed literals may decode an enclosing representation.
    """
    stack: list[str] = []
    quote = ""
    cursor = start
    while cursor < len(text):
        char = text[cursor]
        if quote:
            if char == "\\":
                cursor += 2
                continue
            if char == quote:
                quote = ""
                if not stack:
                    return cursor + 1
        elif char in "\"'":
            quote = char
        elif char in "{[(":
            stack.append({"{": "}", "[": "]", "(": ")"}[char])
        elif char in "}])":
            if not stack or stack.pop() != char:
                return None
            if not stack:
                return cursor + 1
        cursor += 1
    return None


def _mask_literal_value(value: Any, depth: int) -> Any:
    """Apply the shared predicate, including structures encoded inside strings."""
    if isinstance(value, dict):
        return {
            key: REDACTION_MASK if _should_mask(key, item) else _mask_literal_value(item, depth)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_mask_literal_value(item, depth) for item in value]
    if isinstance(value, tuple):
        return tuple(_mask_literal_value(item, depth) for item in value)
    if isinstance(value, str):
        return _mask_error_text(value, depth + 1)
    return value


def _split_string_container(value: str) -> bool:
    """Reject prose-string prefixes that end partway through a container.

    A complete encoded string is authoritative at its own escape layer. For
    prose, only the first container matters: its quoted values may contain
    arbitrary unmatched braces.
    """
    try:
        json.loads(value)
        return False
    except ValueError:
        try:
            ast.literal_eval(value)
            return False
        except (ValueError, TypeError, SyntaxError, RecursionError):
            pass
    opening = re.search(r"[{\[(]", value)
    return opening is not None and _literal_end(value, opening.start()) is None


def _mask_embedded_json(text: str, depth: int) -> str:
    """Mask complete JSON/repr literals; leave other spans to the fallback.

    Never use raw_decode: accepting a prefix of a represented document can change
    its escape grammar and expose the remainder of a credential value.
    """
    literals: list[tuple[int, int, str]] = []
    position = 0
    while position < len(text):
        char = text[position]
        if char not in "{[(\"'" or (
            char in "\"'"
            and position
            and (text[position - 1].isalnum() or text[position - 1] == "\\")
        ):
            position += 1
            continue
        end = _literal_end(text, position)
        if end is None:
            position += 1
            continue
        span = text[position:end]
        try:
            value = json.loads(span)
            is_json = True
        except ValueError:
            try:
                value = ast.literal_eval(span)
                is_json = False
            except (ValueError, TypeError, SyntaxError, RecursionError):
                position += 1
                continue
        if isinstance(value, str) and _split_string_container(value):
            # A prose quote can close inside a represented container. Test the
            # decoded layer, never raw nested offsets from another escape layer.
            position += 1
            continue
        if isinstance(value, str):
            try:
                inner = ast.literal_eval(value)
            except (ValueError, TypeError, SyntaxError, RecursionError):
                position += 1
                continue
            if not isinstance(inner, (dict, list, tuple, str)):
                position += 1
                continue
        masked = _mask_literal_value(value, depth)
        if masked != value:
            rendered = json.dumps(masked, ensure_ascii=False) if is_json else repr(masked)
            # Render before the quoting-agnostic final fallback scan.
            literals.append((position, end, rendered))
            position = end
        elif isinstance(value, (dict, list, tuple, str)):
            literals.append((position, end, span))
            position = end
        else:
            # A valid string may only be a prefix delimited by prose quotes.
            # Keep looking inside it for an independently complete structure.
            position += 1
    # Scan the FINAL rendering too, including every structured span. Descendants
    # such as bytes and sets may contain credential pairs that literal traversal
    # does not interpret; no enclosing container grants them an exemption.
    pieces: list[str] = []
    cursor = 0
    for first, end, rendered in literals:
        pieces.extend((text[cursor:first], rendered))
        cursor = end
    pieces.append(text[cursor:])
    return _fail_closed_error_text("".join(pieces))


def mask_error_text(text: str) -> str:
    """Error text with every credential field's value masked, whatever form carries it.

    The one boundary every tool error passes on its way to the client under
    ``UNIFI_REDACT_SECRETS`` (``server.SecretScrubMiddleware``); the per-site renderings
    (``client.upstream_error_value`` and friends) mask first, and this is the guarantee
    behind them. The keys are the documented credential fields (:func:`_should_mask`,
    the list :func:`redact_credentials` and ``route_secrets`` use), in every form an
    upstream value takes once formatted into a message:

    * an embedded JSON object or array, parsed and re-rendered masked;
    * a JSON or Python-repr pair (``"k": "v"``, ``'k': 'v'``, ``'k': "it's"``) at any
      escape depth: inside a repr'd or JSON-encoded string (``\\"k\\": \\"v\\"``), with
      escaped quotes and apostrophes in the value, and with an object, array, number or
      ``true``/``false`` value (masked under the same type rules as a response);
    * a ``k=v`` pair, quoted (``password='v'``) or bare (``api_key=v``).

    A key is read whole, any characters included (``1_password``,
    ``service.auth_password``, ``é_password``), and decoded through its escape layers
    (``pass\\u0077ord``) before the same rules :func:`redact_credentials` applies to a
    response key decide whether it is a credential field. A bare key that is not one is
    retried from each later segment (``service.password=v`` is read as ``password``).

    Single-level JSON/repr diagnostics are preserved. Nested strings are decoded
    up to six layers; ambiguous credential spans fail closed through the end of
    the message and may discard following identifiers and reasons. Parser errors
    never escape this boundary. Masking is idempotent.
    """
    if not isinstance(text, str) or not text:
        return text
    return _mask_error_text(text, 0)


def _fail_closed_error_text(text: str) -> str:
    """Find credential tokens through escape layers and drop an uncertain suffix.

    Keep source offsets while decoding so an escaped key cannot hide the start
    of the unsafe span. Scan each level, including the final result, until a
    fixed point. Exhausting the decoding bound withholds the whole message.
    This fallback does not attempt to recover diagnostics.
    """
    decoded = text
    offsets = list(range(len(text)))
    earliest = len(text)
    for iteration in range(_ERROR_ESCAPE_ITERATIONS + 1):
        for token in re.finditer(r"[\w./@$+-]+", decoded):
            # Only keys qualify; prose and longer tool identifiers are preserved.
            separator = re.match(r"[\"']?\s*[:=]\s*", decoded[token.end() :])
            if separator is None:
                continue
            if decoded[: token.start()].endswith("Error calling tool '") and re.match(
                r"[\w.-]+':", decoded[token.start() :]
            ):
                continue  # Only a complete, identifier-only tool header is exempt.
            value_start = token.end() + separator.end()
            value: Any = decoded[value_start:]
            if (quote := _ERROR_QUOTE.match(decoded, value_start)) is not None:
                last, end = _quoted_value_end(decoded, quote.end(), quote.group())
                quoted = decoded[quote.end() : last]
                if last != end and quoted == REDACTION_MASK:
                    continue  # Proven masked value, not a trusted container span.
                # Empty quoted values are valid; a third quote is ambiguous.
                closed = last != end
                triple = not quoted and decoded.startswith(quote.group(), end)
                value = quoted if closed and not triple else decoded[value_start:]
            elif value_start < len(decoded) and decoded[value_start] in "{[(":
                literal_end = _literal_end(decoded, value_start)
                if literal_end is not None:
                    try:
                        value = ast.literal_eval(decoded[value_start:literal_end])
                    except (ValueError, TypeError, SyntaxError, RecursionError):
                        pass
            elif (bare := _ERROR_BARE_VALUE.match(decoded, value_start)) is not None:
                value = _bare_value(bare.group())
            word = token.group()
            starts = [0, *(match.end() for match in re.finditer(r"[./@$+-]", word))]
            for start in starts:
                if _should_mask(word[start:], value):
                    earliest = min(earliest, offsets[token.start() + start])
        matches = list(_KEY_ESCAPE.finditer(decoded))
        if not matches:
            break
        parts: list[str] = []
        mapped: list[int] = []
        cursor = 0
        for match in matches:
            parts.append(decoded[cursor : match.start()])
            mapped.extend(offsets[cursor : match.start()])
            replacement = _unescape_key(match.group())
            parts.append(replacement)
            mapped.extend([offsets[match.start()]] * len(replacement))
            cursor = match.end()
        parts.append(decoded[cursor:])
        mapped.extend(offsets[cursor:])
        updated = "".join(parts)
        if updated == decoded:
            break
        if iteration == _ERROR_ESCAPE_ITERATIONS:
            # The final decoded level was scanned above. Further decoding is
            # unresolved, so even an apparently safe prefix cannot be trusted.
            return _ERROR_WITHHELD
        decoded, offsets = updated, mapped
    return text[:earliest] + REDACTION_MASK if earliest < len(text) else text


def _mask_error_text(text: str, depth: int) -> str:
    """Decode at most six enclosing strings; every failure uses the same guard."""
    try:
        if depth >= _ERROR_KEY_DEPTH:
            return _fail_closed_error_text(text)
        return _mask_embedded_json(text, depth)
    except Exception:
        try:
            return _fail_closed_error_text(text)
        except Exception:
            return REDACTION_MASK


def _mask_error_pairs(text: str, literals: list[tuple[int, int, str]]) -> str:
    """Scan original grammar outside literals, allowing enclosing credential pairs."""
    replacements = list(literals)
    position = literal_index = 0
    while (match := _ERROR_KEY.search(text, position)) is not None:
        while literal_index < len(literals) and literals[literal_index][1] <= match.start():
            literal_index += 1
        if literal_index < len(literals):
            first, end, _ = literals[literal_index]
            if first <= match.start() < end:
                position = end
                continue
        if (opening := match.group("q")) is not None:
            found = _quoted_error_key(text, match.end(), opening)
            if found is None:
                position = match.start() + 1  # A shallower opening, or the next quote.
                continue
            raw, start = found
        else:
            raw, start = match.group("bare"), match.end()
        keys = _error_key_forms(raw)
        if not any(is_credential_field(key) for key in keys):
            # A non-credential value (a JSON string, an object) is scanned too, and a
            # bare key's later segments are tried as keys of their own.
            position = start if opening is not None else match.start() + 1
            continue
        position = start
        value: Any
        prefix = _ERROR_LITERAL_PREFIX.match(text, start)
        quote_start = prefix.end() if prefix else start
        if (quote := _ERROR_QUOTE.match(text, quote_start)) is not None:
            content_start = quote.end()
            last, end = _quoted_value_end(text, content_start, quote.group())
            value = text[content_start:last]
            if prefix:
                first, last = start, end
            else:
                first = content_start
        elif start < len(text) and text[start] in "{[":
            first, end = start, _structure_end(text, start)
            last, value = end, {"value": text[start:end]}  # An object: masked by name only.
        elif (bare := _ERROR_PAIR_BARE_VALUE.match(text, start)) is not None:
            first, last = bare.span()
            end, value = last, _bare_value(bare.group())
        else:
            continue
        if value == REDACTION_MASK or not any(_should_mask(key, value) for key in keys):
            continue
        replacements.append((first, last, REDACTION_MASK))
        position = end
    pieces: list[str] = []
    cursor = 0
    # An enclosing credential value wins over any literals parsed inside it.
    # Reverse insertion order so a whole-value mask also wins an identical span.
    for first, last, rendered in sorted(
        reversed(replacements), key=lambda item: (item[0], -item[1])
    ):
        if first < cursor:
            continue
        pieces.extend((text[cursor:first], rendered))
        cursor = last
    return "".join((*pieces, text[cursor:])) if pieces else text


#: Additive key on a write tool's result listing the body fields that held exactly
#: :data:`REDACTION_MASK` and were therefore left out of the upstream request.
MASKED_FIELDS_KEY = "_redactedFieldsNotSent"

#: Per tool call: the masked body-field paths the client dropped from its writes.
#: ``None`` outside a tool call (direct client use); the tool wrapper sets a fresh list.
_dropped_masked_fields: ContextVar[list[str] | None] = ContextVar(
    "unifi_dropped_masked_fields", default=None
)


_write_redaction: ContextVar[bool | None] = ContextVar("unifi_write_redaction", default=None)


def write_redaction_enabled() -> bool:
    """Use the enclosing tool/client setting, or the explicit environment opt-in."""
    enabled = _write_redaction.get()
    return env_flag("UNIFI_REDACT_SECRETS", False) if enabled is None else enabled


@contextmanager
def write_redaction_scope(enabled: bool) -> Iterator[None]:
    """Bind mask interpretation to the same setting as response redaction."""
    token = _write_redaction.set(enabled)
    try:
        yield
    finally:
        _write_redaction.reset(token)


class RedactionScopeMiddleware(Middleware):
    """Use the runtime setting for mask handling even before the tool handler runs."""

    def __init__(self, should_redact: Callable[[], bool]) -> None:
        self._should_redact = should_redact

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        with write_redaction_scope(self._should_redact()):
            return await call_next(context)


def drop_masked_fields(body: Any) -> tuple[Any, list[str]]:
    """Return ``(body without masked fields, dropped field paths)``.

    A read under ``UNIFI_REDACT_SECRETS`` returns credential fields as
    :data:`REDACTION_MASK`. Sending that object back to a write would overwrite the real
    secret with the literal mask, so every object field whose value is exactly the mask
    is left out of the request and the upstream keeps its stored value. Recurses through
    nested objects and lists; a list keeps every element (only object fields inside it
    are dropped). Paths are dotted with list indices in brackets (``radius.x_secret``,
    ``peers[0].private_key``). The input is never mutated; a body with no masked field
    is returned as the same object.
    """
    if not write_redaction_enabled():
        return body, []
    dropped: list[str] = []

    def walk(node: Any, path: str) -> Any:
        if isinstance(node, dict):
            out: dict[Any, Any] = {}
            changed = False
            for k, v in node.items():
                child = f"{path}.{k}" if path else str(k)
                if isinstance(v, str) and v == REDACTION_MASK:
                    dropped.append(child)
                    changed = True
                    continue
                new_v = walk(v, child)
                changed = changed or new_v is not v
                out[k] = new_v
            return out if changed else node
        if isinstance(node, list):
            items = [walk(item, f"{path}[{i}]") for i, item in enumerate(node)]
            return items if any(a is not b for a, b in zip(items, node, strict=True)) else node
        return node

    return walk(body, ""), dropped


def note_dropped_fields(paths: list[str]) -> None:
    """Record masked field paths dropped from a write, for the current tool call."""
    sink = _dropped_masked_fields.get()
    if sink is not None:
        sink.extend(p for p in paths if p not in sink)


def drop_and_note_masked_fields(body: Any) -> Any:
    """:func:`drop_masked_fields` plus :func:`note_dropped_fields`; returns the clean body."""
    clean, dropped = drop_masked_fields(body)
    if dropped:
        note_dropped_fields(dropped)
    return clean


def _with_dropped_report(result: Any, dropped: list[str]) -> Any:
    """Add the dropped masked-field paths to a tool result (additive ``_`` key).

    An object result gains :data:`MASKED_FIELDS_KEY`. Bare arrays keep their shape:
    metadata goes on their object records, as with write warnings. An array containing
    only scalars (or no records) has nowhere for additive keys and stays unchanged.
    Other scalar results use the server's list envelope.
    """
    if not dropped:
        return result
    # Local import: the tools' client imports redaction during module initialization.
    from .tools._keys import with_context

    if isinstance(result, dict):
        return with_context(result, {MASKED_FIELDS_KEY: list(dropped)})
    if isinstance(result, list):
        return [
            with_context(record, {MASKED_FIELDS_KEY: list(dropped)})
            if isinstance(record, dict)
            else record
            for record in result
        ]
    return {"result": result, MASKED_FIELDS_KEY: list(dropped)}


_WRAPPED_FLAG = "_unifi_redaction_wrapped"


def _make_redacting_fn(
    fn: Callable[..., Any], should_redact: Callable[[], bool]
) -> Callable[..., Any]:
    """Wrap a tool handler so its result is redacted when ``should_redact()`` is True.

    ``should_redact`` is evaluated at call time, so toggling the setting takes effect
    without re-installing. When it returns False the handler result is returned
    unchanged (identity) — no transform, byte-identical output.

    The wrapper also collects, per call, the body fields the client left out of a write
    because they held exactly :data:`REDACTION_MASK` (see :func:`drop_masked_fields`)
    and reports them on the result under :data:`MASKED_FIELDS_KEY`. A call that dropped
    nothing is returned unchanged.
    """
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            sink: list[str] = []
            token = _dropped_masked_fields.set(sink)
            try:
                with write_redaction_scope(should_redact()):
                    result = await fn(*args, **kwargs)
            finally:
                _dropped_masked_fields.reset(token)
            result = _with_dropped_report(result, sink)
            if should_redact():
                return redact_credentials(result)
            return result

        setattr(async_wrapper, _WRAPPED_FLAG, True)
        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        sink: list[str] = []
        token = _dropped_masked_fields.set(sink)
        try:
            with write_redaction_scope(should_redact()):
                result = fn(*args, **kwargs)
        finally:
            _dropped_masked_fields.reset(token)
        result = _with_dropped_report(result, sink)
        if should_redact():
            return redact_credentials(result)
        return result

    setattr(sync_wrapper, _WRAPPED_FLAG, True)
    return sync_wrapper


def install_response_redaction(mcp: Any, should_redact: Callable[[], bool]) -> int:
    """Install opt-in credential redaction at one shared point for EVERY tool.

    Wraps the handler of every registered tool so that, when ``should_redact()``
    returns True, the documented credential fields are masked in the response.
    Idempotent: a handler already wrapped is skipped. Returns the number of tool
    handlers wrapped. Relies only on the public ``fn`` attribute of each registered
    tool. If FastMCP internals change, an enabled redaction policy fails closed
    rather than silently leaving credentials visible.
    """
    try:
        components = mcp._local_provider._components  # noqa: SLF001
    except AttributeError:
        if should_redact():
            raise RuntimeError(
                "UNIFI_REDACT_SECRETS is enabled but tool handlers are unavailable; "
                "credential redaction could not be installed."
            ) from None
        return 0
    wrapped = 0
    protected = 0
    for component in components.values():
        fn = getattr(component, "fn", None)
        if fn is None or not callable(fn):
            continue
        if getattr(fn, _WRAPPED_FLAG, False):
            protected += 1
            continue
        component.fn = _make_redacting_fn(fn, should_redact)
        wrapped += 1
    if not (wrapped or protected) and should_redact():
        raise RuntimeError(
            "UNIFI_REDACT_SECRETS is enabled but no tool handlers could be protected; "
            "credential redaction could not be installed."
        )
    return wrapped
