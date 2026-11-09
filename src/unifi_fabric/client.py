"""Async HTTP client for UniFi Site Manager API with backoff, pagination, and multi-key support."""

from __future__ import annotations

import asyncio
import codecs
import hashlib
import inspect
import json
import math
import mimetypes
import random
import re
from collections.abc import Awaitable
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlsplit

import httpx
from fastmcp.exceptions import ToolError

from . import route_secrets
from ._paging_identity import PageHistory, page_is_repeat, page_stop, unique_page_rows
from .audit import AuditStream, build_audit_stream
from .config import APIKeyConfig, Settings
from .header_credentials import CredentialCache, header_mode_enabled, request_key_configs
from .policy import note_upstream_call
from .read_only import (
    AreaOptOutError,
    ReadOnlyModeError,
    decoded_path,
    guard_area_write,
    guard_request,
    guard_tool_write,
    is_write_request,
    state_changing_get_route,
)
from .redaction import (
    drop_and_note_masked_fields,
    mask_error_text,
    redact_credentials,
    write_redaction_enabled,
    write_redaction_scope,
)
from .route_secrets import (
    mask_request_body,
    mask_response_body,
    matching,
    response_secrets,
)
from .secret_scrub import (
    call_secret_values,
    configured_secrets,
    contains_secret,
    install_log_scrubber,
    request_secret_scope,
    scrub,
    scrub_bytes,
    scrub_json_strings,
    track_settings_holder,
)
from .selector_args import unknown_key_label_problem
from .switches import READ_ONLY_ENV, dry_run_active
from .write_body import require_unmasked_fields

#: Gateway statuses after which a sent write may or may not have been applied.
UNKNOWN_OUTCOME_STATUSES = frozenset({502, 503, 504})

#: Transport failures raised before the request left this process: nothing was sent.
_NOT_SENT_ERRORS: tuple[type[httpx.HTTPError], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.PoolTimeout,
    httpx.ProxyError,
    httpx.UnsupportedProtocol,
    httpx.LocalProtocolError,
)

#: Read tools that verify a write, by upstream family (path prefix, tool names).
_VERIFY_TOOLS: tuple[tuple[str, str], ...] = (
    ("/v1/carrier/", "list_carrier_subscribers / list_carrier_service_plans"),
    ("/v1/mobility/", "list_mobility_devices / list_mobility_workspaces"),
)

_CONSOLE_ROUTE = re.compile(r"^/v1/connector/consoles/([^/]+)/proxy/(.*)\Z")


def unknown_outcome_hint(path: str) -> str:
    """Advice appended after an uncertain write; the upstream status and body stay intact.

    Names the read tool that verifies the affected resource: a console route
    (``/v1/connector/consoles/{id}/proxy/...``) is read back with ``fabric_connector_get``
    on the same console (or the typed get_/list_ tool for that resource). A state-changing
    GET route (:func:`~.read_only.state_changing_get_route`) is verified through the camera
    it acts on, never by sending the action GET again.
    """
    verify = "the get_/list_ tool for the affected resource"
    if re.fullmatch(r"/ea/sites/[^/]+/rest/firewallrule", path):
        verify = "list_firewall_rules for the same host and site"
    for prefix, tools in _VERIFY_TOOLS:
        if path.startswith(prefix):
            verify = tools
            break
    else:
        match = _CONSOLE_ROUTE.match(path)
        if match is not None and state_changing_get_route(path):
            # The action is itself a GET: reading the same path back would repeat it.
            camera = match.group(2).rsplit("/", 1)[0]
            verify = (
                f"get_camera, or fabric_connector_get on console {match.group(1)} (GET "
                f"{camera}, not GET {match.group(2)}, which repeats the action)"
            )
        elif match is not None:
            verify = (
                f"fabric_connector_get on console {match.group(1)} (GET {match.group(2)}, "
                "or its collection for a create, delete or action route) or the typed "
                "get_/list_ tool for that resource"
            )
    return (
        "; outcome unknown: the write may have been applied; it was not retried. "
        f"Verify with {verify} before retrying."
    )


_secure_random = random.SystemRandom()


NON_CHARSET_CODECS = frozenset(
    {"idna", "punycode", "unicode-escape", "raw-unicode-escape", "undefined", "charmap"}
)


def text_codec(charset: str) -> str | None:
    """A real character-set codec, excluding Python transforms and non-text codecs."""
    try:
        info = codecs.lookup(charset)
    except Exception:
        return None
    if not getattr(info, "_is_text_encoding", True) or info.name in NON_CHARSET_CODECS:
        return None
    return info.name


def content_type_charset(content_type: str | None) -> str | None:
    """The raw charset parameter (None when absent or empty)."""
    for param in (content_type or "").split(";")[1:]:
        name, _, value = param.partition("=")
        if name.strip().lower() == "charset":
            return value.strip().strip('"').strip("'") or None
    return None


def declared_text_codec(content_type: str | None) -> str | None:
    """Declared text codec, UTF-8 when absent, or None for an unusable charset."""
    charset = content_type_charset(content_type)
    return text_codec(charset) if charset else "utf-8"


def _scrub_content_type(value: bytes, secrets: tuple[str, ...]) -> bytes:
    """Keep recognised media/codec identifiers; scrub other header text as usual."""
    parts = value.split(b";")
    media = parts[0].strip().decode("ascii", errors="replace").lower()
    if mimetypes.guess_extension(media) is None:
        parts[0] = scrub_bytes(parts[0], secrets)
    for index in range(1, len(parts)):
        name, sep, parameter = parts[index].partition(b"=")
        if sep and name.strip().lower() == b"charset":
            try:
                codec = text_codec(parameter.strip().strip(b'"').strip(b"'").decode("ascii"))
            except UnicodeError:
                pass
            else:
                if codec is not None:
                    continue
        parts[index] = scrub_bytes(parts[index], secrets)
    return b";".join(parts)


class UniFiConnectionError(Exception):
    """Raised when a network-level error prevents reaching the UniFi API.

    request_sent marks transport failures beyond connection establishment; a write
    at that point may have reached the controller. Never retry it automatically.
    """

    def __init__(
        self, message: str, *, request_sent: bool = False, status: int | None = None
    ) -> None:
        super().__init__(message)
        self.request_sent = request_sent
        #: The upstream HTTP status of an error answer (None for a transport failure).
        self.status = status


class UniFiHTTPError(UniFiConnectionError, ToolError):
    """An upstream HTTP error safely reported by FastMCP."""


def log_reason(exc: BaseException) -> str:
    """A bounded reason code for a log line about a failed upstream call.

    The exception text carries the complete upstream body for the caller; a log line
    never does (``UNIFI_LOG_LEVEL``: request/response bodies are never logged). This is
    ``HTTP <status>`` for an upstream error answer (also when a wrapping error chains
    it as its cause), else the exception type name.
    """
    seen: set[int] = set()
    cause: BaseException | None = exc
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        status = getattr(cause, "status", None)
        if isinstance(cause, UniFiConnectionError) and isinstance(status, int):
            return f"HTTP {status}"
        cause = cause.__cause__
    return type(exc).__name__


class ResponseShapeError(UniFiConnectionError, ValueError):
    """An upstream field of the wrong JSON type (an int or list where a string is
    expected, a string where an object is expected).

    Both a :class:`UniFiConnectionError` (the upstream answered something unusable) and a
    ``ValueError`` (so a caller that skips one bad record on ``ValueError`` keeps doing
    so), never a bare ``TypeError`` / ``AttributeError``.
    """


class ClassicApiError(UniFiConnectionError):
    """A Classic controller route answered HTTP 2xx without ``meta.rc == "ok"``.

    The Classic surface (``api/s/<site>/...``, ``api/self``, ``api/stat/sites``) reports
    its outcome in the body: ``{"meta": {"rc": "error", "msg": "api.err.X"}, "data": []}``
    with HTTP 200 is a rejected request, not a success. The message carries the complete
    upstream body (meta and data, verbatim) like every other upstream error.
    """


#: A Classic controller route reached through the Fabric connector: the legacy ``api``
#: surface the controller UI rides (``api/s/<site>/{rest,stat,cmd,set,upd,list,...}`` and
#: the controller-level ``api/self``, ``api/stat/sites``). Every response of it carries the
#: ``{"meta": {"rc": ...}, "data": [...]}`` envelope. ``network/v2/api`` and
#: ``network/integration`` are different surfaces (no ``meta.rc``) and do not match.
CLASSIC_ROUTE_RE = re.compile(r"^/v1/connector/consoles/[^/]+/proxy/network/api(?:/|\Z)")


def is_classic_route(path: Any) -> bool:
    """True when ``path`` (a request path, query string ignored) is a Classic route."""
    return isinstance(path, str) and CLASSIC_ROUTE_RE.match(path.split("?", 1)[0]) is not None


def classic_rc_error(path: Any, status: Any, body: Any) -> str | None:
    """Why a Classic response is not a success, or ``None``.

    The one rule for the whole server (typed tools through :meth:`UniFiClient.request`,
    the generic relay through its ``_classicRcError`` marker): a Classic route's response
    is a success only when the HTTP status is 2xx AND ``meta.rc == "ok"``. ``None`` for a
    non-Classic path, a non-2xx status (already an HTTP error), ``rc == "ok"``, or a body
    that carries no ``meta`` at all (no envelope states an outcome; passed through).
    Otherwise the reason names the status, ``meta.rc`` and ``meta.msg`` as received; the
    caller attaches the complete body verbatim.

    ``body`` is the decoded body (:func:`decode_body`).
    """
    if not is_classic_route(path):
        return None
    if not isinstance(status, int) or isinstance(status, bool) or not 200 <= status < 300:
        return None
    if not isinstance(body, dict) or "meta" not in body:
        # No Classic envelope (an empty, text or bare-JSON body, or an object without
        # ``meta``): nothing in it states an outcome, so it passes through verbatim like
        # any 2xx body, and an applied write is never reported as failed on its shape.
        return None
    meta = body["meta"]
    if not isinstance(meta, dict):
        return (
            f"HTTP {status} with a meta that is not an object ({describe_shape(meta)}): "
            "the controller did not report success"
        )
    rc = meta.get("rc")
    if rc == "ok":
        return None
    reason = (
        f"HTTP {status} with meta.rc {upstream_error_text(rc)!r}"
        if "rc" in meta
        else f"HTTP {status} without meta.rc"
    )
    if "msg" in meta:
        reason += f" (meta.msg {upstream_error_text(meta['msg'])!r})"
    return reason + ": the controller did not report success"


def wrong_type_error(name: str, value: Any, expected: str = "a string") -> ResponseShapeError:
    """The actionable shape error for a field ``name`` holding ``value`` of the wrong type."""
    return ResponseShapeError(
        f"Unexpected response shape: {name!r} is {describe_shape(value)} ("
        f"{upstream_error_text(value)}), "
        f"expected {expected}"
    )


def is_finite_number(value: Any) -> bool:
    """True for a JSON number (an ``int`` or ``float``, never a ``bool``) that is finite."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return not isinstance(value, float) or math.isfinite(value)


def finite_number(value: Any, name: str) -> int | float | None:
    """An upstream number field read strictly: the number when it is a finite
    JSON number, ``None`` when it is not a number at all (absent, null, a string -- never
    coerced). NaN / Infinity (which Python's JSON decoder accepts as bare tokens) is a
    :class:`ResponseShapeError` naming the field: it is not a JSON number, and a
    non-finite value must never reach arithmetic or a serializer that rejects it."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        raise wrong_type_error(name, value, "a finite number")
    return value


# --------------------------------------------------------------------------- paging fields
# One strict reader per pagination control a drain consumes. A wrong-typed
# control (an int nextToken, a string totalCount, a links that is not an object) is a
# ResponseShapeError naming the field and the request -- never a TypeError from a set
# lookup, a truthy string read as "more", or a total silently ignored.


def read_page_token(data: Any, field: str, path: str, name: str | None = None) -> str | None:
    """The cursor ``data[field]`` (``nextToken`` / ``nextCursor``): a string, or ``None``
    when absent, null or empty (the last page)."""
    value = data.get(field) if isinstance(data, dict) else None
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise wrong_type_error(f"{name or field} of GET {path}", value, "a string or null")
    return value


def page_total(data: Any, path: str) -> int | None:
    """The upstream total (``totalCount``; Mobility's ``total``): a non-negative integer,
    or ``None`` when the upstream reports none (absent or null)."""
    if not isinstance(data, dict):
        return None
    for field in ("totalCount", "total"):
        if field not in data or data[field] is None:
            continue
        value = data[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise wrong_type_error(
                f"{field} of GET {path}", value, "a non-negative integer or null"
            )
        return value
    return None


def page_has_next_link(data: Any, path: str) -> bool:
    """True when ``data.links.next`` names a next page. ``links`` must be an object (or
    absent / null) and ``links.next`` a string (or absent / null)."""
    if not isinstance(data, dict):
        return False
    links = data.get("links")
    if links is None:
        return False
    if not isinstance(links, dict):
        raise wrong_type_error(f"links of GET {path}", links, "an object ({prev, next}) or null")
    nxt = links.get("next")
    if nxt is None:
        return False
    if not isinstance(nxt, str):
        raise wrong_type_error(f"links.next of GET {path}", nxt, "a string or null")
    return bool(nxt)


def page_has_more(meta: dict[str, Any], path: str) -> bool:
    """Carrier Fabric ``meta.hasMore``: a boolean (absent / null reads as false), never
    a truthy string such as ``"false"``."""
    value = meta.get("hasMore")
    if value is None:
        return False
    if not isinstance(value, bool):
        raise wrong_type_error(f"meta.hasMore of GET {path}", value, "a boolean")
    return value


class RateLimitError(ToolError):
    """Raised when rate limit is exceeded after all retries."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.status = 429


_ID_SAFE_RE = re.compile(r"^[a-zA-Z0-9_-]+\Z")
_HOST_ID_SAFE_RE = re.compile(r"^[a-zA-Z0-9_:-]+\Z")
_UNSAFE_PATH_RE = re.compile(r"\.\.|[\x00\r\n]")
_SCHEME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+.-")


def _starts_with_scheme(value: str) -> bool:
    """True when ``value`` starts with a URL scheme (``https:``, ``javascript:``,
    ``C:`` ...): a letter, then letters, digits, ``+``, ``.`` or ``-``, then ``:``."""
    colon = value.find(":")
    if colon <= 0:
        return False
    scheme = value[:colon]
    return scheme[0].isascii() and scheme[0].isalpha() and all(c in _SCHEME_CHARS for c in scheme)


_UNSAFE_CONTROL_RE = re.compile(r"[\x00\r\n]")


def _decoded_dot_segment(path: str) -> bool:
    """True when ``path`` (query dropped), or any percent-decoding of it, holds a ``.`` /
    ``..`` segment (``/`` or ``\\`` separated); fail-closed when it is still changing after
    as many rounds as :func:`~unifi_fabric.read_only.decoded_path` undoes, one more than
    a :func:`path_segment` value's own check allows, so an id that check accepted (and
    then encoded once more into the path) always decodes in time."""
    seen = path.split("?", 1)[0]
    for _ in range(_PATH_DECODE_ROUNDS):
        if any(part in (".", "..") for part in re.split(r"[/\\]", seen)):
            return True
        decoded = unquote(seen)
        if decoded == seen:
            return False
        seen = decoded
    return True


#: Decoding rounds for the request-path dot-segment check (a path_segment value is
#: checked over 4; the path holds it encoded once more).
_PATH_DECODE_ROUNDS = 8


def unsafe_path_reason(path: Any) -> str | None:
    """Why ``path`` cannot be sent by :meth:`UniFiClient.request`, or None.

    Defense in depth for the one request chokepoint: the path must be a string that
    starts with ``/`` (never an absolute URL, a scheme-bearing value or a scheme-relative
    ``//host`` -- httpx would send the API key header to that host). The path as given
    may not hold ``..`` or a NUL, CR or LF, and its percent-decoded form
    (:func:`~unifi_fabric.read_only.decoded_path`, so ``%2e%2e``, ``%252e%252e`` and
    ``%0a`` count) may not hold a ``.`` / ``..`` segment or a NUL, CR or LF. An id that
    :func:`path_segment` encoded (``a..b`` -> ``a%2E%2Eb``) is one segment, never a dot
    segment, so it still passes.
    """
    if not isinstance(path, str):
        return f"is {type(path).__name__}, not a string"
    if _starts_with_scheme(path) or "://" in path.split("?", 1)[0]:
        return "is an absolute URL or carries a scheme; pass a path starting with '/'"
    if not path.startswith("/"):
        return "does not start with '/'"
    decoded = decoded_path(path)
    if path.startswith("//") or decoded.startswith("//") or "://" in decoded:
        return "is (or decodes to) a URL with a host ('//host'); pass a path starting with one '/'"
    if (
        _UNSAFE_PATH_RE.search(path)
        or _UNSAFE_CONTROL_RE.search(decoded)
        or _decoded_dot_segment(path)
    ):
        return "contains traversal sequences or control characters (percent-encoded included)"
    return None


# Write-vs-read request classification lives in ``read_only.is_write_request``: one
# classifier decides read-only refusal, dry-run, audit and additive-key stripping, so
# those modes can never disagree about which request is a write. Re-exported here.


def _outcome_label(status: int | None) -> str:
    if status is None:
        return "no_response"
    if 200 <= status < 300:
        return "success"
    # A 3xx is not a success: redirects are never followed, so the request did not land.
    return f"http_{status}"


def _transport_label(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "Request timed out"
    if isinstance(exc, httpx.ConnectError):
        return "Connection failed"
    if isinstance(exc, httpx.NetworkError):
        return "Network error"
    if isinstance(exc, httpx.RemoteProtocolError | httpx.LocalProtocolError):
        return "Protocol error"
    return "Transport error"


def _transport_cause(exc: BaseException) -> str:
    """``Class: message`` for a transport error, following the cause chain when the
    httpx message is empty (e.g. a refused connection on a non-TLS port)."""
    parts: list[str] = []
    current: BaseException | None = exc
    seen = 0
    while current is not None and seen < 4:
        text = str(current).strip()
        parts.append(f"{type(current).__name__}: {text}" if text else type(current).__name__)
        current = current.__cause__  # explicit chain only (httpx maps from httpcore)
        seen += 1
    joined = " <- ".join(parts)
    if not any(str(p).partition(": ")[2] for p in parts):
        joined += " (no further detail from the network stack)"
    return joined


def strip_additive_keys(body: Any) -> Any:
    """Drop the additive ``_``-prefixed top-level keys this server adds to read results.

    Read results may carry server-added keys (``_keyLabel``, ``_resolved_networks``,
    ``_warnings``, ...); a caller that feeds a read result back into a write must not
    send them upstream. ``_id`` is a real Classic REST field and is kept. A non-dict
    body is returned unchanged; the input is never mutated.
    """
    if not isinstance(body, dict):
        return body
    return {k: v for k, v in body.items() if not k.startswith("_") or k == "_id"}


def multipart_summary(files: dict[str, Any]) -> list[dict[str, Any]]:
    """What a multipart ``files`` mapping would send, without the content.

    One entry per part: ``{field, filename, contentType, sizeBytes}``. The content type is
    the one the part declares, else the one httpx would send (guessed from the filename,
    ``application/octet-stream`` when it cannot be guessed). The bytes are never included.
    """
    out: list[dict[str, Any]] = []
    for field, part in files.items():
        filename: Any = None
        content: Any = part
        content_type: Any = None
        if isinstance(part, tuple):
            filename = part[0] if len(part) > 0 else None
            content = part[1] if len(part) > 1 else None
            content_type = part[2] if len(part) > 2 else None
        if isinstance(content, bytes | bytearray):
            size: int | None = len(content)
        elif isinstance(content, str):
            size = len(content.encode("utf-8"))
        elif hasattr(content, "getbuffer"):
            size = content.getbuffer().nbytes
        else:
            size = None
        if content_type is None and isinstance(filename, str):
            content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        out.append(
            {"field": field, "filename": filename, "contentType": content_type, "sizeBytes": size}
        )
    return out


def _key_fingerprint(key: str) -> str:
    """A one-way fingerprint of an API key, for cache keys only (never logged)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


#: ``message`` of the synthetic dry-run preview (see ``UniFiClient._dry_run_response``).
DRY_RUN_MESSAGE = "DRY RUN - no upstream write was performed"


def is_dry_run_preview(body: Any) -> bool:
    """True when a decoded write response is the client's ``dry-run policy`` preview.

    A tool that verifies its write (read-before / write / read-after) must return the
    preview instead of verifying: no write was sent, so a read-after can only show the
    unchanged state and would misreport the write as rejected.
    """
    return (
        isinstance(body, dict)
        and body.get("dryRun") is True
        and body.get("message") == DRY_RUN_MESSAGE
        and isinstance(body.get("preview"), dict)
    )


def describe_shape(value: Any) -> str:
    """A description of a JSON value's shape for unexpected-response errors.

    An object lists every key it carries; the list is never truncated.
    """
    if isinstance(value, dict):
        return f"object with keys {sorted(str(k) for k in value)}"
    if isinstance(value, list):
        return f"array of {len(value)} item(s)"
    return type(value).__name__


def nullable_object_records(items: Any, where: str) -> list[Any]:
    """Validate a spec-nullable object array without dropping its null placeholders."""
    if not isinstance(items, list):
        object_records(items, where)  # raises the normal array-shape error
    object_records([item for item in items if item is not None], where)
    return items


def object_records(items: Any, where: str) -> list[dict[str, Any]]:
    """``items`` as a list of JSON objects, or raise an actionable shape error.

    The one check for record lists the registry and the aggregation tools consume (the
    Site Manager host and site lists, the per-console site list): a list holding a bare
    value or a null entry raises :class:`UniFiConnectionError` naming ``where`` (the
    request), the first offending item's index and shape, and how many items are not
    objects, instead of failing later with a Python attribute error.
    """
    if not isinstance(items, list):
        raise UniFiConnectionError(
            f"Unexpected response shape from {where}: expected an array of objects, got "
            f"{describe_shape(items)}"
        )
    bad = [i for i, item in enumerate(items) if not isinstance(item, dict)]
    if bad:
        first = bad[0]
        raise UniFiConnectionError(
            f"Unexpected response shape from {where}: expected an array of objects, but "
            f"{len(bad)} of {len(items)} item(s) are not objects (item {first} is "
            f"{describe_shape(items[first])})"
        )
    return items


def error_body_text(text: str, *, redact_secrets: bool) -> str:
    """The upstream error body for an exception message: complete, never truncated.

    Identifiers (console ids, UUIDs, ObjectIds) are not secrets and are kept so the
    error stays actionable. Credential-named fields are masked only when the operator
    opted in with ``UNIFI_REDACT_SECRETS`` — the same opt-in, same field list, as
    response bodies. The API key is a request header and never appears here.
    """
    if not redact_secrets:
        return text
    try:
        parsed = json.loads(text)
    except ValueError:
        # Not one JSON document (text around a body, a repr, k=v pairs): every
        # credential field in it is masked where it stands.
        return mask_error_text(text)
    # ensure_ascii=False: upstream text (a non-ASCII name or message) stays verbatim
    # instead of becoming \uXXXX escapes; only the credential fields are masked.
    return json.dumps(redact_credentials(parsed), separators=(",", ":"), ensure_ascii=False)


def _error_redaction(client: Any) -> bool:
    """``client``'s ``UNIFI_REDACT_SECRETS`` setting, else the enclosing tool call's."""
    settings = getattr(client, "_settings", None)
    enabled = getattr(settings, "redact_secrets", None)
    return write_redaction_enabled() if enabled is None else bool(enabled)


def upstream_error_text(body: Any, client: Any = None) -> str:
    """Format upstream evidence for errors without changing evidence used for comparisons."""
    redact = _error_redaction(client)
    if isinstance(body, BaseException):
        # Exceptions can surround a JSON body with method/status context and retry
        # guidance. Redact those structured bodies without losing the surrounding
        # evidence or treating the whole message as a JSON string value.
        raw = str(body)
        if not redact:
            return raw
        return mask_error_text(raw)
    raw = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False, default=str)
    return error_body_text(raw, redact_secrets=redact)


def upstream_error_value(value: Any, client: Any = None) -> Any:
    """One upstream field value for an error message, shown as before: a scalar or a
    plain string as is, so ``!r`` and plain formatting keep their shape; an object or
    array (or a string holding one) as :func:`upstream_error_text` renders it, with
    credential fields masked under ``UNIFI_REDACT_SECRETS``."""
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict | list):
            return upstream_error_text(value, client)
        # A plain string stays as is unless it carries a credential pair ("a / {...}",
        # k=v, a JSON-encoded object): that value alone is masked.
        return mask_error_text(value) if _error_redaction(client) else value
    if value is None or isinstance(value, bool | int | float):
        return value
    return upstream_error_text(value, client)


def decode_body(resp: httpx.Response) -> Any:
    """Decode an upstream response body with the server's single pass-through rule.

    - A 204 or an empty body returns ``None``.
    - A JSON body returns the parsed value (object, array or scalar), as received.
    - Any other body returns its text verbatim; no key is invented around it.

    Status handling is not done here: :meth:`UniFiClient.request` has already raised for
    transport failures and error statuses. GET, POST, PUT, PATCH, DELETE and the
    connector relay all decode through this function.
    """
    if resp.status_code == 204 or not resp.content:
        return None
    encoding = declared_text_codec(resp.headers.get("content-type"))
    if encoding is not None:
        try:
            text = bytes(resp.content).decode(encoding, errors="strict")
        except UnicodeError:
            text = None
        if text is not None:
            bom = "\ufeff" if text.startswith("\ufeff") else ""
            try:
                body = json.loads(text.removeprefix(bom) if bom else text)
            except ValueError:
                body = text
        else:
            body = resp.text
    else:
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
    return body


def validate_id(value: str, name: str) -> None:
    """Validate an ID string is safe for use in an API URL path segment.

    Accepts alphanumeric characters, hyphens, and underscores only.
    Raises ValueError if the value is empty or contains characters that could
    enable path traversal or injection attacks.
    """
    if not isinstance(value, str):
        raise wrong_type_error(name, value)
    if not value:
        raise ValueError(f"{name!r} must not be empty")
    if not _ID_SAFE_RE.match(value):
        raise ValueError(
            f"Invalid {name!r} {upstream_error_value(value)!r}: expected alphanumeric, "
            "hyphens, and underscores only"
        )


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def validate_selector(value: Any, name: str) -> None:
    """Validate a free-form selector argument (an id, MAC or exact name a tool looks up).

    The server's one argument check for selectors that are not path-safe ids: the value
    must be a non-empty string with no control character (a trailing newline included)
    and no leading or trailing whitespace. Raises ``ValueError`` naming the argument;
    makes no request, so a tool calls it before any resolution.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name!r} must not be empty")
    if _CONTROL_RE.search(value) or value != value.strip():
        raise ValueError(
            f"Invalid {name!r} {value!r}: contains a control character or surrounding "
            "whitespace (a trailing newline included)"
        )


def _has_dot_segment(value: str) -> bool:
    """True when ``value`` (or any percent-decoding of it) holds a ``.`` / ``..`` segment."""
    seen = value
    for _ in range(4):
        if any(part in (".", "..") for part in re.split(r"[/\\]", seen)):
            return True
        decoded = unquote(seen)
        if decoded == seen:
            return False
        seen = decoded
    return True


def path_segment(value: Any, name: str, *, max_length: int | None = None) -> str:
    """Validate a spec ``type: string`` path id and return it encoded as ONE path segment.

    For a path parameter whose published schema is a plain string (Protect ``cameraId``,
    ``alarmTriggerId`` -- "user defined string" -- and the other Protect ids, Site Manager
    ``sd-wan-configs/{id}``), the tool is no stricter than the spec: any non-empty string
    without a control character is accepted (spaces, ``.``, ``:``, ``@``, ``+``, non-ASCII
    included), up to ``max_length`` characters when the schema sets ``maxLength``. The
    value is percent-encoded with nothing left safe (``/``, ``?``, ``#`` and ``%`` included;
    ``.`` too inside a ``..`` run), so it always arrives as exactly one segment and can
    never rewrite the request path or query. The one refusal beyond the spec is path
    traversal: a value whose ``/``-separated part (after any percent-decoding) is ``.`` or
    ``..`` would name another resource if any hop decoded it, so it fails fast. Raises
    ``ValueError`` naming the argument; makes no request.
    """
    if not isinstance(value, str):
        raise wrong_type_error(name, value)
    if not value:
        raise ValueError(f"{name!r} must not be empty")
    if _CONTROL_RE.search(value):
        raise ValueError(f"Invalid {name!r} {value!r}: contains a control character")
    if max_length is not None and len(value) > max_length:
        raise ValueError(
            f"Invalid {name!r}: {len(value)} characters; the spec allows at most {max_length}"
        )
    if _has_dot_segment(value):
        raise ValueError(
            f"Invalid {name!r} {value!r}: a '.' or '..' segment is a path traversal, not an id"
        )
    encoded = quote(value, safe="")
    # A '..' run inside one segment is no traversal, but the client's path guard refuses
    # any literal '..'; its dots travel encoded (the same bytes to the upstream).
    return encoded.replace(".", "%2E") if ".." in encoded else encoded


def validate_host_id(value: str, name: str, *, client: Any = None) -> None:
    """Validate a host ID string is safe for use in an API URL path segment.

    Extends validate_id to also allow colons, which appear in UniFi composite
    hostId values of the form ``{MAC}:{numericId}`` (e.g. ``aabbccdd...0000:12345``).
    The colon character is safe in URL path segments — only disallowed in the
    scheme portion of a URL.
    Raises ValueError if the value is empty or contains characters that could
    enable path traversal or injection attacks.
    """
    if not isinstance(value, str):
        raise wrong_type_error(name, value)
    if not value:
        raise ValueError(f"{name!r} must not be empty")
    if _UNSAFE_PATH_RE.search(value):
        raise ValueError(
            f"Invalid {name!r} {upstream_error_value(value, client)!r}: contains unsafe characters"
        )
    if not _HOST_ID_SAFE_RE.match(value):
        raise ValueError(
            f"Invalid {name!r} {upstream_error_value(value, client)!r}: expected alphanumeric, "
            "hyphens, underscores, and colons"
        )


_SPEC_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z", re.IGNORECASE
)


def validate_spec_id(
    value: Any, name: str, *, uuid: bool = False, max_length: int | None = None
) -> None:
    """Validate an id that travels only in a request body or query string, per its spec.

    Path rules (:func:`validate_id`, :func:`validate_host_id`) exist to keep a URL path
    segment safe; an id that never reaches a path is held to its published schema
    instead: a non-empty string, a UUID when the schema says ``format: uuid``, and at
    most ``max_length`` characters when the schema sets ``maxLength``. A JSON body or an
    encoded query value carries any other character safely. The server-wide argument
    hygiene of :func:`validate_selector` still applies (no control character, no leading
    or trailing whitespace: a pasted id with a trailing newline fails fast). Raises
    ``ValueError`` naming the argument and the rule; makes no request.
    """
    if not isinstance(value, str) or not value:
        raise ValueError(
            f"{name!r} must be a non-empty string (got {upstream_error_value(value)!r})"
        )
    validate_selector(value, name)
    if uuid and not _SPEC_UUID_RE.match(value):
        raise ValueError(
            f"Invalid {name!r} {upstream_error_value(value)!r}: the spec requires a UUID "
            "(format: uuid), e.g. "
            "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        )
    if max_length is not None and len(value) > max_length:
        raise ValueError(
            f"Invalid {name!r}: {len(value)} characters; the spec allows at most {max_length}"
        )


def _attempts(count: int) -> str:
    """``"1 attempt"`` / ``"6 attempts"``."""
    return f"{count} attempt" + ("" if count == 1 else "s")


class PaginationAbortedError(Exception):
    """Raised when pagination is aborted due to stall detection or page cap.

    Attributes:
        path: The API path being paginated.
        page_count: Number of pages fetched before abort.
        reason: Human-readable reason for the abort.
        items: Records gathered across the pages fetched *before* the abort. A
            caller that prefers a partial-but-clearly-incomplete result over a
            hard failure can recover these instead of discarding them — the
            drain never silently truncates, but it also never throws the pages
            it already paid for on the floor.
    """

    def __init__(
        self,
        path: str,
        page_count: int,
        reason: str,
        *,
        items: list[dict[str, Any]] | None = None,
        total_count: int | None = None,
        envelope: dict[str, Any] | None = None,
        array_key: str | None = None,
    ) -> None:
        self.path = path
        self.page_count = page_count
        self.reason = reason
        self.items: list[dict[str, Any]] = items if items is not None else []
        # The upstream-reported total for an offset drain, or None when it sent none.
        self.total_count = total_count
        # The first page's envelope fields (see :func:`page_envelope`).
        self.envelope: dict[str, Any] = envelope or {}
        self.array_key = array_key
        super().__init__(f"Pagination aborted on {path!r} after {page_count} pages: {reason}")


#: Per-page paging controls of every drain protocol. They describe one page (where it
#: starts, how long it is, where the next one is), so a drained result does not carry them.
PAGING_CONTROL_KEYS = frozenset({"offset", "limit", "count", "nextToken", "links"})


def page_envelope(
    page: Any, records_key: str, *, extra: frozenset[str] = frozenset()
) -> dict[str, Any]:
    """The envelope fields of one upstream list page: every top-level key except the
    records array and the paging controls (:data:`PAGING_CONTROL_KEYS` plus ``extra``).

    A drain returns the FIRST page's envelope beside the records (``traceId``,
    ``httpStatusCode``, ``totalCount`` and any field the API adds), so no upstream
    top-level key is dropped by draining. A bare-array page has no envelope.
    """
    if not isinstance(page, dict):
        return {}
    skip = PAGING_CONTROL_KEYS | extra | {records_key}
    return {k: v for k, v in page.items() if k not in skip}


class DrainedItems(list[Any]):
    """A drained list carrying the upstream total, first-page envelope and array key.

    ``array_key`` is None for a bare list; an object with only ``data`` still
    carries its key even though its remaining envelope is empty.
    """

    def __init__(
        self,
        items: list[Any],
        total_count: int | None = None,
        envelope: dict[str, Any] | None = None,
        array_key: str | None = None,
    ) -> None:
        super().__init__(items)
        self.total_count = total_count
        self.envelope: dict[str, Any] = envelope or {}
        self.array_key = array_key


#: Backward-compatible name: a drained offset list.
OffsetItems = DrainedItems


async def gather_or_cancel(*aws: Awaitable[Any]) -> list[Any]:
    """Run ``aws`` concurrently and return their results in order, like
    :func:`asyncio.gather`, except that the FIRST failure cancels every sibling and
    waits for it to finish before the failure propagates.

    A plain ``asyncio.gather`` raises the first exception at once and leaves the other
    requests running (still holding connections and concurrency slots, their results
    discarded). Here no sibling outlives the call: every failure, including a child
    cancellation, cancels and drains the other tasks before re-raising the original
    exception (never an ``ExceptionGroup``). Cancelling the caller cancels every
    sibling too.
    """
    tasks = [asyncio.create_task(_awaited(aw)) for aw in aws]
    try:
        return list(await asyncio.gather(*tasks))
    except BaseException as failure:
        # TaskGroup treats a child's CancelledError as normal completion, so it can
        # wait forever for a blocked sibling. gather propagates it immediately;
        # drain all children before passing the original failure to the caller.
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if isinstance(failure, BaseExceptionGroup):
            raise _first_failure(failure) from None
        raise


async def _awaited(aw: Awaitable[Any]) -> Any:
    return await aw


def _first_failure(group: BaseExceptionGroup[BaseException]) -> BaseException:
    """The first leaf exception of a (possibly nested) task-group failure."""
    first = group.exceptions[0]
    return _first_failure(first) if isinstance(first, BaseExceptionGroup) else first


class UniFiClient:
    """Async HTTP client wrapping httpx with backoff, pagination, and multi-key support."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        # Keyed by (label, key fingerprint), never by label alone: two configs that share
        # a label must not share a connection pool that carries the first key's header.
        self._clients: dict[tuple[str, str], httpx.AsyncClient] = {}
        # Header mode (UNIFI_KEY_MODE=header): per-request keys live in a bounded
        # identity cache (label + full key digest, at most 256 identities, pinned while
        # a call runs, LRU close-once eviction); environment keys keep _clients.
        self._credential_cache = CredentialCache()
        self._semaphore = asyncio.Semaphore(settings.max_concurrency)
        # Fan-out tasks (``gather``) are bounded by their OWN semaphore. Sharing the
        # request semaphore deadlocked as soon as the number of fan-out tasks reached
        # max_concurrency: every slot was held by an outer task waiting on an inner
        # request that needed a slot.
        self._fanout_semaphore = asyncio.Semaphore(settings.max_concurrency)
        # Opt-in audit, default off -> byte-identical path. Dry-run is the write policy,
        # read per request (switches.dry_run_active).
        self._audit_sink: AuditStream | None = build_audit_stream(settings)
        # Log records (httpcore traces quote an illegal header value) are scrubbed of
        # this client's keys while it is alive.
        track_settings_holder(self)
        # Direct typed-tool and library callers do not import server.py; install the
        # process-wide guard only after this client registers its configured secrets.
        install_log_scrubber()

    async def _get_client(self, key_config: APIKeyConfig) -> httpx.AsyncClient:
        if header_mode_enabled():
            client: httpx.AsyncClient = self._credential_cache.client(
                key_config, "site_manager", self._new_http_client
            )
            return client
        cache_key = (key_config.label, _key_fingerprint(key_config.key))
        if cache_key not in self._clients:
            self._clients[cache_key] = self._new_http_client(key_config)
        return self._clients[cache_key]

    def _new_http_client(self, key_config: APIKeyConfig) -> httpx.AsyncClient:
        try:
            headers = httpx.Headers({"X-API-KEY": key_config.key, "Accept": "application/json"})
        except UnicodeEncodeError:
            # Settings validation rejects a non-ASCII key at startup; a key built in
            # code can still reach here. The codec message quotes the offending
            # character, so it is dropped and the key is named by label only.
            raise ValueError(
                f"API key {key_config.label!r} contains a non-ASCII character, which "
                "an HTTP header cannot carry. Set its value in UNIFI_API_KEYS (or "
                "UNIFI_API_KEY for the single 'default' key) to the exact key with "
                "nothing added; the value is not shown here"
            ) from None
        return httpx.AsyncClient(
            base_url=self._settings.api_base_url,
            headers=headers,
            timeout=None,  # noqa: S113 -- await completion or lifecycle cancellation
            # Never follow a redirect: a 3xx is raised (see request), so a write is
            # never re-sent to another location and the API key never leaves the
            # configured origin.
            follow_redirects=False,
        )

    @property
    def paginate_max_pages(self) -> int | None:
        """The opt-in UNIFI_PAGINATE_MAX_PAGES drain backstop (None = no page limit)."""
        return self._settings.paginate_max_pages

    def _scrub(self, text: str, key: APIKeyConfig | None = None) -> str:
        """Mask configured secrets always and call credentials under the opt-in."""
        extra: tuple[str, ...] = (key.key,) if key is not None else ()
        if self._settings.redact_secrets:
            extra += call_secret_values()
        return scrub(text, configured_secrets(self._settings, extra=extra, include_call=False))

    def _scrubbed_response(
        self, resp: httpx.Response, key: APIKeyConfig, *, extra: tuple[str, ...] = ()
    ) -> httpx.Response:
        """Scrub configured server secrets from every response, regardless of status.

        Registered error credential values are supplied through extra. Successful
        upstream credential fields use the opt-in route wrapper. The server's own
        configured secrets must never leave in a body or header, including an echo.
        JSON string values are scrubbed without changing scalar types or syntax.
        Binary bodies are scrubbed as bytes without decoding or re-encoding.
        A response containing no configured secret is returned unchanged.
        """
        # Call-bound secrets are present only when the caller explicitly applies the
        # opt-in redaction policy; configured server secrets are always included.
        secrets = configured_secrets(self._settings, extra=(key.key, *extra), include_call=False)
        raw_headers = resp.headers.raw
        dirty_body = contains_secret(resp.content, secrets)
        dirty_headers = any(contains_secret(value, secrets) for _, value in raw_headers)
        if not dirty_body and not dirty_headers:
            return resp
        body = resp.content
        if dirty_body:
            content_type = resp.headers.get("content-type", "").split(";", 1)[0].lower()
            if (
                not content_type
                or content_type == "application/json"
                or content_type.endswith("+json")
                or content_type.startswith("text/")
            ):
                # Strict decoding preserves a relay's binary/text classification:
                # Response.text would silently replace invalid encoded bytes.
                encoding = declared_text_codec(resp.headers.get("content-type"))
                if encoding is None:
                    body = scrub_bytes(body, secrets)
                else:
                    try:
                        text = body.decode(encoding, errors="strict")
                        bom = "\ufeff" if text.startswith("\ufeff") else ""
                        parsed = json.loads(text.removeprefix(bom) if bom else text)
                    except (ValueError, UnicodeError, LookupError):
                        body = scrub_bytes(body, secrets)
                    else:
                        clean = scrub_json_strings(parsed, secrets)
                        if clean != parsed:
                            body = (bom + json.dumps(clean, separators=(",", ":"))).encode(encoding)
            else:
                body = scrub_bytes(body, secrets)
        clean_headers = [
            (
                name,
                _scrub_content_type(value, secrets)
                if name.lower() == b"content-type"
                else scrub_bytes(value, secrets),
            )
            for name, value in raw_headers
        ]
        if body == resp.content and clean_headers == raw_headers:
            return resp
        headers = [
            (name, value)
            for name, value in clean_headers
            if name.lower() not in (b"content-length", b"content-encoding")
        ]
        return httpx.Response(resp.status_code, headers=headers, content=body, request=resp.request)

    def _response_trace(self, method: str, path: str) -> dict[str, Any]:
        """Hide registered header credentials before httpcore formats DEBUG traces."""
        if not any(entry.response_headers for entry in matching(method, path)):
            return {}

        async def trace(event: str, info: dict[str, Any]) -> None:
            if not event.endswith("receive_response_headers.complete"):
                return
            result = info.get("return_value")
            if not isinstance(result, tuple) or len(result) not in (2, 4):
                return
            headers = result[-1]
            values = response_secrets(
                method,
                path,
                b"",
                [(name.decode("latin-1"), value.decode("latin-1")) for name, value in headers],
            )
            if values:
                # Trace invokes this callback before logging info. Replace its display
                # value only; the transport's original response headers stay untouched.
                info["return_value"] = (
                    *result[:-1],
                    [(name, scrub_bytes(value, values)) for name, value in headers],
                )

        return {"trace": trace}

    def _route_response(
        self, resp: httpx.Response, key: APIKeyConfig, method: str, path: str
    ) -> httpx.Response:
        """Scrub registered error credentials before formatting; opt-in mask successes."""
        if not 200 <= resp.status_code < 300:
            extra: tuple[str, ...] = ()
            if self._settings.redact_secrets:
                extra = response_secrets(
                    method,
                    path,
                    resp.content,
                    resp.headers.multi_items(),
                    status_code=resp.status_code,
                )
            # Server-configured values are scrubbed at every status even when this route
            # has no registered caller credential.
            return self._scrubbed_response(resp, key, extra=extra)
        if not self._settings.redact_secrets:
            return resp
        codec = declared_text_codec(resp.headers.get("content-type")) or "utf-8"
        try:
            body = resp.json()
        except (ValueError, UnicodeError):
            # Not JSON: a response_body route (e.g. openvpn-client-config) is a text
            # credential body; mask it as text instead of returning it unmasked.
            text_masked = mask_response_body(method, path, resp.text, redact_secrets=True)
            if text_masked == resp.text:
                return resp
            headers = [
                (name, value)
                for name, value in resp.headers.raw
                if name.lower() not in (b"content-length", b"content-encoding")
            ]
            return httpx.Response(
                resp.status_code,
                headers=headers,
                content=str(text_masked).encode(codec),
                request=resp.request,
                extensions=resp.extensions,
            )
        masked = mask_response_body(method, path, body, redact_secrets=True)
        if masked == body:
            return resp
        headers = [
            (name, value)
            for name, value in resp.headers.raw
            if name.lower() not in (b"content-length", b"content-encoding")
        ]
        # Re-encode in the declared charset: the Content-Type header is kept, so a
        # UTF-16 (or Latin-1) body must stay decodable as what it declares.
        return httpx.Response(
            resp.status_code,
            headers=headers,
            content=json.dumps(masked, separators=(",", ":")).encode(codec),
            request=resp.request,
            extensions=resp.extensions,
        )

    def _key_configs(self) -> list[APIKeyConfig]:
        """The keys a call may use: the request's keys in header mode (none outside a
        request, so no header means no upstream call), else the configured keys."""
        request = request_key_configs()
        return self._settings.get_key_configs() if request is None else request

    def get_key_by_label(self, label: str) -> APIKeyConfig:
        """Look up an API key config by its label."""
        for cfg in self._key_configs():
            if cfg.label == label:
                return cfg
        problem = unknown_key_label_problem(label, self.list_key_labels())
        raise ValueError(problem or f"No API key with label {label!r}")

    def list_key_labels(self) -> list[str]:
        """Return the labels of all configured API keys."""
        return [cfg.label for cfg in self._key_configs()]

    def _default_key(self) -> APIKeyConfig:
        configs = self._key_configs()
        if not configs:
            if header_mode_enabled():
                raise ValueError(
                    "No API key on this request: header mode takes keys only from the "
                    "X-UniFi-Api-Key header of the call."
                )
            raise ValueError("No API key configured. Set UNIFI_API_KEY or UNIFI_API_KEYS.")
        return configs[0]

    async def request(
        self,
        method: str,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
        json: Any = None,
        files: dict[str, Any] | None = None,
        max_retries: int | None = None,
        raise_on_error: bool = True,
        strip_additive: bool = True,
        always_write: bool = False,
        send_json_null: bool = False,
        accept: str | None = None,
    ) -> httpx.Response:
        """Bind request credentials for error and log scrubbing across the whole call.

        The registered request values (:data:`route_secrets.ROUTE_SECRETS`) join the
        enclosing tool call's secret scope before anything can echo them, so every log and
        audit line of the call is scrubbed of them, and every error under
        ``UNIFI_REDACT_SECRETS``, whichever tool (typed or the generic relay) sent the
        request; a standalone request gets its own scope.
        """
        with request_secret_scope(), write_redaction_scope(self._settings.redact_secrets):
            route_secrets.bind_request(method, path, json, params)
            return await self._request(
                method,
                path,
                key=key,
                params=params,
                json=json,
                files=files,
                max_retries=max_retries,
                raise_on_error=raise_on_error,
                strip_additive=strip_additive,
                always_write=always_write,
                send_json_null=send_json_null,
                accept=accept,
            )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
        json: Any = None,
        files: dict[str, Any] | None = None,
        max_retries: int | None = None,
        raise_on_error: bool = True,
        strip_additive: bool = True,
        always_write: bool = False,
        send_json_null: bool = False,
        accept: str | None = None,
    ) -> httpx.Response:
        """Make an HTTP request; a read via GET retries HTTP 429 with backoff + jitter.

        The retry rule is one rule for the whole server, set here: a read via ``GET`` retries HTTP
        429 (Too Many Requests) with exponential backoff and jitter (5 retries, 6
        attempts); a state-changing GET and every other method (``POST``, ``PUT``, ``PATCH``,
        ``DELETE``, the read-POST queries included) is sent ONCE and a 429 is raised with its body.
        A 429 does not prove the request was not acted on, so an automatic retry could
        apply a write, an action or a physical actuation twice; the caller decides
        whether to retry. Network errors (timeouts, connection failures) raise
        immediately without retry.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE, etc.)
            path: API path (without base URL; e.g., "/v1/sites")
            key: API key config to use; defaults to the configured key
            params: Query string parameters
            json: JSON request body
            files: Form files for multipart uploads
            accept: Per-request response media types; None keeps the JSON default.
            max_retries: Retries for a read via GET (``None``, the default: 5). Every other
                request (writes, state-changing GETs and every other method) is sent once
                whatever value is passed.
            raise_on_error: When True (default) a non-429 4xx/5xx response is raised as
                UniFiConnectionError (the behaviour every typed tool relies on). When
                False the response is returned regardless of status so the caller can
                inspect status/body itself — used by the guarded connector relay, whose
                invalid-ID probes must read a 4xx as reachability evidence, not a failure.
                The 429 retry/backoff loop is unaffected by this flag.
            strip_additive: When True (default) a write body loses the additive
                ``_``-prefixed top-level keys this server adds to read results (see
                :func:`strip_additive_keys`), so a get -> update round trip never sends
                them upstream. The raw connector relay passes False: it forwards the
                caller's body exactly as given.
            always_write: When True a non-GET is a write whatever its path, for read-only
                mode, dry-run and the audit log. The raw connector relay passes True: its
                caller picks the path, so an allowlisted read-POST route must not
                let a relayed POST skip dry-run or the audit. The typed tools pass False and
                keep the documented read-POST routes (``stat/session``) as reads.

        Returns:
            httpx.Response with HTTP status 2xx (or, with ``raise_on_error=False``, any
            non-429 status, a 3xx included). Every status has its body and every header
            value (``Location`` included) scrubbed of configured secrets.

        Raises:
            UniFiConnectionError: Network error (timeout, connection, DNS), an HTTP
                redirect (3xx: never followed, raised with its status and Location), or
                an HTTP error with body (400, 401, 403, 404, 500, etc.). Non-retryable.
                Every message is scrubbed of configured secrets.
            RateLimitError: HTTP 429 (a non-GET at once; a GET after its retries).
            ValueError: Invalid/unsafe API path (path traversal attempt).

        Retry Strategy (GET, 429 only):
            - Attempt 1: immediate
            - Attempt 2: wait 1 + jitter(0-1) seconds
            - Attempt 3: wait 2 + jitter(0-2) seconds
            - Attempt 4: wait 4 + jitter(0-4) seconds
            - Attempt 5: wait 8 + jitter(0-8) seconds
            - Attempt 6: wait 16 + jitter(0-16) seconds
            - Attempt 7: wait 32 + jitter(0-32) seconds (if max_retries > 5)
            - Capped at 32 seconds base delay

            Jitter is random uniform(0, base_delay) to spread load.
        """
        is_write = is_write_request(method, path, json) or (
            always_write and method.strip().upper() != "GET"
        )
        reason = unsafe_path_reason(path)
        if reason is not None:
            message = f"Unsafe API path {path!r}: {reason}"
            if is_write:
                # The audited reason never quotes the path (a query or fragment, raw or
                # percent-encoded, can carry credentials): the record's ``path`` field
                # holds the cut path, and the raised message is the caller's own input.
                audited = f"Unsafe API path: {reason}"
                self._audit_write(method, path, "refused", None, reason=audited, body=json)
            raise ValueError(message)
        # Global read-only switch (UNIFI_WRITE_POLICY=deny, opt-in/default-off): refuse every
        # mutating upstream call before it is sent. This is the single central
        # chokepoint — every write tool routes its POST/PUT/PATCH/DELETE through here,
        # so the guard covers them all. The allowlisted read-POST routes
        # (read_post_routes.READ_POST_ROUTES, raw and exact) and Classic read commands
        # (read_post_routes.READ_COMMANDS, exact route and body) are reads under the same
        # read_only.is_write_request classifier used below for dry-run and audit. No-op
        # when read-only is off, so the default dispatch path stays byte-identical.
        #
        # Precedence: read-only WINS over dry-run. guard_request runs first and raises
        # before the dry-run block below, so a read-only server makes no upstream call
        # AND never returns a dry-run preview for a write — the two opt-in modes decide
        # off the same write classification, so their coverage can never diverge.
        # A refused write is still a write attempt: it is audited as outcome=refused.
        try:
            guard_request(method, path, always_write=is_write, body=json)
        except ReadOnlyModeError:
            self._audit_write(method, path, "refused", None, reason=READ_ONLY_ENV, body=json)
            raise
        # Per-area write opt-outs (family:network=deny, family:protect=deny,
        # family:mobility=deny, family:carrier=deny,
        # family:innerspace=deny; all default on)
        # bind every write request to the area's routes here, the same chokepoint, so no
        # typed tool, shared helper or relay path can send one. Same precedence as
        # read-only mode: the opt-out wins over dry-run (no preview for a refused area).
        # The tool middleware refuses the area's write tools earlier, before any request.
        try:
            guard_area_write(method, path, always_write=is_write, body=json)
            # The calling tool's own write mode (family:<id>=deny for every family, and
            # tool:<name>=deny), so no deny exception is weaker at the chokepoint.
            guard_tool_write(method, path, always_write=is_write, body=json)
        except AreaOptOutError as exc:
            self._audit_write(method, path, "refused", None, reason=exc.env, body=json)
            raise
        # The method as every message names it (``get`` and ``GET`` read the same).
        verb = method.strip().upper()
        if verb != "GET" or is_write:
            # Only reads via GET may retry, whatever the caller passes: a write, an action
            # GET route or a read-POST is sent once (a 429 does not prove it was not applied).
            max_retries = 0
        elif max_retries is None:
            max_retries = 5
        if is_write and strip_additive and json is not None:
            json = strip_additive_keys(json)
        if is_write and json is not None:
            # A field holding exactly the redaction mask (a UNIFI_REDACT_SECRETS read fed
            # back into a write) is left out so the upstream keeps its stored secret; the
            # dropped paths are reported on the tool result. Applies to the raw relay too.
            # A non-empty body of nothing but masked values would be sent as {}: refused.
            try:
                require_unmasked_fields(json, f"{verb} body")
            except ValueError as exc:
                self._audit_write(method, path, "refused", None, reason=str(exc), body=json)
                raise
            json = drop_and_note_masked_fields(json)
        from .request_policy import request_dry_run_active

        if is_write and (dry_run_active(path=decoded_path(path)) or request_dry_run_active()):
            # Opt-in dry-run: no upstream write is sent; return a labeled preview. It names
            # the key the write would use when one is configured; a preview needs no key.
            self._audit_write(method, path, "dry_run", None, body=json)
            configs = self._key_configs()
            preview_key = key or (configs[0] if configs else None)
            return self._dry_run_response(method, path, json, params, files, key=preview_key)
        key = key or self._default_key()
        client = await self._get_client(key)

        for attempt in range(max_retries + 1):
            try:
                async with self._semaphore:
                    note_upstream_call()  # counted for the policy.refusal record
                    resp = await client.request(
                        method,
                        path,
                        params=params,
                        json=json,
                        files=files,
                        content=b"null" if send_json_null and json is None else None,
                        headers={
                            **({"Content-Type": "application/json"} if send_json_null else {}),
                            **({"Accept": accept} if accept is not None else {}),
                        }
                        or None,
                        extensions=self._response_trace(verb, path),
                    )
            except httpx.HTTPError as exc:
                # Every transport failure (timeout, connect/TLS/DNS, protocol, read/write,
                # proxy, ...) is wrapped with method, path and the cause, and every write
                # attempt is audited. ``from None`` keeps the chained httpx exception (whose
                # request carries the API key header) out of every rendered traceback.
                # The cause text is scrubbed: httpx quotes an illegal header value (an API
                # key with a newline, NUL or trailing space) in its message.
                if is_write:
                    self._audit_write(method, path, "error", None, body=json)
                # A failure before the request left (connect, pool, local protocol) never
                # reached the controller; anything later may have (never auto-retried).
                request_sent = not isinstance(exc, _NOT_SENT_ERRORS)
                raise UniFiConnectionError(
                    self._scrub(
                        f"{_transport_label(exc)}: {verb} {path} ({_transport_cause(exc)})"
                        + (
                            f" [decoded path: {decoded_path(path)}]"
                            if decoded_path(path) != path
                            else ""
                        )
                        + (
                            unknown_outcome_hint(path)
                            if is_write and not isinstance(exc, _NOT_SENT_ERRORS)
                            else ""
                        ),
                        key,
                    ),
                    request_sent=request_sent,
                ) from None

            # A registered secret route's response secrets (a share link in a body or a
            # redirect Location) are bound into the call scope before any error, log or
            # relay result is built, from the response as received.
            # route_secrets decodes the body with its declared charset (non-UTF-8 JSON too).
            route_secrets.bind_response(
                method,
                path,
                resp.content,
                resp.headers.multi_items(),
                status_code=resp.status_code,
            )
            # Registry-driven credentials must be scrubbed before any exception/log.
            resp = self._route_response(resp, key, verb, path)
            if resp.status_code != 429:
                # A Classic route reports its outcome in meta.rc: HTTP 2xx with any rc but
                # "ok" is an upstream error (the one rule: :func:`classic_rc_error`).
                classic_error = (
                    classic_rc_error(path, resp.status_code, decode_body(resp))
                    if is_classic_route(path) and resp.is_success
                    else None
                )
                if is_write:
                    self._audit_write(
                        method,
                        path,
                        "classic_rc_error"
                        if classic_error is not None
                        else _outcome_label(resp.status_code),
                        resp.status_code,
                        body=json,
                    )
                if 300 <= resp.status_code < 400 and raise_on_error:
                    # A 3xx is never success and is never followed (a write must not be
                    # re-sent to another location, and the key must not leave the origin).
                    location = resp.headers.get("location") or "(no Location header)"
                    body = error_body_text(
                        resp.text, redact_secrets=bool(self._settings.redact_secrets)
                    )
                    raise UniFiHTTPError(
                        self._scrub(
                            f"HTTP {resp.status_code} redirect from {verb} {path} to "
                            f"{location}: redirects are not followed, so the request did not "
                            "complete"
                            + (" (the write was not re-sent)" if is_write else "")
                            + ". Check UNIFI_API_BASE_URL (the API origin, e.g. "
                            "https://api.ui.com) and the request path"
                            + (f": {body}" if body else ""),
                            key,
                        ),
                        status=resp.status_code,
                    )
                if resp.is_error and raise_on_error:
                    body = error_body_text(
                        resp.text, redact_secrets=bool(self._settings.redact_secrets)
                    )
                    # Raise UniFiConnectionError (not httpx.HTTPStatusError) so that
                    # the request object — which contains the X-API-KEY header —
                    # is never embedded in the exception and cannot leak into logs.
                    # The body is scrubbed: an upstream may echo the key header back.
                    hint = self._authentication_hint(resp.status_code, key)
                    if is_write and resp.status_code in UNKNOWN_OUTCOME_STATUSES:
                        hint += unknown_outcome_hint(path)
                    raise UniFiHTTPError(
                        self._scrub(
                            f"HTTP {resp.status_code} from {verb} {path}: {body}" + hint,
                            key,
                        ),
                        status=resp.status_code,
                    )
                if classic_error is not None and raise_on_error:
                    body = error_body_text(
                        resp.text, redact_secrets=bool(self._settings.redact_secrets)
                    )
                    raise ClassicApiError(
                        self._scrub(
                            f"Classic API error from {verb} {path}: {classic_error}: {body}",
                            key,
                        )
                    )
                # Always scrub configured server secrets. Bound route/call values are
                # scrubbed only when the operator opted in to redaction, at every status.
                response = self._scrubbed_response(
                    resp,
                    key,
                    extra=call_secret_values() if self._settings.redact_secrets else (),
                )
                hint = self._authentication_hint(resp.status_code, key)
                if is_write and resp.status_code in UNKNOWN_OUTCOME_STATUSES:
                    hint += unknown_outcome_hint(path)
                if hint:
                    response.extensions["unifi_auth_hint"] = self._scrub(hint.lstrip("; "), key)
                return response

            if attempt == max_retries:
                if is_write:
                    self._audit_write(method, path, "rate_limited", 429, body=json)
                body = error_body_text(
                    resp.text, redact_secrets=bool(self._settings.redact_secrets)
                )
                raise RateLimitError(
                    self._scrub(
                        f"Rate limited after {_attempts(max_retries + 1)} on {verb} {path}: "
                        f"HTTP 429: {body}",
                        key,
                    )
                )

            base_delay = min(2**attempt, 32)
            jitter = _secure_random.uniform(0, base_delay)
            await asyncio.sleep(base_delay + jitter)

        raise RateLimitError("Unreachable")  # pragma: no cover

    def _authentication_hint(self, status: int, key: APIKeyConfig) -> str:
        """Append key-specific advice without rewriting an upstream response body."""
        if status not in (401, 403):
            return ""
        if header_mode_enabled():
            source = f"X-UniFi-Api-Key label {key.label!r}"
        else:
            source = (
                f"UNIFI_API_KEYS key label {key.label!r}"
                if self._settings.api_keys
                else "UNIFI_API_KEY"
            )
        action = (
            "check that the key is valid and has not expired or been revoked"
            if status == 401
            else "check the key's permissions, API scopes, and allowed sites"
        )
        return (
            f"\nHint: {source}: {action}. Create or check keys at "
            "https://unifi.ui.com (Site Manager > API Keys); "
            "see README#1-join-your-fabric-and-create-an-api-key."
        )

    def _audit_write(
        self,
        method: str,
        path: str,
        outcome: str,
        status: int | None,
        *,
        reason: str | None = None,
        body: Any = None,
    ) -> None:
        """Record a write attempt to the opt-in audit stream (no-op when unconfigured).

        Records method, resolved path, outcome and status (and, for a refused attempt,
        the gate as ``reason``). The request ``body`` is written only at
        ``UNIFI_AUDIT_LEVEL=debug``, credential fields masked and secrets scrubbed.
        """
        if self._audit_sink is not None:
            self._audit_sink.record(
                method=self._scrub(method.upper()),
                path=self._scrub(decoded_path(path)),
                outcome=outcome,
                status=status,
                reason=self._scrub(reason) if reason is not None else None,
                body=body,
            )

    def audit_refusal(
        self,
        *,
        reason: str,
        tool: str | None = None,
        method: str | None = None,
        path: str | None = None,
    ) -> None:
        """Audit a write attempt refused before any upstream call (``outcome=refused``).

        ``reason`` names the gate (``UNIFI_WRITE_POLICY=deny``, an area opt-out variable,
        ``empty_update`` ...). A refusal made before the tool body runs passes the
        ``tool`` name and no ``method`` / ``path``. No-op when the audit log is off.
        """
        if self._audit_sink is not None:
            self._audit_sink.record(
                method=self._scrub(method.strip().upper()) if method else None,
                path=self._scrub(path) if path is not None else None,
                outcome="refused",
                status=None,
                tool=self._scrub(tool) if tool is not None else None,
                reason=self._scrub(reason),
            )

    @property
    def audit_enabled(self) -> bool:
        """True when the opt-in audit stream writes records (a sink, level not off)."""
        return self._audit_sink is not None and self._audit_sink.enabled

    @property
    def audit_stream(self) -> AuditStream | None:
        """The configured audit stream (``None`` when no sink is configured)."""
        return self._audit_sink

    @property
    def dry_run(self) -> bool:
        """True when the write policy previews this call's writes (``UNIFI_WRITE_POLICY=
        dry-run`` or a ``dry-run`` exception for the calling tool), or the call being served
        runs under a request ``dry-run`` write mode (:mod:`unifi_fabric.request_policy`):
        writes return a preview, never sent.

        A verifying write tool consults it so its no-op short-circuit never stands in for
        the preview: under dry-run the write is always "sent" (to the preview), so the
        result is ``status: "dry_run"`` with the preview whether or not the change was
        already applied.
        """
        from .request_policy import request_dry_run_active

        return dry_run_active() or request_dry_run_active()

    def _dry_run_response(
        self,
        method: str,
        path: str,
        json: Any,
        params: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        *,
        key: APIKeyConfig | None = None,
    ) -> httpx.Response:
        """Synthetic 200 response for a suppressed write under dry-run.

        The body is a clearly-labeled preview (method, resolved path, query parameters,
        body) so a caller cannot mistake it for an executed result. ``params`` is the
        query string the write would have carried (``null`` when it has none): for many
        writes it selects the target or changes the effect (a bulk-delete ``filter``,
        ``force`` on a network delete, the zone ids of a policy ordering), so a preview
        without it would not show what would have been sent. No upstream request is sent.

        The preview shows the caller's own input, with configured server secrets always
        scrubbed. Credential-named fields (every
        documented credential field name, e.g. ``password``, ``passphrase``,
        ``x_passphrase``, ``psk``, ``x_private_key``, ``secret``, ``token``, plus string
        values under the suffix and ``x_`` rules; see ``redaction.CREDENTIAL_FIELDS``,
        ``CREDENTIAL_SUFFIXES`` and ``X_FIELD_CREDENTIAL_ENDINGS``) are masked with
        ``REDACTION_MASK`` only when the operator opted in with ``UNIFI_REDACT_SECRETS``:
        the same opt-in and the same rules as response bodies and upstream error bodies
        (:func:`error_body_text`). A registered secret route's fields
        (:data:`route_secrets.ROUTE_SECRETS`, e.g. the Matter ``setup_code``) follow the
        same opt-in, for the typed tool and the generic relay alike.
        """
        redact = bool(self._settings.redact_secrets)
        # A registered secret route's secret fields (a Matter setup code, a share link)
        # are masked only under the operator's redaction opt-in (route_secrets).
        json = route_secrets.mask_request_body(method, path, json, redact_secrets=redact)
        query = dict(params) if params is not None else None
        detail: dict[str, Any] = {
            "method": method.upper(),
            "path": route_secrets.mask_request_path(method, path, redact_secrets=redact),
            "params": redact_credentials(query) if redact and query is not None else query,
            "body": (
                mask_request_body(method, path, redact_credentials(json), redact_secrets=True)
                if redact
                else json
            ),
        }
        if key is not None and key.label:
            detail["keyLabel"] = key.label
        preview = {
            "status": "dry_run",
            "dryRun": True,
            "sent": False,
            "message": DRY_RUN_MESSAGE,
            "preview": detail,
        }
        if files is not None:
            # A multipart upload: what would be sent, never the content itself.
            detail["multipart"] = multipart_summary(files)
        base = self._settings.api_base_url.rstrip("/")
        req = httpx.Request(method, base + path)
        secrets = configured_secrets(
            self._settings, extra=(key.key,) if key is not None else (), include_call=False
        )
        return httpx.Response(200, json=scrub_json_strings(preview, secrets), request=req)

    async def get(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """GET request; returns the upstream body as decoded by :func:`decode_body`."""
        resp = await self.request("GET", path, key=key, params=params)
        return decode_body(resp)

    async def get_binary(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[bytes, str | None]:
        """GET request, return ``(raw bytes, Content-Type)`` for binary responses.

        The upstream ``Content-Type`` header is surfaced so a caller can report the true
        media type of an image/asset instead of guessing from a file extension. When
        the upstream sends no Content-Type, ``None`` is returned; no type is invented.

        The complete body is returned; no size limit is applied.
        """
        resp = await self.request("GET", path, key=key, params=params)
        return resp.content, resp.headers.get("content-type")

    async def post(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """POST request; returns the upstream body as decoded by :func:`decode_body`.

        Sent once: a 429 is raised, never auto-retried (the retry rule in :meth:`request`).
        """
        resp = await self.request("POST", path, key=key, json=json, params=params)
        return decode_body(resp)

    async def post_multipart(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        files: dict[str, Any],
        params: dict[str, Any] | None = None,
    ) -> Any:
        """POST multipart/form-data request; returns the body as decoded by :func:`decode_body`."""
        resp = await self.request("POST", path, key=key, files=files, params=params)
        return decode_body(resp)

    async def put(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """PUT request; returns the upstream body as decoded by :func:`decode_body`."""
        resp = await self.request("PUT", path, key=key, json=json, params=params)
        return decode_body(resp)

    async def patch(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """PATCH request (sent once); returns the body as decoded by :func:`decode_body`."""
        resp = await self.request("PATCH", path, key=key, json=json, params=params)
        return decode_body(resp)

    async def delete(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """DELETE request (sent once); returns the upstream body as received.

        Decoded by :func:`decode_body`: JSON parsed, a non-JSON body as its verbatim
        text (no key is invented around it), and an empty or 204 body as ``None``.
        """
        resp = await self.request("DELETE", path, key=key, json=json, params=params)
        return decode_body(resp)

    async def paginate(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
        page_size: int | None = 200,
    ) -> DrainedItems:
        """Auto-paginate a list endpoint using nextToken cursor.

        The returned list carries the first page's envelope (``envelope``; see
        :func:`page_envelope`).

        ``page_size=None`` sends no ``pageSize`` (for a list whose published spec
        defines no query parameters, such as Site Manager ``/v1/sd-wan-configs``); a
        ``nextToken`` in a response is still followed.

        Two-layer runaway-loop defense:
        1. Stall detection (primary): if the same nextToken is returned twice in a
           row, the API is looping — raises PaginationAbortedError immediately.
        2. Absolute page cap (backstop): if UNIFI_PAGINATE_MAX_PAGES is set and the
           page count reaches it, raises PaginationAbortedError.
        """
        all_items: list[dict[str, Any]] = []
        req_params = dict(params or {})
        # Site Manager /v1 list endpoints take ``pageSize`` (published spec v1.0.0).
        if page_size is not None:
            req_params.setdefault("pageSize", page_size)
        max_pages = self._settings.paginate_max_pages
        prev_token: str | None = None
        prev_items: list[Any] | None = None
        # Every cursor already requested: a nextToken pointing back to any of them is a
        # cycle (A -> B -> A), not only the consecutive repeat (A -> A).
        seen_tokens: set[str] = set()
        page_count = 0
        envelope: dict[str, Any] | None = None
        array_key: str | None = None

        while True:
            data = await self.get(path, key=key, params=req_params)
            page_count += 1
            if envelope is None:
                envelope = page_envelope(data, "data")
                array_key = "data" if isinstance(data, dict) else None

            if isinstance(data, list):  # a bare array is a complete, unpaged list
                all_items.extend(data)
                break
            raw_items = data.get("data") if isinstance(data, dict) else None
            if not isinstance(raw_items, list):
                raise UniFiConnectionError(
                    f"Unexpected response shape from GET {path}: expected an object with a "
                    f"'data' array, got {describe_shape(data)}"
                )
            items = raw_items
            next_token = read_page_token(data, "nextToken", path)

            if next_token and next_token in seen_tokens:
                # Stalled or cycling cursor: keep this page only if it is not a repeat of
                # the last, then stop with what was gathered.
                if items != prev_items:
                    all_items.extend(items)
                reason = (
                    "stall detected — nextToken repeated"
                    if next_token == prev_token
                    else "cursor cycle detected — nextToken was already requested"
                )
                raise PaginationAbortedError(
                    path,
                    page_count,
                    reason,
                    items=all_items,
                    envelope=envelope,
                    array_key=array_key,
                )
            all_items.extend(items)
            if not next_token:
                break

            if max_pages is not None and page_count >= max_pages:
                raise PaginationAbortedError(
                    path,
                    page_count,
                    f"page cap of {max_pages} reached",
                    items=all_items,
                    envelope=envelope,
                    array_key=array_key,
                )

            prev_token = next_token
            prev_items = items
            seen_tokens.add(next_token)
            req_params["nextToken"] = next_token

        return DrainedItems(all_items, None, envelope, array_key)

    async def paginate_offset(
        self,
        path: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
        page_size: int = 200,
    ) -> DrainedItems:
        """Drain an offset-paginated list; the returned list carries ``total_count``
        (the upstream ``totalCount``, or ``None`` when the API reports none) and the first
        page's ``envelope``.

        The UniFi Network *Integration* proxy endpoints (per-site clients, devices,
        firewall policies, switching resources, DPI catalogues, …) respond with
        ``{data, offset, limit, count, totalCount}``. Termination, in priority order:

        1. ``totalCount`` reported: keep requesting until that many items are gathered,
           advancing ``offset`` by the number of items actually returned (a server that
           clamps ``limit`` below the requested page size still drains completely). An
           empty page before the total is reached raises PaginationAbortedError
           (carrying what was gathered) — never a silent short result.
        2. ``UNIFI_PAGINATE_MAX_PAGES`` (opt-in) backstops everything else.

        A page is final only on affirmative evidence: the declared total is reached, an echoed
        limit or size (`limit`, `meta.limit`, `links` pageSize) is larger than the rows returned,
        the page is empty, or the continuation (`nextToken`, `meta.hasMore`/`nextCursor`,
        `links.next`, `total_page_count`) is absent or terminal. The response shape is never
        evidence: an object envelope with neither a total nor a size echo is drained until an
        empty page exactly like a bare array; a page larger than the sent size is not terminal,
        and a repeated page is an abort unless the repeated page exceeded the sent size and
        nothing shows more records exist (no declared total above the records gathered and no
        continuation that is present and non-terminal), in which case the endpoint is unpaged
        and the drain is complete; otherwise the repeat stays an abort that keeps the records
        gathered once, the upstream total verbatim, and a reason naming the evidence.
        """
        # A local import: tools._pagination imports this module.
        from .tools._pagination import validate_pagination

        # validate_pagination reads None as "not given"; here both values are always used,
        # so a None is checked under its printed form and refused like any non-integer.
        start_offset = (params or {}).get("offset", 0)
        validate_pagination(
            page_size="None" if page_size is None else page_size,
            offset="None" if start_offset is None else start_offset,
        )
        all_items: list[dict[str, Any]] = []
        gathered_identities: set[tuple[str, str | int] | None] = set()
        base = dict(params or {})
        max_pages = self._settings.paginate_max_pages
        offset = base.get("offset", 0)
        # ``totalCount`` is the size of the WHOLE collection: a drain that starts at a
        # nonzero offset is complete once it reaches the end, i.e. after
        # ``totalCount - start`` items, not ``totalCount``.
        start = max(offset, 0)
        limit = page_size
        page_count = 0
        envelope: dict[str, Any] | None = None
        array_key: str | None = None
        history = PageHistory()
        first_oversized = False
        total_count: int | None = None

        while True:
            req_params = dict(base)
            req_params["offset"] = offset
            req_params["limit"] = limit
            data = await self.get(path, key=key, params=req_params)
            page_count += 1
            if envelope is None:
                envelope = page_envelope(data, "data")
                array_key = "data" if isinstance(data, dict) else None

            if isinstance(data, list):
                items = data
            else:
                raw_items = data.get("data") if isinstance(data, dict) else None
                if not isinstance(raw_items, list):
                    raise UniFiConnectionError(
                        f"Unexpected response shape from GET {path}: expected an object "
                        f"with a 'data' array, got {describe_shape(data)}"
                    )
                items = raw_items
                # Network reports ``totalCount``; Mobility reports ``total``.
                raw_total = page_total(data, path)
                if raw_total is None and data.get("total_element_count") is not None:
                    raw_total = data["total_element_count"]
                    if (
                        not isinstance(raw_total, int)
                        or isinstance(raw_total, bool)
                        or raw_total < 0
                    ):
                        raise wrong_type_error(
                            f"total_element_count of GET {path}",
                            raw_total,
                            "a non-negative integer or null",
                        )
                if raw_total is not None:
                    total_count = raw_total
            stop = page_stop(
                items,
                data,
                family="offset",
                history=history,
                seen=gathered_identities,
                page=page_count,
                position=offset,
                sent=req_params["limit"],
                total=total_count,
                supplied=start + len(all_items),
                kept=len(all_items),
                first_oversized=first_oversized,
            )
            if stop is not None:
                if stop.reason is None:
                    break
                raise PaginationAbortedError(
                    path,
                    page_count,
                    stop.reason,
                    items=all_items,
                    envelope=envelope,
                    array_key=array_key,
                    total_count=total_count,
                )
            if page_count == 1:
                first_oversized = len(items) > req_params["limit"]
            if items:
                history.add(items, offset)
            all_items.extend(unique_page_rows(items, all_items, gathered_identities))

            if total_count is not None:
                if start + len(all_items) >= total_count:
                    break
                if not items:
                    raise PaginationAbortedError(
                        path,
                        page_count,
                        f"upstream reported totalCount {upstream_error_value(total_count)} but "
                        f"returned no more items after {len(all_items)}"
                        + (f" (starting at offset {start})" if start else ""),
                        items=all_items,
                        envelope=envelope,
                        array_key=array_key,
                        total_count=total_count,
                    )
            elif not items or (
                isinstance(data, dict)
                and isinstance(data.get("limit"), int)
                and not isinstance(data["limit"], bool)
                and data["limit"] > 0
                and len(items) < data["limit"]
            ):
                # An envelope can prove a short terminal page.
                # Feeds without a total or size echo require an empty page;
                # returning more or fewer rows than requested is not terminal evidence.
                break

            if max_pages is not None and page_count >= max_pages:
                raise PaginationAbortedError(
                    path,
                    page_count,
                    f"page cap of {max_pages} reached",
                    items=all_items,
                    envelope=envelope,
                    array_key=array_key,
                    total_count=total_count,
                )

            offset += len(items)

        return DrainedItems(all_items, total_count, envelope, array_key)

    async def paginate_links(
        self,
        path: str,
        array_field: str,
        *,
        key: APIKeyConfig | None = None,
        params: dict[str, Any] | None = None,
        page_size: int = 200,
    ) -> DrainedItems:
        """Auto-paginate a ``links.next`` / page-number list endpoint (the returned list
        carries the first page's envelope).

        The private Protect *recognition* endpoints (face/vehicle groups and their
        detections) are neither cursor- nor offset-paginated. They return a
        ``{<array_field>: [...], "links": {"prev": ..., "next": ...}}`` envelope where
        ``links.next`` is a relative URL carrying ``&page=N`` (or ``null`` on the last
        page). This is a third pagination family, so this is its dedicated drainer:
        the page counter is advanced locally and pages are fetched until ``links.next``
        is null. An empty page with a continuation link is still followed.

        Termination is defensive, in priority order:
        1. ``links.next`` is null — the last page;
        2. ``UNIFI_PAGINATE_MAX_PAGES`` backstops a server that never signals an end —
           reaching it raises PaginationAbortedError (carrying the pages already
           gathered) rather than looping forever or truncating silently.

        Bare-list responses are tolerated: with no ``links`` envelope there is no next
        page, so a single fetch is returned.
        """
        all_items: list[dict[str, Any]] = []
        base = dict(params or {})
        base["pageSize"] = page_size
        max_pages = self._settings.paginate_max_pages
        page = 1
        page_count = 0
        envelope: dict[str, Any] | None = None
        array_key: str | None = None
        previous: list[Any] | None = None

        while True:
            req_params = dict(base)
            req_params["page"] = page
            data = await self.get(path, key=key, params=req_params)
            page_count += 1
            if envelope is None:
                envelope = page_envelope(data, array_field)
                array_key = array_field if isinstance(data, dict) else None

            if isinstance(data, list):
                items = data
                has_next = False
            else:
                raw_items = data.get(array_field) if isinstance(data, dict) else None
                if not isinstance(raw_items, list):
                    raise UniFiConnectionError(
                        f"Unexpected response shape from GET {path}: expected an object "
                        f"with a {array_field!r} array, got {describe_shape(data)}"
                    )
                items = raw_items
                has_next = page_has_next_link(data, path)
                # A next link can echo a console clamp; subsequent page numbers
                # must retain that physical size to preserve their record boundary.
                effective = data.get("limit")
                if has_next:
                    sizes = parse_qs(urlsplit(data["links"]["next"]).query).get("pageSize", [])
                    if sizes and sizes[0].isdigit():
                        effective = int(sizes[0])
                if isinstance(effective, int) and not isinstance(effective, bool) and effective > 0:
                    base["pageSize"] = effective
                elif page_count == 1 and items and has_next:
                    base["pageSize"] = len(items)
            if previous is not None and page_is_repeat(items, previous):
                # A server that ignores ``page`` repeats it, though live fields (a client
                # count, a timestamp) can differ between answers: compare by record
                # identity, as the offset and window drains do, and stop instead of looping.
                raise PaginationAbortedError(
                    path,
                    page_count,
                    "the server returned the same page again (page not honoured)",
                    items=all_items,
                    envelope=envelope,
                    array_key=array_key,
                )
            previous = items
            all_items.extend(items)

            if not has_next:
                break

            if max_pages is not None and page_count >= max_pages:
                raise PaginationAbortedError(
                    path,
                    page_count,
                    f"page cap of {max_pages} reached",
                    items=all_items,
                    envelope=envelope,
                    array_key=array_key,
                )

            page += 1

        return DrainedItems(all_items, None, envelope, array_key)

    async def gather(
        self,
        coros: list[Any],
    ) -> list[Any]:
        """Run coroutines concurrently, at most ``max_concurrency`` at a time.

        The fan-out bound uses a semaphore separate from the per-request one, so the
        HTTP requests made inside the coroutines never wait on a slot held by their
        own outer task (and the request count stays bounded by the request semaphore).
        Do not call ``gather`` from inside a coroutine passed to ``gather``.
        """

        async def _bounded(coro: Any) -> Any:
            try:
                async with self._fanout_semaphore:
                    return await coro
            finally:
                # Cancelled while queued for a slot: close the never-started coroutine
                # (no "coroutine was never awaited" warning).
                if asyncio.iscoroutine(coro) and inspect.getcoroutinestate(coro) == "CORO_CREATED":
                    coro.close()

        # The first failure cancels (and awaits) every sibling: none outlives the call.
        return await gather_or_cancel(*[_bounded(c) for c in coros])

    async def close(self) -> None:
        """Close all HTTP clients."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()
        await self._credential_cache.aclose()
