"""HTTP transport hardening: startup warnings, Origin checks and token verification.

Everything here applies to the HTTP transports (``streamable-http``, ``sse``) only:

- :func:`startup_warnings` lists the risky-but-allowed postures the server starts with
  (no auth on a non-loopback bind, mTLS ``optional`` without auth, a short bearer token,
  a plain-http JWKS URI). Each warning names the variables and a fix; none refuses.
- :class:`OriginGuardMiddleware` rejects a browser request whose ``Origin`` is not
  allowed (DNS-rebinding and cross-site defence); FastMCP's own guard checks ``Host``.
- :class:`ConstantTimeTokenVerifier` checks ``MCP_BEARER_TOKEN`` with
  :func:`hmac.compare_digest`.
- :class:`StrictJWTVerifier` requires ``exp`` and checks ``nbf`` / ``iat`` (60 s leeway)
  on top of FastMCP's checks, and downloads the JWKS with a 1 MiB cap;
  :class:`ClaimRejectionMiddleware` makes the 401 name the rejected claim.
- :class:`WriteScopeMiddleware` enforces the opt-in ``MCP_OAUTH_WRITE_SCOPE`` on write
  tools.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hmac
import ipaddress
import json
import logging
import math
import time
from collections.abc import AsyncIterator, Callable, Sequence
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import fastmcp
import httpx2
from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.server.auth import AccessToken, RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier, StaticTokenVerifier
from fastmcp.server.http import HostOriginGuardMiddleware
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.middleware import Middleware as ASGIMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

if TYPE_CHECKING:
    from .config import MCPTransportSettings

_logger = logging.getLogger(__name__)

#: Transports with a network surface (``http`` is FastMCP's alias of streamable-http).
HTTP_TRANSPORTS = ("streamable-http", "http", "sse")
#: A bearer token shorter than this draws a startup warning.
MIN_BEARER_TOKEN_LENGTH = 32
#: The command every token warning and doc suggests.
TOKEN_COMMAND = "openssl rand -hex 32"  # noqa: S105 -- a shell command, not a secret
#: Clock-skew allowance for the ``nbf`` and ``iat`` claims, in seconds.
JWT_LEEWAY_SECONDS = 60
#: The largest JWKS document the verifier downloads.
JWKS_MAX_BYTES = 1024 * 1024
#: The variables the Origin refusal names.
ORIGINS_ENV = "MCP_ALLOWED_ORIGINS"
PROTECTION_ENV = "MCP_HOST_ORIGIN_PROTECTION"
WRITE_SCOPE_ENV = "MCP_OAUTH_WRITE_SCOPE"
#: A Content-Length with more significant digits than this is never passed to ``int()``.
MAX_LENGTH_DIGITS = 18


def length_digits(value: str | bytes) -> str | None:
    """A Content-Length value's significant ASCII digits (``"0"`` for zero), or None when
    it is not a plain run of ASCII digits.

    Callers compare the digit count before calling ``int()``: ``int()`` raises ValueError
    past :func:`sys.get_int_max_str_digits` (4300 digits by default), and
    :meth:`str.isdigit` alone also accepts non-ASCII digits such as ``"\u00b2"`` that
    ``int()`` rejects.
    """
    text = value.decode("latin-1") if isinstance(value, bytes) else value
    if not text or not (text.isascii() and text.isdigit()):
        return None
    return text.lstrip("0") or "0"


def is_loopback_host(host: str) -> bool:
    """True for ``localhost`` (and ``*.localhost``) and loopback IP literals."""
    name = host.strip().lower()
    if name.startswith("[") and name.endswith("]"):
        name = name[1:-1]
    if name == "localhost" or name.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


# --- Startup warnings ---------------------------------------------------------------


def startup_warnings(s: MCPTransportSettings, transport: str, host: str, port: int) -> list[str]:
    """The startup WARNING lines for ``s`` (empty for a safe posture). Never a value of a
    secret; every line names the variables involved and a fix."""
    if transport not in HTTP_TRANSPORTS:
        return []
    out: list[str] = []
    if s.auth_mode == "none" and not is_loopback_host(host):
        out.append(
            f"WARNING: the {transport} transport listens on FASTMCP_HOST={host} (not loopback) "
            "with MCP_AUTH_MODE=none: anyone who can reach port "
            f"{port} can call every tool, writes included, with the configured UniFi API key. "
            "Fix: set MCP_AUTH_MODE=bearer and MCP_BEARER_TOKEN to a random secret "
            f"(`{TOKEN_COMMAND}`), or MCP_AUTH_MODE=oauth; or bind FASTMCP_HOST=127.0.0.1. "
            "See docs/AUTH-TLS.md."
        )
    if s.tls_mode == "mtls" and s.tls_cert_reqs == "optional" and s.auth_mode == "none":
        out.append(
            "WARNING: MCP_TLS_MODE=mtls with MCP_TLS_CERT_REQS=optional and MCP_AUTH_MODE=none "
            "admits a client that presents no certificate, unauthenticated. Fix: set "
            "MCP_TLS_CERT_REQS=required (or unset it), or set MCP_AUTH_MODE=bearer or oauth. "
            "See docs/AUTH-TLS.md."
        )
    if s.auth_mode == "bearer" and len(s.bearer_token) < MIN_BEARER_TOKEN_LENGTH:
        out.append(
            f"WARNING: MCP_BEARER_TOKEN is shorter than {MIN_BEARER_TOKEN_LENGTH} characters, "
            f"so it can be guessed. Fix: generate one with `{TOKEN_COMMAND}`, set it as "
            "MCP_BEARER_TOKEN and in your clients' Authorization header. See docs/AUTH-TLS.md."
        )
    if s.auth_mode == "oauth":
        parts = urlsplit(s.oauth_jwks_uri)
        if parts.scheme.lower() == "http" and not is_loopback_host(parts.hostname or ""):
            out.append(
                "WARNING: MCP_OAUTH_JWKS_URI uses plain http:// to a host that is not loopback, "
                "so anyone on the network path can substitute the signing keys and mint tokens "
                "this server accepts. Fix: use the identity provider's https:// JWKS URI. "
                "See docs/AUTH-OAUTH.md."
            )
    return out


# --- Origin validation --------------------------------------------------------------


def normalize_origin(origin: str) -> str | None:
    """``scheme://host:port`` (lower case, explicit port) for a valid http(s) origin, or
    None for anything else (``null``, a path, credentials, another scheme)."""
    try:
        parts = urlsplit(origin.strip())
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    shown = f"[{host}]" if ":" in host else host
    return f"{scheme}://{shown}:{port}"


def origin_allowed(origin: str, allowed: Sequence[str]) -> bool:
    """True when ``origin`` is a loopback http(s) origin or one of ``allowed``
    (already normalized)."""
    normalized = normalize_origin(origin)
    if normalized is None:
        return False
    if is_loopback_host(urlsplit(normalized).hostname or ""):
        return True
    return normalized in allowed


def allowed_origins(s: MCPTransportSettings) -> tuple[str, ...]:
    """The configured origins: ``MCP_OAUTH_BASE_URL``'s origin plus ``MCP_ALLOWED_ORIGINS``
    (loopback origins are always allowed and are not listed)."""
    out: list[str] = []
    for value in [s.oauth_base_url, *s.allowed_origins]:
        if not value:
            continue
        parts = urlsplit(value)
        normalized = normalize_origin(f"{parts.scheme}://{parts.netloc}")
        if normalized is not None and normalized not in out:
            out.append(normalized)
    return tuple(out)


_ORIGIN_REFUSAL = (
    "Forbidden: this request's Origin header is not allowed, so it was refused before "
    "reaching the MCP server (protection against DNS rebinding and cross-site requests). "
    "Allowed: loopback origins, the origin of MCP_OAUTH_BASE_URL, and "
    f"{ORIGINS_ENV}. To allow a browser client, add its origin to {ORIGINS_ENV} "
    "(comma-separated, e.g. https://app.example.com); to turn the check off, set "
    f"{PROTECTION_ENV}=off.\n"
).encode()


class OriginGuardMiddleware:
    """Refuse (403) an HTTP request whose ``Origin`` is not allowed.

    No ``Origin`` header passes (non-browser clients send none). ``Origin: null`` and
    any malformed or unlisted origin are refused, and the body names the variables.
    """

    def __init__(self, app: ASGIApp, allowed: Sequence[str] = ()) -> None:
        self.app = app
        self.allowed = tuple(allowed)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            origins = Headers(scope=scope).getlist("origin")
            if origins and not all(origin_allowed(o, self.allowed) for o in origins):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [
                            (b"content-type", b"text/plain; charset=utf-8"),
                            (b"content-length", str(len(_ORIGIN_REFUSAL)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": _ORIGIN_REFUSAL})
                return
        await self.app(scope, receive, send)


class HostRefusalHintMiddleware:
    """Delegate every Host decision to FastMCP, adding a hint only to its local 421.

    A downstream response, including a 421, passes through unchanged.
    """

    def __init__(self, app: ASGIApp, /, **options: Any) -> None:
        self.app = app
        self.options = options

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        reached_app = False
        local_refusal = False
        hint = b". Add the server's public host to MCP_ALLOWED_HOSTS."

        async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
            nonlocal reached_app
            reached_app = True
            await self.app(scope, receive, send)

        async def with_hint(message: Message) -> None:
            nonlocal local_refusal
            if message["type"] == "http.response.start":
                local_refusal = not reached_app and message["status"] == 421
                if local_refusal:
                    message = dict(message)
                    message["headers"] = _lengthened(message.get("headers", []), len(hint))
            elif (
                message["type"] == "http.response.body"
                and local_refusal
                and not message.get("more_body", False)
            ):
                message = {**message, "body": message.get("body", b"") + hint}
            await send(message)

        await HostOriginGuardMiddleware(downstream, **self.options)(scope, receive, with_hint)


def _lengthened(headers: Sequence[tuple[bytes, bytes]], extra: int) -> list[tuple[bytes, bytes]]:
    """``headers`` with Content-Length grown by ``extra``. A Content-Length that is not
    plain ASCII digits, or is too long to be a real length, is dropped rather than parsed,
    and the ASGI server then frames the body itself."""
    out: list[tuple[bytes, bytes]] = []
    for key, value in headers:
        if key.lower() == b"content-length":
            digits = length_digits(value)
            if digits is None or len(digits) > MAX_LENGTH_DIGITS:
                continue
            value = str(int(digits) + extra).encode()
        out.append((key, value))
    return out


def install_host_refusal_hint(app: Starlette) -> None:
    """Wrap the upstream guard in place; keep its ordering, options and policy."""
    app.user_middleware = [
        ASGIMiddleware(HostRefusalHintMiddleware, *entry.args, **entry.kwargs)
        if entry.cls is HostOriginGuardMiddleware
        else entry
        for entry in app.user_middleware
    ]


def http_app_options(s: MCPTransportSettings, options: dict[str, Any]) -> dict[str, Any]:
    """FastMCP ``http_app`` options with this server's Host policy applied.

    Unauthenticated loopback servers keep FastMCP's automatic Host defence.
    Authenticated servers accept proxy Host values unless an explicit allowlist or
    strict mode was requested: a browser cannot supply the required bearer token.
    Origin validation remains in :class:`OriginGuardMiddleware`, including for
    authenticated requests. With ``MCP_HOST_ORIGIN_PROTECTION=off`` both are off.
    """
    out = dict(options)
    if not s.host_origin_protection:
        out["host_origin_protection"] = False
        return out
    if (
        out.get("host_origin_protection") is True
        or fastmcp.settings.http_host_origin_protection is True
    ):
        out["host_origin_protection"] = True
    else:
        out["host_origin_protection"] = "auto"
    configured_hosts = out.get("allowed_hosts")
    if configured_hosts is None:
        configured_hosts = fastmcp.settings.http_allowed_hosts
    hosts = [*(configured_hosts or []), *s.allowed_hosts]
    authenticated_auto = (
        s.auth_mode in {"bearer", "oauth"} and out["host_origin_protection"] == "auto"
    )
    out["allowed_hosts"] = (
        hosts if hosts or configured_hosts is not None else (["*"] if authenticated_auto else None)
    )
    out["allowed_origins"] = ["*"]
    return out


# --- Bearer token ---------------------------------------------------------------------


class ConstantTimeTokenVerifier(StaticTokenVerifier):
    """The ``MCP_BEARER_TOKEN`` check, compared in constant time (:func:`hmac.compare_digest`)
    rather than by FastMCP's dictionary lookup."""

    def __init__(self, token: str) -> None:
        super().__init__(tokens={token: {"client_id": "mcp", "scopes": []}})
        self._expected = token.encode("utf-8", "surrogatepass")

    async def verify_token(self, token: str) -> AccessToken | None:
        offered = token.encode("utf-8", "surrogatepass")
        if not offered or not hmac.compare_digest(offered, self._expected):
            return None
        return AccessToken(token=token, client_id="mcp", scopes=[], expires_at=None)


# --- JWT claims and the JWKS download ---------------------------------------------------

#: Why the current request's JWT was rejected by :class:`StrictJWTVerifier` (None if not).
_claim_rejection: ContextVar[str | None] = ContextVar("unifi_fabric_claim_rejection", default=None)


class _OversizedInt(str):
    """A JSON integer literal longer than Python's int-conversion digit limit
    (:func:`sys.get_int_max_str_digits`, 4300 by default), kept as its text."""


def _parse_json_int(text: str) -> int | _OversizedInt:
    """``json.loads(parse_int=...)``: an integer past the digit limit makes ``int()`` raise
    ValueError, which would fail the whole payload and lose which claim was at fault."""
    try:
        return int(text)
    except ValueError:
        return _OversizedInt(text)


def _numeric_date(claims: dict[str, Any], name: str) -> float | None | str:
    value = claims.get(name)
    if value is None:
        return None
    problem = f"claim '{name}' must be a finite NumericDate (seconds since the epoch)"
    if isinstance(value, _OversizedInt):
        return f"{problem}; it is an integer of {len(value.lstrip('-'))} digits"
    if isinstance(value, bool) or not isinstance(value, int | float):
        return problem
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return problem
    return number if math.isfinite(number) else problem


def jwt_time_claim_problem(claims: dict[str, Any], now: float) -> str | None:
    """What is wrong with a verified token's time claims, naming the claim, or None.

    ``exp`` is required; ``nbf`` and ``iat`` may not lie in the future beyond
    :data:`JWT_LEEWAY_SECONDS`. (An ``exp`` in the past is FastMCP's own check.)
    """

    exp = _numeric_date(claims, "exp")
    if exp is None:
        return "claim 'exp' is required (a token without an expiry never expires)"
    if isinstance(exp, str):
        return exp
    if exp < now:
        return "claim 'exp' is in the past (the token has expired)"
    for name, what in (("nbf", "not valid yet"), ("iat", "issued in the future")):
        value = _numeric_date(claims, name)
        if isinstance(value, str):
            return value
        if value is not None and value > now + JWT_LEEWAY_SECONDS:
            return (
                f"claim '{name}' is more than {JWT_LEEWAY_SECONDS} s in the future "
                f"(the token is {what}; check the clocks of this server and the identity "
                "provider)"
            )
    return None


class _CappedStream(httpx2.AsyncByteStream):
    """A decoded response body that fails before buffering more than the cap."""

    def __init__(self, inner: httpx2.Response) -> None:
        self._inner = inner

    async def __aiter__(self) -> AsyncIterator[bytes]:
        total = 0
        async for chunk in self._inner.aiter_bytes():
            total += len(chunk)
            if total > JWKS_MAX_BYTES:
                raise httpx2.ReadError(
                    f"JWKS response from MCP_OAUTH_JWKS_URI exceeds {JWKS_MAX_BYTES} bytes"
                )
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


class _CappedTransport(httpx2.AsyncBaseTransport):
    """Wraps the default transport so no JWKS body larger than the cap is read."""

    def __init__(self, inner: httpx2.AsyncBaseTransport | None = None) -> None:
        self._inner = inner if inner is not None else httpx2.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        response = await self._inner.handle_async_request(request)
        digits = length_digits(response.headers.get("content-length", ""))
        # Content-Length describes wire bytes, not decoded bytes. Only an
        # unencoded response can be rejected from that declaration alone. The digit
        # count is compared first, so a 5000-digit declaration never reaches int().
        if (
            not response.headers.get("content-encoding")
            and digits is not None
            and (len(digits) > len(str(JWKS_MAX_BYTES)) or int(digits) > JWKS_MAX_BYTES)
        ):
            await response.aclose()
            shown = (
                f"{digits} bytes"
                if len(digits) <= MAX_LENGTH_DIGITS
                else f"a {len(digits)}-digit length"
            )
            raise httpx2.ReadError(
                f"JWKS response from MCP_OAUTH_JWKS_URI declares {shown}, over the "
                f"{JWKS_MAX_BYTES}-byte cap"
            )
        # Decode in the original response's streaming iterator, then cap each decoded
        # chunk BEFORE the client's aread()/JSON parser buffers it. httpx2's decoders
        # yield bounded output chunks even for highly compressed input. Remove encoding
        # and wire length so the outer response does not decode this body a second time.
        headers = response.headers.copy()
        headers.pop("content-encoding", None)
        headers.pop("content-length", None)
        return httpx2.Response(
            status_code=response.status_code,
            headers=headers,
            stream=_CappedStream(response),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


def capped_jwks_client(inner: httpx2.AsyncBaseTransport | None = None) -> httpx2.AsyncClient:
    """Await JWKS completion or cancellation while preserving the 1 MiB byte cap.

    ``inner`` replaces the network transport (tests). No elapsed-time deadline is set: a
    download that never answers is left waiting, and :class:`StrictJWTVerifier` keeps
    every other authentication independent of it (see :data:`JWKS_MAX_PENDING_DOWNLOADS`).
    """
    return httpx2.AsyncClient(
        timeout=None,  # noqa: S113 -- retain byte safety, not an elapsed-time cap
        transport=_CappedTransport(inner),
    )


#: How many JWKS downloads may be waiting on the identity provider at once. A download
#: has no elapsed-time deadline, so one that is accepted and never answered stays open; a
#: later refresh (at most one per ``jwks_refresh_interval``, and only when a caller needs
#: one) starts another download beside it rather than waiting behind it. Past this many,
#: starting a new download closes the oldest, so a long stall holds a fixed number of
#: connections. The first download to finish answers every waiting caller and closes the
#: rest.
JWKS_MAX_PENDING_DOWNLOADS = 4


class _JWKSRound:
    """The callers waiting for the next JWKS download to finish, and its outcome."""

    __slots__ = ("document", "error", "settled")

    def __init__(self) -> None:
        self.settled = asyncio.Event()
        self.document: dict[str, Any] | None = None
        self.error: Exception | None = None


#: A settled download that FastMCP's key processing reads through
#: :meth:`StrictJWTVerifier._fetch_jwks` (the download task's own cache fill).
_settled_jwks: ContextVar[_JWKSRound | None] = ContextVar("unifi_fabric_settled_jwks", default=None)
#: Whether FastMCP asked for a download during this caller's key lookup.
_jwks_download_requested: ContextVar[bool] = ContextVar(
    "unifi_fabric_jwks_download_requested", default=False
)


#: What parsing an untrusted token can raise on hostile input: a missing segment
#: (IndexError); malformed base64 or JSON, including invalid UTF-8 and non-ASCII base64
#: text (ValueError, which covers binascii.Error and UnicodeError); and nesting deeper than
#: the interpreter's recursion limit (RecursionError: json's scanner raises it for 10000
#: nested ``[``). Each is the standard 401 invalid-token answer, never a 500. MemoryError
#: is deliberately not caught: the token is bounded by the HTTP server's header-size
#: limit, and an out-of-memory process is not a verdict about a token.
UNTRUSTED_TOKEN_ERRORS: tuple[type[Exception], ...] = (IndexError, ValueError, RecursionError)


class StrictJWTVerifier(JWTVerifier):
    """FastMCP's :class:`JWTVerifier` plus the time-claim checks of
    :func:`jwt_time_claim_problem`, run after the signature and the issuer, audience and
    scope checks pass. A rejection is logged and recorded for the 401 response.

    JWKS refreshes hold no lock across the download. FastMCP's verifier keeps one refresh
    lock for the whole download; as the download has no deadline, an identity provider
    that accepted the connection and never answered kept the lock, and every later
    authentication that needed a refresh (an unknown ``kid``, or any token once the cached
    key set aged out) waited behind it until a restart, even after the provider recovered.
    Here that lock is a no-op and each download runs as its own task: callers wait for the
    next download to finish without holding anything, a caller that goes away leaves the
    download to the others, and a refresh due under FastMCP's ``jwks_refresh_interval``
    starts a new download beside a stalled one. FastMCP's own code still decides when the
    cached keys are fresh and when a refresh is due, and processes and selects the keys.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if not hasattr(self, "_shared_jwks_refresh_lock"):
            raise RuntimeError(
                "FastMCP's JWTVerifier no longer has _shared_jwks_refresh_lock; "
                "StrictJWTVerifier's JWKS refresh must be revisited for this FastMCP version"
            )
        # FastMCP's checks between the cache test and the download contain no await, so
        # on one event loop they stay atomic without the lock.
        self._shared_jwks_refresh_lock = contextlib.nullcontext()  # type: ignore[assignment]
        self._jwks_round = _JWKSRound()
        self._jwks_downloads: list[asyncio.Task[None]] = []

    async def _get_jwks_key(self, kid: str | None) -> str:
        reset = _jwks_download_requested.set(False)
        try:
            return await super()._get_jwks_key(kid)
        except ValueError:
            # FastMCP refused before downloading (a refresh ran inside the refresh
            # interval). Its lock used to make this caller wait for that refresh; wait
            # for the download in flight instead, then let FastMCP answer from its cache.
            if _jwks_download_requested.get() or not self._jwks_downloads:
                raise
        finally:
            _jwks_download_requested.reset(reset)
        await self._jwks_round.settled.wait()
        return await super()._get_jwks_key(kid)

    async def _fetch_jwks(self) -> dict[str, Any]:
        """The document of the next JWKS download to finish (FastMCP processes it)."""
        settled = _settled_jwks.get()
        if settled is None:
            _jwks_download_requested.set(True)
            self._start_jwks_download()
            settled = self._jwks_round
            await settled.settled.wait()
        if settled.error is not None:
            raise settled.error
        if settled.document is None:  # pragma: no cover - a settled round has one or the other
            raise ValueError("JWKS download settled without a document")
        return settled.document

    def _start_jwks_download(self) -> None:
        if len(self._jwks_downloads) >= JWKS_MAX_PENDING_DOWNLOADS:
            self._jwks_downloads.pop(0).cancel()
        task = asyncio.create_task(self._download_jwks(), name="unifi-fabric-jwks-download")
        self._jwks_downloads.append(task)
        # A task cancelled before it starts never runs its body, so it cannot remove
        # itself. Whoever cancels a download here takes it out of the list at once; this
        # covers a cancellation from outside (shutdown).
        task.add_done_callback(self._forget_jwks_download)

    def _forget_jwks_download(self, task: asyncio.Task[None]) -> None:
        if task in self._jwks_downloads:
            self._jwks_downloads.remove(task)

    async def _download_jwks(self) -> None:
        """One download; its outcome answers every caller waiting on the current round.

        Cancelled (to make room for a newer download, or at shutdown), it settles
        nothing: its callers keep waiting for the next download to finish.
        """
        me = asyncio.current_task()
        outcome = _JWKSRound()
        cancelled = False
        try:
            try:
                outcome.document = await JWTVerifier._fetch_jwks(self)
            except asyncio.CancelledError:
                cancelled = True
                raise
            except Exception as exc:  # handed to the waiting callers; FastMCP maps it
                outcome.error = exc
            else:
                # Take the siblings out of the in-flight list before cancelling them: one
                # not yet started never runs its finally, and left in the list it would
                # make a caller refused inside the refresh interval wait for a download
                # that is not running.
                siblings = [other for other in self._jwks_downloads if other is not me]
                self._jwks_downloads[:] = [task for task in self._jwks_downloads if task is me]
                for other in siblings:
                    other.cancel()
                # Fill FastMCP's cache before waking anyone, so a caller arriving next
                # finds it. A document FastMCP cannot process is reported to each waiting
                # caller by its own processing, so nothing is lost here.
                reset = _settled_jwks.set(outcome)
                try:
                    with contextlib.suppress(Exception):
                        await self._refresh_jwks_key(None)
                finally:
                    _settled_jwks.reset(reset)
        finally:
            if me in self._jwks_downloads:
                self._jwks_downloads.remove(me)
            if not cancelled:
                waiting, self._jwks_round = self._jwks_round, _JWKSRound()
                waiting.document, waiting.error = outcome.document, outcome.error
                waiting.settled.set()

    async def load_access_token(self, token: str) -> AccessToken | None:
        _claim_rejection.set(None)
        # FastMCP converts exp to int before returning AccessToken; NaN/inf can
        # therefore fail there, before our post-verification check. Preflight ONLY
        # numeric syntax/range to reject malformed input, never to grant access.
        # All accepted tokens still pass FastMCP's signature/issuer/audience checks.
        try:
            payload = token.split(".")[1]
            claims = json.loads(
                base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)),
                parse_int=_parse_json_int,
            )
        except UNTRUSTED_TOKEN_ERRORS:
            claims = None
        if isinstance(claims, dict):
            for name in ("exp", "nbf", "iat"):
                value = _numeric_date(claims, name)
                if isinstance(value, str):
                    _claim_rejection.set(value)
                    return None
        try:
            access = await super().load_access_token(token)
        except (RecursionError, IndexError):
            # FastMCP can let decoder errors escape. Keep them visible without
            # token content, exception text or a traceback.
            _logger.warning("Bearer token rejected: a token segment could not be parsed")
            return None
        except ValueError:
            # Other malformed input is an ordinary token rejection.
            _logger.debug("Bearer token rejected: a token segment could not be parsed")
            return None
        if access is None:
            return None
        problem = jwt_time_claim_problem(dict(access.claims or {}), time.time())
        if problem is not None:
            _logger.warning("Bearer token rejected for client %s: %s", access.client_id, problem)
            _claim_rejection.set(problem)
            return None
        return access


class ClaimRejectionMiddleware:
    """Answer a request whose JWT failed :class:`StrictJWTVerifier`'s claim check with a
    401 naming the claim (FastMCP's own 401 says only that the token is invalid)."""

    def __init__(self, app: ASGIApp, provider: RemoteAuthProvider) -> None:
        self.app = app
        self.provider = provider

    def _challenge(self, description: str) -> str:
        from mcp.server.auth.routes import build_resource_metadata_url

        parts = ['error="invalid_token"', f'error_description="{description}"']
        mcp_path = getattr(self.provider, "_mcp_path", None)
        resource = self.provider._get_resource_url(mcp_path) if mcp_path else None
        if resource is not None:
            parts.append(f'resource_metadata="{build_resource_metadata_url(resource)}"')
        return "Bearer " + ", ".join(parts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        problem = _claim_rejection.get()
        _claim_rejection.set(None)
        from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser

        user = scope.get("user")
        path = str(scope.get("path", ""))
        if (
            problem is None
            or isinstance(user, AuthenticatedUser)
            or path.startswith("/.well-known/")
        ):
            await self.app(scope, receive, send)
            return
        description = f"The bearer token was rejected: {problem}."
        body = json.dumps({"error": "invalid_token", "error_description": description}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"www-authenticate", self._challenge(description).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


class StrictRemoteAuthProvider(RemoteAuthProvider):
    """:class:`RemoteAuthProvider` whose middleware adds :class:`ClaimRejectionMiddleware`."""

    def get_middleware(self) -> list:
        return [*super().get_middleware(), ASGIMiddleware(ClaimRejectionMiddleware, provider=self)]


# --- Opt-in write scope -----------------------------------------------------------------


class WriteScopeMiddleware(Middleware):
    """Refuse a write tool when ``MCP_OAUTH_WRITE_SCOPE`` is set and the caller's access
    token lacks it. Read tools (``readOnlyHint``) need only the admission scopes, except
    known state-changing GET relay routes, which require the write scope too. Unset
    (the default), every admitted token can call every tool, as before."""

    def __init__(
        self,
        server: Any,
        write_scope: Callable[[], str],
        audit: Callable[[str, str], None] | None = None,
    ) -> None:
        self._server = server
        self._write_scope = write_scope
        self._audit = audit

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        scope = self._write_scope()
        if scope:
            from fastmcp.server.dependencies import get_access_token

            from .read_only_tools import is_write_tool_call

            name = str(getattr(context.message, "name", ""))
            try:
                tool = await self._server.get_tool(name)
            except NotFoundError:  # unknown tool: the framework reports it
                tool = None
            if tool is not None and is_write_tool_call(
                tool, name, getattr(context.message, "arguments", None)
            ):
                token = get_access_token()
                scopes = list(token.scopes) if token is not None else []
                if scope not in scopes:
                    if self._audit is not None:
                        self._audit(name, WRITE_SCOPE_ENV)
                    raise ToolError(
                        f"{name} refused: write tools need the OAuth scope {scope!r} "
                        f"({WRITE_SCOPE_ENV}), and this access token carries "
                        f"{sorted(scopes) or 'no scopes'}. Ask your identity provider for a "
                        "token with that scope, or use read tools only."
                    )
        return await call_next(context)
