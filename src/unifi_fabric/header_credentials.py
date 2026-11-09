"""Header mode: per-request UniFi API keys.

``UNIFI_KEY_MODE=environment`` (the default) keeps the configured keys exactly as
before. ``UNIFI_KEY_MODE=header`` starts with no stored key: every ``tools/call``
carries its keys in one ``X-UniFi-Api-Key`` header, a JSON object of nonempty label to
nonempty key, and the call uses them only for its own duration.

This module owns, for both modes:

* request context population at ingress (:class:`HeaderCredentialMiddleware`): the
  request id, the credential handles in request order, the pre-dispatch refusals this
  module owns (``invalid_api_key_header``, ``missing_api_key_header``,
  ``key_label_not_allowed``, ``credential_cache_saturated`` and the repeated policy
  header ``invalid_policy_header``), and the reset in ``finally``;
* the credential transport: key material kept by handle identity, never in the
  context, never persisted, bound to the call's secret scrubbing scope;
* the header-mode credential cache: per-identity HTTP clients, identity = (label, full
  SHA256 key digest), at most 256 identities, pinned while serving a call, LRU
  eviction among unpinned identities with close-once, and refusal when all are pinned.

Every message names labels, never keys; logs and records carry only the 8-hex
fingerprint.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import uuid
from collections import OrderedDict
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Iterator,
    Mapping,
    Sequence,
)
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .config import APIKeyConfig, credential_problem
from .contracts import (
    CredentialHandle,
    EffectivePolicy,
    RequestContext,
    credentials_index,
    require_selected_credential,
)
from .secret_scrub import add_log_secrets, request_secret_scope
from .selector_syntax import selector_reason

logger = logging.getLogger(__name__)

KEY_MODE_ENV = "UNIFI_KEY_MODE"
ENVIRONMENT_MODE = "environment"
HEADER_MODE = "header"
KEY_MODES = (ENVIRONMENT_MODE, HEADER_MODE)

API_KEY_HEADER = "x-unifi-api-key"
POLICY_HEADERS = ("x-unifi-write-policy", "x-unifi-family-allow", "x-unifi-exclude")

#: Labels this long are treated as possibly key material in log records.
LOG_SCRUB_LABEL_MIN = 16

#: The credential cache bound: credential identities held at once.
MAX_CREDENTIAL_IDENTITIES = 256

# The pre-dispatch codes this module returns (closed list).
INVALID_API_KEY_HEADER = "invalid_api_key_header"
INVALID_POLICY_HEADER = "invalid_policy_header"
MISSING_API_KEY_HEADER = "missing_api_key_header"
KEY_LABEL_NOT_ALLOWED = "key_label_not_allowed"
CREDENTIAL_CACHE_SATURATED = "credential_cache_saturated"

#: Discovery dispatchers whose ``arguments`` object is itself a tool call.
NESTED_DISPATCH_TOOLS = frozenset({"call_read_tool", "call_write_tool"})


# --------------------------------------------------------------------------- errors


class NoCredentials(Exception):
    """Environment mode with no configured key: no context is built."""


class StartupRefusal(Exception):
    """A startup refusal: exits non-zero printing exactly one token."""

    def __init__(self, token: str) -> None:
        super().__init__(token)
        self.token = token


class PreDispatchRefusal(Exception):
    """A refused tools/call: zero upstream calls, one closed-list code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def payload(self) -> str:
        """The one text item of the refused call's MCP error result."""
        return json.dumps(
            {"error": {"code": self.code, "message": self.message}},
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def tool_error(self) -> ToolError:
        return ToolError(self.payload())


# --------------------------------------------------------------------------- mode


def key_mode(environ: Mapping[str, str] | None = None) -> str:
    """The configured ``UNIFI_KEY_MODE`` (default environment).

    A blank or unknown value is a startup refusal ``startup:UNIFI_KEY_MODE``.
    """
    env = os.environ if environ is None else environ
    if KEY_MODE_ENV not in env:
        return ENVIRONMENT_MODE
    value = env[KEY_MODE_ENV]
    if value not in KEY_MODES:
        raise StartupRefusal(f"startup:{KEY_MODE_ENV}")
    return value


def is_header_mode(environ: Mapping[str, str] | None = None) -> bool:
    try:
        return key_mode(environ) == HEADER_MODE
    except StartupRefusal:
        return False


def check_startup(transport: str, environ: Mapping[str, str] | None = None) -> str:
    """Validate the key mode for ``transport``; return the mode.

    Header mode needs an HTTP transport: stdio carries no headers, so
    ``UNIFI_KEY_MODE=header`` with stdio fails with ``startup:UNIFI_KEY_MODE``.
    """
    mode = key_mode(environ)
    if mode == HEADER_MODE and transport == "stdio":
        raise StartupRefusal(f"startup:{KEY_MODE_ENV}")
    return mode


# --------------------------------------------------------------------------- keys


def full_key_digest(key: str) -> str:
    """Full lowercase SHA256 hex of a key: cache/authorization identity, never logged."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def key_fingerprint(key: str) -> str:
    """The 8-hex fingerprint records may carry."""
    return full_key_digest(key)[:8]


class _DuplicateLabel(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> OrderedDict[str, Any]:
    out: OrderedDict[str, Any] = OrderedDict()
    for name, value in pairs:
        if name in out:
            raise _DuplicateLabel(name)
        out[name] = value
    return out


def parse_api_key_header(values: Sequence[str]) -> tuple[tuple[str, str], ...]:
    """Parse the raw ``X-UniFi-Api-Key`` header values -> ``((label, key), ...)``.

    ``values`` holds every occurrence on the wire. Exactly one is accepted; its value
    must be a JSON object of nonempty string labels to nonempty string keys, without
    duplicate labels (checked on the raw pairs before a dict can drop one). Member
    order is request order. Every failure is ``invalid_api_key_header`` and its
    message never quotes the value.
    """
    if len(values) != 1:
        raise PreDispatchRefusal(
            INVALID_API_KEY_HEADER,
            "X-UniFi-Api-Key was sent more than once; send it once, as one JSON object "
            "of label to key.",
        )
    raw = values[0]
    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except _DuplicateLabel:
        raise PreDispatchRefusal(
            INVALID_API_KEY_HEADER,
            "X-UniFi-Api-Key repeats a label; give each key one unique label.",
        ) from None
    except (ValueError, RecursionError):
        raise PreDispatchRefusal(
            INVALID_API_KEY_HEADER,
            "X-UniFi-Api-Key is not valid JSON; send one JSON object of label to key, "
            'for example {"<label>":"<key>"}. The value is not shown here.',
        ) from None
    if not isinstance(parsed, dict):
        raise PreDispatchRefusal(
            INVALID_API_KEY_HEADER,
            "X-UniFi-Api-Key must be a JSON object of label to key.",
        )
    if not parsed:
        raise PreDispatchRefusal(
            INVALID_API_KEY_HEADER,
            "X-UniFi-Api-Key is an empty object; send at least one label and key.",
        )
    out: list[tuple[str, str]] = []
    for index, (label, key) in enumerate(parsed.items()):
        # Messages name the member position only: a swapped pair would put a key in
        # the label slot, so a label is never echoed here.
        if not label.strip() or selector_reason(label) is not None:
            raise PreDispatchRefusal(
                INVALID_API_KEY_HEADER,
                f"X-UniFi-Api-Key member {index} has an empty or invalid label; every key "
                "needs a nonempty label with no surrounding whitespace or control character.",
            )
        if not isinstance(key, str) or not key.strip():
            raise PreDispatchRefusal(
                INVALID_API_KEY_HEADER,
                f"X-UniFi-Api-Key member {index} has an empty or non-string key; the value "
                "is not shown here.",
            )
        if not key.isascii() or credential_problem(key, "header") is not None:
            raise PreDispatchRefusal(
                INVALID_API_KEY_HEADER,
                f"X-UniFi-Api-Key member {index} has a key an HTTP header cannot carry "
                "(non-ASCII, control character or surrounding whitespace); the value is "
                "not shown here.",
            )
        out.append((label, key))
    return tuple(out)


# --------------------------------------------------------------------------- transport


@dataclass
class CredentialTransport:
    """Key material for one request, keyed by handle identity. Never persisted."""

    _keys: dict[CredentialHandle, APIKeyConfig] = field(default_factory=dict)

    @classmethod
    def from_pairs(
        cls, pairs: Iterable[tuple[str, str]]
    ) -> tuple[CredentialTransport, tuple[CredentialHandle, ...]]:
        transport = cls()
        handles: list[CredentialHandle] = []
        for label, key in pairs:
            handle = CredentialHandle(label=label, key_fingerprint=key_fingerprint(key))
            transport._keys[handle] = APIKeyConfig(key=key, label=label)
            handles.append(handle)
        return transport, tuple(handles)

    @classmethod
    def from_configs(
        cls, configs: Iterable[APIKeyConfig]
    ) -> tuple[CredentialTransport, tuple[CredentialHandle, ...]]:
        transport = cls()
        handles: list[CredentialHandle] = []
        for cfg in configs:
            handle = CredentialHandle(label=cfg.label, key_fingerprint=key_fingerprint(cfg.key))
            transport._keys[handle] = cfg
            handles.append(handle)
        return transport, tuple(handles)

    def key_config(self, handle: CredentialHandle) -> APIKeyConfig:
        """The key config of ``handle`` (identity lookup)."""
        try:
            return self._keys[handle]
        except KeyError:
            raise ValueError(
                f"credential {handle.label!r} does not belong to this request"
            ) from None

    def key_configs(self, handles: Iterable[CredentialHandle]) -> list[APIKeyConfig]:
        return [self.key_config(h) for h in handles]

    def secret_values(self) -> tuple[str, ...]:
        return tuple(cfg.key for cfg in self._keys.values())

    def identities(self) -> list[tuple[str, str]]:
        return [(cfg.label, full_key_digest(cfg.key)) for cfg in self._keys.values()]

    def clear(self) -> None:
        self._keys.clear()


# --------------------------------------------------------------------------- active request


@dataclass
class ActiveRequest:
    """What one in-flight request carries below ingress."""

    context: RequestContext
    transport: CredentialTransport
    header_mode: bool
    leased: bool = False

    def key_configs(self) -> list[APIKeyConfig]:
        """The request's keys in request order (stand in for the configured list)."""
        return self.transport.key_configs(self.context.credentials)

    def handle_for_config(self, cfg: APIKeyConfig | None) -> CredentialHandle:
        """The credential a resolve_key_for_host result maps to.

        A returned config maps to the member with the same label; ``None`` (only
        returned for a single-label request) maps to the sole member.
        """
        if cfg is None:
            if len(self.context.credentials) != 1:
                raise ValueError("a host-less selection needs exactly one credential")
            return self.context.credentials[0]
        return self.context.credentials_by_label[cfg.label]


_active: ContextVar[ActiveRequest | None] = ContextVar("unifi_header_active_request", default=None)
_request_id: ContextVar[str | None] = ContextVar("unifi_request_id", default=None)
_header_mode_process: bool | None = None


def set_process_key_mode(mode: str | None) -> None:
    """Pin the process key mode (startup); ``None`` re-reads the environment."""
    global _header_mode_process
    _header_mode_process = None if mode is None else mode == HEADER_MODE


def header_mode_enabled() -> bool:
    """True when this process runs in header mode."""
    if _header_mode_process is not None:
        return _header_mode_process
    return is_header_mode()


def active_request() -> ActiveRequest | None:
    return _active.get()


def current_request_context() -> RequestContext | None:
    active = _active.get()
    return active.context if active is not None else None


def current_request_id() -> str | None:
    return _request_id.get()


def request_key_configs() -> list[APIKeyConfig] | None:
    """The keys a client call may use, or ``None`` to use the configured keys.

    In header mode this is the active request's keys, and an empty list outside a
    request: there is no default key, so no header means no upstream call.
    """
    active = _active.get()
    if active is not None and active.header_mode:
        return active.key_configs()
    if header_mode_enabled():
        return []
    return None


def cache_label(label: str, key: APIKeyConfig | None) -> str:
    """The cache/lock key of a per-key registry entry.

    Environment mode keeps the label (unchanged). In header mode two requests may send
    the same label with different keys, so the identity is label plus the full key
    digest; a truncated fingerprint never keys a cache.
    """
    if key is not None and header_mode_enabled():
        return f"{label}\x00{full_key_digest(key.key)}"
    return label


def new_request_id() -> str:
    return uuid.uuid4().hex


# --------------------------------------------------------------------------- policy


PolicyProvider = Callable[[], EffectivePolicy]
_policy_provider: PolicyProvider | None = None


def set_policy_provider(provider: PolicyProvider | None) -> None:
    """The policy evaluator registers here; until then the operator baseline policy applies."""
    global _policy_provider
    _policy_provider = provider


def baseline_policy(settings: Any = None) -> EffectivePolicy:
    """The pre-registration baseline: writes allowed, every family, no exclusions.

    ``settings`` is accepted for call compatibility and not read; the evaluator, registered
    at startup through :func:`set_policy_provider`, applies ``UNIFI_WRITE_POLICY`` and the
    other policy settings.
    """
    from .families import ALL_FAMILIES

    write_policy = "allow"
    return EffectivePolicy(
        write_policy=write_policy,  # type: ignore[arg-type]
        write_exceptions=(),
        exposed_families=frozenset(ALL_FAMILIES),
        exclusions=frozenset(),
    )


def effective_policy() -> EffectivePolicy:
    return (_policy_provider or baseline_policy)()


#: The request-policy hook: ``hook(headers) -> (EffectivePolicy, ignored_loosening)``,
#: raising :class:`PreDispatchRefusal` (``invalid_policy_header``) for a bad policy header.
RequestPolicyHook = Callable[
    [Callable[[str], "list[str] | None"]], tuple[EffectivePolicy, tuple[str, ...]]
]
_request_policy_hook: RequestPolicyHook | None = None


def set_request_policy_hook(hook: RequestPolicyHook | None) -> None:
    """The request policy registers here; without it the operator policy applies unchanged."""
    global _request_policy_hook
    _request_policy_hook = hook


# --------------------------------------------------------------------------- cache


class CredentialCacheSaturated(PreDispatchRefusal):
    def __init__(self) -> None:
        super().__init__(
            CREDENTIAL_CACHE_SATURATED,
            f"All {MAX_CREDENTIAL_IDENTITIES} credential slots are serving active calls; "
            "retry in a few seconds.",
        )


Identity = tuple[str, str]  # (label, full SHA256 key digest)
ClientFactory = Callable[[APIKeyConfig], Any]


@dataclass
class _Entry:
    clients: dict[str, Any] = field(default_factory=dict)
    pins: int = 0
    closed: bool = False


async def _await(awaitable: Awaitable[Any]) -> None:
    try:
        await awaitable
    except Exception:  # noqa: BLE001 - closing is best effort
        logger.debug("credential client close failed", exc_info=True)


async def _close_all(clients: list[Any]) -> None:
    for client in clients:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001 - closing is best effort, never raises
            logger.debug("credential client close failed", exc_info=True)


class CredentialCache:
    """Per-identity clients for header mode, bounded at ``maxsize`` identities.

    An identity is (label, full SHA256 key digest). All the per-API-source clients of
    one identity count as one entry. :meth:`lease` pins the request's identities for
    the whole call (including cancellation) and releases them in ``finally``; LRU
    eviction picks unpinned identities only and closes each of their clients exactly
    once. When every slot is pinned, a new identity is refused before anything is
    allocated, and existing identities continue.
    """

    def __init__(self, maxsize: int = MAX_CREDENTIAL_IDENTITIES) -> None:
        self.maxsize = maxsize
        self._entries: OrderedDict[Identity, _Entry] = OrderedDict()
        self._lock = asyncio.Lock()
        self._closing: list[Awaitable[Any]] = []
        self._close_tasks: set[asyncio.Task[None]] = set()

    def __len__(self) -> int:
        return len(self._entries)

    def identities(self) -> list[Identity]:
        return list(self._entries)

    def pinned(self, identity: Identity) -> int:
        entry = self._entries.get(identity)
        return entry.pins if entry is not None else 0

    async def _close_entry(self, entry: _Entry) -> None:
        """Close each client of ``entry`` exactly once, even when the caller is cancelled.

        The closes run in their own task, shielded from the caller's cancellation, so a
        cancelled call never leaves an evicted client (which still carries its key) open,
        including the one being closed at the moment of cancellation.
        """
        if entry.closed:
            return
        entry.closed = True
        clients = list(entry.clients.values())
        entry.clients.clear()
        task = asyncio.ensure_future(_close_all(clients))
        self._close_tasks.add(task)
        task.add_done_callback(self._close_tasks.discard)
        await asyncio.shield(task)

    async def acquire(self, identities: Sequence[Identity]) -> list[Identity]:
        """Pin ``identities`` (deduplicated); refuse with saturation before allocating."""
        wanted = list(dict.fromkeys(identities))
        async with self._lock:
            new = [i for i in wanted if i not in self._entries]
            evictable = [i for i, e in self._entries.items() if e.pins == 0 and i not in wanted]
            overflow = len(self._entries) + len(new) - self.maxsize
            if overflow > len(evictable):
                raise CredentialCacheSaturated()
            victims = evictable[: max(overflow, 0)]
            evicted = [self._entries.pop(i) for i in victims]
            for identity in wanted:
                entry = self._entries.get(identity)
                if entry is None:
                    entry = self._entries[identity] = _Entry()
                entry.pins += 1
                self._entries.move_to_end(identity)
        try:
            for entry in evicted:
                await self._close_entry(entry)
        except BaseException:
            # Cancelled (or failed) while closing evicted clients: the caller never gets
            # the identities back to release, so release the pins taken above here.
            self.release(wanted)
            for entry in evicted:
                self._schedule_close(entry)
            raise
        return wanted

    def _schedule_close(self, entry: _Entry) -> None:
        """Close ``entry``'s clients once without awaiting (sync eviction paths)."""
        if entry.closed:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No loop: keep the closes for aclose() (shutdown).
            entry.closed = True
            self._closing.extend(c.aclose() for c in entry.clients.values())
            entry.clients.clear()
            return
        task = loop.create_task(self._close_entry(entry))
        self._close_tasks.add(task)
        task.add_done_callback(self._close_tasks.discard)

    def release(self, identities: Sequence[Identity]) -> None:
        for identity in identities:
            entry = self._entries.get(identity)
            if entry is not None and entry.pins > 0:
                entry.pins -= 1

    @asynccontextmanager
    async def lease(self, identities: Sequence[Identity]) -> AsyncIterator[None]:
        held = await self.acquire(identities)
        try:
            yield
        finally:
            self.release(held)

    def client(self, key: APIKeyConfig, source: str, factory: ClientFactory) -> Any:
        """The client of ``key``'s identity for ``source``, created on first use."""
        identity = (key.label, full_key_digest(key.key))
        entry = self._entries.get(identity)
        if entry is None:
            # A direct library call outside a leased request: hold it like any other
            # unpinned identity (evictable), refusing only when every slot is pinned.
            if len(self._entries) >= self.maxsize:
                victim = next((i for i, e in self._entries.items() if e.pins == 0), None)
                if victim is None:
                    raise CredentialCacheSaturated()
                self._schedule_close(self._entries.pop(victim))
            entry = self._entries[identity] = _Entry()
        self._entries.move_to_end(identity)
        existing = entry.clients.get(source)
        if existing is None:
            existing = entry.clients[source] = factory(key)
        return existing

    async def aclose(self) -> None:
        """Close every client of every identity once (shutdown)."""
        if self._close_tasks:
            await asyncio.gather(*list(self._close_tasks), return_exceptions=True)
        pending, self._closing = self._closing, []
        for awaitable in pending:
            try:
                await awaitable
            except Exception:  # noqa: BLE001
                logger.debug("credential client close failed", exc_info=True)
        entries = list(self._entries.values())
        self._entries.clear()
        for entry in entries:
            await self._close_entry(entry)


# --------------------------------------------------------------------------- ingress


def _raw_header_values(name: str) -> list[str] | None:
    """Every wire value of ``name`` on the current HTTP request (``None`` off HTTP)."""
    try:
        from fastmcp.server.dependencies import get_http_request

        request = get_http_request()
    except Exception:  # noqa: BLE001 - no HTTP request (stdio, direct call)
        return None
    return list(request.headers.getlist(name))


HeaderSource = Callable[[str], list[str] | None]


def _key_label_present(name: str, arguments: Mapping[str, Any]) -> bool:
    if "key_label" in arguments:
        return True
    if name in NESTED_DISPATCH_TOOLS:
        nested = arguments.get("arguments")
        if isinstance(nested, Mapping) and "key_label" in nested:
            return True
    return False


def evaluate_call(
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
    header_mode: bool,
    headers: HeaderSource,
    environment_configs: Callable[[], list[APIKeyConfig]],
) -> tuple[RequestContext, CredentialTransport]:
    """Ingress for one tools/call: the ingress refusals in the closed order, then the context.

    Order: (1) invalid_api_key_header, (2) invalid_policy_header (a repeated policy
    header here; malformed values in the request-policy hook), (3)
    missing_api_key_header, (4) key_label_not_allowed. (9) credential_cache_saturated
    is checked at lease time, after every other check. Nothing here makes an upstream
    call.
    """
    key_values = headers(API_KEY_HEADER) or []
    # (1)
    pairs: tuple[tuple[str, str], ...] | None = None
    if header_mode:
        if key_values:
            pairs = parse_api_key_header(key_values)
    elif key_values:
        raise PreDispatchRefusal(
            INVALID_API_KEY_HEADER,
            "This server uses its configured keys (UNIFI_KEY_MODE=environment) and does not "
            "accept X-UniFi-Api-Key on tool calls; remove the header.",
        )
    # (2)
    for policy_header in POLICY_HEADERS:
        if len(headers(policy_header) or []) > 1:
            raise PreDispatchRefusal(
                INVALID_POLICY_HEADER,
                f"{policy_header} was sent more than once; send each policy header once.",
            )
    # (2), continued: the request-policy hook parses the policy headers (a blank,
    # malformed or invalid value refuses here, before (3) and (4)) and returns the
    # tightened policy for the context.
    tightened = _request_policy_hook(headers) if _request_policy_hook is not None else None
    # (3)
    if header_mode and pairs is None:
        raise PreDispatchRefusal(
            MISSING_API_KEY_HEADER,
            "This server runs in header mode: send your UniFi API key(s) in the "
            'X-UniFi-Api-Key header as a JSON object of label to key, {"<label>":"<key>"}.',
        )
    # (4)
    if header_mode and _key_label_present(tool_name, arguments):
        raise PreDispatchRefusal(
            KEY_LABEL_NOT_ALLOWED,
            "key_label is not accepted in header mode; send only the key(s) this call should "
            "use in X-UniFi-Api-Key and omit key_label.",
        )
    if pairs is not None:
        transport, handles = CredentialTransport.from_pairs(pairs)
    else:
        try:
            configs = environment_configs()
        except ValueError:
            # Malformed key settings: the tool itself reports the configuration error.
            raise NoCredentials() from None
        transport, handles = CredentialTransport.from_configs(configs)
        if not handles:
            # No configured key: the tool itself reports the configuration error.
            raise NoCredentials()
    context = RequestContext(
        present_arguments=frozenset(arguments),
        credentials=handles,
        credentials_by_label=credentials_index(handles),
        selected_credential=None,
        effective_policy=tightened[0] if tightened is not None else effective_policy(),
        request_id=new_request_id(),
        ignored_loosening=tightened[1] if tightened is not None else (),
    )
    return context, transport


@contextmanager
def bind_request(
    context: RequestContext, transport: CredentialTransport, *, header_mode: bool
) -> Iterator[ActiveRequest]:
    """Bind ``context`` for this task and its children; reset and wipe in finally."""
    active = ActiveRequest(context=context, transport=transport, header_mode=header_mode)
    token = _active.set(active)
    rid_token = _request_id.set(context.request_id)
    try:
        if header_mode:
            with request_secret_scope(transport.secret_values()):
                # A key sent in the label slot by mistake: key-length labels are also
                # scrubbed from log records (results to the caller keep their labels).
                add_log_secrets(
                    h.label for h in context.credentials if len(h.label) >= LOG_SCRUB_LABEL_MIN
                )
                yield active
        else:
            yield active
    finally:
        _request_id.reset(rid_token)
        _active.reset(token)
        if header_mode:
            transport.clear()


class HeaderCredentialMiddleware(Middleware):
    """Populate the RequestContext at ingress and apply the ingress refusals.

    initialize and ping never read the credential or policy headers; tools/list reads
    no credential header in either mode (a gateway may forward it on every request) and only
    gets a request id here.
    """

    def __init__(
        self,
        *,
        environment_configs: Callable[[], list[APIKeyConfig]],
        headers: HeaderSource | None = None,
        header_mode: Callable[[], bool] | None = None,
        on_refusal: Callable[[MiddlewareContext[Any], str], Awaitable[None]] | None = None,
    ) -> None:
        self._on_refusal = on_refusal
        self._environment_configs = environment_configs
        self._headers = headers
        self._header_mode = header_mode

    def _header_source(self) -> HeaderSource:
        return self._headers or (lambda name: _raw_header_values(name))

    async def on_list_tools(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        token = _request_id.set(new_request_id())
        try:
            return await call_next(context)
        finally:
            _request_id.reset(token)

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        if _active.get() is not None:
            # A nested dispatch inside a request keeps the request's credentials.
            return await call_next(context)
        message = context.message
        name = getattr(message, "name", "") or ""
        arguments = getattr(message, "arguments", None) or {}
        header_mode = (self._header_mode or header_mode_enabled)()
        try:
            request_context, transport = evaluate_call(
                tool_name=name,
                arguments=arguments,
                header_mode=header_mode,
                headers=self._header_source(),
                environment_configs=self._environment_configs,
            )
        except PreDispatchRefusal as refusal:
            if self._on_refusal is not None:
                # Ingress runs outside the refused-write audit: it records its own refusal
                # (the closed code only) before the error leaves.
                try:
                    await self._on_refusal(context, refusal.code)
                except Exception:  # noqa: BLE001 - the audit never changes the caller's refusal
                    logger.warning("header-ingress refusal audit failed; refusal unchanged")
            raise refusal.tool_error() from None
        except NoCredentials:
            return await call_next(context)
        with bind_request(request_context, transport, header_mode=header_mode):
            return await call_next(context)


class CredentialLeaseMiddleware(Middleware):
    """Pin the request's credential identities for the call (refusal 9).

    Added innermost, after the policy, request-policy and Code Mode refusals, so
    ``credential_cache_saturated`` is the last pre-dispatch check and no slot is taken
    for a call an earlier check refuses.
    The pins are released in ``finally`` on success, error and cancellation.
    """

    def __init__(self, cache: Callable[[], CredentialCache | None]) -> None:
        self._cache = cache

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        active = _active.get()
        cache = self._cache()
        if active is None or not active.header_mode or cache is None or active.leased:
            return await call_next(context)
        try:
            held = await cache.acquire(active.transport.identities())
        except PreDispatchRefusal as refusal:
            raise refusal.tool_error() from None
        active.leased = True
        try:
            return await call_next(context)
        finally:
            active.leased = False
            cache.release(held)


# --------------------------------------------------------------------------- selection


def hostless_selection(tool_name: str, fanout_tools: frozenset[str]) -> list[CredentialHandle]:
    """The credentials a host-less call with key_label omitted uses, in request order.

    A tool whose baseline covers every key (the fan-out set) gets one child per
    credential; any other host-less tool uses ``credentials[0]``.
    """
    context = current_request_context()
    if context is None:
        raise RuntimeError("no active request context")
    if tool_name in fanout_tools:
        return list(context.credentials)
    return [context.credentials[0]]


def children_for(
    raw_arguments: Mapping[str, Any], handles: Sequence[CredentialHandle]
) -> list[RequestContext]:
    """One child context per handle (fan-out), built only through child()."""
    context = current_request_context()
    if context is None:
        raise RuntimeError("no active request context")
    return [context.child(raw_arguments, selected_credential=h) for h in handles]


def require_selected(context: RequestContext) -> CredentialHandle:
    """The handle an upstream call uses; ``None`` is a programming error (no call)."""
    return require_selected_credential(context)
