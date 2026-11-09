"""Audit every refused write tool call exactly once, whichever layer refused it.

A write tool call can be refused before its write is sent at many layers: the read-only
and area opt-out gates, the empty-update guard, the selector / argument-value / spec-limit
checks, the framework's own argument parsing, a guard inside the tool (the update-field
check, a list-first resolution that finds no such id, an unknown host or site), the HTTP
chokepoint, or the connector relay's validation. Some of those layers audit their refusal
themselves, naming their gate as the ``reason``; the rest raise an error.

:class:`RefusedWriteAuditMiddleware` wraps every tool call. It counts the
``outcome=refused`` records written during the call (:func:`refusal_scope`; the count
travels in a context variable, so it follows the call into the tool body and the HTTP
client). When a write tool call ends in an error that no upstream failure caused, and no
layer audited a refusal, it writes one ``outcome=refused`` record whose ``reason`` is the
error message the caller receives, with the call's own credential argument values
(a ``password``, ``x_passphrase`` ... at any depth) scrubbed out: the audit log never
records a credential, even one a refusal message quotes. A call that completes, or
that fails because the
upstream failed (an HTTP error status, a transport error, a 429, a response of the wrong
shape), writes nothing here: the chokepoint already audited any write it sent. With the
audit log off (the default) the call passes straight through.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

import httpx
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .read_only_tools import AreaOptOutMiddleware, ReadOnlyToolMiddleware, is_write_tool_call
from .secret_scrub import scrub

#: Refused records written during the current tool call (``None`` outside one).
_REFUSED_IN_CALL: ContextVar[list[int] | None] = ContextVar("_REFUSED_IN_CALL", default=None)

#: ``audit(tool, reason)``: records a refused write tool call (``outcome=refused``).
RefusalAudit = Callable[[str, str], None]


def note_refused_record() -> None:
    """Count one ``outcome=refused`` record against the current tool call (if any)."""
    counter = _REFUSED_IN_CALL.get()
    if counter is not None:
        counter[0] += 1


@contextmanager
def refusal_scope() -> Iterator[list[int]]:
    """A fresh refused-record count for one tool call; yields the mutable counter."""
    counter = [0]
    token = _REFUSED_IN_CALL.set(counter)
    try:
        yield counter
    finally:
        _REFUSED_IN_CALL.reset(token)


def upstream_caused(exc: BaseException) -> bool:
    """True when the error (or any error in its cause / context chain) is an upstream
    failure: an HTTP error status, a transport error, a 429, a page drain that stopped,
    or a response of an unexpected shape."""
    from .client import PaginationAbortedError, RateLimitError, UniFiConnectionError

    seen: set[int] = set()
    node: BaseException | None = exc
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        if isinstance(
            node, UniFiConnectionError | RateLimitError | PaginationAbortedError | httpx.HTTPError
        ):
            return True
        node = node.__cause__ or node.__context__
    return False


def credential_values(arguments: Any) -> list[str]:
    """Every non-empty string a documented credential field holds in ``arguments``,
    at any depth (a top-level argument or a key inside a body object or list)."""
    from .redaction import is_credential_field

    out: list[str] = []
    stack: list[Any] = [arguments]
    seen: set[int] = set()  # a self-referential argument must end the walk, not feed it
    while stack:
        node = stack.pop()
        if isinstance(node, dict | list | tuple):
            if id(node) in seen:
                continue
            seen.add(id(node))
        if isinstance(node, dict):
            for key, value in node.items():
                secret_field = is_credential_field(key) or (
                    isinstance(key, str) and key.casefold() == "key"
                )
                if secret_field and isinstance(value, str) and value:
                    out.append(value)
                else:
                    stack.append(value)
        elif isinstance(node, list | tuple):
            stack.extend(node)
    return out


def refusal_code(exc: BaseException) -> str | None:
    """The closed pre-dispatch refusal code a ``ToolError`` carries, else None."""
    try:
        body = json.loads(str(exc))
    except ValueError:
        return None
    error = body.get("error") if isinstance(body, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    return code if isinstance(code, str) else None


def denial_reason(name: str, arguments: Any) -> str:
    """The setting that denies write tool ``name`` for the current request.

    The strictest of the effective policy: ``UNIFI_WRITE_POLICY`` when the global policy
    is deny, else the ``tool:<name>=deny`` or ``family:<id>=deny`` exception.
    """
    from . import families, header_credentials, policy
    from .request_policy import call_target
    from .switches import READ_ONLY_ENV

    context = header_credentials.current_request_context()
    effective = context.effective_policy if context is not None else policy.current()
    target, _inner = call_target(name, arguments if isinstance(arguments, dict) else {})
    if effective.write_policy == "deny":
        return (
            READ_ONLY_ENV if policy.current().write_policy == "deny" else policy.WRITE_POLICY_HEADER
        )
    if (f"tool:{target}", "deny") in effective.write_exceptions:
        return f"tool:{target}=deny"
    family = families.build_family_index().get(target)
    return f"family:{family}=deny" if family else "write_denied"


class RefusedWriteAuditMiddleware(Middleware):
    """Write one ``outcome=refused`` record for a refused write tool call no layer audited.

    ``enabled()`` says whether the audit log is on; ``audit(tool, reason)`` writes the
    record. Install it outside every middleware that can refuse a call.
    """

    def __init__(self, server: Any, enabled: Callable[[], bool], audit: RefusalAudit) -> None:
        self._server = server
        self._enabled = enabled
        self._audit = audit

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        if not self._enabled():
            return await call_next(context)
        with refusal_scope() as counter:
            try:
                return await call_next(context)
            except Exception as exc:
                if counter[0] == 0 and not upstream_caused(exc):
                    await self._record(context, exc)
                raise

    async def audit_ingress_refusal(self, context: MiddlewareContext[Any], code: str) -> None:
        """Audit a write tool call refused at header-credential ingress, exactly once.

        The ingress middleware runs outside this one, so its refusal never reaches
        ``on_call_tool``; it calls here instead with the closed refusal code. The reason is
        that code alone: never the header value, never a key.
        """
        if not self._enabled():
            return
        await self._record(context, None, code=code)

    def _hidden_write(self, name: str) -> bool:
        """True when ``name`` is a write tool hidden at startup (the gates keep its name)."""
        for middleware in getattr(self._server, "middleware", ()):
            if isinstance(middleware, ReadOnlyToolMiddleware) and name in getattr(
                middleware, "_hidden_write_names", ()
            ):
                return True
            if isinstance(middleware, AreaOptOutMiddleware) and name in getattr(
                middleware, "_hidden_writes", ()
            ):
                return True
        return False

    async def _record(
        self, context: MiddlewareContext[Any], exc: BaseException | None, *, code: str | None = None
    ) -> None:
        name = str(getattr(context.message, "name", ""))
        try:
            tool = await self._server.get_tool(name)
        except Exception:  # unknown tool: the framework reports it
            tool = None
        arguments = getattr(context.message, "arguments", None)
        if tool is None:
            # A write hidden from the provider at startup (read-only mode, an area opt-out)
            # is no longer found, but an ingress refusal comes before the gate that audits
            # it: classify it from the names those gates kept.
            if code is None or not self._hidden_write(name):
                return
        elif not is_write_tool_call(tool, name, arguments):
            return
        if code is None and exc is not None:
            code = refusal_code(exc)
            if code is None:
                reason = str(exc) or type(exc).__name__
            elif code == "write_denied":
                reason = denial_reason(name, arguments)
            else:
                reason = code
        else:
            reason = code or ""
        secrets = credential_values(arguments)
        self._audit(name, scrub(reason, secrets) if secrets else reason)
