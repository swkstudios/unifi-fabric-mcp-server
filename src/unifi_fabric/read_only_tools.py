"""Hide and refuse write tools under the write policy.

Startup selection removes annotated writes from the local provider: every write under
``UNIFI_WRITE_POLICY=deny``, and the writes of an area whose family
``UNIFI_WRITE_EXCEPTIONS`` denies (``switches.AREA_WRITE_SWITCHES``, plus the connector
relay's ``family:connector=deny``). Hidden names remain classified in the middleware so
direct calls receive the same audited refusal.

The HTTP chokepoint (:func:`unifi_fabric.read_only.guard_request`) refuses every
mutating upstream request, but a write tool that reads before it writes would still make
those reads before the write was refused. A denied write tool must not touch the console
at all.

:class:`ReadOnlyToolMiddleware` refuses the call before the tool body runs, with the
pre-dispatch refusal ``write_denied``, when the effective write mode of the tool
(:func:`unifi_fabric.policy.write_mode`: the global policy, its family exception and its
``tool:<name>`` exception) is deny and the call is a write. It writes the
``policy.refusal`` record. The chokepoint stays as the second layer for any request this
check does not see.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from typing import Any

from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .families import _list_tools, _remove_tool
from .read_only import is_write_request, read_only_message
from .switches import READ_ONLY_ENV, family_denied

#: The pre-dispatch refusal code for a denied write (closed refusal list).
WRITE_DENIED = "write_denied"
#: The pre-dispatch refusal code for a tool the policy does not expose.
TOOL_NOT_EXPOSED = "tool_not_exposed"
#: The discovery dispatchers whose ``name`` argument is the call's real target.
_DISPATCHERS = frozenset({"call_read_tool", "call_write_tool"})

#: ``audit(tool, reason)``: records a refused write tool call (``outcome=refused``).
RefusalAudit = Callable[[str, str], None]


def canonical_tool_id(name: str) -> str | None:
    """``<family>.<name>`` for a registered tool name, ``meta.<name>`` for a meta tool."""
    from . import families, policy

    if name in policy.META_TOOL_NAMES:
        return f"{policy.META_FAMILY}.{name}"
    family = families.build_family_index().get(name)
    return f"{family}.{name}" if family else None


def refusal(name: str, code: str, message: str) -> ToolError:
    """The pre-dispatch refusal (MCP isError, one text item holding
    ``{"error": {"code", "message"}}``), after writing its ``policy.refusal`` record."""
    from . import policy
    from .header_credentials import current_request_id

    policy.emit(
        policy.refusal_record(
            request_id=current_request_id() or uuid.uuid4().hex,
            tool_id=canonical_tool_id(name),
            code=code,
            # Counted at the client chokepoint for this call: 0 for a pre-dispatch refusal.
            upstream_calls=policy.upstream_calls(),
        )
    )
    return ToolError(json.dumps({"error": {"code": code, "message": message}}))


def is_coded_refusal(exc: BaseException) -> bool:
    """True for a ToolError that already carries the pre-dispatch refusal envelope."""
    return isinstance(exc, ToolError) and str(exc).startswith('{"error": {"code": ')


def denied_cause(exc: BaseException) -> BaseException | None:
    """The write-policy refusal (chokepoint or in-tool) behind ``exc``, else None."""
    from .read_only import is_write_denied

    seen: set[int] = set()
    node: BaseException | None = exc
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        if is_write_denied(node):
            return node
        node = node.__cause__ or node.__context__
    return None


def dispatch_target(name: str, arguments: Any) -> tuple[str, Any]:
    """``(target name, target arguments)``: the dispatcher's ``name`` for
    call_read_tool/call_write_tool, else the call itself."""
    if name in _DISPATCHERS and isinstance(arguments, dict):
        target = arguments.get("name")
        if isinstance(target, str) and target:
            inner = arguments.get("arguments")
            return target, inner if isinstance(inner, dict) else {}
    return name, arguments


def _is_read_tool(tool: Any) -> bool:
    # MCP SDK v1 names the hint readOnlyHint, v2 read_only_hint; accept either.
    ann = getattr(tool, "annotations", None)
    if ann is None:
        return False
    hint = getattr(ann, "read_only_hint", None)
    if hint is None:
        hint = getattr(ann, "readOnlyHint", None)
    return bool(hint)


def is_write_tool_call(tool: Any, name: str, arguments: Any) -> bool:
    """Classify a call using annotations and the GET relay's actual upstream route."""
    if name == "fabric_connector_get" and isinstance(arguments, dict):
        path = arguments.get("path")
        return isinstance(path, str) and is_write_request("GET", path)
    return not _is_read_tool(tool)


async def apply_read_only_tool_filter(server: Any, enabled: bool) -> set[str]:
    """Hide annotated writes at startup; keep their names for audited refusals.

    Apply after family and API-source selection. The annotations are derived from
    upstream effects and checked against source by the schema contract tests.
    """
    if not enabled:
        return set()
    # A mixed read/write relay stays available; its actual path is checked per call.
    hidden = {
        tool.name
        for tool in await _list_tools(server)
        if not _is_read_tool(tool) and tool.name != "fabric_connector_get"
    }
    for name in hidden:
        _remove_tool(server, name)
    for middleware in server.middleware:
        if isinstance(middleware, ReadOnlyToolMiddleware):
            middleware.remember_hidden_writes(hidden)
    return hidden


def area_opt_out_env(name: str, family: str | None, connector_write_enabled: bool) -> str | None:
    """The opt-out variable hiding write tool ``name`` (of ``family``) now, else None.

    An area's switch (``switches.AREA_WRITE_SWITCHES``) governs its families. The connector
    write switch governs the relay's write tools and every typed write tool that checks it
    (derived from source at generation time: :func:`families.connector_write_tools`).
    """
    from . import families
    from .tools import connector

    env = connector.area_write_env(family)
    if (
        env is None
        and not connector_write_enabled
        and (family == "connector" or name in families.connector_write_tools())
    ):
        env = connector.CONNECTOR_WRITE_ENV
    return env


def hidden_area_write_refusal(name: str, env: str) -> str:
    """The refusal for a write tool hidden by the denying exception ``env``."""
    from . import families
    from .tools import connector

    if env == connector.CONNECTOR_WRITE_ENV:
        return connector.connector_write_refusal(name)
    text = connector.area_write_refusal(families.build_family_index().get(name))
    return text or (
        f"{name!r} is a write tool hidden at startup because UNIFI_WRITE_EXCEPTIONS contains "
        f"{env}; remove that item and restart the server to list it."
    )


def _token_family(env: str) -> str:
    """The family of a ``family:<id>=deny`` token."""
    return env.split(":", 1)[1].split("=", 1)[0]


async def apply_area_opt_out_tool_filter(
    server: Any, connector_write_enabled: bool
) -> dict[str, str]:
    """Hide the annotated writes of every opted-out area at startup.

    Uses the same classification (annotations) and de-registration as
    :func:`apply_read_only_tool_filter`, and the family index of the area switches. Returns
    ``{hidden tool: opt-out variable}``; :class:`AreaOptOutMiddleware` keeps the names so a
    direct call is still refused with the area's reason and audited. With every area on
    (the default) nothing is hidden.
    """
    from . import families

    index = families.build_family_index()
    hidden: dict[str, str] = {}
    for tool in await _list_tools(server):
        if _is_read_tool(tool) or tool.name == "fabric_connector_get":
            continue
        env = area_opt_out_env(tool.name, index.get(tool.name), connector_write_enabled)
        if env is not None:
            hidden[tool.name] = env
    for name in hidden:
        _remove_tool(server, name)
    for middleware in server.middleware:
        if isinstance(middleware, AreaOptOutMiddleware):
            middleware.remember_hidden_writes(hidden)
    return hidden


class ReadOnlyToolMiddleware(Middleware):
    """Refuse a denied write before any upstream call, and code every write-policy refusal.

    Before dispatch: the call's target (the dispatcher's ``name`` for call_read_tool /
    call_write_tool) is refused with ``write_denied`` when it is a write and its write mode,
    :func:`unifi_fabric.policy.write_mode` over the target's own family and name, is deny:
    ``UNIFI_WRITE_POLICY=deny``, ``family:<id>=deny`` for any of the 13 families, or
    ``tool:<name>=deny``. The Network area's wider reach (its related families and routes)
    is added by :class:`AreaOptOutMiddleware` and the chokepoint.

    After dispatch: a write the chokepoint or an in-tool check refused under the policy
    (:func:`unifi_fabric.read_only.is_write_denied`) is re-raised as the same coded
    refusal. Each refusal writes one ``policy.refusal`` record with the target's canonical
    id and the upstream requests counted for the call, and is audited (``outcome=refused``,
    ``reason`` = the denying setting) through ``audit`` when given.
    """

    def __init__(self, server: Any, audit: RefusalAudit | None = None) -> None:
        self._server = server
        self._audit = audit
        self._hidden_write_names: set[str] = set()

    def remember_hidden_writes(self, names: set[str]) -> None:
        """Retain classification after a write leaves the local provider."""
        self._hidden_write_names.update(names)

    async def _is_write(self, name: str, target: str, arguments: Any, read_only: bool) -> bool:
        if name == "call_write_tool" and read_only:
            return True
        if target in self._hidden_write_names and target not in _DISPATCHERS:
            return True
        try:
            tool = await self._server.get_tool(target)
        except NotFoundError:  # unknown tool: the framework reports it
            tool = None
        return tool is not None and is_write_tool_call(tool, target, arguments)

    def _denial(self, target: str, read_only: bool) -> tuple[str, str] | None:
        """``(reason, message)`` when the target's write mode is deny, else None."""
        from . import families, policy
        from .tools import connector

        current = policy.current()
        if read_only:
            return READ_ONLY_ENV, read_only_message(target, tool=True)
        if (f"tool:{target}", "deny") in current.write_exceptions:
            return f"tool:{target}=deny", (
                f"{target} refused: UNIFI_WRITE_EXCEPTIONS contains tool:{target}=deny. "
                "No request was sent. Remove that item to allow this tool's writes."
            )
        family = families.build_family_index().get(target) or ""
        if policy.write_mode(current, tool_name=target, family=family) != "deny":
            return None
        token = f"family:{family}=deny"
        message = (
            connector.connector_write_refusal(target)
            if family == "connector"
            else connector.area_write_refusal(family)
        ) or (
            f"{target} refused: UNIFI_WRITE_EXCEPTIONS contains {token}, which denies the "
            f"writes of the {family} family. No request was sent. Remove that item to allow "
            "them."
        )
        return token, message

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        from . import policy

        name = str(getattr(context.message, "name", ""))
        target, arguments = dispatch_target(name, getattr(context.message, "arguments", None))
        current = policy.current()
        read_only = current.write_policy == "deny"
        if (read_only or any(v == "deny" for _t, v in current.write_exceptions)) and (
            await self._is_write(name, target, arguments, read_only)
        ):
            denial = self._denial(target, read_only)
            if denial is not None:
                if self._audit is not None:
                    self._audit(target, denial[0])
                raise refusal(target, WRITE_DENIED, denial[1])
        try:
            return await call_next(context)
        except Exception as exc:
            if is_coded_refusal(exc):
                raise
            cause = denied_cause(exc)
            if cause is None:
                raise
            raise refusal(target, WRITE_DENIED, str(cause)) from None


class AreaOptOutMiddleware(Middleware):
    """Refuse a write tool of an opted-out area before its body runs.

    The per-area write opt-outs (``family:network=deny``,
    ``family:protect=deny``, ``family:mobility=deny``,
    ``family:carrier=deny``, ``family:innerspace=deny``, from the one table
    ``switches.AREA_WRITE_SWITCHES``) and the connector relay's
    ``family:connector=deny`` refuse every write tool of their family here, first:
    before argument validation, resolution or any upstream call, so the opt-out message
    always comes first whatever else is wrong with the call. The second layer is the
    client chokepoint (``read_only.guard_area_write``), which refuses every write request
    to an opted-out area's routes whichever tool or relay call sends it. With every area
    on (the default) calls pass through.
    An opted-out area's write tools are also hidden at startup
    (:func:`apply_area_opt_out_tool_filter`); this middleware remembers their names, so a
    client that calls a hidden name still gets the area's refusal rather than "unknown tool".
    A refusal is audited (``outcome=refused``, ``reason`` = the opt-out variable) through
    ``audit`` when given.
    """

    def __init__(
        self,
        server: Any,
        connector_write_enabled: Any,
        audit: RefusalAudit | None = None,
    ) -> None:
        self._server = server
        self._connector_write_enabled = connector_write_enabled
        self._audit = audit
        self._hidden_writes: dict[str, str] = {}

    def remember_hidden_writes(self, hidden: dict[str, str]) -> None:
        """Retain ``{name: opt-out variable}`` after an opted-out write leaves the provider."""
        self._hidden_writes.update(hidden)

    def _hidden_refusal(self, name: str) -> tuple[str, str] | None:
        """``(refusal, variable)`` for a startup-hidden write whose opt-out is still set."""
        from .tools import connector

        env = self._hidden_writes.get(name)
        if env is None:
            return None
        if env == connector.CONNECTOR_WRITE_ENV:
            opted_out = not self._connector_write_enabled()
        else:
            opted_out = family_denied(_token_family(env))
        return (hidden_area_write_refusal(name, env), env) if opted_out else None

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        from . import families
        from .tools import connector

        name = str(getattr(context.message, "name", ""))
        hidden = self._hidden_refusal(name)
        if hidden is not None:
            # A write hidden at startup: refused with its area's reason, never "unknown tool".
            if self._audit is not None:
                self._audit(name, hidden[1])
            raise refusal(name, WRITE_DENIED, hidden[0])
        family = families.build_family_index().get(name)
        area_refusal = connector.area_write_refusal(family)
        gate = connector.area_write_env(family)
        if area_refusal is None and family == "connector" and not self._connector_write_enabled():
            area_refusal = connector.connector_write_refusal(name)
            gate = connector.CONNECTOR_WRITE_ENV
        if area_refusal is not None:
            try:
                tool = await self._server.get_tool(name)
            except NotFoundError:  # unknown tool: the framework reports it
                tool = None
            if tool is not None and is_write_tool_call(
                tool, name, getattr(context.message, "arguments", None)
            ):
                if self._audit is not None and gate is not None:
                    self._audit(name, gate)
                raise refusal(name, WRITE_DENIED, area_refusal)
        return await call_next(context)


class ExposureMiddleware(Middleware):
    """Refuse a call to a tool the operator policy does not expose (``tool_not_exposed``).

    Covers a direct ``tools/call`` of a name the exposure settings (``UNIFI_FAMILY_ALLOW``,
    ``UNIFI_EXCLUDE``) de-registered at startup and the discovery dispatchers
    ``call_read_tool`` / ``call_write_tool`` naming one. Refused before dispatch with zero
    upstream calls and a ``policy.refusal`` record carrying the target's canonical id.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        from . import policy

        with policy.upstream_call_scope():
            name = str(getattr(context.message, "name", ""))
            target, _arguments = dispatch_target(name, getattr(context.message, "arguments", None))
            if target in policy.excluded_names():
                raise not_exposed(target)
            return await call_next(context)


def not_exposed(target: str) -> ToolError:
    """The ``tool_not_exposed`` refusal for ``target`` (with its record)."""
    return refusal(
        target,
        TOOL_NOT_EXPOSED,
        f"{target!r} is not exposed: the operator's UNIFI_FAMILY_ALLOW or UNIFI_EXCLUDE "
        "removes it. No request was sent. Use search_tools to list the exposed tools.",
    )
