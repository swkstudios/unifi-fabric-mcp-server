"""Hide and refuse write tools under ``UNIFI_READ_ONLY`` and the per-area write opt-outs.

Startup selection removes annotated writes from the local provider: every write under
``UNIFI_READ_ONLY``, and the writes of an opted-out area (``switches.AREA_WRITE_SWITCHES``,
plus the connector relay's ``UNIFI_ENABLE_CONNECTOR_WRITE``). Hidden names remain
classified in the middleware so direct calls receive the same audited refusal.

The HTTP chokepoint (:func:`unifi_fabric.read_only.guard_request`) refuses every
mutating upstream request, but a write tool that reads before it writes (port-profile
allow/exclude read networkconf and portconf, ``update_setting`` reads the setting,
``locate_device`` resolves a UUID to a MAC, Carrier and Mobility writes read the
subscriber or device, Protect writes read the object to merge) would still make those
reads before the write was refused. With read-only mode on, a write tool must not touch
the console at all.

:class:`ReadOnlyToolMiddleware` refuses the call before the tool body runs when the mode
is on and the tool is not annotated ``readOnlyHint: true``. With the mode off (the
default) it only checks one environment variable and passes the call through, so the
default path is unchanged. The chokepoint stays as the second layer for any request
this check does not see.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastmcp.exceptions import NotFoundError, ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from .families import _list_tools, _remove_tool
from .read_only import is_read_only, is_write_request, read_only_message
from .switches import READ_ONLY_ENV, TRUE_HINT

#: ``audit(tool, reason)``: records a refused write tool call (``outcome=refused``).
RefusalAudit = Callable[[str, str], None]


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
    (derived from source: :func:`families.tools_referencing`).
    """
    from . import families
    from .tools import connector

    env = connector.area_write_env(family)
    if (
        env is None
        and not connector_write_enabled
        and (family == "connector" or name in families.tools_referencing("CONNECTOR_WRITE_ENV"))
    ):
        env = connector.CONNECTOR_WRITE_ENV
    return env


def hidden_area_write_refusal(name: str, env: str) -> str:
    """The refusal for a write tool hidden by the opt-out ``env`` (discovery describe)."""
    from . import families
    from .tools import connector

    if env == connector.CONNECTOR_WRITE_ENV:
        return connector.connector_write_refusal(name)
    refusal = connector.area_write_refusal(families.build_family_index().get(name))
    return refusal or (
        f"{name!r} is a write tool hidden at startup because {env} opted its area out; "
        f"set {env} to a true value ({TRUE_HINT}) and restart the server to list it."
    )


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
    """Refuse a write tool before any upstream call while ``UNIFI_READ_ONLY`` is on.

    The refusal is audited (``outcome=refused``, ``reason=UNIFI_READ_ONLY``) through
    ``audit`` when given.
    """

    def __init__(self, server: Any, audit: RefusalAudit | None = None) -> None:
        self._server = server
        self._audit = audit
        self._hidden_write_names: set[str] = set()

    def remember_hidden_writes(self, names: set[str]) -> None:
        """Retain classification after a write leaves the local provider."""
        self._hidden_write_names.update(names)

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        if is_read_only():
            name = str(getattr(context.message, "name", ""))
            try:
                tool = await self._server.get_tool(name)
            except NotFoundError:  # unknown tool: the framework reports it
                tool = None
            if name in self._hidden_write_names or (
                tool is not None
                and is_write_tool_call(tool, name, getattr(context.message, "arguments", None))
            ):
                if self._audit is not None:
                    self._audit(name, READ_ONLY_ENV)
                raise ToolError(read_only_message(name, tool=True))
        return await call_next(context)


class AreaOptOutMiddleware(Middleware):
    """Refuse a write tool of an opted-out area before its body runs.

    The per-area write opt-outs (``UNIFI_ENABLE_NETWORK_WRITE``,
    ``UNIFI_PROTECT_MUTATIONS_ENABLED``, ``UNIFI_ENABLE_MOBILITY_WRITE``,
    ``UNIFI_ENABLE_CARRIER_FABRIC_WRITE``, ``UNIFI_ENABLE_INNERSPACE_WRITE``, from the one table
    ``switches.AREA_WRITE_SWITCHES``) and the connector relay's
    ``UNIFI_ENABLE_CONNECTOR_WRITE`` refuse every write tool of their family here, first:
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
        from .switches import env_flag
        from .tools import connector

        env = self._hidden_writes.get(name)
        if env is None:
            return None
        if env == connector.CONNECTOR_WRITE_ENV:
            opted_out = not self._connector_write_enabled()
        else:
            opted_out = not env_flag(env, True)
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
            raise ToolError(hidden[0])
        family = families.build_family_index().get(name)
        refusal = connector.area_write_refusal(family)
        gate = connector.area_write_env(family)
        if refusal is None and family == "connector" and not self._connector_write_enabled():
            refusal = connector.connector_write_refusal(name)
            gate = connector.CONNECTOR_WRITE_ENV
        if refusal is not None:
            try:
                tool = await self._server.get_tool(name)
            except NotFoundError:  # unknown tool: the framework reports it
                tool = None
            if tool is not None and is_write_tool_call(
                tool, name, getattr(context.message, "arguments", None)
            ):
                if self._audit is not None and gate is not None:
                    self._audit(name, gate)
                raise ToolError(refusal)
        return await call_next(context)
