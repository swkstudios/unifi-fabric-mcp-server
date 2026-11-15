"""Opt-in MCP background tasks for the long multi-site reads (public #45).

``UNIFI_BACKGROUND_TASKS=on`` lets a client that opts in to the SEP-2663 tasks extension
(``io.modelcontextprotocol/tasks``) run :data:`TASK_OPTIONAL_TOOLS` as a background task:
``tools/call`` answers at once with a task handle (``resultType: "task"``), and the client
polls ``tasks/get`` for the result or stops the call with ``tasks/cancel``. Off by default.

Negotiation is per request, as the extension specifies. A call runs as a task only when
all of these hold; otherwise it runs synchronously on the unchanged path:

* the server runs with ``UNIFI_BACKGROUND_TASKS=on``;
* the tool's task mode is ``optional`` (:func:`task_mode`; no tool is ``required``);
* the request was made on the 2026-07-28 protocol (the extension mechanism exists only
  there; the SDK strips ``extensions`` from every earlier handshake), and its ``_meta``
  declares the tasks extension under ``io.modelcontextprotocol/clientCapabilities``;
* the call came from the client, not from another tool (``call_read_tool``, a resource
  read), and fewer than :data:`MAX_WORKING_TASKS` tasks are working.

What runs in the task is the whole tool call: :class:`BackgroundTaskMiddleware` is the
outermost middleware, so every other middleware (header credentials, redaction and secret
scrubbing, request policy, write refusals, audit) and the tool body run inside the task in
the request's own context, exactly as they run for a synchronous call. Upstream pacing is
the same process-wide limiter. Task state is held in this process only: no Redis, no disk.
A finished task keeps only its inlined result (or error), its timestamps and an opaque
caller scope (:func:`caller_scope`); the running call's ``asyncio.Task``, and with it the
request's copied context (the HTTP request and its headers), is dropped the moment the
task finishes or is cancelled. The scope decides who may read or cancel a task.

This is FastMCP's own extension API (``ServerExtension``, ``MethodBinding``), not the
``fastmcp-tasks`` package: that package's Docket worker calls the bare tool function
outside the middleware chain and stores a snapshot of the request headers in task state.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import hmac
import logging
import os
import secrets
import time
from collections import OrderedDict
from collections.abc import AsyncGenerator, Coroutine, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

import mcp_types
from fastmcp.exceptions import DisabledError, FastMCPError, NotFoundError
from fastmcp.server.extensions import (
    MethodBinding,
    ServerExtension,
    read_client_extension_settings,
)
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult
from fastmcp.utilities.tasks import TASKS_EXTENSION_ID, TaskMode
from mcp.shared.exceptions import MCPError
from mcp_types.jsonrpc import HEADER_MISMATCH, MISSING_REQUIRED_CLIENT_CAPABILITY
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from fastmcp import FastMCP
    from mcp.server.context import ServerRequestContext

logger = logging.getLogger(__name__)

#: The opt-in switch: ``on`` or ``off`` (the default).
ENV = "UNIFI_BACKGROUND_TASKS"

#: The tools a client may run as a background task (task mode ``optional``). Each drains
#: many pages or many sites and can outlast a client's request timeout. Every other tool
#: is ``forbidden``, and none is ``required``.
TASK_OPTIONAL_TOOLS: frozenset[str] = frozenset(
    {
        "search_across_sites",
        "collect_network_incident_evidence",
        "collect_protect_incident_evidence",
    }
)

#: How long a finished task and its result stay retrievable after the task finishes. A
#: working task is never ended by time: only by finishing or by ``tasks/cancel``.
TASK_TTL_MS = 30 * 60 * 1000
#: The poll interval each task handle suggests.
POLL_INTERVAL_MS = 2000
#: Working tasks per process; a further opted-in call runs synchronously.
MAX_WORKING_TASKS = 16
#: Finished tasks kept per caller scope; a caller's oldest finished task goes first.
MAX_RETAINED_PER_SCOPE = 32
#: Finished tasks kept per process; past it, the scope holding the most loses its oldest,
#: so one caller cannot flush another caller's results.
MAX_RETAINED_TASKS = 256

TaskStatus = Literal["working", "input_required", "completed", "failed", "cancelled"]

_MODERN = frozenset(MODERN_PROTOCOL_VERSIONS)
#: Per-process key for the caller scope: never stored, logged or sent.
_SCOPE_KEY = secrets.token_bytes(32)
#: Set while a tool call is in progress, so a call a tool makes in turn runs inline.
_IN_CALL: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "unifi_background_task_in_call", default=False
)
#: A strong reference to each running call's Task until it is done, cleanup after
#: ``tasks/cancel`` included. The event loop holds Tasks only weakly, and a finished or
#: cancelled task record drops its own reference, so without this set a cancelled call could
#: be collected mid-cleanup. Each Task removes itself in its done-callback.
_RUNNING: set[asyncio.Task[None]] = set()


def _spawn(task: _Task, call: Coroutine[Any, Any, None], name: str) -> None:
    """Start ``call`` for ``task``: the record and :data:`_RUNNING` hold its Task."""
    runner = asyncio.create_task(call, name=name)
    _RUNNING.add(runner)
    runner.add_done_callback(_RUNNING.discard)
    task.runner = runner


def task_mode(name: str) -> TaskMode:
    """The task mode of tool ``name``: ``optional`` for :data:`TASK_OPTIONAL_TOOLS`."""
    return "optional" if name in TASK_OPTIONAL_TOOLS else "forbidden"


def enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Whether ``UNIFI_BACKGROUND_TASKS`` is ``on`` (read when the server module loads).

    Any other value leaves task support off here; :class:`unifi_fabric.config.Settings`
    refuses a value other than ``on``, ``off`` or empty at startup.
    """
    raw = (os.environ if environ is None else environ).get(ENV, "")
    return raw.strip().lower() == "on"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def caller_scope() -> str:
    """An opaque scope for the current caller, keyed by its stable identity.

    The parts, hashed with the per-process :data:`_SCOPE_KEY` (so the value reveals nothing
    and is meaningless outside this process):

    * with a verified access token (``MCP_AUTH_MODE=oauth`` or ``bearer``): the principal,
      its ``client_id`` and, when the token has one, its ``sub`` claim, never the token
      itself, so a refreshed token keeps its tasks. Every caller of a ``bearer`` server
      holds the same token, so they share one principal;
    * without one (``MCP_AUTH_MODE=none``): the ``Authorization`` header value, if sent;
    * the ``X-UniFi-Api-Key`` header value (header key mode): the UniFi keys the call runs
      with.

    With no HTTP request (stdio) the scope is the single local client. Callers that present
    the same parts, such as every user behind a gateway that calls this server with one
    credential, share a scope; only the unguessable task id, which goes to the creator
    alone, separates their tasks.
    """
    from fastmcp.server import dependencies

    token = dependencies.get_access_token()
    try:
        headers = dependencies.get_http_request().headers
    except RuntimeError:
        headers = None
    if token is None and headers is None:
        return "local"
    parts: list[tuple[str, str]] = []
    if token is not None:
        parts.append(("client_id", str(token.client_id or "")))
        sub = (token.claims or {}).get("sub")
        if sub:
            parts.append(("sub", str(sub)))
    elif headers is not None:
        parts.extend(("authorization", value) for value in headers.getlist("authorization"))
    if headers is not None:
        parts.extend(("x-unifi-api-key", value) for value in headers.getlist("x-unifi-api-key"))
    mac = hmac.new(_SCOPE_KEY, digestmod=hashlib.sha256)
    for name, value in parts:
        mac.update(name.encode() + b"\0" + value.encode() + b"\0")
    return mac.hexdigest()


# --------------------------------------------------------------------------- wire models


class _TaskFields(BaseModel):
    """The SEP-2663 task fields every task result carries."""

    model_config = ConfigDict(populate_by_name=True)

    task_id: str = Field(serialization_alias="taskId")
    status: TaskStatus
    created_at: str = Field(serialization_alias="createdAt")
    last_updated_at: str = Field(serialization_alias="lastUpdatedAt")
    ttl_ms: int = Field(serialization_alias="ttlMs")
    poll_interval_ms: int = Field(serialization_alias="pollIntervalMs")
    status_message: str | None = Field(default=None, serialization_alias="statusMessage")


class CreateTaskResult(_TaskFields):
    """``tools/call`` answered with a task handle."""

    result_type: Literal["task"] = Field(default="task", serialization_alias="resultType")


class GetTaskResult(_TaskFields):
    """``tasks/get``: the task, with its ``result`` (completed) or ``error`` (failed)."""

    result_type: Literal["complete"] = Field(default="complete", serialization_alias="resultType")
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class TaskParams(mcp_types.RequestParams):
    """``tasks/get`` and ``tasks/cancel`` params: the task id."""

    model_config = ConfigDict(populate_by_name=True)

    task_id: str = Field(alias="taskId")


class UpdateTaskParams(TaskParams):
    """``tasks/update`` params. No task here asks for input, so an update is a no-op."""

    input_responses: dict[str, Any] = Field(default_factory=dict, alias="inputResponses")


class _Ack(mcp_types.Result):
    result_type: Literal["complete"] = Field(default="complete", serialization_alias="resultType")


# --------------------------------------------------------------------------- task store


@dataclass
class _Task:
    task_id: str
    scope: str
    created_at: str
    updated_at: str
    finished: float | None = None  # monotonic time the task left ``working``
    status: TaskStatus = "working"
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    runner: asyncio.Task[None] | None = None

    def handle(self) -> CreateTaskResult:
        return CreateTaskResult(
            task_id=self.task_id,
            status=self.status,
            created_at=self.created_at,
            last_updated_at=self.updated_at,
            ttl_ms=TASK_TTL_MS,
            poll_interval_ms=POLL_INTERVAL_MS,
        )

    def detail(self) -> GetTaskResult:
        return GetTaskResult(
            task_id=self.task_id,
            status=self.status,
            created_at=self.created_at,
            last_updated_at=self.updated_at,
            ttl_ms=TASK_TTL_MS,
            poll_interval_ms=POLL_INTERVAL_MS,
            result=self.result,
            error=self.error,
        )

    def finish(self, status: TaskStatus, **payload: Any) -> None:
        if self.status != "working":
            return
        self.status = status
        self.result = payload.get("result")
        self.error = payload.get("error")
        self.updated_at = _now()
        self.finished = time.monotonic()
        # The running call's Task holds the request's copied context (the HTTP request and
        # its headers): never keep it past the call.
        self.runner = None


class TaskStore:
    """The in-process tasks: id -> task. Finished tasks are kept for :data:`TASK_TTL_MS`
    after they finish, and at most :data:`MAX_RETAINED_TASKS` of them."""

    def __init__(self) -> None:
        self._tasks: OrderedDict[str, _Task] = OrderedDict()

    def _evict(self) -> None:
        now = time.monotonic()
        retention = TASK_TTL_MS / 1000
        for task_id in [
            t
            for t, task in self._tasks.items()
            if task.finished is not None and now - task.finished >= retention
        ]:
            self._drop(task_id)
        by_scope: dict[str, list[str]] = {}
        for task_id, task in self._tasks.items():
            if task.status != "working":
                by_scope.setdefault(task.scope, []).append(task_id)
        for ids in by_scope.values():
            while len(ids) > MAX_RETAINED_PER_SCOPE:
                self._drop(ids.pop(0))
        total = sum(len(ids) for ids in by_scope.values())
        while total > MAX_RETAINED_TASKS:
            largest = max(by_scope.values(), key=len)
            self._drop(largest.pop(0))
            total -= 1

    def finish(self, task: _Task, status: TaskStatus, **payload: Any) -> None:
        """Record ``task``'s outcome, release its call, and apply the retention limits."""
        task.finish(status, **payload)
        self._evict()

    def _drop(self, task_id: str) -> None:
        self._tasks.pop(task_id, None)

    def working(self) -> int:
        return sum(1 for task in self._tasks.values() if task.status == "working")

    def create(self, scope: str) -> _Task | None:
        """A new working task, or None when :data:`MAX_WORKING_TASKS` are working."""
        self._evict()
        if self.working() >= MAX_WORKING_TASKS:
            return None
        now = _now()
        task = _Task(
            task_id=secrets.token_urlsafe(32),
            scope=scope,
            created_at=now,
            updated_at=now,
        )
        self._tasks[task.task_id] = task
        return task

    def get(self, scope: str, task_id: str) -> _Task:
        """The caller's task; a missing, expired or other caller's id is not found."""
        self._evict()
        task = self._tasks.get(task_id)
        if task is None or not hmac.compare_digest(task.scope, scope):
            raise MCPError(code=mcp_types.INVALID_PARAMS, message="Task not found")
        return task

    def cancel_all(self) -> None:
        for task in self._tasks.values():
            if task.runner is not None and not task.runner.done():
                task.runner.cancel()
        self._tasks.clear()


# --------------------------------------------------------------------------- tools/call


def _opted_in(context: MiddlewareContext[Any]) -> bool:
    """Whether this request opted in to the tasks extension on the 2026-07-28 protocol."""
    ctx = context.fastmcp_context
    if ctx is None:
        return False
    try:
        rc = ctx.request_context
    except RuntimeError:
        return False
    if rc is None or rc.protocol_version not in _MODERN:
        return False
    return ctx.client_extension_settings(TASKS_EXTENSION_ID) is not None


def _call_result(result: Any) -> dict[str, Any]:
    """A finished call's ``CallToolResult``, as the synchronous ``tools/call`` sends it."""
    from fastmcp.server.mixins.mcp_operations import _normalize_call_tool_result

    if isinstance(result, ToolResult):
        model = _normalize_call_tool_result(result.to_mcp_result())
    elif isinstance(result, mcp_types.CallToolResult):
        model = result
    else:
        raise TypeError(f"tool call returned {type(result).__name__}")
    return model.model_dump(by_alias=True, mode="json", exclude_none=True)


def _error_result(text: str) -> dict[str, Any]:
    return _call_result(
        mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=text)], is_error=True
        )
    )


class BackgroundTaskMiddleware(Middleware):
    """The outermost ``tools/call`` middleware: runs an opted-in call as a task.

    Everything below it, every other middleware and the tool, runs inside the task with
    the request's context, so a task call is checked, scrubbed, paced and audited exactly
    as the same synchronous call. A call that is not run as a task passes straight
    through, untouched.
    """

    def __init__(self, store: TaskStore) -> None:
        self._store = store

    async def on_call_tool(
        self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
    ) -> Any:
        if _IN_CALL.get():
            return await call_next(context)
        token = _IN_CALL.set(True)
        try:
            name = getattr(context.message, "name", None)
            if not (isinstance(name, str) and task_mode(name) == "optional" and _opted_in(context)):
                return await call_next(context)
            task = self._store.create(caller_scope())
            if task is None:
                return await call_next(context)
            # create_task copies the current context: the request, its headers and
            # _IN_CALL, so the call runs as it would inline.
            _spawn(task, _run(self._store, task, context, call_next), f"unifi-task:{name}")
            return task.handle()
        finally:
            _IN_CALL.reset(token)


async def _run(
    store: TaskStore, task: _Task, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]
) -> None:
    """Run the call and record its outcome as the synchronous path would answer it."""
    try:
        result = await call_next(context)
    except asyncio.CancelledError:
        store.finish(task, "cancelled")
        raise
    except (DisabledError, NotFoundError):
        name = getattr(context.message, "name", "")
        store.finish(task, "completed", result=_error_result(f"Unknown tool: {name!r}"))
    except FastMCPError as exc:
        store.finish(task, "completed", result=_error_result(str(exc)))
    except MCPError as exc:
        error: dict[str, Any] = {"code": exc.error.code, "message": exc.error.message}
        if exc.error.data is not None:
            error["data"] = exc.error.data
        store.finish(task, "failed", error=error)
    except Exception as exc:  # noqa: BLE001 - recorded as the task's failure, never raised
        logger.error("background task failed: %s", type(exc).__name__)
        store.finish(
            task, "failed", error={"code": mcp_types.INTERNAL_ERROR, "message": "Internal error"}
        )
    else:
        try:
            store.finish(task, "completed", result=_call_result(result))
        except Exception as exc:  # noqa: BLE001
            logger.error("background task result failed: %s", type(exc).__name__)
            store.finish(
                task,
                "failed",
                error={"code": mcp_types.INTERNAL_ERROR, "message": "Internal error"},
            )


# --------------------------------------------------------------------------- tasks/*


class BackgroundTasksExtension(ServerExtension):
    """Advertises the tasks extension and serves ``tasks/get``, ``tasks/cancel`` and
    ``tasks/update`` on the 2026-07-28 protocol (any other version: method not found)."""

    identifier = TASKS_EXTENSION_ID

    def __init__(self, store: TaskStore) -> None:
        self._store = store

    def clone(self) -> BackgroundTasksExtension:
        return BackgroundTasksExtension(self._store)

    def settings(self) -> dict[str, Any]:
        return {}

    def methods(self) -> Sequence[MethodBinding]:
        return [
            MethodBinding("tasks/get", TaskParams, self._get, protocol_versions=_MODERN),
            MethodBinding("tasks/cancel", TaskParams, self._cancel, protocol_versions=_MODERN),
            MethodBinding(
                "tasks/update", UpdateTaskParams, self._update, protocol_versions=_MODERN
            ),
        ]

    def _task(self, ctx: ServerRequestContext[Any, Any], task_id: str) -> _Task:
        if read_client_extension_settings(ctx, TASKS_EXTENSION_ID) is None:
            raise MCPError(
                code=MISSING_REQUIRED_CLIENT_CAPABILITY,
                message=f"This request did not declare the {TASKS_EXTENSION_ID} extension.",
                data={"requiredCapabilities": {"extensions": {TASKS_EXTENSION_ID: {}}}},
            )
        _check_name_header(task_id)
        return self._store.get(caller_scope(), task_id)

    async def _get(self, ctx: ServerRequestContext[Any, Any], params: TaskParams) -> GetTaskResult:
        return self._task(ctx, params.task_id).detail()

    async def _cancel(self, ctx: ServerRequestContext[Any, Any], params: TaskParams) -> _Ack:
        task = self._task(ctx, params.task_id)
        if task.status == "working" and task.runner is not None:
            task.runner.cancel()
            self._store.finish(task, "cancelled")
        return _Ack()

    async def _update(self, ctx: ServerRequestContext[Any, Any], params: UpdateTaskParams) -> _Ack:
        self._task(ctx, params.task_id)
        return _Ack()

    @asynccontextmanager
    async def lifespan(self) -> AsyncGenerator[None, None]:
        try:
            yield
        finally:
            self._store.cancel_all()


def _check_name_header(task_id: str) -> None:
    """SEP-2243: an ``Mcp-Name`` header, when sent, must name the body's ``taskId``."""
    from fastmcp.server.dependencies import get_http_request
    from mcp.shared.inbound import MCP_NAME_HEADER, decode_header_value

    try:
        header = get_http_request().headers.get(MCP_NAME_HEADER)
    except RuntimeError:
        return
    if header is not None and decode_header_value(header) != task_id:
        raise MCPError(
            code=HEADER_MISMATCH,
            message=f"{MCP_NAME_HEADER} header does not match the request body's 'taskId'",
        )


def install(mcp: FastMCP, environ: Mapping[str, str] | None = None) -> bool:
    """Turn task support on for ``mcp`` when ``UNIFI_BACKGROUND_TASKS=on``.

    Off (the default) this changes nothing. On, it puts :class:`BackgroundTaskMiddleware`
    outermost and registers :class:`BackgroundTasksExtension`.
    """
    if not enabled(environ):
        return False
    store = TaskStore()
    mcp.middleware.insert(0, BackgroundTaskMiddleware(store))
    mcp.add_extension(BackgroundTasksExtension(store))
    return True
