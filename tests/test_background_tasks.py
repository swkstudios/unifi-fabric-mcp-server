"""MCP background tasks (public #45, ``UNIFI_BACKGROUND_TASKS``): negotiation and fallback.

Drives the streamable-HTTP app in-process (``httpx.ASGITransport``, real lifespan) on the
recorded-fixture upstream. A client that does not opt in, on any protocol version, gets
the synchronous answer byte for byte as with the switch off; a client that opts in on
2026-07-28 gets a task handle for the three long reads, polls ``tasks/get`` to the same
result, and can cancel. Task state holds no caller header.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import importlib
import json
from collections.abc import AsyncIterator, Mapping
from datetime import datetime
from typing import Any

import httpx
import pytest

from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric import background_tasks
from unifi_fabric.catalog.models import ToolSpec

TASKS = "io.modelcontextprotocol/tasks"
LEGACY = "2025-06-18"
MODERN = "2026-07-28"
_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
_SLEEP = uh._real_sleep  # the harness makes asyncio.sleep a no-op

#: initialize capabilities as each client sends them (073-45-async-research.md matrix).
LEGACY_CLIENTS: dict[str, dict[str, Any]] = {
    "claude-desktop": {"roots": {"listChanged": True}, "sampling": {}},
    "chatgpt": {},
    "cursor": {"roots": {"listChanged": False}},
    # A legacy handshake that names the extension anyway: still no task (no extensions
    # before 2026-07-28).
    "legacy-with-tasks": {"extensions": {TASKS: {}}},
}


class _Frozen(datetime):
    """The evidence documents' ``collected_at`` clock, pinned so two runs compare by byte."""

    @classmethod
    def now(cls, tz: Any = None) -> _Frozen:
        return cls(2026, 11, 11, 12, 0, 0, tzinfo=tz)


def _install(monkeypatch: pytest.MonkeyPatch) -> None:
    from unifi_fabric.shared_shapes import _incident_document

    uh.install(monkeypatch, uh.FakeUpstream())
    monkeypatch.setattr(_incident_document, "datetime", _Frozen)


def _modern_meta(tasks: bool) -> dict[str, Any]:
    caps: dict[str, Any] = {"extensions": {TASKS: {}}} if tasks else {}
    return {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientCapabilities": caps,
        "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "1.0"},
    }


def _reload(monkeypatch: pytest.MonkeyPatch, on: bool, env: Mapping[str, str] | None = None) -> Any:
    monkeypatch.setenv("UNIFI_API_KEY", "k-test")
    monkeypatch.setenv("FASTMCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_AUTH_MODE", "none")
    if on:
        monkeypatch.setenv(background_tasks.ENV, "on")
    else:
        monkeypatch.delenv(background_tasks.ENV, raising=False)
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    import unifi_fabric.server as srv

    importlib.reload(srv)
    srv._configure_transport()
    return srv


@pytest.fixture
def restore_server(monkeypatch: pytest.MonkeyPatch) -> Any:
    yield
    monkeypatch.delenv(background_tasks.ENV, raising=False)
    monkeypatch.delenv("UNIFI_KEY_MODE", raising=False)
    import unifi_fabric.server as srv

    importlib.reload(srv)


@contextlib.asynccontextmanager
async def _client(srv: Any) -> AsyncIterator[httpx.AsyncClient]:
    app = srv.mcp.http_app()
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://tasks.test"
        ) as client:
            yield client


def _body(resp: httpx.Response) -> dict[str, Any]:
    text = resp.text
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        text = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")][-1]
    return json.loads(text)


async def _modern(
    client: httpx.AsyncClient,
    method: str,
    params: Mapping[str, Any],
    *,
    tasks: bool,
    name: str | None = None,
    headers: Mapping[str, str] | None = None,
) -> httpx.Response:
    hdrs = {**_HEADERS, "MCP-Protocol-Version": MODERN, "Mcp-Method": method, **(headers or {})}
    if name is not None:
        hdrs["Mcp-Name"] = name
    return await client.post(
        "/mcp",
        headers=hdrs,
        json={
            "jsonrpc": "2.0",
            "id": 7,
            "method": method,
            "params": {**params, "_meta": _modern_meta(tasks)},
        },
    )


async def _legacy_call(
    client: httpx.AsyncClient, caps: Mapping[str, Any], name: str, args: Mapping[str, Any]
) -> tuple[dict[str, Any], httpx.Response]:
    init = await client.post(
        "/mcp",
        headers=_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": LEGACY,
                "capabilities": dict(caps),
                "clientInfo": {"name": "legacy", "version": "1.0"},
            },
        },
    )
    headers = {**_HEADERS, "MCP-Protocol-Version": LEGACY}
    session = init.headers.get("mcp-session-id")
    if session:
        headers["Mcp-Session-Id"] = session
    call = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": dict(args)},
        },
    )
    return _body(init), call


async def _args(srv: Any, name: str) -> dict[str, Any]:
    tool = await srv.mcp.get_tool(name)
    return tool_args.resolve_placeholders(name, tool_args.generated_args(tool))


async def _poll(client: httpx.AsyncClient, task_id: str, **kw: Any) -> dict[str, Any]:
    for _ in range(400):
        got = _body(
            await _modern(client, "tasks/get", {"taskId": task_id}, tasks=True, name=task_id, **kw)
        )
        if got["result"]["status"] != "working":
            return got
        await _SLEEP(0.01)
    raise AssertionError("task never finished")


# --------------------------------------------------------------------------- the switch


def test_off_by_default_and_parsing() -> None:
    from unifi_fabric.config import Settings

    assert background_tasks.enabled({}) is False
    assert background_tasks.enabled({background_tasks.ENV: "off"}) is False
    assert background_tasks.enabled({background_tasks.ENV: " ON "}) is True
    assert background_tasks.enabled({background_tasks.ENV: "yes"}) is False
    assert Settings(api_key="k").background_tasks == "off"
    assert Settings(api_key="k", background_tasks=" On ").background_tasks == "on"
    with pytest.raises(ValueError, match="UNIFI_BACKGROUND_TASKS must be on or off"):
        Settings(api_key="k", background_tasks="yes")
    from fastmcp import FastMCP

    mcp = FastMCP("scratch")
    before = list(mcp.middleware)
    assert background_tasks.install(mcp, {}) is False
    assert mcp.middleware == before and TASKS not in mcp._extensions


def test_only_the_three_long_reads_are_optional() -> None:
    assert background_tasks.TASK_OPTIONAL_TOOLS == {
        "search_across_sites",
        "collect_network_incident_evidence",
        "collect_protect_incident_evidence",
    }
    assert ToolSpec.__dataclass_fields__["task_mode"].default == "forbidden"
    assert background_tasks.task_mode("list_devices") == "forbidden"
    assert {background_tasks.task_mode(n) for n in background_tasks.TASK_OPTIONAL_TOOLS} == {
        "optional"
    }


def test_on_installs_outermost_middleware_and_extension(
    monkeypatch: pytest.MonkeyPatch, restore_server: Any
) -> None:
    srv = _reload(monkeypatch, on=True)
    assert isinstance(srv.mcp.middleware[0], background_tasks.BackgroundTaskMiddleware)
    assert TASKS in srv.mcp._extensions
    off = _reload(monkeypatch, on=False)
    assert not any(
        isinstance(m, background_tasks.BackgroundTaskMiddleware) for m in off.mcp.middleware
    )
    assert TASKS not in off.mcp._extensions


# --------------------------------------------------------------------------- sync fallback


async def _sync_answers(srv: Any, monkeypatch: pytest.MonkeyPatch) -> dict[str, list[bytes]]:
    """Every non-opting client's raw tools/call response bytes, per tool."""
    out: dict[str, list[bytes]] = {}
    for name in sorted(background_tasks.TASK_OPTIONAL_TOOLS):
        _install(monkeypatch)
        args = await _args(srv, name)
        answers: list[bytes] = []
        async with _client(srv) as client:
            for caps in LEGACY_CLIENTS.values():
                init, call = await _legacy_call(client, caps, name, args)
                assert "extensions" not in json.dumps(init["result"]["capabilities"])
                answers.append(call.content)
            resp = await _modern(
                client, "tools/call", {"name": name, "arguments": args}, tasks=False, name=name
            )
            answers.append(resp.content)
        out[name] = answers
    return out


def test_non_opting_clients_get_identical_bytes_with_the_switch_on_or_off(
    monkeypatch: pytest.MonkeyPatch, restore_server: Any
) -> None:
    off = asyncio.run(_sync_answers(_reload(monkeypatch, on=False), monkeypatch))
    on = asyncio.run(_sync_answers(_reload(monkeypatch, on=True), monkeypatch))
    assert on == off
    for answers in on.values():
        for raw in answers:
            body = (
                json.loads(raw.decode().split("data:")[-1])
                if raw.startswith(b"event")
                else json.loads(raw)
            )
            assert body["result"].get("resultType") in (None, "complete")
            assert "taskId" not in body["result"]


# --------------------------------------------------------------------------- task path


def test_opted_in_call_returns_a_task_with_the_sync_result(
    monkeypatch: pytest.MonkeyPatch, restore_server: Any
) -> None:
    srv = _reload(monkeypatch, on=True)

    async def run() -> None:
        for name in sorted(background_tasks.TASK_OPTIONAL_TOOLS):
            _install(monkeypatch)
            args = await _args(srv, name)
            async with _client(srv) as client:
                sync = _body(
                    await _modern(
                        client,
                        "tools/call",
                        {"name": name, "arguments": args},
                        tasks=False,
                        name=name,
                    )
                )
                handle = _body(
                    await _modern(
                        client,
                        "tools/call",
                        {"name": name, "arguments": args},
                        tasks=True,
                        name=name,
                    )
                )["result"]
                assert handle["resultType"] == "task" and handle["status"] == "working"
                assert handle["ttlMs"] == background_tasks.TASK_TTL_MS
                done = await _poll(client, handle["taskId"])
                assert done["result"]["status"] == "completed", done
                task_result = done["result"]["result"]
                # The same CallToolResult; the response-level serverInfo stamp is not part of it.
                assert task_result == {k: v for k, v in sync["result"].items() if k != "_meta"}

    asyncio.run(run())


def test_forbidden_tool_runs_sync_even_when_opted_in(
    monkeypatch: pytest.MonkeyPatch, restore_server: Any
) -> None:
    srv = _reload(monkeypatch, on=True)
    uh.install(monkeypatch, uh.FakeUpstream())

    async def run() -> None:
        async with _client(srv) as client:
            body = _body(
                await _modern(
                    client,
                    "tools/call",
                    {"name": "list_hosts", "arguments": {}},
                    tasks=True,
                    name="list_hosts",
                )
            )
            assert body["result"]["resultType"] == "complete" and "taskId" not in body["result"]

    asyncio.run(run())


def test_cancel_scope_capability_and_no_secret_in_task_state(
    monkeypatch: pytest.MonkeyPatch, restore_server: Any
) -> None:
    srv = _reload(monkeypatch, on=True)
    started = asyncio.Event()

    def stalled(upstream: uh.FakeUpstream) -> Any:
        async def handler(req: httpx.Request) -> httpx.Response:
            started.set()
            await asyncio.Event().wait()  # the upstream never answers; only a cancel ends it
            return upstream(req)

        return handler

    monkeypatch.setattr(uh, "_yielding", stalled)
    uh.install(monkeypatch, uh.FakeUpstream())
    secret = "Bearer sekret-token-value-123"

    async def run() -> None:
        async with _client(srv) as client:
            mine = {"Authorization": secret}
            handle = _body(
                await _modern(
                    client,
                    "tools/call",
                    {"name": "search_across_sites", "arguments": {"query": "ap"}},
                    tasks=True,
                    name="search_across_sites",
                    headers=mine,
                )
            )["result"]
            task_id = handle["taskId"]
            store = srv.mcp._extensions[TASKS]._store
            for _ in range(500):
                if started.is_set() or store._tasks[task_id].status != "working":
                    break
                await _SLEEP(0.01)
            assert started.is_set(), repr(store._tasks[task_id].detail())
            store = srv.mcp._extensions[TASKS]._store
            assert secret not in repr(store._tasks) and "sekret" not in repr(
                vars(store._tasks[task_id])
            )
            # another caller cannot see or cancel it
            other = _body(
                await _modern(
                    client,
                    "tasks/get",
                    {"taskId": task_id},
                    tasks=True,
                    name=task_id,
                    headers={"Authorization": "Bearer someone-else"},
                )
            )
            assert other["error"]["message"] == "Task not found"
            # tasks/* without the capability: -32021
            nocap = _body(
                await _modern(
                    client,
                    "tasks/get",
                    {"taskId": task_id},
                    tasks=False,
                    name=task_id,
                    headers=mine,
                )
            )
            assert nocap["error"]["code"] == -32021
            working = _body(
                await _modern(
                    client, "tasks/get", {"taskId": task_id}, tasks=True, name=task_id, headers=mine
                )
            )
            assert working["result"]["status"] == "working"
            runner = store._tasks[task_id].runner
            assert runner in background_tasks._RUNNING
            ack = _body(
                await _modern(
                    client,
                    "tasks/cancel",
                    {"taskId": task_id},
                    tasks=True,
                    name=task_id,
                    headers=mine,
                )
            )
            assert (
                ack["result"] == {"resultType": "complete"}
                or ack["result"]["resultType"] == "complete"
            )
            gone = _body(
                await _modern(
                    client, "tasks/get", {"taskId": task_id}, tasks=True, name=task_id, headers=mine
                )
            )
            assert gone["result"]["status"] == "cancelled"
            await _SLEEP(0)
            assert store._tasks[task_id].runner is None
            for _ in range(500):
                if runner.done():
                    break
                await _SLEEP(0.01)
            assert runner.cancelled() and runner not in background_tasks._RUNNING
            del runner
            assert _retained_refs(store, secret) == []

    asyncio.run(run())


def test_task_methods_are_not_found_on_a_legacy_connection(
    monkeypatch: pytest.MonkeyPatch, restore_server: Any
) -> None:
    srv = _reload(monkeypatch, on=True)

    async def run() -> None:
        async with _client(srv) as client:
            init = await client.post(
                "/mcp",
                headers=_HEADERS,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": LEGACY,
                        "capabilities": {"extensions": {TASKS: {}}},
                        "clientInfo": {"name": "legacy", "version": "1.0"},
                    },
                },
            )
            headers = {**_HEADERS, "MCP-Protocol-Version": LEGACY}
            if init.headers.get("mcp-session-id"):
                headers["Mcp-Session-Id"] = init.headers["mcp-session-id"]
            resp = await client.post(
                "/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "id": 3, "method": "tasks/get", "params": {"taskId": "x"}},
            )
            assert _body(resp)["error"]["code"] == -32601

    asyncio.run(run())


# --------------------------------------------------------------------------- retention (C1)


def _retained_refs(store: Any, *secrets: str) -> list[str]:
    """What stays reachable from the task store that it must not hold: an HTTP request, a
    copied context, a running Task, or a string carrying one of ``secrets`` (a RETAINED_REFS
    probe over every object the store reaches, not only its repr)."""
    import gc
    import types

    from starlette.requests import Request

    gc.collect()
    found: list[str] = []
    seen: set[int] = set()
    stack: list[Any] = [store]
    while stack:
        obj = stack.pop()
        if id(obj) in seen or isinstance(obj, (type, types.ModuleType, types.FunctionType)):
            continue
        seen.add(id(obj))
        if isinstance(obj, Request):
            found.append("Request")
        elif isinstance(obj, (contextvars.Context, asyncio.Task)):
            found.append(type(obj).__name__)
        elif isinstance(obj, (str, bytes)):
            text = obj if isinstance(obj, str) else obj.decode("latin-1")
            found.extend(f"secret:{x[:6]}" for x in secrets if x in text)
            continue
        stack.extend(gc.get_referents(obj))
    return found


@pytest.mark.parametrize(
    ("env", "headers"),
    [
        ({}, {"Authorization": "Bearer retained-probe-token-abc"}),
        (
            {"UNIFI_KEY_MODE": "header"},
            {"X-UniFi-Api-Key": json.dumps({"primary": "retained-probe-unifi-key-xyz"})},
        ),
    ],
    ids=["authorization", "header-key-mode"],
)
def test_a_finished_task_keeps_no_request_header_or_context(
    monkeypatch: pytest.MonkeyPatch,
    restore_server: Any,
    env: dict[str, str],
    headers: dict[str, str],
) -> None:
    srv = _reload(monkeypatch, on=True, env=env)
    _install(monkeypatch)
    secret = next(iter(headers.values()))

    async def run() -> None:
        async with _client(srv) as client:
            handle = _body(
                await _modern(
                    client,
                    "tools/call",
                    {"name": "search_across_sites", "arguments": {"query": "probe-object"}},
                    tasks=True,
                    name="search_across_sites",
                    headers=headers,
                )
            )["result"]
            done = await _poll(client, handle["taskId"], headers=headers)
            assert done["result"]["status"] == "completed", done
            store = srv.mcp._extensions[TASKS]._store
            assert store._tasks[handle["taskId"]].runner is None
            assert _retained_refs(store, secret, secret[-12:]) == []

    asyncio.run(run())


# --------------------------------------------------------------------------- isolation (C2)


def _scope(
    monkeypatch: pytest.MonkeyPatch, token: Any = None, headers: Mapping[str, str] | None = None
) -> str:
    from fastmcp.server import dependencies
    from starlette.datastructures import Headers

    class _Req:
        def __init__(self, h: Mapping[str, str]) -> None:
            self.headers = Headers(dict(h))

    def no_request() -> Any:
        raise RuntimeError("no request")

    monkeypatch.setattr(dependencies, "get_access_token", lambda: token)
    monkeypatch.setattr(
        dependencies,
        "get_http_request",
        (lambda: _Req(headers)) if headers is not None else no_request,
    )
    return background_tasks.caller_scope()


def _token(raw: str, client: str = "client-a", sub: str | None = "user-1") -> Any:
    from fastmcp.server.auth import AccessToken

    return AccessToken(token=raw, client_id=client, scopes=[], claims={"sub": sub} if sub else {})


def test_an_oauth_refresh_keeps_the_scope_and_subjects_are_separate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _scope(monkeypatch, _token("token-1"), {"authorization": "Bearer token-1"})
    refreshed = _scope(monkeypatch, _token("token-2"), {"authorization": "Bearer token-2"})
    assert first == refreshed  # the principal, not the token, is the scope
    other = _scope(monkeypatch, _token("token-3", sub="user-2"), {"authorization": "Bearer x"})
    assert other != first
    other_client = _scope(monkeypatch, _token("token-4", client="client-b"), {})
    assert other_client != first


def test_a_shared_credential_is_one_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    # bearer mode: one static token, client_id "mcp", no sub: every caller is one principal.
    bearer = _token("static", client="mcp", sub=None)
    a = _scope(monkeypatch, bearer, {"authorization": "Bearer static", "x-forwarded-user": "a"})
    b = _scope(monkeypatch, bearer, {"authorization": "Bearer static", "x-forwarded-user": "b"})
    assert a == b  # documented: users behind one gateway credential share a scope
    # auth none: the Authorization value separates; none sent is one shared scope.
    assert _scope(monkeypatch, None, {"authorization": "Bearer g1"}) != _scope(
        monkeypatch, None, {"authorization": "Bearer g2"}
    )
    assert _scope(monkeypatch, None, {}) == _scope(monkeypatch, None, {"x-forwarded-user": "z"})
    # header key mode: different UniFi keys are different callers.
    assert _scope(monkeypatch, None, {"x-unifi-api-key": '{"a":"k1"}'}) != _scope(
        monkeypatch, None, {"x-unifi-api-key": '{"a":"k2"}'}
    )
    assert _scope(monkeypatch, None, None) == "local"


# --------------------------------------------------------------------------- retention caps (F1)


def test_one_caller_cannot_flush_another_callers_results() -> None:
    store = background_tasks.TaskStore()
    victim = store.create("victim")
    assert victim is not None
    store.finish(victim, "completed", result={"content": []})
    for n in range(20):  # 20 other callers, each over its own cap
        for _ in range(background_tasks.MAX_RETAINED_PER_SCOPE + 5):
            task = store.create(f"other-{n}")
            assert task is not None
            store.finish(task, "completed", result={"content": []})
    assert store.get("victim", victim.task_id).status == "completed"
    finished = [t for t in store._tasks.values() if t.status != "working"]
    assert len(finished) <= background_tasks.MAX_RETAINED_TASKS
    per_scope: dict[str, int] = {}
    for task in finished:
        per_scope[task.scope] = per_scope.get(task.scope, 0) + 1
    assert max(per_scope.values()) <= background_tasks.MAX_RETAINED_PER_SCOPE
    assert all(t.runner is None for t in finished)


# --------------------------------------------------------------------------- discovery (F2)


def test_only_discovery_changes_when_the_switch_is_on(
    monkeypatch: pytest.MonkeyPatch, restore_server: Any
) -> None:
    async def answers(srv: Any) -> tuple[bytes, dict[str, Any]]:
        async with _client(srv) as client:
            listed = await _modern(client, "tools/list", {}, tasks=True)
            discover = _body(await _modern(client, "server/discover", {}, tasks=True))
        return listed.content, discover["result"]["capabilities"]

    off_list, off_caps = asyncio.run(answers(_reload(monkeypatch, on=False)))
    on_list, on_caps = asyncio.run(answers(_reload(monkeypatch, on=True)))
    assert on_list == off_list  # no per-tool task support is advertised
    assert b"taskSupport" not in on_list
    assert on_caps["extensions"].pop(TASKS) == {}
    assert on_caps == off_caps


# --------------------------------------------------------------------------- strong refs (N3)


def test_a_cancelled_call_is_held_until_its_cleanup_ends() -> None:
    import gc
    import weakref

    async def run() -> None:
        release = asyncio.Event()
        cleaned: list[bool] = []

        async def call() -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await release.wait()  # cleanup that outlasts the cancel request
                cleaned.append(True)
                raise

        store = background_tasks.TaskStore()
        task = store.create("scope")
        assert task is not None
        background_tasks._spawn(task, call(), "unifi-task:test")
        await _SLEEP(0)
        runner = weakref.ref(task.runner)
        # what tasks/cancel does: cancel, then the record drops its reference
        task.runner.cancel()
        store.finish(task, "cancelled")
        assert task.runner is None
        await _SLEEP(0)
        gc.collect()
        alive = runner()
        assert alive is not None and alive in background_tasks._RUNNING and not alive.done()
        del alive
        release.set()
        for _ in range(100):
            await _SLEEP(0)
            if cleaned:
                break
        await _SLEEP(0)
        assert cleaned == [True]
        gc.collect()
        assert runner() is None or runner() not in background_tasks._RUNNING

    asyncio.run(run())
