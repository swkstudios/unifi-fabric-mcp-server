"""Fresh-interpreter probes for tests/test_deferred_loading.py (public #41).

Each scenario runs in its own interpreter, so ``sys.modules`` and the server's load state
start empty, and prints one JSON object on its last stdout line. Run from the repository
root: ``python -m tests.deferred_probe <scenario> [arg]``. No live console: every call goes
to the shape-faithful fake upstream of ``tests/upstream_harness.py``.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import sys
import threading
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "src", ROOT, ROOT / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

for _name in [n for n in os.environ if n.startswith(("UNIFI_", "MCP_"))]:
    if _name not in ("UNIFI_PRELOAD", "UNIFI_EXCLUDE", "UNIFI_WRITE_POLICY", "UNIFI_TOOL_MODE"):
        del os.environ[_name]

FAMILIES_PREFIX = "unifi_fabric.families."
_FAKES: list[Any] = []


def family_modules() -> list[str]:
    """Every imported module under a family directory (not the package root)."""
    return sorted(
        name
        for name in sys.modules
        if name.startswith(FAMILIES_PREFIX) and name.count(".") >= 3 and sys.modules[name]
    )


@contextlib.asynccontextmanager
async def session(mode: str = "full", env: dict[str, str] | None = None) -> AsyncIterator[Any]:
    import pytest
    from fastmcp import Client

    from tests import upstream_harness as uh
    from unifi_fabric import server

    with pytest.MonkeyPatch.context() as mp:
        for name, value in (env or {}).items():
            mp.setenv(name, value)
        fake = uh.FakeUpstream()
        _FAKES.append(fake)
        uh.install(mp, fake, tool_mode=mode)
        async with Client(server.mcp) as client:
            yield client


def envelope(result: Any) -> dict[str, Any]:
    return {
        "isError": bool(result.is_error),
        "content": [b.model_dump(by_alias=True, exclude_none=True) for b in result.content],
        "structuredContent": result.structured_content,
    }


async def call(client: Any, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        return envelope(await client.call_tool(name, arguments, raise_on_error=False))
    except Exception as exc:  # noqa: BLE001 - a protocol failure is a result too
        return {"raised": type(exc).__name__, "message": str(exc)}


def read_args(name: str) -> dict[str, Any]:
    from tests import tool_args
    from unifi_fabric import server

    tool = server.mcp._local_provider._components[f"tool:{name}@"]  # noqa: SLF001
    return dict(tool_args.generated_args(tool))


def controller() -> Any:
    from unifi_fabric import server
    from unifi_fabric.catalog import deferred

    found = deferred.controller_for(server.mcp)
    assert found is not None, "the server is not deferring"
    return found


def capture_events(ctrl: Any) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    previous = ctrl._emit  # noqa: SLF001

    def emit(line: str) -> None:
        events.append(json.loads(line))
        if previous is not None:
            previous(line)

    ctrl._emit = emit  # noqa: SLF001
    return events


def step_of(name: str) -> int:
    return int(controller().records[name]["step"])


# ----------------------------------------------------------------------------- scenarios


async def parity() -> dict[str, Any]:
    """Cold listing and describe equal warm; each family's pinned read call cold equals
    warm; no family module is imported before the first call."""
    import dump_tool_baseline as dtb

    from unifi_fabric import server
    from unifi_fabric.catalog import deferred

    os.environ["UNIFI_PRELOAD"] = "none"
    imported_at_import = family_modules()
    cold_full, _ = await dtb.capture_tools()
    names = [entry["name"] for entry in cold_full]
    sample = names[:: max(1, len(names) // 40)]
    cold_describe = await dtb.capture_describe(sample)
    imported_after_list = family_modules()
    cold_calls: dict[str, Any] = {}
    warm_calls: dict[str, Any] = {}
    for family, plan in dtb.FAMILY_CALLS.items():
        tool = str(plan["read"])
        args = read_args(tool)
        async with session() as client:
            cold_calls[family] = await call(client, tool, args)
            warm_calls[family] = await call(client, tool, args)
    deferred.load_all(server.mcp)
    warm_full, _ = await dtb.capture_tools()
    warm_describe = await dtb.capture_describe(sample)
    return {
        "imported_at_import": imported_at_import,
        "imported_after_list": imported_after_list,
        "listed": len(cold_full),
        "full_equal": cold_full == warm_full,
        "describe_equal": cold_describe == warm_describe,
        "described": len(sample),
        "calls_equal": cold_calls == warm_calls,
        "calls_errors": sorted(f for f, r in cold_calls.items() if r.get("isError")),
        "loaded": sum(1 for v in controller().state().values() if v == "loaded"),
    }


async def disabled(family: str) -> dict[str, Any]:
    """``UNIFI_EXCLUDE=family:<family>`` with ``UNIFI_PRELOAD=all``: call one read tool of
    every other family; report which of the family's modules were imported and which of
    its steps ran."""
    import dump_tool_baseline as dtb

    ctrl = controller()
    events = capture_events(ctrl)
    env = {"UNIFI_EXCLUDE": f"family:{family}", "UNIFI_PRELOAD": "all"}
    results: dict[str, Any] = {}
    # Arguments from the registered stubs, before the session hides the excluded family.
    args = {str(plan["read"]): read_args(str(plan["read"])) for plan in dtb.FAMILY_CALLS.values()}
    async with session(env=env) as client:
        for other, plan in dtb.FAMILY_CALLS.items():
            if other == family:
                continue
            tool = str(plan["read"])
            results[other] = await call(client, tool, args[tool])
        own = str(dtb.FAMILY_CALLS[family]["read"])
        refused = await call(client, own, args[own])
    prefix = f"{FAMILIES_PREFIX}{family}."
    family_steps = {s.entry.ref for s in ctrl.steps if s.entry.family == family}
    tools_of_family = {n for n, r in ctrl.records.items() if r["family"] == family}
    loaded_with_family_tools = sorted(
        s.entry.ref
        for s in ctrl.steps
        if s.state == "loaded" and any(n in tools_of_family for n in s.names)
    )
    return {
        "family": family,
        "imported": sorted(m for m in family_modules() if m.startswith(prefix)),
        "steps_of_family_ran": sorted(
            e["step"] for e in events if e["step"] in family_steps and e["outcome"] == "loaded"
        ),
        "steps_with_family_tools_loaded": loaded_with_family_tools,
        "other_calls_ok": sorted(f for f, r in results.items() if not r.get("isError")),
        "other_calls_error": sorted(f for f, r in results.items() if r.get("isError")),
        "own_call_refused": bool(refused.get("isError")),
        "own_call_code": _code(refused),
        "preload_loaded": len([e for e in events if e["trigger"] == "preload"]),
    }


def _code(result: dict[str, Any]) -> str | None:
    try:
        return json.loads(result["content"][0]["text"])["error"]["code"]
    except (KeyError, IndexError, TypeError, ValueError):
        return None


async def concurrent() -> dict[str, Any]:
    """20 parallel first calls of one cold tool, 30 more on two other tools of the same
    step, and 8 threads resolving a ``server.<tool>`` re-export of it, all at once."""
    import importlib

    from unifi_fabric import server

    ctrl = controller()
    events = capture_events(ctrl)
    name, others = "list_hosts", ("get_host", "list_sites")
    index = step_of(name)
    step = ctrl.steps[index]
    assert all(step_of(o) == index for o in others)
    module = importlib.import_module(step.entry.module_path)
    original = getattr(module, step.entry.function)
    calls = {"n": 0}
    lock = threading.Lock()

    def counting(*args: Any, **kwargs: Any) -> Any:
        with lock:
            calls["n"] += 1
        return original(*args, **kwargs)

    setattr(module, step.entry.function, counting)
    export = next(iter(step.exports))
    thread_results: list[Any] = []
    barrier = threading.Barrier(8)

    def resolve_attribute() -> None:
        barrier.wait()
        thread_results.append(getattr(server, export))

    os.environ["UNIFI_PRELOAD"] = "none"
    async with session() as client:
        args = {n: read_args(n) for n in (name, *others)}
        threads = [threading.Thread(target=resolve_attribute) for _ in range(8)]
        for thread in threads:
            thread.start()
        batch = [call(client, name, args[name]) for _ in range(20)]
        batch += [call(client, others[i % 2], args[others[i % 2]]) for i in range(30)]
        results = await asyncio.gather(*batch)
        for thread in threads:
            thread.join()
        swapped = type(server.mcp._local_provider._components[f"tool:{name}@"]).__name__  # noqa: SLF001
    first = results[:20]
    return {
        "register_calls": calls["n"],
        "load_events": len([e for e in events if e["step"] == step.entry.ref]),
        "outcomes": sorted({e["outcome"] for e in events}),
        "same_results": all(r == first[0] for r in first),
        "errors": sum(1 for r in results if r.get("isError") or "raised" in r),
        "threads_same_object": (
            len({id(r) for r in thread_results}) == 1 and len(thread_results) == 8
        ),
        "registered_type": swapped,
        "parallel_same_tool": len(first),
        "total_calls": len(results),
    }


async def failure(preload: str = "none") -> dict[str, Any]:
    """A seeded import error (one step) and a seeded register that registers its tools on
    staging and then raises with a key-shaped string and a host name in its message."""
    import dump_tool_baseline as dtb

    from unifi_fabric import server

    ctrl = controller()
    events = capture_events(ctrl)
    secret = "sk-test-0123456789abcdefABCDEF0123456789"  # noqa: S105  # gitleaks:allow
    host = "console-7.internal.example.test"
    # (1) import error: the event_streams step's module cannot be imported.
    poisoned_import = ctrl.steps[step_of("get_event_stream_status")]
    sys.modules[poisoned_import.entry.module_path] = None  # type: ignore[assignment]
    # (2) register raising after registering every tool on staging.
    import importlib

    raising = ctrl.steps[step_of("list_hotspot_operators")]
    module = importlib.import_module(raising.entry.module_path)
    original = getattr(module, raising.entry.function)

    def half(mcp: Any, deps: Any) -> Any:
        original(mcp, deps)
        raise RuntimeError(f"seeded failure for {host} with key {secret}")

    setattr(module, raising.entry.function, half)
    os.environ["UNIFI_PRELOAD"] = preload
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        listed_before, _ = await dtb.capture_tools()
        async with session() as client:
            failed_import = await call(client, "get_event_stream_status", {})
            failed_register = await call(
                client, "list_hotspot_operators", read_args("list_hotspot_operators")
            )
            failed_write = await call(
                client, "delete_hotspot_operator", read_args("delete_hotspot_operator")
            )
            again = await call(
                client, "list_hotspot_operators", read_args("list_hotspot_operators")
            )
            same_family = await call(client, "get_system_log", read_args("get_system_log"))
            other_family = await call(client, "list_networks", read_args("list_networks"))
    listed_after, _ = await dtb.capture_tools()
    captured = stderr.getvalue()
    records = [e for e in events if e["outcome"] != "loaded"]
    hotspot_types = {
        type(server.mcp._local_provider._components[f"tool:{n}@"]).__name__  # noqa: SLF001
        for n in raising.names
    }
    return {
        "import_code": _code(failed_import),
        "register_code": _code(failed_register),
        "write_code": _code(failed_write),
        "again_code": _code(again),
        "same_family_ok": not same_family.get("isError"),
        "same_family_code": _code(same_family),
        # Steps sharing the poisoned module: one family's steps live in one registrar module,
        # so its import error fails each of them (the failure stays inside the family).
        "poisoned_steps": sum(
            1 for step in ctrl.steps if step.entry.module_path == poisoned_import.entry.module_path
        ),
        "other_family_ok": not other_family.get("isError"),
        "listed_unchanged": listed_before == listed_after,
        "hotspot_registered_types": sorted(hotspot_types),
        "failed_records": records,
        "record_keys": sorted({k for e in records for k in e}),
        "secret_in_stderr": secret in captured,
        "host_in_stderr": host in captured,
        "secret_in_events": secret in json.dumps(events),
        "host_in_events": host in json.dumps(events),
        "states": {
            "import": ctrl.steps[poisoned_import.index].state,
            "register": ctrl.steps[raising.index].state,
        },
        "triggers": sorted({e["trigger"] for e in records}),
        "loaded_steps": sum(1 for v in ctrl.state().values() if v == "loaded"),
        "stderr_tail": captured[-2000:],
    }


async def mismatch(kind: str) -> dict[str, Any]:
    """A stale snapshot: one record's wire entry (``wire``) or write verbs (``verbs``)
    differs from what its step registers. The step must fail closed."""
    ctrl = controller()
    events = capture_events(ctrl)
    name = "create_network"
    record = dict(ctrl.records[name])
    if kind == "wire":
        record["description"] = (record.get("description") or "") + " (stale)"
    else:
        # The dangerous direction: the snapshot calls a write tool a read.
        record["write_verbs"] = []
    ctrl.records[name] = record
    os.environ["UNIFI_PRELOAD"] = "none"
    os.environ["UNIFI_WRITE_POLICY"] = "allow"
    async with session() as client:
        write = await call(client, name, read_args(name))
        sibling = await call(client, "list_networks", read_args("list_networks"))
    upstream_writes = _upstream_writes()
    return {
        "write_code": _code(write),
        "sibling_code": _code(sibling),
        "outcomes": [e["outcome"] for e in events],
        "state": ctrl.steps[step_of(name)].state,
        "upstream_writes": upstream_writes,
    }


def _upstream_writes() -> int:
    """Non-GET requests the fake upstreams of this process served."""
    return sum(1 for fake in _FAKES for served in fake.served if served.method != "GET")


async def floor(path: str) -> dict[str, Any]:
    """Safety floor per load path: once a step is loaded by ``path`` (call, backstop,
    attribute, adapter, preload), every live tool of it carries the resolution-state and
    redaction wrappers, and a cold write under ``UNIFI_WRITE_POLICY=dry-run`` sends nothing."""
    from unifi_fabric import redaction, resolution_state, server
    from unifi_fabric.catalog import deferred

    ctrl = controller()
    name = "create_network"
    index = step_of(name)
    env = {"UNIFI_WRITE_POLICY": "dry-run", "UNIFI_REDACT_SECRETS": "true"}
    result: dict[str, Any] | None = None
    if path == "attribute":
        export = sorted(ctrl.steps[index].exports)[0]
        getattr(server, export)
    elif path == "adapter":
        from unifi_fabric._adapter_runtime import registered_wrapper

        registered_wrapper(name)
    os.environ["UNIFI_PRELOAD"] = "all" if path == "preload" else "none"
    async with session(env=env) as client:
        if path == "call":
            result = await call(client, name, read_args(name))
        elif path == "backstop":
            stub = server.mcp._local_provider._components[f"tool:{name}@"]  # noqa: SLF001
            assert isinstance(stub, deferred.DeferredTool)
            await stub._run(read_args(name))  # noqa: SLF001 - the hashed-dispatch entry
        elif path in ("attribute", "adapter", "preload"):
            result = await call(client, name, read_args(name))
        upstream_writes = _upstream_writes()
    live = server.mcp._local_provider._components  # noqa: SLF001
    tools = [live[f"tool:{n}@"] for n in ctrl.steps[index].names if f"tool:{n}@" in live]
    return {
        "path": path,
        "state": ctrl.steps[index].state,
        "deferred_left": sum(1 for t in tools if isinstance(t, deferred.DeferredTool)),
        "redaction_wrapped": all(
            getattr(t.fn, redaction._WRAPPED_FLAG, False)  # noqa: SLF001
            or getattr(getattr(t.fn, "__wrapped__", None), redaction._WRAPPED_FLAG, False)  # noqa: SLF001
            for t in tools
        ),
        "resolution_wrapped": all(_has_flag(t.fn, resolution_state._WRAPPED) for t in tools),  # noqa: SLF001
        "tools": len(tools),
        "dry_run_preview": None if result is None else not result.get("isError"),
        "upstream_writes": upstream_writes,
    }


def _has_flag(fn: Any, flag: str) -> bool:
    seen = 0
    while fn is not None and seen < 10:
        if getattr(fn, flag, False):
            return True
        fn = getattr(fn, "__wrapped__", None)
        seen += 1
    return False


async def cancelwaiter() -> dict[str, Any]:
    """Two concurrent cold first calls of one step through the server's ``get_tool``; one
    is cancelled while the step is still loading. The other must still get the real tool,
    the shared load must not be cancelled, and later sync and async loads must work."""
    from unifi_fabric import server

    ctrl = controller()
    name = "list_hosts"
    index = step_of(name)
    step = ctrl.steps[index]
    first = asyncio.ensure_future(server.mcp.get_tool(name))
    second = asyncio.ensure_future(server.mcp.get_tool(name))
    while step.future is None:
        await asyncio.sleep(0)
    await asyncio.sleep(0)  # both callers are now waiting on the shared load
    loading_when_cancelled = not step.future.done()
    second.cancel()
    try:
        await second
        second_outcome = "not cancelled"
    except asyncio.CancelledError:
        second_outcome = "CancelledError"
    try:
        tool = await first
        first_outcome = type(tool).__name__
    except BaseException as exc:  # noqa: BLE001 - the outcome is the result
        first_outcome = type(exc).__name__
    try:
        ctrl.ensure(index, "adapter")
        sync_outcome = "ok"
    except BaseException as exc:  # noqa: BLE001
        sync_outcome = type(exc).__name__
    export = sorted(step.exports)[0]
    try:
        getattr(server, export)
        attribute_outcome = "ok"
    except BaseException as exc:  # noqa: BLE001
        attribute_outcome = type(exc).__name__
    try:
        await server.mcp.get_tool(name)
        later_async = "ok"
    except BaseException as exc:  # noqa: BLE001
        later_async = type(exc).__name__
    return {
        "loading_when_cancelled": loading_when_cancelled,
        "cancelled_caller": second_outcome,
        "other_caller": first_outcome,
        "shared_future_cancelled": step.future.cancelled(),
        "state": step.state,
        "later_sync_ensure": sync_outcome,
        "later_attribute": attribute_outcome,
        "later_async": later_async,
    }


async def syncloop() -> dict[str, Any]:
    """Design review C1: an async first load owns a step, and before it is built a
    synchronous load of the same step runs on the event-loop thread (an adapter or a
    ``server.<name>`` access). The owner must have submitted the build before its first
    suspension, so the synchronous caller waits for a running build, never a deadlock."""
    ctrl = controller()
    index = step_of("list_hosts")
    step = ctrl.steps[index]
    task = asyncio.ensure_future(ctrl.ensure_async(index, "call"))
    await asyncio.sleep(0)  # the owner runs up to its first suspension
    claimed = step.future is not None
    submitted = getattr(ctrl, "_executor", None) is not None  # the build is queued
    if not (claimed and submitted):
        task.cancel()
        return {"claimed": claimed, "submitted": submitted, "sync_returned": False}
    ctrl.ensure(index, "adapter")  # on the loop thread, as an adapter would
    state_after_sync = step.state
    await task
    return {
        "claimed": claimed,
        "submitted": submitted,
        "sync_returned": True,
        "state_after_sync": state_after_sync,
        "state": step.state,
    }


SCENARIOS = {
    "cancelwaiter": cancelwaiter,
    "syncloop": syncloop,
    "parity": parity,
    "disabled": disabled,
    "concurrent": concurrent,
    "failure": failure,
    "mismatch": mismatch,
    "floor": floor,
}


def main() -> None:
    scenario = sys.argv[1]
    args = sys.argv[2:]
    out = asyncio.run(SCENARIOS[scenario](*args))
    sys.stdout.write("\n" + json.dumps(out, sort_keys=True, default=str) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
