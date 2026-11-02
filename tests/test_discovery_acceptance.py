"""Discovery-mode acceptance at the full catalog.

Each test names the binding acceptance bullet it proves. Every property runs over the
whole registered catalog, so a tool added later is covered on registration. Full-mode
direct calls and discovery-wrapper calls run on two clones of the same registered tools
against the same recorded-shape mock transport, so any difference is the wrapper's.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import os
import subprocess
import sys
import textwrap
import time
from collections import Counter
from functools import cache
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import Client, FastMCP
from pydantic import ValidationError

from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_catalog import LazyCatalog, lazy_parametrize
from unifi_fabric import _read_only_audit, server, switches
from unifi_fabric._read_only_audit import derive_write_tools, is_destructive, write_verbs_for
from unifi_fabric.config import Settings
from unifi_fabric.discovery import META_TOOLS, apply_tool_mode
from unifi_fabric.families import (
    _REGISTER_MODULES,
    ALL_FAMILIES,
    MODULE_FAMILY,
    apply_tool_family_filter,
    build_family_index,
)
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.tools import protect

FIVE = ("search_tools", "describe_tool", "call_read_tool", "call_write_tool", "list_tool_families")
GATEWAY_PREFIX = "gateway-prefix-"


TOOLS = LazyCatalog()
NO_UPSTREAM = {"list_configured_api_keys"}


@cache
def _writes() -> set[str]:
    return derive_write_tools(list(TOOLS.values()))


def _reads() -> list[str]:
    return sorted(set(TOOLS) - _writes())


def _clone() -> FastMCP:
    app = FastMCP("discovery-acceptance")
    for tool in TOOLS.values():
        app.add_tool(tool)
    app.middleware = list(server.mcp.middleware)
    return app


@pytest.fixture(scope="module", autouse=True)
def _catalog_apps():
    global WRITES, READS, FAMILY, FULL, DISCOVERY
    WRITES = _writes()
    READS = _reads()
    FAMILY = build_family_index()
    FULL = _clone()
    DISCOVERY = _clone()
    asyncio.run(apply_tool_mode(DISCOVERY, "discovery"))


def _envelope(result: Any) -> str:
    """The client-visible CallToolResult, serialized byte-exactly."""
    if isinstance(result, _Raised):
        return f"raised {result.kind}"
    return json.dumps(
        {
            "content": [
                block.model_dump(by_alias=True, exclude_none=True) for block in result.content
            ],
            "structuredContent": result.structured_content,
            "isError": result.is_error,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )


class _Raised:
    """A call that raised instead of returning a CallToolResult (e.g. a mock-transport
    replay gap); both paths must raise the same exception type."""

    is_error = True
    content: list[Any] = []
    structured_content = None

    def __init__(self, exc: BaseException) -> None:
        self.kind = type(exc).__name__


async def _direct(name: str, arguments: dict[str, Any]) -> Any:
    try:
        async with Client(FULL) as client:
            return await client.call_tool(name, arguments, raise_on_error=False)
    except Exception as exc:  # noqa: BLE001 - compared against the wrapped path below
        return _Raised(exc)


async def _wrapped(wrapper: str, name: str, arguments: dict[str, Any]) -> Any:
    try:
        async with Client(DISCOVERY) as client:
            return await client.call_tool(
                wrapper, {"name": name, "arguments": arguments}, raise_on_error=False
            )
    except Exception as exc:  # noqa: BLE001 - compared against the direct path
        return _Raised(exc)


def _error_text(result: Any) -> str:
    return " ".join(getattr(block, "text", "") for block in result.content)


#: A fixed wall clock: tools that default a time window to "now" (collect_protect_events)
#: must build the same request on the direct and wrapped call for a byte-exact compare.
FROZEN_NOW = 1_792_000_000.0


def _env(monkeypatch, name: str, extra: dict[str, str] | None = None) -> None:
    monkeypatch.setattr(time, "time", lambda: FROZEN_NOW)
    for key, value in {**tool_args.TOOL_ENV.get(name, {}), **(extra or {})}.items():
        monkeypatch.setenv(key, value)


# --------------------------------------------------------------------------- bullet 1
async def test_b1_discovery_lists_exactly_the_five_meta_tools() -> None:
    async with Client(DISCOVERY) as client:
        tools = await client.list_tools()
    assert sorted(tool.name for tool in tools) == sorted(FIVE)
    assert len(tools) == 5
    # Inner names are raw underscore names; a gateway prefixes hyphenated slugs. The
    # slug rule is injective and inverts to the raw name, so the documented
    # gateway-prefixed surface maps back to exactly these five.
    slugs = {GATEWAY_PREFIX + name.replace("_", "-"): name for name in FIVE}
    assert len(slugs) == 5
    for slug, raw in slugs.items():
        assert slug[len(GATEWAY_PREFIX) :].replace("-", "_") == raw
    annotations = {tool.name: tool.annotations for tool in tools}
    assert annotations["call_read_tool"].read_only_hint is True
    assert annotations["call_write_tool"].read_only_hint is not True
    assert annotations["call_write_tool"].destructive_hint is True


# --------------------------------------------------------------------------- bullet 2
async def test_b2_empty_query_null_limit_returns_the_full_mode_catalog() -> None:
    async with Client(FULL) as client:
        full = {tool.name for tool in await client.list_tools()}
    async with Client(DISCOVERY) as client:
        rows = (await client.call_tool("search_tools", {"query": "", "limit": None})).data
    assert len(rows) == len(full) == len(TOOLS)
    assert {row["name"] for row in rows} == full


async def test_b2_omitted_limit_is_ten_and_every_positive_limit_is_honoured() -> None:
    count = len(TOOLS)
    async with Client(DISCOVERY) as client:
        assert len((await client.call_tool("search_tools", {"query": ""})).data) == 10
        for limit in (1, 2, 7, 10, 11, 50, 333, count - 1, count, count + 1, 10**6):
            rows = (await client.call_tool("search_tools", {"query": "", "limit": limit})).data
            assert len(rows) == min(limit, count), limit
        every = (await client.call_tool("search_tools", {"query": "camera", "limit": None})).data
        assert len(every) > 10
        for limit in (1, 3, 10, len(every)):
            rows = (
                await client.call_tool("search_tools", {"query": "camera", "limit": limit})
            ).data
            assert [r["name"] for r in rows] == [r["name"] for r in every[:limit]]


# --------------------------------------------------------------------------- bullet 3
async def test_b3_describe_returns_the_bare_full_mode_schema_with_derived_hints() -> None:
    async with Client(FULL) as client:
        full = {
            tool.name: tool.model_dump(by_alias=True, exclude_none=True)
            for tool in await client.list_tools()
        }
    bad: list[str] = []
    async with Client(DISCOVERY) as client:
        for name in sorted(TOOLS):
            schema = (await client.call_tool("describe_tool", {"name": name})).data
            if schema != full[name]:
                bad.append(f"{name}: differs from its full-mode tools/list entry")
                continue
            if "tool" in schema or schema.get("name") != name:
                bad.append(f"{name}: wrapped or renamed schema")
            if not isinstance(schema.get("inputSchema"), dict):
                bad.append(f"{name}: no inputSchema")
            hint = (schema.get("annotations") or {}).get("readOnlyHint")
            if hint is not (name not in WRITES):
                bad.append(f"{name}: readOnlyHint {hint!r} != derived {name not in WRITES}")
    assert bad == [], bad[:20]


# --------------------------------------------------------------------------- bullet 4
async def test_b4_read_wrapper_refuses_every_derived_write_before_any_request(
    monkeypatch,
) -> None:
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    leaked = []
    for name in sorted(WRITES):
        arguments = tool_args.generated_args(TOOLS[name])
        if name == "fabric_connector_get":
            arguments["path"] = f"protect/api/cameras/{uh.ARG_ID}/enable-control"
        result = await _wrapped("call_read_tool", name, arguments)
        if not result.is_error or "call_write_tool" not in _error_text(result):
            leaked.append(name)
    assert leaked == [], leaked[:20]
    assert up.served == [], [s.path for s in up.served][:10]


async def test_b4_read_and_write_wrappers_share_the_name_arguments_envelope() -> None:
    async with Client(DISCOVERY) as client:
        schemas = {tool.name: tool.input_schema for tool in await client.list_tools()}
    read, write = schemas["call_read_tool"], schemas["call_write_tool"]
    assert set(read["properties"]) == set(write["properties"]) == {"name", "arguments"}
    assert sorted(read["required"]) == sorted(write["required"]) == ["arguments", "name"]
    for key in ("name", "arguments"):
        assert read["properties"][key].get("type") == write["properties"][key].get("type")


@pytest.mark.parametrize("enabled", [False, True], ids=["redaction-off", "redaction-on"])
@pytest.mark.parametrize(
    ("wrapper", "name", "module", "handler", "arguments"),
    [
        ("call_read_tool", "list_devices", "site_manager", "list_devices", {}),
        (
            "call_write_tool",
            "update_wlan_config",
            "network_services_proxy",
            "update_wlan_config",
            {"host": "h", "site": "s", "wlan_id": "w", "payload": {"enabled": True}},
        ),
    ],
)
async def test_b4_dispatch_redaction_matches_direct_calls(
    monkeypatch, enabled, wrapper, name, module, handler, arguments
) -> None:
    secret = "synthetic-upstream-password"
    response = {"data": [{"name": "example", "password": secret}]}
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1" if enabled else "0")
    monkeypatch.setattr(server, "_settings", Settings())
    monkeypatch.setattr(server, "_require", lambda: (MagicMock(), MagicMock()))
    handler_mock = AsyncMock(return_value=response)
    monkeypatch.setattr(getattr(server, module), handler, handler_mock)

    direct = await _direct(name, arguments)
    wrapped = await _wrapped(wrapper, name, arguments)
    assert not direct.is_error and not wrapped.is_error
    assert handler_mock.await_count == 2
    assert _envelope(wrapped) == _envelope(direct)
    visible = _envelope(wrapped)
    assert (REDACTION_MASK in visible) is enabled
    assert (secret in visible) is not enabled
    assert "example" in visible


def _reset_collector_pacing(monkeypatch, name: str) -> None:
    """Suppress pacing for direct and wrapped calls; tool arguments define the poll count."""
    if name not in {"collect_protect_events", "collect_protect_device_changes"}:
        return

    async def sleep(_seconds: float) -> None:
        pass

    monkeypatch.setattr(protect, "_sleep", sleep)


# Bullets 4 + 5: every read through call_read_tool returns the byte-identical envelope a
# full-mode direct call returns on the same mock transport (errors included).
@lazy_parametrize("name", lambda: [n for n in _reads() if n not in NO_UPSTREAM])
async def test_b5_read_wrapper_envelope_is_byte_identical_to_a_direct_call(
    monkeypatch, name: str
) -> None:
    _env(monkeypatch, name)
    arguments = tool_args.generated_args(TOOLS[name])
    uh.install(monkeypatch, uh.FakeUpstream())
    _reset_collector_pacing(monkeypatch, name)
    direct = await _direct(name, arguments)
    uh.install(monkeypatch, uh.FakeUpstream())
    _reset_collector_pacing(monkeypatch, name)
    wrapped = await _wrapped("call_read_tool", name, arguments)
    assert _envelope(wrapped) == _envelope(direct)


# Bullet 4: per-area opt-outs, UNIFI_READ_ONLY and dry-run bind through call_write_tool
# exactly as on a direct call (Build rules 6 and 7), and call_read_tool never runs a write.
_AREA_OPT_OUT = {
    family: switch.env
    for switch in switches.AREA_WRITE_SWITCHES
    for family in (switch.family, *switch.related_families)
}
_AREA_OPT_OUT["connector"] = "UNIFI_ENABLE_CONNECTOR_WRITE"


def _scenarios(name: str) -> dict[str, dict[str, str]]:
    out = {"read_only": {"UNIFI_READ_ONLY": "1"}, "dry_run": {"UNIFI_DRY_RUN": "1"}}
    if FAMILY.get(name) in _AREA_OPT_OUT:
        out["opt_out"] = {_AREA_OPT_OUT[FAMILY[name]]: "0"}
    return out


@lazy_parametrize("name", lambda: sorted(_writes()))
async def test_b4_write_wrapper_binds_opt_outs_read_only_and_dry_run(
    monkeypatch, name: str
) -> None:
    arguments = tool_args.generated_args(TOOLS[name])
    if name == "fabric_connector_get":
        arguments["path"] = f"protect/api/cameras/{uh.ARG_ID}/enable-control"
    scenarios = _scenarios(name)
    assert {"read_only", "dry_run"} <= set(scenarios)
    for scenario, env in scenarios.items():
        with monkeypatch.context() as m:
            _env(m, name, env)
            direct_up, wrapped_up = uh.FakeUpstream(), uh.FakeUpstream()
            uh.install(m, direct_up)
            direct = await _direct(name, arguments)
            uh.install(m, wrapped_up)
            wrapped = await _wrapped("call_write_tool", name, arguments)
            assert _envelope(wrapped) == _envelope(direct), scenario
            assert wrapped_up.writes() == [] == direct_up.writes(), scenario
            if scenario == "opt_out":
                assert wrapped.is_error and next(iter(env)) in _error_text(wrapped)
                assert wrapped_up.served == [], scenario


# --------------------------------------------------------------------------- bullet 6
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "discovery"),
        ("", "discovery"),
        (" ", "discovery"),
        ("\t\n ", "discovery"),
        ("discovery", "discovery"),
        (" Discovery ", "discovery"),
        ("full", "full"),
        ("FULL", "full"),
        ("  full\n", "full"),
    ],
)
def test_b6_tool_mode_accepts_blank_as_default_and_either_mode(value, expected) -> None:
    assert Settings(tool_mode=value).tool_mode == expected


@pytest.mark.parametrize("value", ["typo", "full,discovery", "0", "true", "fulll", "all"])
def test_b6_malformed_tool_mode_names_the_variable_and_both_modes(value) -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(tool_mode=value)
    message = str(exc.value)
    assert "UNIFI_TOOL_MODE" in message
    assert "discovery" in message and "full" in message


def test_b6_malformed_tool_mode_fails_startup_naming_the_variable() -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))}
    env.update(UNIFI_API_KEY="mode-parse-test-key", UNIFI_TOOL_MODE="discovery,full")
    proc = subprocess.run(  # noqa: S603 - this interpreter running the package entry point
        [sys.executable, "-c", "from unifi_fabric.entrypoint import main; main()"],
        env=env,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    stderr = proc.stderr.decode()
    assert "UNIFI_TOOL_MODE must be one of discovery, full" in stderr, stderr[-500:]


# --------------------------------------------------------------------------- bullet 7
async def test_b7_full_mode_advertises_the_registry_unchanged() -> None:
    """Full mode adds, removes and rewrites nothing: tools/list is the registry itself."""
    registry = [
        tool.to_mcp_tool().model_dump(by_alias=True, exclude_none=True) for tool in TOOLS.values()
    ]
    app = _clone()
    restore = await apply_tool_mode(app, "full")
    try:
        async with Client(app) as client:
            listed = [
                t.model_dump(by_alias=True, exclude_none=True) for t in await client.list_tools()
            ]
    finally:
        restore()
    key = lambda row: row["name"]  # noqa: E731
    assert sorted(listed, key=key) == sorted(registry, key=key)
    assert not META_TOOLS & {row["name"] for row in listed}


# ---------------------------------------------------------------- families roster (§2.3)
def test_roster_every_registered_tool_and_module_has_a_family() -> None:
    assert set(TOOLS) - FAMILY.keys() == set(), "unclassified tools"
    assert FAMILY.keys() - set(TOOLS) == set(), "stale family entries"
    defining = {inspect.unwrap(tool.fn).__module__.rsplit(".", 1)[-1] for tool in TOOLS.values()}
    modules = defining - {"server"}
    assert modules - MODULE_FAMILY.keys() == set(), "tool modules without a family"
    assert modules - set(_REGISTER_MODULES) == set(), "register() modules not indexed"
    assert set(FAMILY.values()) == set(ALL_FAMILIES)


async def test_roster_list_tool_families_returns_every_family_and_count() -> None:
    async with Client(DISCOVERY) as client:
        rows = (await client.call_tool("list_tool_families", {})).data
    expected = Counter(FAMILY[name] for name in TOOLS)
    assert {row["family"]: row["tools"] for row in rows} == dict(expected)
    assert [row["family"] for row in rows] == sorted(ALL_FAMILIES)
    assert sum(row["tools"] for row in rows) == len(TOOLS)


@pytest.mark.parametrize("family", ALL_FAMILIES)
async def test_roster_tool_families_removes_and_keeps_each_family(family: str) -> None:
    others = ",".join(f for f in ALL_FAMILIES if f != family)
    without = _clone()
    removed = await apply_tool_family_filter(without, others)
    assert set(removed) == {n for n in TOOLS if FAMILY[n] == family}
    only = _clone()
    await apply_tool_family_filter(only, family)
    kept = {tool.name for tool in await only.list_tools()}
    assert kept == {n for n in TOOLS if FAMILY[n] == family}
    restore = await apply_tool_mode(only, "discovery")
    try:
        async with Client(only) as client:
            rows = (await client.call_tool("list_tool_families", {})).data
            assert rows == [{"family": family, "tools": len(kept)}]
            listed = (await client.call_tool("search_tools", {"query": "", "limit": None})).data
            assert {row["name"] for row in listed} == kept
    finally:
        restore()


# ------------------------------------------------------- startup regression (§2.1 defect)
# Root cause of "server exited before answering request 1": discovery mode derives the
# write set at startup by walking every tool's call graph, and each walk re-read and
# re-parsed every shared helper (and re-parsed whole modules for classes). At 784 tools
# that took ~100 s before `initialize` was answered, past the stdio client's watchdog.


def test_write_derivation_reads_each_source_once(monkeypatch) -> None:
    calls: Counter[Any] = Counter()
    real = inspect.getsource

    def counting(obj: Any) -> str:
        # Code equality can conflate distinct source functions; count identities.
        calls[id(obj)] += 1
        return real(obj)

    _read_only_audit._source_facts.cache_clear()
    _read_only_audit._cached_source_facts.cache_clear()
    _read_only_audit._derive_write_tools.cache_clear()
    monkeypatch.setattr(_read_only_audit.inspect, "getsource", counting)
    tools = list(TOOLS.values())
    first = derive_write_tools(tools)
    destructive = {tool.name for tool in tools if is_destructive(tool.fn)}
    assert max(calls.values()) == 1, calls.most_common(3)
    reads = sum(calls.values())
    assert derive_write_tools(tools) == first == WRITES
    assert {tool.name for tool in tools if is_destructive(tool.fn)} == destructive
    assert sum(calls.values()) == reads, "a warm pass re-read source"


_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "startup-test", "version": "1"},
    },
}


def _stdio_initialize(argv: list[str], env: dict[str, str], stderr_path) -> dict[str, Any]:
    """Send ``initialize`` to a stdio server and return its id-1 response.

    The request is followed by end-of-input, so a server that never answers exits at EOF
    and the read ends at stdout EOF instead of blocking. Stderr goes to a file, never an
    undrained pipe: a server logging more than a pipe buffer cannot stall its own reply.
    """
    with open(stderr_path, "wb") as stderr:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv chosen by the caller (this repo)
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, env=env
        )
    assert proc.stdin is not None and proc.stdout is not None
    try:
        proc.stdin.write((json.dumps(_INITIALIZE) + "\n").encode())
        proc.stdin.close()
        for line in iter(proc.stdout.readline, b""):
            response = json.loads(line)
            if response.get("id") == 1:
                return response
        tail = open(stderr_path, "rb").read()[-2000:]  # noqa: SIM115 - one short read
        raise AssertionError(
            f"server closed stdout without answering initialize (rc={proc.wait()}): {tail!r}"
        )
    finally:
        proc.kill()
        proc.wait()


def test_stdio_initialize_survives_a_noisy_stderr(tmp_path) -> None:
    """A peer logging far more than a pipe buffer before answering still gets read."""
    peer = tmp_path / "peer.py"
    peer.write_text(
        "import json, sys\n"
        "sys.stderr.write('x' * (4 * 1024 * 1024)); sys.stderr.flush()\n"
        "request = json.loads(sys.stdin.readline())\n"
        "print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': {}}), flush=True)\n"
    )
    response = _stdio_initialize([sys.executable, str(peer)], dict(os.environ), tmp_path / "e")
    assert response == {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_stdio_initialize_reports_a_server_that_never_answers(tmp_path) -> None:
    """A peer that reads its input and answers nothing fails the read, never hangs it."""
    peer = tmp_path / "peer.py"
    peer.write_text("import sys\nsys.stdin.read()\nsys.stderr.write('no answer')\n")
    with pytest.raises(AssertionError, match=r"without answering initialize \(rc=0\)"):
        _stdio_initialize([sys.executable, str(peer)], dict(os.environ), tmp_path / "e")


def test_discovery_startup_answers_initialize(tmp_path) -> None:
    """Both catalog modes answer the real stdio initialize protocol.

    Source-work scaling is guarded by the deterministic read-once test above;
    host load never changes whether this functional protocol test passes.
    """

    def start(mode: str) -> dict[str, Any]:
        env = {
            k: v for k, v in os.environ.items() if not k.startswith(("UNIFI_", "MCP_", "FASTMCP_"))
        }
        env.update(UNIFI_API_KEY="startup-test-key", UNIFI_TOOL_MODE=mode)
        argv = [sys.executable, "-c", "from unifi_fabric.entrypoint import main; main()"]
        return _stdio_initialize(argv, env, tmp_path / f"{mode}.stderr")

    for mode in ("full", "discovery"):
        response = start(mode)
        assert "error" not in response, (mode, response)
        assert response["result"]["protocolVersion"] == "2025-06-18"
        assert "tools" in response["result"]["capabilities"]


def test_memoized_source_facts_still_resolve_live_globals(tmp_path, monkeypatch) -> None:
    """Only source facts are cached: rebinding a module global changes the derivation."""
    module = tmp_path / "unifi_fabric_w3probe.py"
    module.write_text(
        textwrap.dedent(
            """
            def helper():
                return None

            def writer(client):
                return client.post("/probe")

            def tool():
                return helper()
            """
        )
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    probe = importlib.import_module("unifi_fabric_w3probe")
    try:
        assert write_verbs_for(probe.tool) == set()
        monkeypatch.setattr(probe, "helper", probe.writer)
        assert write_verbs_for(probe.tool) == {"POST"}
    finally:
        sys.modules.pop("unifi_fabric_w3probe", None)
