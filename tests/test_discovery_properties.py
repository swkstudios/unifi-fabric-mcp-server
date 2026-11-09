"""Run cross-tool properties through the registered discovery split dispatch meta-tools.

Each original suite is loaded in an isolated namespace with its registry-derived
parameterization intact. Only the transport changes, so new tools and properties
automatically gain discovery coverage without changing full-mode test modules.
Explicit real MCP Client gates cover every tool and specialized result transport.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

import pytest
from fastmcp import Client, FastMCP

import tests as _tests_package
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import tool_batches
from unifi_fabric import server
from unifi_fabric.discovery import apply_tool_mode


def _load_suite(filename: str):
    module_name = f"tests._discovery_{Path(filename).stem}"
    spec = importlib.util.spec_from_file_location(module_name, Path(__file__).with_name(filename))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    # Importlib's normal package import binds the child module on its parent;
    # executing a spec directly does not. Some originating tests use pytest's
    # dotted monkeypatch target form (`__name__ + "._call"`), which resolves
    # through that package attribute.
    setattr(_tests_package, module_name.rpartition(".")[2], module)
    spec.loader.exec_module(module)
    return module


_suite = _load_suite("test_cross_tool_invariants.py")
# Temporarily bind extension imports to the isolated suite, then restore both
# bindings. The original full-mode modules remain untouched.
_missing = object()
_original_cti = sys.modules.get("tests.test_cross_tool_invariants", _missing)
_original_attribute = getattr(_tests_package, "test_cross_tool_invariants", _missing)
_ADDITIONAL_FILES = (
    "test_invariants_arrays_numbers_and_path_ids.py",
    "test_invariants_carrier_devices_and_relay_writes.py",
    "test_invariants_envelopes_and_previews.py",
    "test_invariants_paging_ids_and_relays.py",
    "test_cross_tool_chokepoints.py",
    "test_apps_nullable_properties.py",
    "test_secret_leak_invariant.py",
)
try:
    sys.modules["tests.test_cross_tool_invariants"] = _suite
    _tests_package.test_cross_tool_invariants = _suite
    _additional_suites = [_load_suite(filename) for filename in _ADDITIONAL_FILES]
finally:
    if _original_cti is _missing:
        sys.modules.pop("tests.test_cross_tool_invariants", None)
    else:
        sys.modules["tests.test_cross_tool_invariants"] = _original_cti
    if _original_attribute is _missing:
        delattr(_tests_package, "test_cross_tool_invariants")
    else:
        _tests_package.test_cross_tool_invariants = _original_attribute

# Subprocess, HTTP startup, raw client and scrubber-complexity secret tests do not
# dispatch registered tools. Repeat the four registered-tool secret properties.
_SECRET_DISPATCH_TESTS = {
    "test_no_secret_in_any_tool_error",
    "test_no_secret_in_argument_errors",
    "test_2xx_body_with_a_secret_is_returned_byte_identical",
    "test_2xx_secret_echo_is_actually_returned",
}
_WIRE_TESTS = {
    "test_s_list_valued_write_response_through_a_real_fastmcp_client",
    "test_bp_empty_body_write_through_a_real_fastmcp_client",
}
_EXPORTED_TESTS = {}


def _export_suite(module, prefix: str = "", selected=None):
    exported = set()
    for name, test in vars(module).items():
        if not name.startswith("test_") or not callable(test):
            continue
        if selected is not None and name not in selected:
            continue
        if module is _suite and name in _WIRE_TESTS:
            continue
        target = f"test_{prefix}__{name[5:]}" if prefix else name
        assert target not in globals(), f"Discovery test name collision: {target}"
        globals()[target] = test
        exported.add(name)
    _EXPORTED_TESTS[module.__name__] = exported


_export_suite(_suite)
for _module in _additional_suites:
    _prefix = Path(_module.__file__).stem.removeprefix("test_")
    _export_suite(
        _module,
        _prefix,
        _SECRET_DISPATCH_TESTS if _prefix == "secret_leak_invariant" else None,
    )

# Preserve the non-autouse fixtures needed by the selected extension tests.
carrier = _additional_suites[1].carrier
captured_logs = _additional_suites[-1].captured_logs
secret_env = _additional_suites[-1].secret_env


@pytest.fixture(autouse=True)
def _quiet_logs(request):
    # Match the originating suite's logging posture rather than imposing the main
    # suite's quiet fixture on extensions that capture audit handlers themselves.
    # Explicit capture fixtures always keep logs enabled, regardless of the origin.
    origin = sys.modules.get(request.node.obj.__module__)
    native_quiet = origin is not None and hasattr(origin, "_quiet_logs")
    capture_fixtures = {"captured_logs", "caplog", "capsys", "capfd", "capsysbinary", "capfdbinary"}
    captures = bool(capture_fixtures.intersection(request.fixturenames))
    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL if native_quiet and not captures else logging.NOTSET)
    try:
        yield
    finally:
        logging.disable(previous)


def test_discovery_suite_export_is_complete(request):
    """Missing exports or collected tests fail rather than silently lose coverage."""
    for module in [_suite, *_additional_suites]:
        expected = {
            name
            for name, test in vars(module).items()
            if name.startswith("test_") and callable(test)
        }
        if module is _suite:
            expected -= _WIRE_TESTS
        elif module is _additional_suites[-1]:
            expected &= _SECRET_DISPATCH_TESTS
        assert _EXPORTED_TESTS[module.__name__] == expected, module.__name__
    assert all(module.cti is _suite for module in _additional_suites if hasattr(module, "cti"))
    collected = {
        item.originalname for item in request.session.items if item.path == request.node.path
    }
    exported = {
        name for name, test in globals().items() if name.startswith("test_") and callable(test)
    }
    # A full, unfiltered invocation must collect every exported property.
    if not request.config.option.keyword and not request.config.option.markexpr:
        assert collected == exported, (collected - exported, exported - collected)


def test_isolated_suite_import_paths_resolve_to_the_loaded_modules():
    for module in [_suite, *_additional_suites]:
        child_name = module.__name__.rpartition(".")[2]
        assert sys.modules[module.__name__] is module
        assert getattr(_tests_package, child_name) is module


class _DiscoveryDispatcher:
    """Dispatch through the registered meta-tool and the production middleware."""

    def __init__(self, app: FastMCP):
        self.app = app

    async def call_tool(self, name: str, arguments: dict):
        # This app dispatch bypasses the full-mode call_tool wrapper installed by
        # uh.install. Prepare the same fixture and resolve only probe placeholders
        # before crossing the discovery meta-tool boundary.
        tool_args.prepare_upstream(name, getattr(server, "_harness_upstream", None))
        arguments = tool_args.resolve_placeholders(name, arguments)
        dispatcher = "call_write_tool" if name in _suite.WRITE_TOOLS else "call_read_tool"
        return await self.app.call_tool(dispatcher, {"name": name, "arguments": arguments})


class _DiscoveryServer:
    """Route both original call forms through the registered discovery meta-tool."""

    def __init__(self, app):
        self.mcp = _DiscoveryDispatcher(app)

    def __getattr__(self, name):
        if name in _suite.TOOLS:

            async def invoke(**arguments):
                return await self.mcp.call_tool(name, arguments)

            return invoke
        return getattr(server, name)


@pytest.fixture(scope="module")
async def _discovery_app():
    # The fake upstream owns client/registry installation: omit production lifespan.
    # Copy exact registered functions and middleware. Their catalog lookups still
    # see the intact original production registry.
    app = FastMCP("discovery-cross-tool-properties")
    for tool in _suite.TOOLS.values():
        app.add_tool(tool)
    app.middleware = list(server.mcp.middleware)
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        yield app
    finally:
        cleanup()


@pytest.fixture(autouse=True)
def _use_discovery_dispatch(monkeypatch, _discovery_app):
    proxy = _DiscoveryServer(_discovery_app)
    for module in [_suite, *_additional_suites]:
        if hasattr(module, "server"):
            monkeypatch.setattr(module, "server", proxy)


async def _wire_call(monkeypatch, app, name, up):
    for key, value in tool_args.TOOL_ENV.get(name, {}).items():
        monkeypatch.setenv(key, value)
    uh.install(monkeypatch, up)
    async with Client(app) as client:
        return await client.call_tool(
            "call_write_tool" if name in _suite.WRITE_TOOLS else "call_read_tool",
            {"name": name, "arguments": tool_args.generated_args(_suite.TOOLS[name])},
        )


@tool_batches("name", lambda: sorted(_suite.TOOLS))
async def test_discovery_every_tool_dispatches_over_real_mcp(monkeypatch, _discovery_app, name):
    """All underlying tools also cross an actual MCP protocol connection."""
    up = uh.FakeUpstream()
    res = await _wire_call(monkeypatch, _discovery_app, name, up)
    assert not res.is_error
    assert res.content
    if name not in _suite.NO_UPSTREAM and name not in _suite.DERIVED:
        payload = uh.result_payload(res)
        problems = _suite._fidelity_violations(name, payload, up) + _suite._binary_problems(
            name, payload, up
        )
        assert problems == [], f"{name}: " + "; ".join(problems[:5])


@pytest.mark.parametrize(
    "name",
    [
        "get_innerspace_project",
        "get_innerspace_summary",
        "get_unifi_placement_snapshot",
        "list_innerspace_devices",
    ],
)
async def test_large_innerspace_bodies_complete_through_discovery(
    monkeypatch, _discovery_app, name
):
    """The distinct large InnerSpace project shape survives real MCP dispatch."""
    up = uh.FakeUpstream(mode="big", big_items=_suite.LARGE_LIST_ITEMS)
    up.project_body = _suite._large_innerspace_project()
    res = await _wire_call(monkeypatch, _discovery_app, name, up)
    assert not res.is_error
    problems = _suite._innerspace_large_body_problems(name, uh.result_payload(res), up)
    assert problems == [], f"{name}: " + "; ".join(problems)


@pytest.mark.parametrize("name", _suite._LIST_DATA_WRITES)
async def test_s_list_valued_write_response_through_a_real_fastmcp_client(
    monkeypatch, _discovery_app, name
):
    up = uh.FakeUpstream()
    res = await _wire_call(monkeypatch, _discovery_app, name, up)
    assert not res.is_error
    write = [s for s in up.served if s.method in ("POST", "PUT")]
    assert len(write) == 1 and isinstance(write[0].body["data"], list)
    assert res.structured_content == write[0].body


@pytest.mark.parametrize("name", _suite._BP_WIRE_TOOLS)
async def test_bp_empty_body_write_through_a_real_fastmcp_client(monkeypatch, _discovery_app, name):
    up = uh.FakeUpstream(write_body="empty")
    res = await _wire_call(monkeypatch, _discovery_app, name, up)
    assert not res.is_error and up.writes()
    assert [getattr(b, "text", None) for b in res.content] == ["null"]
    assert res.structured_content == {"result": None}
    assert res.data is None
