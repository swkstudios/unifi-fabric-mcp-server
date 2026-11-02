"""Per-area write opt-outs bind every write route into the area.

Two layers enforce each opt-out in ``switches.AREA_WRITE_SWITCHES`` (Network, Protect,
Mobility, Carrier Fabric; every one default on):

* the tool middleware (``read_only_tools.AreaOptOutMiddleware``) refuses an opted-out
  area's write tools before their body runs, so an MCP call makes zero requests;
* the client chokepoint (``read_only.guard_area_write`` in ``UniFiClient.request``)
  refuses every write REQUEST to one of the area's routes, whichever tool, shared helper
  or relay sent it, so no path can bypass the opt-out (the same two layers as
  ``UNIFI_READ_ONLY``).

The tool set and each tool's areas are derived, never listed: the write tools come from
``derive_write_tools`` and a tool's areas are the routes its writes actually reach when
every area is on. For every write tool and every area opt-out set to ``0``:

* a tool writing to that area is refused naming the variable: through MCP with zero
  upstream requests, and called directly (middleware bypassed) with zero write requests;
* a tool writing only to other areas sends exactly the writes it sends with every area on.

The guard is route-based, not key-aware: no key is consulted before it refuses.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import tool_batches
from unifi_fabric import switches
from unifi_fabric._read_only_audit import derive_write_tools, write_verbs_for
from unifi_fabric.read_only import AreaOptOutError, decoded_path
from unifi_fabric.tools import connector

TOOLS = cti.TOOLS


@functools.cache
def _lz_DERIVED_WRITE_TOOLS():
    return sorted(derive_write_tools(list(TOOLS.values())))


SWITCHES = {s.env: s for s in switches.AREA_WRITE_SWITCHES}


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _env_off() -> dict[str, str]:
    """Every area on, explicitly (a deployment's environment never leaks in)."""
    return {env: "1" for env in SWITCHES}


async def _run_direct(mp: pytest.MonkeyPatch, name: str, up: uh.FakeUpstream, env: dict):
    """Run the tool body with the middleware bypassed (``FunctionTool.run``)."""
    for k, v in {**tool_args.TOOL_ENV.get(name, {}), **env}.items():
        mp.setenv(k, v)
    uh.install(mp, up)
    args = tool_args.generated_args(TOOLS[name])
    if name == "fabric_connector_get":
        # This derived-write sweep must reach the mixed relay's mutating route.
        args["path"] = f"protect/api/cameras/{uh.ARG_ID}/enable-control"
    return await TOOLS[name].run(args)


def _writes(up: uh.FakeUpstream) -> list[tuple[str, str]]:
    return [(s.method, s.path) for s in up.writes()]


def _areas(writes: list[tuple[str, str]]) -> set[str]:
    return {env for env, s in SWITCHES.items() for _m, p in writes if s.owns_route(decoded_path(p))}


async def _baseline(name: str) -> list[tuple[str, str]]:
    up = uh.FakeUpstream()
    mp = pytest.MonkeyPatch()
    try:
        try:
            await _run_direct(mp, name, up, _env_off())
        except Exception:  # noqa: BLE001 - only the writes sent matter here
            pass
    finally:
        mp.undo()
    return _writes(up)


def test_every_derived_write_tool_is_advertised_as_a_write():
    assert set(_lz_DERIVED_WRITE_TOOLS()) == set(cti.WRITE_TOOLS)
    assert len(_lz_DERIVED_WRITE_TOOLS()) > 400


def test_every_area_switch_has_routes():
    assert "UNIFI_ENABLE_NETWORK_WRITE" in {s.env for s in switches.AREA_WRITE_SWITCHES}
    for s in switches.AREA_WRITE_SWITCHES:
        assert s.routes, s.env


def _is_derived_write(name: str) -> bool:
    """``derive_write_tools`` for one tool (a write verb is reachable from its body),
    decided at test execution; the whole set is compared in the test above."""
    return bool(write_verbs_for(TOOLS[name].fn))


@tool_batches("name", lambda: sorted(TOOLS), member=_is_derived_write)
async def test_area_opt_out_binds_every_write_tool(name):
    base = await _baseline(name)
    areas = _areas(base)
    problems: list[str] = []
    governing = [s.env for s in SWITCHES.values() if s.governs(cti.FAMILY.get(name))]
    if not base:
        problems.append("no write reached the transport with every area on")
    if not set(governing) <= areas:
        # The family's area switch must govern a route the tool actually writes.
        problems.append(f"family {cti.FAMILY.get(name)} is governed by {governing}")
    for env in sorted(SWITCHES):
        off = {**_env_off(), env: "0"}
        # Direct call: the client chokepoint alone.
        up = uh.FakeUpstream()
        mp = pytest.MonkeyPatch()
        error: BaseException | None = None
        try:
            await _run_direct(mp, name, up, off)
        except Exception as exc:  # noqa: BLE001
            error = exc
        finally:
            mp.undo()
        sent = _writes(up)
        if env in areas:
            if sent:
                problems.append(f"{env}=0 direct: {len(sent)} write(s) sent, first {sent[0]}")
            if error is None or env not in str(error):
                problems.append(f"{env}=0 direct: not refused naming {env}: {error!s:.160}")
            # Through MCP: the middleware or the chokepoint, and the refusal names the area.
            up = uh.FakeUpstream()
            mp = pytest.MonkeyPatch()
            try:
                with pytest.raises(ToolError) as exc_info:
                    await cti._call(mp, name, up, env=off)
            except pytest.fail.Exception:
                problems.append(f"{env}=0 MCP: not refused")
            else:
                if env not in str(exc_info.value):
                    problems.append(f"{env}=0 MCP: refusal does not name {env}")
                if up.served:
                    first = up.served[0]
                    problems.append(
                        f"{env}=0 MCP: {len(up.served)} request(s) before the refusal, "
                        f"first {first.method} {first.path}"
                    )
            finally:
                mp.undo()
        elif sent != base and isinstance(error, AreaOptOutError):
            problems.append(f"{env}=0 refused a tool writing only to {sorted(areas)}: {error}")
    assert problems == [], f"{name} (writes to {sorted(areas)}): {problems}"


@pytest.mark.parametrize("switch", switches.AREA_WRITE_SWITCHES, ids=lambda s: s.env)
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_relay_area_routes_refused_at_the_chokepoint(monkeypatch, switch, method):
    """A request to the area's routes is refused by the client even when the relay's own
    route-class check is not consulted (the chokepoint is the last layer)."""
    from unifi_fabric.client import UniFiClient
    from unifi_fabric.config import Settings

    console = f"/v1/connector/consoles/{uh.HOST_ID}/proxy"
    paths = {
        "UNIFI_ENABLE_NETWORK_WRITE": f"{console}/network/api/s/default/rest/x",
        "UNIFI_PROTECT_MUTATIONS_ENABLED": f"{console}/protect/integration/v1/sirens/a/play",
        "UNIFI_ENABLE_MOBILITY_WRITE": "/v1/mobility/workspaces/w/devices/d",
        "UNIFI_ENABLE_CARRIER_FABRIC_WRITE": "/v1/carrier/subscribers/s",
        "UNIFI_ENABLE_INNERSPACE_WRITE": f"{console}/innerspace/api/project/plan",
    }
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    monkeypatch.setenv(switch.env, "0")
    client = UniFiClient(Settings(api_key="sk-test-optout"))
    try:
        with pytest.raises(AreaOptOutError, match=switch.env):
            await client.request(method, paths[switch.env], json={})
        # Percent-encoded spellings of the same route are the same route.
        encoded = paths[switch.env].replace("/proxy/", "/proxy%2F").replace("/v1/", "/v1%2F", 1)
        if encoded != paths[switch.env]:
            with pytest.raises((AreaOptOutError, ValueError)):
                await client.request(method, encoded, json={})
        # Reads of the area still run; other areas' writes are untouched.
        monkeypatch.setenv(switch.env, "1")
        await client.request(method, paths[switch.env], json={}, raise_on_error=False)
    finally:
        await client.close()
    assert len([s for s in up.served if s.method == method]) == 1  # the enabled call, once


_RELAY_PATHS = {
    "UNIFI_ENABLE_NETWORK_WRITE": "network/api/s/{site}/rest/x",
    "UNIFI_PROTECT_MUTATIONS_ENABLED": "protect/integration/v1/sirens/a/play",
    "UNIFI_ENABLE_INNERSPACE_WRITE": "innerspace/api/project/plan",
}


@pytest.mark.parametrize(
    "switch",
    [s for s in switches.AREA_WRITE_SWITCHES if s.env in _RELAY_PATHS],
    ids=lambda s: s.env,
)
async def test_relay_tool_honours_area_opt_out_via_mcp(monkeypatch, switch):
    """The generic relay tools are write tools of every area with a console route."""
    path = _RELAY_PATHS[switch.env]
    for tool in ("fabric_connector_post", "fabric_connector_put", "fabric_connector_delete"):
        args: dict[str, Any] = {**tool_args.generated_args(TOOLS[tool]), "path": path}
        if "{site}" in path:
            args["site"] = uh.SITE
        up = uh.FakeUpstream()
        mp = pytest.MonkeyPatch()
        try:
            with pytest.raises(ToolError, match=switch.env):
                await cti._call(mp, tool, up, args, env={switch.env: "0"})
        finally:
            mp.undo()
        assert up.writes() == [], (tool, up.writes())


@pytest.mark.parametrize("switch", switches.AREA_WRITE_SWITCHES, ids=lambda s: s.env)
def test_area_refusal_text_comes_from_the_one_table(monkeypatch, switch):
    monkeypatch.setenv(switch.env, "0")
    assert switch.env in (connector.area_write_refusal(switch.family) or "")


@pytest.mark.parametrize("switch", switches.AREA_WRITE_SWITCHES, ids=lambda s: s.env)
@pytest.mark.parametrize("value", ["0", " False "])
def test_area_refusal_names_variable_current_value_and_that_nothing_was_sent(
    monkeypatch, switch, value
):
    """Every area's refusal, whichever layer raises it, carries the switch's current value."""
    monkeypatch.setenv(switch.env, value)
    note = f"Current value: {switch.env}={value.strip()}."
    texts = [connector.area_write_refusal(switch.family) or ""]
    with pytest.raises(ValueError) as relay:
        connector._check_area_opt_out("POST", f"{switch.relay_prefix}x")
    texts.append(str(relay.value))
    for text in texts:
        assert switch.env in text and note in text, text
        assert "No request was sent" in text, text
    # Enabled again: no note, no refusal.
    monkeypatch.setenv(switch.env, "1")
    assert connector.area_write_refusal(switch.family) is None
