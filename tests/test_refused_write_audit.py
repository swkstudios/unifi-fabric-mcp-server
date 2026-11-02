"""Refused write attempts are audited.

With ``UNIFI_AUDIT_LOG`` set, a write refused before it is sent is an audit record with
``outcome=refused`` and ``reason`` naming the gate: the read-only mode (every write tool at
the tool middleware, and the HTTP chokepoint), every area / connector write opt-out (every
opted-out write tool, and the connector relay route class), and the empty-update guard
(every write tool with a free-form body). A write that reaches the chokepoint keeps its
record shape.
"""

from __future__ import annotations

import functools
import json
import logging
from typing import Any

import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import class_axis, tool_batches
from unifi_fabric import switches
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.read_only import ReadOnlyModeError
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.write_body import body_argument

TOOLS = cti.TOOLS
_call = cti._call


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _payload(res: Any) -> Any:
    """What a client receives, with FastMCP's ``{"result": ...}`` list wrapper undone."""
    body = uh.result_payload(res)
    if isinstance(body, dict) and set(body) == {"result"}:
        return body["result"]
    return body


# =========================================================================== refusal audit
def _records(path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _audit_env(path) -> dict[str, str]:
    return {"UNIFI_AUDIT_LOG": str(path), "UNIFI_AUDIT_LOG_FORMAT": "json"}


def _refusals(path, tool: str | None = None) -> list[dict[str, Any]]:
    return [
        r
        for r in _records(path)
        if r.get("outcome") == "refused" and (tool is None or r.get("tool") == tool)
    ]


@tool_batches("name", lambda: cti.WRITE_TOOLS)
async def test_read_only_refusal_is_audited(monkeypatch, tmp_path, name):
    log = tmp_path / "audit.jsonl"
    up = uh.FakeUpstream()
    with pytest.raises(ToolError):
        await _call(monkeypatch, name, up, env={**_audit_env(log), "UNIFI_READ_ONLY": "1"})
    assert up.served == []
    recs = _refusals(log, name)
    assert len(recs) == 1, f"{name}: {_records(log)}"
    assert recs[0]["reason"] == switches.READ_ONLY_ENV
    assert recs[0]["method"] is None and recs[0]["path"] is None and recs[0]["status"] is None


async def test_read_only_refusal_at_the_chokepoint_is_audited(monkeypatch, tmp_path):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    client = UniFiClient(Settings(api_key="K" * 20, audit_log=str(log)))
    path = "/v1/connector/consoles/abc/proxy/network/integration/v1/sites/x/networks/y"
    with pytest.raises(ReadOnlyModeError):
        await client.delete(path)
    await client.close()
    line = log.read_text().strip()
    assert f"method=DELETE path={path} outcome=refused status=- reason=UNIFI_READ_ONLY" in line
    assert "tool=" not in line


@tool_batches("name", lambda: cti.OPT_OUT_WRITE_TOOLS)
async def test_area_opt_out_refusal_is_audited(monkeypatch, tmp_path, name):
    log = tmp_path / "audit.jsonl"
    env_var = cti._AREA_WRITE_OPT_OUTS[cti.FAMILY[name]]
    up = uh.FakeUpstream()
    with pytest.raises(ToolError):
        await _call(monkeypatch, name, up, env={**_audit_env(log), env_var: "0"})
    recs = _refusals(log, name)
    assert [r["reason"] for r in recs] == [env_var], f"{name}: {_records(log)}"


@pytest.mark.parametrize("method", sorted(cti._RELAY_MUTATION_TOOLS))
async def test_relay_route_class_opt_out_refusal_is_audited(monkeypatch, tmp_path, method):
    log = tmp_path / "audit.jsonl"
    path = cti._RELAY_CLASS_PATHS["protect-integration"]
    args = {"host": uh.HOST, "site": uh.SITE, "path": path, "body": {"probe": "relay"}}
    env = {**_audit_env(log), switches.PROTECT_WRITES.env: "0"}
    up = uh.FakeUpstream()
    with pytest.raises(ToolError):
        await _call(monkeypatch, cti._RELAY_MUTATION_TOOLS[method], up, args, env=env)
    assert up.served == []
    recs = _refusals(log)
    assert len(recs) == 1, _records(log)
    assert recs[0]["reason"] == switches.PROTECT_WRITES.env
    assert recs[0]["method"] == method and recs[0]["path"] == path


@functools.cache
def _lz__BODY_TOOLS():
    return sorted(n for n in cti.WRITE_TOOLS if body_argument(TOOLS[n]) is not None)


#: The NET-A site-configuration object writes. They carry no dedicated refusal test:
#: the shared catalog sweep below covers them, so this only pins their membership.
NET_A_REQUIRED_OBJECT_BODY_TOOLS = frozenset(
    {
        "create_ap_group",
        "create_dynamic_dns",
        "create_port_profile",
        "create_static_route",
        "create_user_group",
        "update_ap_group",
        "update_radius_account",
        "update_radius_profile",
        "update_static_route",
        "update_user_group",
    }
)


def test_empty_update_sweep_is_non_trivial():
    assert len(_lz__BODY_TOOLS()) >= 30
    assert {"update_setting", "update_network", "create_acl_rule"} <= set(_lz__BODY_TOOLS())
    # The private Protect settings tools take a $ref model body and must be guarded too.
    assert {"update_camera_private", "update_nvr", "update_sensor_private"} <= set(
        _lz__BODY_TOOLS()
    )
    assert NET_A_REQUIRED_OBJECT_BODY_TOOLS <= set(_lz__BODY_TOOLS())


def _validation_topology(topology):
    """The same invalid input must never reach any key or paged/failing resolver."""
    keys = cti._KEYS if topology in {"multi", "all-fail"} else None
    up = uh.FakeUpstream(
        mode="error" if topology == "all-fail" else "normal",
        error_resolution=topology == "all-fail",
        page_resolution=topology == "capped",
        repeat_pages=topology == "capped",
    )
    env = {"UNIFI_PAGINATE_MAX_PAGES": "1"} if topology == "capped" else {}
    return up, keys, env


@class_axis(
    "name", lambda: _lz__BODY_TOOLS(), topology=lambda: (["single", "multi", "capped", "all-fail"])
)
async def test_empty_update_refusal_is_audited(monkeypatch, tmp_path, name, topology):
    log = tmp_path / "audit.jsonl"
    arg = body_argument(TOOLS[name])
    args = {**tool_args.generated_args(TOOLS[name]), arg: {}}
    up, keys, env = _validation_topology(topology)
    with pytest.raises(ToolError):
        await _call(monkeypatch, name, up, args=args, env={**_audit_env(log), **env}, keys=keys)
    assert up.served == []
    recs = _refusals(log, name)
    assert [r["reason"] for r in recs] == ["empty_update"], f"{name}: {_records(log)}"


@pytest.mark.parametrize("method", sorted(cti._RELAY_MUTATION_TOOLS))
@pytest.mark.parametrize("host", [uh.HOST, "probe-unknown-host"])
@pytest.mark.parametrize("topology", ["single", "multi", "capped", "all-fail"])
async def test_mask_only_relay_body_is_refused_before_any_request(
    monkeypatch, tmp_path, method, host, topology
):
    log = tmp_path / "audit.jsonl"
    name = cti._RELAY_MUTATION_TOOLS[method]
    args = {
        **tool_args.generated_args(TOOLS[name]),
        "host": host,
        "body": {"x_passphrase": REDACTION_MASK},
    }
    up, keys, env = _validation_topology(topology)
    with pytest.raises(ToolError, match="No fields provided"):
        await _call(
            monkeypatch,
            name,
            up,
            args=args,
            env={**_audit_env(log), **env, "UNIFI_REDACT_SECRETS": "true"},
            keys=keys,
        )
    assert up.served == []
    assert len(_refusals(log, name)) == 1


async def test_reached_write_record_has_additive_call_context(monkeypatch, tmp_path):
    """A reached write keeps its original fields and adds resolved call context."""
    log = tmp_path / "audit.jsonl"
    up = uh.FakeUpstream()
    await _call(monkeypatch, "update_network", up, env=_audit_env(log))
    recs = _records(log)
    keys = {"timestamp", "method", "path", "outcome", "status"}
    additive = {"tool", "resolvedHost", "resolvedSite", "duration_ms"}
    assert recs and all(set(r) == keys | additive for r in recs), recs


def test_credential_values_walk_ends_on_a_self_referential_argument():
    """A cyclic body ends the walk with every credential found once, in bounded memory.

    Without the visited set the walk re-queued the same containers forever and one
    test worker grew past 12 GB.
    """
    import tracemalloc

    from unifi_fabric.refusal_audit import credential_values

    body: dict = {"password": "synthetic-value"}
    body["again"] = body
    items: list = []
    items.append(items)
    body["items"] = items
    pair: tuple = (body, items)
    body["pair"] = pair
    shared = {"password": "synthetic-shared"}
    tracemalloc.start()
    try:
        found = credential_values({"a": body, "b": shared, "c": shared, "d": [pair]})
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert sorted(found) == ["synthetic-shared", "synthetic-value"]
    assert peak < 1_000_000, peak
