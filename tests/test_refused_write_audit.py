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
from unifi_fabric import server, switches
from unifi_fabric.client import UniFiClient
from unifi_fabric.config import Settings
from unifi_fabric.read_only import ReadOnlyModeError
from unifi_fabric.redaction import REDACTION_MASK
from unifi_fabric.refusal_audit import RefusedWriteAuditMiddleware
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
    return [
        r
        for r in (json.loads(line) for line in path.read_text().splitlines() if line.strip())
        if r.get("event", "audit") == "audit"
    ]


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
        await _call(monkeypatch, name, up, env={**_audit_env(log), "UNIFI_WRITE_POLICY": "deny"})
    assert up.served == []
    recs = _refusals(log, name)
    assert len(recs) == 1, f"{name}: {_records(log)}"
    assert recs[0]["reason"] == switches.READ_ONLY_ENV
    assert recs[0]["method"] is None and recs[0]["path"] is None and recs[0]["status"] is None


@pytest.mark.parametrize(
    ("env", "reason"),
    [
        ({"UNIFI_WRITE_POLICY": "deny"}, switches.READ_ONLY_ENV),
        ({"UNIFI_WRITE_EXCEPTIONS": "tool:create_network=deny"}, "tool:create_network=deny"),
        ({"UNIFI_WRITE_EXCEPTIONS": "family:network=deny"}, "family:network=deny"),
        (
            {"UNIFI_WRITE_POLICY": "dry-run", "UNIFI_WRITE_EXCEPTIONS": "family:network=deny"},
            "family:network=deny",
        ),
    ],
)
async def test_request_policy_write_denied_is_audited_once_with_its_gate(
    monkeypatch, tmp_path, capsys, env, reason
):
    """A write the request policy refuses (write_denied) is one refused audit record naming
    the denying setting, one policy.refusal record, and no upstream request."""
    log = tmp_path / "audit.jsonl"
    up = uh.FakeUpstream()
    capsys.readouterr()
    with pytest.raises(ToolError) as info:
        await _call(monkeypatch, "create_network", up, env={**_audit_env(log), **env})
    assert json.loads(str(info.value))["error"]["code"] == "write_denied"
    assert up.served == []
    recs = _refusals(log, "create_network")
    assert [r["reason"] for r in recs] == [reason], _records(log)
    assert recs[0]["method"] is None and recs[0]["path"] is None
    stderr = [
        json.loads(line)
        for line in capsys.readouterr().err.splitlines()
        if line.startswith("{") and '"event":"policy.refusal"' in line
    ]
    assert [r["code"] for r in stderr] == ["write_denied"]


async def test_read_only_refusal_at_the_chokepoint_is_audited(monkeypatch, tmp_path):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    client = UniFiClient(Settings(api_key="K" * 20, audit_log=str(log), audit_log_format="text"))
    path = "/v1/connector/consoles/abc/proxy/network/integration/v1/sites/x/networks/y"
    with pytest.raises(ReadOnlyModeError):
        await client.delete(path)
    await client.close()
    line = log.read_text().strip()
    assert f"method=DELETE path={path} outcome=refused status=- reason=UNIFI_WRITE_POLICY" in line
    assert "tool=" not in line


@tool_batches("name", lambda: cti.OPT_OUT_WRITE_TOOLS)
async def test_area_opt_out_refusal_is_audited(monkeypatch, tmp_path, name):
    log = tmp_path / "audit.jsonl"
    env_var = cti._AREA_WRITE_OPT_OUTS[cti.FAMILY[name]]
    up = uh.FakeUpstream()
    with pytest.raises(ToolError):
        await _call(
            monkeypatch,
            name,
            up,
            env={**_audit_env(log), "UNIFI_WRITE_EXCEPTIONS": env_var},
        )
    recs = _refusals(log, name)
    assert [r["reason"] for r in recs] == [env_var], f"{name}: {_records(log)}"


@pytest.mark.parametrize("method", sorted(cti._RELAY_MUTATION_TOOLS))
async def test_relay_route_class_opt_out_refusal_is_audited(monkeypatch, tmp_path, method):
    log = tmp_path / "audit.jsonl"
    path = cti._RELAY_CLASS_PATHS["protect-integration"]
    args = {"host": uh.HOST, "site": uh.SITE, "path": path, "body": {"probe": "relay"}}
    env = {**_audit_env(log), "UNIFI_WRITE_EXCEPTIONS": switches.PROTECT_WRITES.env}
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
    # Literal {} is controller-judged for this unpublished create schema. Its
    # nested-empty body remains a local refusal and must still produce an audit.
    body = {"nested": {}} if name == "create_firewall_rule" else {}
    args = {**tool_args.generated_args(TOOLS[name]), arg: body}
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
    keys = {"schema_version", "event", "timestamp_utc", "method", "path", "outcome", "status"}
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


async def test_refusal_through_call_write_tool_is_audited_exactly_once(monkeypatch, tmp_path):
    """Discovery re-enters the middleware chain for the inner tool; the inner audit record
    counts against the outer call, so one refused write is one refused record."""
    from fastmcp import Client

    from tests.test_discovery import clone_app
    from unifi_fabric.discovery import apply_tool_mode

    log = tmp_path / "audit.jsonl"
    up = uh.FakeUpstream()
    for key, value in _audit_env(log).items():
        monkeypatch.setenv(key, value)
    uh.install(monkeypatch, up)
    app = await clone_app()
    cleanup = await apply_tool_mode(app, "discovery")
    try:
        async with Client(app) as client:
            # No gate audits an invalid argument itself: only the middleware records it.
            args = {**tool_args.generated_args(TOOLS["create_network"]), "name": 12345}
            with pytest.raises(Exception):  # noqa: B017, PT011 - any refusal
                await client.call_tool(
                    "call_write_tool", {"name": "create_network", "arguments": args}
                )
    finally:
        cleanup()
    assert up.served == []
    refused = [r for r in _refusals(log) if r.get("outcome") == "refused"]
    assert len(refused) == 1, _records(log)


# ================================================== header-credential ingress refusals
_INGRESS_KEY = "synthetic-" + "ingress-key-0001"  # split for gitleaks (synthetic)


async def _header_call(
    monkeypatch, tmp_path, header, *, name="create_network", args=None, audit=True
):
    """One write call through the whole server stack in header mode, ``header`` being the
    X-UniFi-Api-Key wire value (``None``: no header). Returns (result, upstream, audit log)."""
    from fastmcp import Client

    from unifi_fabric import header_credentials as hc

    log = tmp_path / "audit.jsonl"
    env = {**(_audit_env(log) if audit else {}), "UNIFI_KEY_MODE": "header"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    hc.set_process_key_mode(None)
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    wire = [] if header is None else [header]
    monkeypatch.setattr(
        hc, "_raw_header_values", lambda n: wire if n.lower() == "x-unifi-api-key" else []
    )
    call_args = tool_args.generated_args(TOOLS[name]) if args is None else args
    try:
        async with Client(server.mcp) as client:
            result = await client.call_tool(name, call_args, raise_on_error=False)
    finally:
        hc.set_process_key_mode(None)
    return result, up, log


def _result_text(result: Any) -> str:
    return "\n".join(c.text for c in result.content if hasattr(c, "text"))


@pytest.mark.parametrize(
    ("header", "code"),
    [
        (None, "missing_api_key_header"),
        ("not json {" + _INGRESS_KEY, "invalid_api_key_header"),
        (json.dumps({"alpha": _INGRESS_KEY, "alpha ": _INGRESS_KEY}), "invalid_api_key_header"),
    ],
)
async def test_header_ingress_refusal_of_a_write_is_audited_once(
    monkeypatch, tmp_path, caplog, header, code
):
    """A write refused at header-credential ingress (missing / invalid X-UniFi-Api-Key) is
    one outcome=refused record whose reason is the refusal code, with no key material in the
    record, the error, or any log line."""
    caplog.set_level(logging.DEBUG)
    result, up, log = await _header_call(monkeypatch, tmp_path, header)
    assert result.is_error
    assert json.loads(_result_text(result))["error"]["code"] == code
    assert up.served == []
    recs = _refusals(log, "create_network")
    assert [r["reason"] for r in recs] == [code], _records(log)
    assert len(_refusals(log)) == 1
    assert recs[0]["method"] is None and recs[0]["path"] is None and recs[0]["status"] is None
    blob = (
        log.read_text() + _result_text(result) + "\n".join(r.getMessage() for r in caplog.records)
    )
    for secret in (_INGRESS_KEY, header or "\0"):
        assert secret not in blob


async def test_header_ingress_refusal_of_a_read_is_not_audited(monkeypatch, tmp_path):
    result, up, log = await _header_call(monkeypatch, tmp_path, None, name="list_networks")
    assert result.is_error and up.served == []
    assert _refusals(log) == []


async def test_header_ingress_refusal_with_the_sink_failing_carries_the_notice(
    monkeypatch, tmp_path
):
    """The refusal is still raised, the failing sink loses the record, and the caller gets
    the audit_unavailable notice on the error."""
    from fastmcp import Client

    from unifi_fabric import header_credentials as hc
    from unifi_fabric.audit import AUDIT_UNAVAILABLE

    # The sink's directory does not exist: every write to it fails.
    broken = tmp_path / "missing-dir" / "audit.jsonl"
    for key, value in {**_audit_env(broken), "UNIFI_KEY_MODE": "header"}.items():
        monkeypatch.setenv(key, value)
    hc.set_process_key_mode(None)
    up = uh.FakeUpstream()
    uh.install(monkeypatch, up)
    monkeypatch.setattr(hc, "_raw_header_values", lambda n: [])
    try:
        async with Client(server.mcp) as client:
            result = await client.call_tool(
                "create_network",
                tool_args.generated_args(TOOLS["create_network"]),
                raise_on_error=False,
            )
    finally:
        hc.set_process_key_mode(None)
    assert result.is_error and up.served == []
    text = _result_text(result)
    assert "missing_api_key_header" in text
    assert text.endswith(f"[{AUDIT_UNAVAILABLE}]")
    assert not broken.exists()


async def test_header_ingress_refusal_of_a_hidden_write_is_audited_once(monkeypatch, tmp_path):
    """A write hidden at startup (read-only mode, an area opt-out) is no longer in the
    provider, but its ingress refusal is still one refused record."""
    from fastmcp.exceptions import NotFoundError

    from unifi_fabric.read_only_tools import ReadOnlyToolMiddleware

    real_get_tool = server.mcp.get_tool

    async def get_tool(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "create_network":
            raise NotFoundError(name)
        return await real_get_tool(name, *args, **kwargs)

    monkeypatch.setattr(server.mcp, "get_tool", get_tool)
    gate = next(m for m in server.mcp.middleware if isinstance(m, ReadOnlyToolMiddleware))
    monkeypatch.setattr(gate, "_hidden_write_names", {"create_network"})
    result, up, log = await _header_call(monkeypatch, tmp_path, None)
    assert result.is_error and up.served == []
    assert [r["reason"] for r in _refusals(log, "create_network")] == ["missing_api_key_header"]
    assert len(_refusals(log)) == 1


async def test_header_ingress_refusal_audit_failure_keeps_the_refusal(monkeypatch, tmp_path):
    """A hook that raises cannot change the refusal the caller receives."""

    async def boom(self, context, code):
        raise RuntimeError("audit hook failed")

    monkeypatch.setattr(RefusedWriteAuditMiddleware, "audit_ingress_refusal", boom)
    result, up, _log = await _header_call(monkeypatch, tmp_path, None)
    assert result.is_error and up.served == []
    assert json.loads(_result_text(result))["error"]["code"] == "missing_api_key_header"


async def test_header_ingress_refusal_with_the_audit_log_off_writes_nothing(monkeypatch, tmp_path):
    result, up, log = await _header_call(monkeypatch, tmp_path, None, audit=False)
    assert result.is_error and up.served == []
    assert _records(log) == [] and not log.exists()
