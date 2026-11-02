"""Cross-tool invariant (ci): a Classic controller response is a success only when the HTTP
status is 2xx AND ``meta.rc == "ok"``, enforced across EVERY registered tool that reaches a
Classic route (``/proxy/network/api/...``: ``api/s/<site>/{rest,stat,cmd,set,upd,...}``,
``api/self``, ``api/stat/sites``).

The harness and helpers are those of ``tests/test_cross_tool_invariants``.

ci-a. HTTP 200 ``{"meta": {"rc": "error", "msg": "X"}, "data": []}`` from a Classic route
      is an upstream error: a typed tool raises with the complete upstream body (meta and
      data, verbatim, never truncated); a tool that reports per-item failures in its result
      (fan-out, read-after) carries the same text there. No result claims success
      (``verified`` / ``noOp`` / ``changed`` / ``deleted`` / ``success`` / ``applied``
      true, a non-empty ``forgotten``).
ci-b. The generic relay reports an upstream error status instead of raising, so a Classic
      rc error is reported the same way: ``status`` and ``body`` verbatim plus the additive
      ``_classicRcError`` marker carrying ``meta.msg``, and no ``noOp`` / ``changed``
      verdict, on the write and on ``readBefore`` / ``readAfter``.
ci-c. HTTP 200 with ``meta.rc == "ok"`` passes the ``{meta, data}`` envelope through
      unchanged (never unwrapped or replaced).
ci-d. The shared helper (``client.classic_rc_error``) and the client chokepoint: Classic
      routes only, 2xx only, full body in the message, audited ``classic_rc_error``.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import tool_batches
from tests.test_invariants_envelopes_and_previews import COMPOSITE
from unifi_fabric.client import (
    ClassicApiError,
    UniFiClient,
    UniFiConnectionError,
    classic_rc_error,
    is_classic_route,
)
from unifi_fabric.config import Settings

TOOLS = cti.TOOLS
_call = cti._call

RC_MSG = "api.err.ProbeClassicRc"
RC_BODY = {"meta": {"rc": "error", "msg": RC_MSG}, "data": []}
RC_TEXT = json.dumps(RC_BODY, separators=(",", ":"))

#: Result fields that state an outcome; none may be true for a rejected Classic request.
_SUCCESS_FLAGS = ("verified", "deleted", "success", "applied", "noOp", "changed")

#: Tools that must be seen reaching a Classic route (so the derived set cannot silently
#: shrink): one or more per Classic module, the reported instances included.
_MUST_BE_CLASSIC = {
    # statistics.py
    "get_site_statistics",
    "get_historical_stats",
    "list_known_clients",
    "get_device_port_state",
    # hotspot.py
    "list_hotspot_operators",
    "update_hotspot_operator",
    "delete_hotspot_operator",
    # network_services_proxy.py
    "list_port_forwards",
    "update_setting",
    "get_setting",
    "list_port_profiles",
    "exclude_network_on_port_profile",
    "get_wlan_group",
    "list_rogue_aps",
    # device_mgmt.py
    "forget_device",
    # vpn.py
    "delete_vpn_server",
    # site_manager.py
    "get_site_health_summary",
    # network.py
    "list_wan_interfaces",
    # clients.py
    "block_client",
    # the generic relay (Classic path)
    "fabric_connector_get",
    "fabric_connector_post",
    "fabric_connector_put",
    "fabric_connector_delete",
}


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _classic_served(up: uh.FakeUpstream) -> list[uh.Served]:
    return [s for s in up.served if not s.resolution and uh.family(s.path) == "classic"]


def _args(name: str) -> dict[str, Any] | None:
    """Generated arguments; the relays get a Classic path (their default is Integration)."""
    # RAW_RELAY also includes typed private Protect tools preserving relay envelopes.
    # Only the generic connector tools accept a caller-selected Classic path.
    if not name.startswith("fabric_connector_"):
        return None
    args = tool_args.generated_args(TOOLS[name])
    method = name.rsplit("_", 1)[1]
    suffix = "" if method in ("get", "post") else f"/{uh.ARG_HEX}"
    args["path"] = "network/api/s/{site}/rest/portforward" + suffix
    return args


def _walk(obj: Any) -> list[Any]:
    out: list[Any] = []
    stack = [obj]
    while stack:
        node = stack.pop()
        out.append(node)
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return out


def _success_claims(payload: Any) -> list[str]:
    claims: list[str] = []
    for node in _walk(payload):
        if not isinstance(node, dict):
            continue
        claims += [f"{flag}=true" for flag in _SUCCESS_FLAGS if node.get(flag) is True]
        if isinstance(node.get("forgotten"), list) and node["forgotten"]:
            claims.append(f"forgotten={node['forgotten']!r}")
        if node.get("status") == "success":
            claims.append("status=success")
    return claims


async def _eligible_ci_classic_rc_error_is_an_upstream_error(monkeypatch, name):
    up = uh.FakeUpstream(classic_rc_body=RC_BODY)
    try:
        await _call(monkeypatch, name, up, args=_args(name))
    except ToolError as exc:
        if not _classic_served(up):
            raise
        assert RC_TEXT in str(exc), (
            f"{name}: the Classic rc error is not raised with the full upstream body: {exc}"
        )
        return True
    if not _classic_served(up):
        assert name not in _MUST_BE_CLASSIC, f"{name}: reached no Classic route"
        return False
    return True


# =========================================================================== (ci-a/b)
@tool_batches(
    "name",
    lambda: sorted(n for n in TOOLS if n not in cti.NO_UPSTREAM),
    eligible=_eligible_ci_classic_rc_error_is_an_upstream_error,
)
async def test_ci_classic_rc_error_is_an_upstream_error(monkeypatch, name):
    up = uh.FakeUpstream(classic_rc_body=RC_BODY)
    try:
        res = await _call(monkeypatch, name, up, args=_args(name))
    except ToolError as exc:
        if not _classic_served(up):
            raise
        assert RC_TEXT in str(exc), (
            f"{name}: the Classic rc error is not raised with the full upstream body: {exc}"
        )
        return
    if not _classic_served(up):
        assert name not in _MUST_BE_CLASSIC, f"{name}: reached no Classic route"
        raise AssertionError("inapplicable case was not filtered before batching")
    payload = uh.result_payload(res)
    leaves = [n for n in _walk(payload) if isinstance(n, str)]
    assert any(RC_MSG in leaf for leaf in leaves), (
        f"{name}: a Classic rc error was swallowed (no error, meta.msg absent): "
        f"{uh.all_strings(payload)[:400]}"
    )
    claims = _success_claims(payload)
    assert not claims, f"{name}: a rejected Classic request reported success: {claims}"
    if name in cti.RAW_RELAY:
        assert payload["status"] == 200 and payload["body"] == RC_BODY, payload
        assert RC_MSG in payload["_classicRcError"], payload
        assert payload.get("noOp") is None and "changed" not in payload, payload


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
async def test_ci_relay_write_rejected_by_rc_draws_no_verdict(monkeypatch, method):
    """Both reads succeed and are identical; the write is a Classic rc error."""
    name = f"fabric_connector_{method.lower()}"
    up = uh.FakeUpstream(classic_rc_body=RC_BODY, classic_rc_methods=(method,))
    payload = uh.result_payload(await _call(monkeypatch, name, up, args=_args(name)))
    assert payload["status"] == 200 and payload["body"] == RC_BODY
    assert RC_MSG in payload["_classicRcError"]
    assert "_classicRcError" not in payload["readBefore"]
    assert payload["noOp"] is None and "changed" not in payload, payload


async def test_ci_relay_read_after_rc_error_is_reported(monkeypatch):
    """The write succeeds (rc ok); both reads are Classic rc errors: no verdict, and the
    read-after failure is reported with meta.msg."""
    name = "fabric_connector_put"
    up = uh.FakeUpstream(classic_rc_body=RC_BODY, classic_rc_methods=("GET",))
    payload = uh.result_payload(await _call(monkeypatch, name, up, args=_args(name)))
    assert "_classicRcError" not in payload, payload
    assert RC_MSG in payload["readBefore"]["_classicRcError"]
    assert RC_MSG in payload["readAfter"]["_classicRcError"]
    assert payload["readAfter"]["body"] == RC_BODY
    assert payload["noOp"] is None and "changed" not in payload, payload
    assert RC_MSG in payload["readAfterError"], payload


def test_ci_must_be_classic_names_real_tools():
    assert _MUST_BE_CLASSIC <= set(TOOLS), sorted(_MUST_BE_CLASSIC - set(TOOLS))


# =========================================================================== (ci-c)
#: Composite results (several upstream bodies, each kept verbatim inside the result) and
#: projections: their records are covered by test_a / test_ca, not by whole-body equality.
_PROJECTIONS = set(cti.SELECT) | set(cti.DERIVED) | set(cti.AUXILIARY) | set(COMPOSITE)


async def _eligible_ci_classic_rc_ok_envelope_passes_through(monkeypatch, name):
    up = uh.FakeUpstream()
    payload = uh.result_payload(await _call(monkeypatch, name, up, args=_args(name)))
    served = [s for s in up.served if not s.resolution]
    classic = _classic_served(up)
    if not classic:
        assert name not in _MUST_BE_CLASSIC, f"{name}: reached no Classic route"
        return False
    if name in cti.RAW_RELAY:
        assert payload["body"] == classic[0].body and "_classicRcError" not in payload
        return True
    if len(served) != 1 or name in _PROJECTIONS:
        return False
    return True


@tool_batches(
    "name",
    lambda: sorted(n for n in cti.READ_TOOLS if n not in cti.NO_UPSTREAM),
    eligible=_eligible_ci_classic_rc_ok_envelope_passes_through,
)
async def test_ci_classic_rc_ok_envelope_passes_through(monkeypatch, name):
    up = uh.FakeUpstream()
    payload = uh.result_payload(await _call(monkeypatch, name, up, args=_args(name)))
    served = [s for s in up.served if not s.resolution]
    classic = _classic_served(up)
    if not classic:
        assert name not in _MUST_BE_CLASSIC, f"{name}: reached no Classic route"
        raise AssertionError("inapplicable case was not filtered before batching")
    if name in cti.RAW_RELAY:
        assert payload["body"] == classic[0].body and "_classicRcError" not in payload
        return
    if len(served) != 1 or name in _PROJECTIONS:
        raise AssertionError("inapplicable case was not filtered before batching")
    body = classic[0].body
    assert body["meta"] == {"rc": "ok"}
    assert uh.strip_additive(payload, body) == body, (
        f"{name}: the Classic envelope was not passed through unchanged: {payload!r:.400}"
    )


# =========================================================================== (ci-d)
_CLASSIC = "/v1/connector/consoles/h1/proxy/network/api/s/default/rest/portforward"
BASE = "https://api.ui.com"


def test_ci_helper_routes_and_statuses():
    assert is_classic_route(_CLASSIC)
    assert is_classic_route("/v1/connector/consoles/h1/proxy/network/api/self/sites")
    assert is_classic_route("/v1/connector/consoles/h1/proxy/network/api/stat/sites?x=1")
    for other in (
        "/v1/connector/consoles/h1/proxy/network/integration/v1/sites",
        "/v1/connector/consoles/h1/proxy/network/v2/api/site/default/trafficroutes",
        "/v1/connector/consoles/h1/proxy/protect/api/cameras",
        "/v1/hosts",
    ):
        assert not is_classic_route(other), other
        assert classic_rc_error(other, 200, RC_BODY) is None
    assert classic_rc_error(_CLASSIC, 200, {"meta": {"rc": "ok"}, "data": []}) is None
    assert classic_rc_error(_CLASSIC, 400, RC_BODY) is None  # already an HTTP error
    reason = classic_rc_error(_CLASSIC, 200, RC_BODY)
    assert reason is not None and RC_MSG in reason and "'error'" in reason
    # An envelope that does not say rc "ok" is not a success.
    assert classic_rc_error(_CLASSIC, 200, {"meta": {}, "data": []}) is not None
    assert classic_rc_error(_CLASSIC, 200, {"meta": "x", "data": []}) is not None
    assert classic_rc_error(_CLASSIC, 200, {"meta": {"rc": "OK"}, "data": []}) is not None
    # No envelope at all (empty, text, bare JSON, an object without meta): nothing states
    # an outcome; passed through (an applied write is never reported failed on its shape,
    # test_w_write_body_returned_verbatim_never_raised).
    for bare in (None, "text", True, 7, [], {"data": []}):
        assert classic_rc_error(_CLASSIC, 200, bare) is None, bare


def _client(**kw: Any) -> UniFiClient:
    return UniFiClient(Settings(api_key="probe-key-1", api_base_url=BASE, **kw))


@respx.mock
async def test_ci_client_raises_with_the_full_body(tmp_path):
    long_msg = "api.err.Sample " + "x" * 5000
    body = {"meta": {"rc": "error", "msg": long_msg, "extra": 1}, "data": [{"k": "v"}]}
    text = json.dumps(body, separators=(",", ":"))
    respx.post(BASE + _CLASSIC).mock(
        return_value=httpx.Response(
            200, content=text.encode(), headers={"content-type": "application/json"}
        )
    )
    audit = tmp_path / "audit.jsonl"
    client = _client(audit_log=str(audit), audit_log_format="json")
    with pytest.raises(ClassicApiError) as exc:
        await client.post(_CLASSIC, json={"name": "n"})
    assert isinstance(exc.value, UniFiConnectionError)
    assert text in str(exc.value)  # complete, never truncated
    assert str(exc.value).startswith(f"Classic API error from POST {_CLASSIC}: HTTP 200")
    rec = json.loads(audit.read_text().strip())
    assert rec["outcome"] == "classic_rc_error" and rec["status"] == 200
    # raise_on_error=False (the relay) gets the response back, body verbatim.
    resp = await client.request("POST", _CLASSIC, json={"name": "n"}, raise_on_error=False)
    assert resp.status_code == 200 and resp.json() == body


@respx.mock
async def test_ci_client_passes_rc_ok_and_ignores_other_surfaces():
    ok = {"meta": {"rc": "ok"}, "data": [{"_id": "a"}]}
    respx.get(BASE + _CLASSIC).mock(return_value=httpx.Response(200, json=ok))
    integ = "/v1/connector/consoles/h1/proxy/network/integration/v1/sites"
    respx.get(BASE + integ).mock(return_value=httpx.Response(200, json=RC_BODY))
    client = _client()
    assert await client.get(_CLASSIC) == ok
    assert await client.get(integ) == RC_BODY  # not a Classic route: no meta.rc rule
