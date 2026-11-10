"""A Network v2 ``{"error": {"code", "message"}}`` answered with HTTP 2xx is an upstream error.

``client.v2_error_envelope`` is the one rule: typed tools raise with the complete body, the
relay adds ``_upstreamError``, writes are audited ``upstream_error_body``. Legitimate
payloads that merely contain an ``error`` field are never flagged. The body is never
rewritten.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from tests._tool_classes import tool_batches
from unifi_fabric.client import (
    UniFiClient,
    UniFiConnectionError,
    UniFiHTTPError,
    UpstreamErrorBodyError,
    is_v2_route,
    v2_error_envelope,
)
from unifi_fabric.config import Settings

BASE = "https://api.ui.com"
CONSOLE = "/v1/connector/consoles/h1/proxy"
V2 = f"{CONSOLE}/network/v2/api/site/default/nat"
CLASSIC = f"{CONSOLE}/network/api/s/default/rest/portforward"
INTEGRATION = f"{CONSOLE}/network/integration/v1/sites"

ERR_BODY = {"error": {"code": 400, "message": "api.err.InvalidPayload"}}
ERR_TEXT = json.dumps(ERR_BODY, separators=(",", ":"))
ERR_MSG = "api.err.InvalidPayload"

TOOLS = cti.TOOLS
_call = cti._call
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _client(**kw: Any) -> UniFiClient:
    return UniFiClient(Settings(api_key="probe-key-1", api_base_url=BASE, **kw))


def _json(status: int, body: Any, **headers: str) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json", **headers},
    )


# =========================================================================== A: the detector
def test_a_detector_flags_only_the_bare_error_envelope_on_a_v2_route():
    assert is_v2_route(V2) and is_v2_route(f"{V2}?x=1")
    for other in (CLASSIC, INTEGRATION, f"{CONSOLE}/protect/api/cameras", "/v1/hosts"):
        assert not is_v2_route(other), other
        assert v2_error_envelope(other, 200, ERR_BODY) is None, other
    reason = v2_error_envelope(V2, 200, ERR_BODY)
    assert reason is not None and ERR_MSG in reason and "400" in reason
    # A string code (the v2 errors we captured use ``api.err.X`` codes) is the same shape.
    assert v2_error_envelope(V2, 201, {"error": {"code": "api.err.X", "message": "m"}})
    # Not 2xx: already an HTTP error.
    for status in (199, 300, 400, 404, 500, None, True, "200"):
        assert v2_error_envelope(V2, status, ERR_BODY) is None, status


@pytest.mark.parametrize(
    "body",
    [
        # ``error`` is not an object, or lacks a code or a string message.
        {"error": "x"},
        {"error": None},
        {"error": []},
        {"error": {}},
        {"error": {"code": 1}},
        {"error": {"message": "x"}},
        {"error": {"code": True, "message": "x"}},
        {"error": {"code": "", "message": "x"}},
        {"error": {"code": 1, "message": 7}},
        {"error": {"code": None, "message": "x"}},
        # Anything beside ``error``: a record, a payload with data, an envelope with more.
        {"data": [{"id": "a"}], "error": {}},
        {"data": [], "error": {"code": 1, "message": "x"}},
        {"id": "r1", "name": "n", "error": {"code": 1, "message": "x"}},
        {"error": {"code": 1, "message": "x"}, "traceId": "t"},
        # ``error`` deeper down.
        {"data": [{"id": "a", "error": {"code": 1, "message": "x"}}]},
        {"result": {"error": {"code": 1, "message": "x"}}},
        # Not an object at all.
        [{"error": {"code": 1, "message": "x"}}],
        [],
        "text",
        "",
        None,
        7,
        True,
    ],
)
def test_a_detector_ignores_everything_else(body):
    assert v2_error_envelope(V2, 200, body) is None


def _recorded_v2_bodies() -> list[tuple[str, int, str, Any]]:
    rows: list[tuple[str, int, str, Any]] = []
    for path in sorted(FIXTURES.rglob("*.json")):
        try:
            doc = json.loads(path.read_text())
        except ValueError:
            continue
        request = doc.get("request") if isinstance(doc, dict) else None
        if not isinstance(request, dict) or "/v2/api" not in str(request.get("path", "")):
            continue
        rows.append((path.name, doc.get("status", 200), request["path"], doc.get("body")))
    return rows


def test_a_every_recorded_v2_payload_passes_through():
    """Negative corpus: every Network v2 response our fixtures recorded (lists, records,
    stats, defaults, dashboards), taken as an HTTP 200, is not an error."""
    rows = _recorded_v2_bodies()
    assert len(rows) > 40, "the recorded v2 fixtures went missing"
    for name, _status, path, body in rows:
        assert v2_error_envelope(path, 200, body) is None, name


def test_a_fixture_shaped_bodies_that_carry_an_error_field_pass_through():
    """Real recorded shapes that contain ``error``: an automation-run record (a string
    ``error`` beside run fields) and a recorded 403 envelope (``error`` object plus
    ``traceId``) are payloads, not the bare refusal, even when served as a 200 from v2."""
    history = json.loads((FIXTURES / "protect_automation_backup" / "history.json").read_text())
    assert any("error" in row for row in history)
    assert v2_error_envelope(V2, 200, history) is None
    for row in history:
        assert v2_error_envelope(V2, 200, row) is None
    forbidden = json.loads(
        (FIXTURES / "recorded/errors/v1_carrier_subscribers__403.json").read_text()
    )
    assert forbidden["body"]["error"]["code"] and forbidden["body"]["error"]["message"]
    assert v2_error_envelope(V2, 200, forbidden["body"]) is None
    # The same envelope on the status it was recorded under is an ordinary HTTP error.
    assert v2_error_envelope(V2, 403, {"error": forbidden["body"]["error"]}) is None


@respx.mock
async def test_a_client_raises_with_the_complete_body_and_audits_failure(tmp_path):
    long_msg = "api.err.Sample " + "x" * 5000
    body = {"error": {"code": 400, "message": long_msg}}
    text = json.dumps(body, separators=(",", ":"))
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        audit = tmp_path / f"{method}.jsonl"
        client = _client(audit_log=str(audit), audit_log_format="json")
        respx.route(method=method, url=BASE + V2).mock(
            return_value=httpx.Response(
                200, content=text.encode(), headers={"content-type": "application/json"}
            )
        )
        with pytest.raises(UpstreamErrorBodyError) as exc:
            await client.request(method, V2, json={"name": "n"})
        assert isinstance(exc.value, UniFiConnectionError)
        assert text in str(exc.value)  # verbatim, never truncated
        assert str(exc.value).startswith(f"Upstream error body from {method} {V2}: HTTP 200")
        rec = json.loads(audit.read_text().strip())
        assert rec["outcome"] == "upstream_error_body" and rec["status"] == 200, rec
        # raise_on_error=False (the relay) gets the response back, body verbatim.
        resp = await client.request(method, V2, json={"name": "n"}, raise_on_error=False)
        assert resp.status_code == 200 and resp.json() == body


@respx.mock
async def test_a_client_raises_on_a_v2_read_too():
    respx.get(BASE + V2).mock(return_value=_json(200, ERR_BODY))
    with pytest.raises(UpstreamErrorBodyError, match="HTTP 200 with an error object"):
        await _client().get(V2)


@respx.mock
async def test_a_client_passes_legitimate_v2_payloads_and_other_surfaces(tmp_path):
    audit = tmp_path / "audit.jsonl"
    client = _client(audit_log=str(audit), audit_log_format="json")
    records = [
        {"id": "n1", "name": "rule", "error": {"code": 1, "message": "stored value"}},
        {"data": [{"id": "n1"}], "error": {}},
        [{"id": "n1", "error": "x"}],
        {"ok": True},
    ]
    for payload in records:
        respx.post(BASE + V2).mock(return_value=_json(200, payload))
        resp = await client.request("POST", V2, json={"name": "n"})
        assert resp.json() == payload
    # Another surface answering the same bare envelope: no v2 rule.
    respx.post(BASE + INTEGRATION).mock(return_value=_json(200, ERR_BODY))
    assert (await client.request("POST", INTEGRATION, json={})).json() == ERR_BODY
    outcomes = [json.loads(line)["outcome"] for line in audit.read_text().splitlines()]
    assert outcomes == ["success"] * 5


@respx.mock
async def test_a_a_real_v2_4xx_is_unchanged():
    body = {"code": "api.err.X", "errorCode": 400, "message": "bad"}
    respx.post(BASE + V2).mock(return_value=_json(400, body))
    with pytest.raises(UniFiHTTPError) as exc:
        await _client().post(V2, json={})
    assert exc.value.status == 400 and json.dumps(body, separators=(",", ":")) in str(exc.value)


# --- the cross-tool invariant over every tool that reaches a v2 route -----------------------
#: Tools that must be seen reaching a v2 route (so the derived set cannot silently shrink).
_MUST_BE_V2 = {
    "create_nat_rule",
    "update_nat_rule",
    "delete_nat_rule",
    "create_wireguard_users",
    "restart_vpn_server",
    "create_static_dns_record",
    "create_traffic_route",
    "update_global_network_config",
    "mark_critical_logs_read",
    "get_controller_stats",
    "fabric_connector_get",
    "fabric_connector_post",
    "fabric_connector_put",
    "fabric_connector_patch",
    "fabric_connector_delete",
}
_SUCCESS_FLAGS = ("verified", "deleted", "success", "applied", "noOp", "changed")


def _v2_served(up: uh.FakeUpstream) -> list[uh.Served]:
    return [s for s in up.served if not s.resolution and uh.family(s.path) == "v2"]


def _args(name: str) -> dict[str, Any] | None:
    """Generated arguments; the generic relays get a v2 path (their default is Integration)."""
    if not name.startswith("fabric_connector_"):
        return None
    args = tool_args.generated_args(TOOLS[name])
    method = name.rsplit("_", 1)[1]
    suffix = "" if method in ("get", "post") else f"/{uh.ARG_HEX}"
    args["path"] = "network/v2/api/site/{site}/nat" + suffix
    return args


def _walk(obj: Any) -> list[Any]:
    out, stack = [], [obj]
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


async def _eligible_v2_error_is_an_upstream_error(monkeypatch, name):
    up = uh.FakeUpstream(v2_error_body=ERR_BODY)
    try:
        await _call(monkeypatch, name, up, args=_args(name))
    except Exception as exc:  # noqa: BLE001 - any failure of a tool that never reached v2
        if not _v2_served(up):
            if isinstance(exc, UniFiConnectionError) or name not in _MUST_BE_V2:
                return False
            raise
        return True
    if not _v2_served(up):
        assert name not in _MUST_BE_V2, f"{name}: reached no v2 route"
        return False
    return True


@tool_batches(
    "name",
    lambda: sorted(n for n in TOOLS if n not in cti.NO_UPSTREAM),
    eligible=_eligible_v2_error_is_an_upstream_error,
)
async def test_a_v2_error_envelope_is_an_upstream_error_for_every_tool(monkeypatch, name):
    up = uh.FakeUpstream(v2_error_body=ERR_BODY)
    try:
        res = await _call(monkeypatch, name, up, args=_args(name))
    except Exception as exc:  # noqa: BLE001
        assert _v2_served(up), f"{name}: failed before any v2 route: {exc}"
        assert ERR_TEXT in str(exc), (
            f"{name}: the v2 error is not raised with the full upstream body: {exc}"
        )
        return
    payload = uh.result_payload(res)
    leaves = [n for n in _walk(payload) if isinstance(n, str)]
    assert any(ERR_MSG in leaf for leaf in leaves), (
        f"{name}: a v2 error envelope was swallowed (no error, message absent): "
        f"{uh.all_strings(payload)[:400]}"
    )
    claims = _success_claims(payload)
    assert not claims, f"{name}: a refused v2 request reported success: {claims}"
    if name in cti.RAW_RELAY:
        assert payload["status"] == 200 and payload["body"] == ERR_BODY, payload
        assert ERR_MSG in payload["_upstreamError"], payload
        assert payload.get("noOp") is None and "changed" not in payload, payload


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
async def test_a_relay_write_refused_inside_a_200_draws_no_verdict(monkeypatch, method):
    """Both reads succeed and are identical; the write is a v2 error envelope."""
    name = f"fabric_connector_{method.lower()}"
    up = uh.FakeUpstream(v2_error_body=ERR_BODY, v2_error_methods=(method,))
    payload = uh.result_payload(await _call(monkeypatch, name, up, args=_args(name)))
    assert payload["status"] == 200 and payload["body"] == ERR_BODY
    assert ERR_MSG in payload["_upstreamError"]
    assert "_upstreamError" not in payload["readBefore"]
    assert payload["noOp"] is None and "changed" not in payload, payload


async def test_a_relay_read_after_error_envelope_is_reported(monkeypatch):
    name = "fabric_connector_put"
    up = uh.FakeUpstream(v2_error_body=ERR_BODY, v2_error_methods=("GET",))
    payload = uh.result_payload(await _call(monkeypatch, name, up, args=_args(name)))
    assert "_upstreamError" not in payload, payload
    assert ERR_MSG in payload["readBefore"]["_upstreamError"]
    assert ERR_MSG in payload["readAfter"]["_upstreamError"]
    assert payload["readAfter"]["body"] == ERR_BODY
    assert payload["noOp"] is None and "changed" not in payload, payload
    assert ERR_MSG in payload["readAfterError"], payload


async def test_a_relay_passes_a_clean_v2_body_without_a_marker(monkeypatch):
    up = uh.FakeUpstream()
    payload = uh.result_payload(
        await _call(monkeypatch, "fabric_connector_get", up, args=_args("fabric_connector_get"))
    )
    served = _v2_served(up)[0]
    assert payload["body"] == served.body and "_upstreamError" not in payload


async def test_a_relay_audits_the_refused_write_as_a_failure(monkeypatch, tmp_path):
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("UNIFI_AUDIT_SINK", "file")
    monkeypatch.setenv("UNIFI_AUDIT_LOG", str(audit))
    monkeypatch.setenv("UNIFI_AUDIT_LOG_FORMAT", "json")
    up = uh.FakeUpstream(v2_error_body=ERR_BODY, v2_error_methods=("POST",))
    await _call(monkeypatch, "fabric_connector_post", up, args=_args("fabric_connector_post"))
    records = [json.loads(line) for line in audit.read_text().splitlines() if line]
    outcomes = {r["outcome"] for r in records if r.get("event") == "audit"}
    assert "upstream_error_body" in outcomes, records
    assert "success" not in outcomes, records
