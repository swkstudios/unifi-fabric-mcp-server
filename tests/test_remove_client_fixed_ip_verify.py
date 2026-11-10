"""Public issue #47: ``remove_client_fixed_ip`` confirms only what the returned record shows.

A 2xx answer to the PUT is not proof the reservation is gone. The result says ``deleted:
true`` only when the same client's returned row has ``use_fixedip: false``; a row that still
says ``true`` (or a body with no state for the client) returns ``deleted: false`` in the
canonical ``{deleted, message, response}`` deletion result with the upstream body kept, the
PUT is sent exactly once and a dry run sends nothing. Synthetic data only (RFC 7042
documentation MAC).
"""

from __future__ import annotations

import copy
from typing import Any

import httpx
import pytest

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh

TARGET = "6523f0c1e4b0a1b2c3d4e5f6"
MAC = "00:00:5e:00:53:42"
USERS = {"meta": {"rc": "ok"}, "data": [{"_id": TARGET, "mac": MAC, "use_fixedip": True}]}


class _Upstream(uh.FakeUpstream):
    def __init__(self, put_body: Any) -> None:
        super().__init__()
        self.put_body = put_body

    def __call__(self, req: httpx.Request) -> httpx.Response:
        response = super().__call__(req)
        path = req.url.path
        if req.method == "GET" and path.endswith("/rest/user"):
            body = copy.deepcopy(USERS)
            self.served[-1].body = body
            return httpx.Response(200, json=body)
        if req.method == "PUT" and path.endswith(f"/rest/user/{TARGET}"):
            body = copy.deepcopy(self.put_body)
            self.served[-1].body = body
            return httpx.Response(200, json=body)
        return response


@pytest.fixture(scope="module", autouse=True)
def _tool_catalog_ready() -> Any:
    return cti.TOOLS["remove_client_fixed_ip"]


async def _remove(monkeypatch, up: _Upstream, env: dict[str, str] | None = None):
    args = {**tool_args.generated_args(cti.TOOLS["remove_client_fixed_ip"]), "client": MAC}
    res = await cti._call(monkeypatch, "remove_client_fixed_ip", up, args=args, env=env)
    return uh.result_payload(res)


def _envelope(*rows: dict[str, Any]) -> dict[str, Any]:
    return {"meta": {"rc": "ok"}, "data": list(rows)}


async def test_use_fixedip_still_true_is_not_a_removal(monkeypatch):
    body = _envelope({"_id": TARGET, "mac": MAC, "use_fixedip": True})
    up = _Upstream(body)
    payload = await _remove(monkeypatch, up)
    assert set(payload) == {"deleted", "message", "response"}
    assert payload["deleted"] is False and "not confirmed" in payload["message"]
    assert "removed." not in payload["message"] and "use_fixedip: true" in payload["message"]
    assert payload["response"] == body
    assert len(up.writes()) == 1 and up.writes()[0].sent_json == {"use_fixedip": False}


async def test_use_fixedip_false_confirms_and_keeps_the_upstream_body(monkeypatch):
    body = _envelope({"_id": TARGET, "mac": MAC, "use_fixedip": False})
    up = _Upstream(body)
    payload = await _remove(monkeypatch, up)
    assert payload == {
        "deleted": True,
        "message": f"Fixed-IP reservation of client {MAC} removed.",
        "response": body,
    }
    assert len(up.writes()) == 1


@pytest.mark.parametrize(
    "body",
    [
        _envelope(),
        _envelope({"_id": TARGET, "mac": MAC}),
        _envelope({"_id": "6523f0c1e4b0a1b2c3d4e5ff", "use_fixedip": False}),
        _envelope({"_id": TARGET, "use_fixedip": "false"}),
        _envelope({"_id": TARGET, "use_fixedip": False}, {"_id": TARGET, "use_fixedip": True}),
    ],
    ids=["no-rows", "no-state", "other-client", "non-boolean", "conflicting-rows"],
)
async def test_missing_or_ambiguous_state_is_not_verified_removal(monkeypatch, body):
    up = _Upstream(body)
    payload = await _remove(monkeypatch, up)
    assert set(payload) == {"deleted", "message", "response"}
    assert payload["deleted"] is False and "not confirmed" in payload["message"]
    assert payload["response"] == body
    assert len(up.writes()) == 1


@pytest.mark.parametrize(
    "body",
    [
        {"meta": {"rc": "ok"}, "data": [{"_id": TARGET, "use_fixedip": False}, "not-a-row"]},
        {"meta": {"rc": "ok"}, "data": {"_id": TARGET, "use_fixedip": False}},
        {"meta": {"rc": "ok"}},
        [{"_id": TARGET, "use_fixedip": False}],
        "accepted",
    ],
    ids=["non-object-row", "data-object", "no-data", "bare-array", "text-body"],
)
async def test_an_unexpected_shape_is_never_skipped_into_a_confirmation(monkeypatch, body):
    """No row of the upstream body is dropped before it is judged: a shape that is not a
    list of client records is reported as not confirmed, never read as confirmation."""
    up = _Upstream(body)
    payload = await _remove(monkeypatch, up)
    assert set(payload) == {"deleted", "message", "response"}
    assert payload["deleted"] is False and "not confirmed" in payload["message"]
    assert payload["response"] == body
    assert len(up.writes()) == 1


async def test_dry_run_sends_nothing_and_never_reports_deletion(monkeypatch):
    up = _Upstream(_envelope({"_id": TARGET, "use_fixedip": False}))
    payload = await _remove(monkeypatch, up, env={"UNIFI_WRITE_POLICY": "dry-run"})
    assert up.writes() == []
    assert payload["status"] == "dry_run" and payload["deleted"] is False
