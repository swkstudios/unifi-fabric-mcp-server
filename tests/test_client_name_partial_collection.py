"""Public issue #48: ``set_client_name`` resolves an explicit id the collection omits.

The Classic ``rest/user`` collection is one answer that can be partial. A known-client
``_id`` absent from it is read from ``rest/user/{id}`` before the rename is declared
not found; a missing, mismatched or unsafe id still fails with no write. Synthetic data
only (RFC 7042 documentation MACs, generated ids).
"""

from __future__ import annotations

import copy
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh

TARGET = "6523f0c1e4b0a1b2c3d4e5f6"
TARGET_MAC = "00:00:5e:00:53:42"
RECORD = {"_id": TARGET, "mac": TARGET_MAC, "name": "old-name"}


def _others(count: int) -> list[dict[str, Any]]:
    def mac(i: int) -> str:
        return f"00:00:5e:{i >> 16 & 255:02x}:{i >> 8 & 255:02x}:{i & 255:02x}"

    return [{"_id": f"{i:024x}", "mac": mac(i)} for i in range(1, count + 1)]


class _Upstream(uh.FakeUpstream):
    """Classic user collection and individual resource, with a configurable collection."""

    def __init__(
        self,
        *,
        collection: list[dict[str, Any]],
        single: dict[str, Any] | int | str | None,
    ) -> None:
        super().__init__()
        self.collection = collection
        self.single = single

    def __call__(self, req: httpx.Request) -> httpx.Response:
        response = super().__call__(req)
        path = req.url.path
        if req.method == "GET" and path.endswith("/rest/user"):
            body = {"meta": {"rc": "ok"}, "data": copy.deepcopy(self.collection)}
            self.served[-1].body = body
            return httpx.Response(200, json=body)
        if req.method == "GET" and "/rest/user/" in path:
            if isinstance(self.single, str):
                body = {"meta": {"rc": "error", "msg": self.single}, "data": []}
                self.served[-1].body = body
                return httpx.Response(200, json=body)
            if isinstance(self.single, int):
                body = {"meta": {"rc": "error", "msg": "api.err.Test"}, "data": []}
                self.served[-1].body = body
                self.served[-1].status = self.single
                return httpx.Response(self.single, json=body)
            rows = [copy.deepcopy(self.single)] if self.single else []
            body = {"meta": {"rc": "ok"}, "data": rows}
            self.served[-1].body = body
            return httpx.Response(200, json=body)
        return response

    def gets(self, suffix: str) -> list[Any]:
        return [s for s in self.served if s.method == "GET" and s.path.endswith(suffix)]


@pytest.fixture(scope="module", autouse=True)
def _tool_catalog_ready() -> Any:
    return cti.TOOLS["set_client_name"]


async def _rename(monkeypatch, up: _Upstream, client: str):
    args = {
        **tool_args.generated_args(cti.TOOLS["set_client_name"]),
        "client": client,
        "name": "new-name",
    }
    return await cti._call(monkeypatch, "set_client_name", up, args=args)


def _put_targets(up: _Upstream) -> list[tuple[str, Any]]:
    return [(s.path.rsplit("/", 1)[-1], s.sent_json) for s in up.writes()]


async def test_partial_collection_and_readable_id_sends_one_put_to_that_resource(monkeypatch):
    up = _Upstream(collection=_others(3000), single=RECORD)
    await _rename(monkeypatch, up, TARGET)
    assert _put_targets(up) == [(TARGET, {"name": "new-name"})]
    assert len(up.gets(f"/rest/user/{TARGET}")) == 1


async def test_complete_collection_control_needs_no_individual_read(monkeypatch):
    up = _Upstream(collection=[*_others(3), RECORD], single=None)
    await _rename(monkeypatch, up, TARGET)
    assert _put_targets(up) == [(TARGET, {"name": "new-name"})]
    assert up.gets(f"/rest/user/{TARGET}") == []


@pytest.mark.parametrize("single", [404, {}], ids=["http-404", "no-row"])
async def test_individually_missing_id_still_fails_without_a_write(monkeypatch, single):
    up = _Upstream(collection=_others(5), single=single or None)
    with pytest.raises(ToolError, match="not found by _id or MAC"):
        await _rename(monkeypatch, up, TARGET)
    assert up.writes() == []


async def test_mismatched_returned_identity_never_causes_a_write(monkeypatch):
    other = {"_id": "6523f0c1e4b0a1b2c3d4e5ff", "mac": "00:00:5e:00:53:99"}
    up = _Upstream(collection=_others(5), single=other)
    with pytest.raises(ToolError, match="not found by _id or MAC"):
        await _rename(monkeypatch, up, TARGET)
    assert up.writes() == []


async def test_individual_read_server_error_is_not_absence_and_sends_no_write(monkeypatch):
    up = _Upstream(collection=_others(5), single=500)
    with pytest.raises(ToolError):
        await _rename(monkeypatch, up, TARGET)
    assert up.writes() == []


async def test_unknown_mac_is_not_looked_up_individually(monkeypatch):
    up = _Upstream(collection=_others(5), single=RECORD)
    with pytest.raises(ToolError, match="not found among this site"):
        await _rename(monkeypatch, up, TARGET_MAC)
    assert up.writes() == []
    assert not [s for s in up.served if "/rest/user/" in s.path]


async def test_a_mac_in_the_collection_resolves_as_before(monkeypatch):
    up = _Upstream(collection=[*_others(3), RECORD], single=None)
    await _rename(monkeypatch, up, TARGET_MAC)
    assert _put_targets(up) == [(TARGET, {"name": "new-name"})]
    assert up.gets(f"/rest/user/{TARGET}") == []


@pytest.mark.parametrize("code", ["api.err.NotFound", "api.err.ClientNotFound"])
async def test_classic_not_found_code_is_absence_and_sends_no_write(monkeypatch, code):
    up = _Upstream(collection=_others(5), single=code)
    with pytest.raises(ToolError, match="not found by _id or MAC"):
        await _rename(monkeypatch, up, TARGET)
    assert up.writes() == []


@pytest.mark.parametrize(
    "code", ["api.err.NoPermission", "api.err.LoginRequired", "api.err.InvalidObject"]
)
async def test_classic_permission_login_and_other_errors_propagate(monkeypatch, code):
    up = _Upstream(collection=_others(5), single=code)
    with pytest.raises(ToolError) as exc:
        await _rename(monkeypatch, up, TARGET)
    assert code in str(exc.value)
    assert "not found by _id or MAC" not in str(exc.value)
    assert up.writes() == []
