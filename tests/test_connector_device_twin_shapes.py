"""Classic device twin shape validation preserves responses and unknown verdicts."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from tests.test_core_data_path_regressions import (
    DEV_ID,
    _device_row,
    _relay_registry,
    _Resp,
)
from unifi_fabric.tools import connector


@pytest.mark.parametrize("method", sorted(connector._REMAPPED_TWIN_METHODS))
@pytest.mark.parametrize("bad", [None, "scalar", 7, []], ids=repr)
@pytest.mark.parametrize("phase", ["before", "after", "both"])
async def test_every_device_twin_write_preserves_malformed_rows_and_unknown_verdict(
    method, bad, phase
):
    clean = {"meta": {"rc": "ok"}, "data": [_device_row("AP", 10)]}
    malformed = {"meta": {"rc": "ok"}, "data": [_device_row("AP", 10), bad]}
    pending = [
        malformed if phase in ("before", "both") else clean,
        malformed if phase in ("after", "both") else clean,
    ]

    async def request(verb, path, **kwargs):
        if verb == "GET":
            return _Resp(200, pending.pop(0))
        return _Resp(200, {"meta": {"rc": "ok"}, "data": []})

    client = AsyncMock()
    client.request = AsyncMock(side_effect=request)
    result = await connector.connector_write(
        client,
        _relay_registry(),
        "h",
        method,
        "network/api/s/{site}/rest/device/" + DEV_ID,
        site="Default",
        body={"name": "AP"},
        scope="device",
    )
    assert result["status"] == 200
    assert result["noOp"] is None
    assert "changed" not in result
    assert sum(call.args[0] != "GET" for call in client.request.await_args_list) == 1
    for key, malformed_phase in (
        ("readBefore", phase in ("before", "both")),
        ("readAfter", phase in ("after", "both")),
    ):
        if malformed_phase:
            assert result[key]["body"] == malformed
            assert "Unexpected response shape" in result[key]["twinError"]
            assert "item 1" in result[key]["twinError"]
    if phase in ("after", "both"):
        assert result["readAfterError"] == result["readAfter"]["twinError"]


@pytest.mark.parametrize("shape", ["bare", "absent", "ambiguous"])
async def test_unsupported_or_unresolved_twin_keeps_verdict_unknown(shape):
    target = _device_row("AP", 10)
    raw = (
        [target]
        if shape == "bare"
        else {"meta": {"rc": "ok"}, "data": [] if shape == "absent" else [target, target]}
    )
    client = AsyncMock()
    client.request = AsyncMock(return_value=_Resp(200, raw))
    result = await connector.connector_write(
        client,
        _relay_registry(),
        "h",
        "PUT",
        "network/api/s/{site}/rest/device/" + DEV_ID,
        site="Default",
        body={"name": "AP"},
        scope="device",
    )
    assert result["noOp"] is None
    assert "changed" not in result
    assert result["readBefore"]["body"] == raw
    assert result["readAfter"]["body"] == raw
    assert sum(call.args[0] == "PUT" for call in client.request.await_args_list) == 1


async def test_delete_same_path_reads_are_passed_through_without_device_selection():
    raw = {"meta": {"rc": "ok"}, "data": [_device_row("AP", 10), None]}
    client = AsyncMock()
    client.request = AsyncMock(return_value=_Resp(200, raw))
    result = await connector.connector_write(
        client,
        _relay_registry(),
        "h",
        "DELETE",
        "network/api/s/{site}/rest/device/" + DEV_ID,
        site="Default",
        scope="device",
    )
    assert result["readBefore"]["body"] == raw
    assert result["readAfter"]["body"] == raw
    assert "noOpBasis" not in result
    assert sum(call.args[0] == "DELETE" for call in client.request.await_args_list) == 1


@pytest.mark.parametrize("method", sorted(connector._REMAPPED_TWIN_METHODS))
async def test_device_twin_preserves_every_upstream_record_separately_from_comparison(method):
    target_before = _device_row("AP", 10)
    target_after = _device_row("AP", 20)
    other = {"_id": "ffffffffffffffffffffffff", "name": "other", "password": "synthetic"}
    before = {"meta": {"rc": "ok", "extra": "before"}, "data": [other, target_before]}
    after = {"meta": {"rc": "ok", "extra": "after"}, "data": [target_after, other]}
    pending = [before, after]

    async def request(verb, path, **kwargs):
        return _Resp(200, pending.pop(0) if verb == "GET" else {"meta": {"rc": "ok"}})

    client = AsyncMock()
    client.request = AsyncMock(side_effect=request)
    result = await connector.connector_write(
        client,
        _relay_registry(),
        "h",
        method,
        "network/api/s/{site}/rest/device/" + DEV_ID,
        site="Default",
        body={"name": "AP"},
        scope="device",
    )
    assert result["readBefore"]["body"] == before
    assert result["readAfter"]["body"] == after
    assert result["readBefore"]["comparisonRecords"] == [target_before]
    assert result["readAfter"]["comparisonRecords"] == [target_after]
    assert result["noOp"] is True
