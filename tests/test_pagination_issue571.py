"""Synthetic regressions for pagination completion and translation."""

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools._continuation import encode_continuation
from unifi_fabric.tools._pagination import collect_batch
from unifi_fabric.tools.network_nat_qos_traffic import _flow_page_batch, _nc_drain


@pytest.mark.parametrize("family", ["cursor", "carrier"])
@pytest.mark.parametrize("resume", [False, True])
async def test_cursor_boundary_cycle(family, resume):
    async def fetch(controls):
        row = 2 if controls.get("nextToken") or controls.get("cursor") else 1
        if family == "cursor":
            return {"data": [{"id": row}], "nextToken": "T"}
        return {"data": [{"id": row}], "meta": {"hasMore": True, "nextCursor": "T"}}

    token = (
        encode_continuation(
            {
                "cursor" if family == "carrier" else "pageToken": "T",
                "limit" if family == "carrier" else "pageSize": 1,
            }
        )
        if resume
        else None
    )
    result = await collect_batch(
        fetch, requested=1 if resume else 2, known_max=1, family=family, token=token
    )
    assert result["incomplete"]
    assert "cursor cycle" in result["incompleteReason"]
    assert "_continuation" not in result


@pytest.mark.parametrize("requested", [None, 6])
async def test_offset_overlap_declared_total_shortfall(requested):
    async def fetch(controls):
        rows = [0, 1, 2] if controls.get("offset", 0) == 0 else [2, 3, 4]
        return {"data": [{"id": n} for n in rows], "totalCount": 6, "limit": 3}

    result = await collect_batch(fetch, requested=requested, known_max=3, family="offset")
    assert len(result["items"]) == 5
    assert result["incomplete"]
    assert result["incompleteReason"]


@pytest.mark.parametrize("evidence", ["total", "trimmed"])
async def test_empty_offset_witness_contradicts_remaining_evidence(evidence):
    async def fetch(controls):
        if controls.get("offset", 0):
            return {"data": [], "totalCount": 5} if evidence == "total" else {"data": []}
        return {
            "data": [{"id": n} for n in range(3 if evidence == "trimmed" else 2)],
            **({"totalCount": 5} if evidence == "total" else {}),
        }

    result = await collect_batch(fetch, requested=2, known_max=2, family="offset")
    assert result["incomplete"]
    assert "remaining records" in result["incompleteReason"]
    assert result["nextOffset"] is None


async def test_failed_traffic_translation_excludes_probe_rows():
    body, batch = _flow_page_batch({"pageNumber": 1, "pageSize": 1000})
    first = {
        "data": [{"id": n} for n in range(200, 400)],
        "limit": 200,
        "has_next": True,
        "page_number": 1,
    }

    async def fetch(body):
        assert body["pageNumber"] == 5
        raise UniFiConnectionError("synthetic failure", status=503)

    result = await _nc_drain(None, "/synthetic", body, first, fetch, batch)
    assert result["data"] == []
    assert result["incomplete"]
    assert "_nextPage" not in result
