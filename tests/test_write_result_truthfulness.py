from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools import carrier_fabric as cf
from unifi_fabric.tools import placement_snapshot as ps
from unifi_fabric.tools import protect_private as pp


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "write_status,before_status", [(404, 404), (404, 200), (200, 404), (500, 200), (200, 500)]
)
async def test_unconfirmed_delete_not_verified(monkeypatch, write_status, before_status):
    monkeypatch.setattr(pp, "_guard", lambda *_: None)
    monkeypatch.setattr(pp, "_device_path", AsyncMock(return_value="path"))
    result = {
        "status": write_status,
        "readBefore": {"status": before_status, "body": {"id": "id"}},
        "readAfter": {"status": 404, "body": None},
        "_verified": None,
    }
    monkeypatch.setattr(pp, "_action", AsyncMock(return_value=result))
    out = await pp.unadopt_protect_device(None, None, "host", "camera", "id")
    assert out["_verified"] is None
    assert out.get("changed") is not True


@pytest.mark.asyncio
async def test_carrier_mismatched_write_response_reads_addressed_resource(monkeypatch):
    client = object()
    response = {"data": {"id": "other", "name": "new"}}
    fetch = AsyncMock(return_value={"data": {"id": "target", "name": "old"}})
    monkeypatch.setattr(cf, "_fetch_subscriber", fetch)
    body, error = await cf._after_write(client, "target", None, response)
    assert body["data"]["id"] == "target"
    assert error is None
    fetch.assert_awaited_once()


@pytest.mark.asyncio
async def test_carrier_mismatched_preread_does_not_claim_noop(monkeypatch):
    client = AsyncMock()
    monkeypatch.setattr(
        cf,
        "first_success",
        AsyncMock(return_value=(None, {"data": {"id": "other", "name": "new"}})),
    )
    with pytest.raises(UniFiConnectionError):
        await cf.update_carrier_subscriber(client, "target", name="new")
    client.patch.assert_not_awaited()


@pytest.mark.asyncio
async def test_carrier_missing_cursor_at_exact_limit(monkeypatch):
    async def request(*args, **kwargs):
        return {"data": [{"id": "one"}], "meta": {"hasMore": True}}

    client = AsyncMock()
    client.list_key_labels = lambda: []
    client.paginate_max_pages = None
    client.get.side_effect = request
    result = await cf.list_carrier_subscribers(client, limit=1)
    assert result["incomplete"] is True
    assert "nextCursor" in result["incompleteReason"]
    assert result["data"] == [{"id": "one"}]
    assert result["meta"]["hasMore"] is True


def test_unique_cross_source_mac_deduplicated_and_links():
    cameras = [{"id": "cam1", "mac": "aa:bb:cc:dd:ee:ff", "name": "Door"}]
    devices = [{"mac": "AA-BB-CC-DD-EE-FF", "name": "Door", "ip": "192.0.2.1"}]
    inventory = ps._topology_inventory(cameras=cameras, sensors=[], network_devices=devices)
    assert len(inventory) == 1
    assert inventory[0]["kind"] == "protect_camera"
    assert ps._unique_name_links([{"source_id": "place", "display_name": "Door"}], inventory)


def test_ambiguous_cross_source_mac_not_deduplicated():
    cameras = [
        {"id": "cam1", "mac": "aa:bb:cc:dd:ee:ff"},
        {"id": "cam2", "mac": "aa:bb:cc:dd:ee:ff"},
    ]
    devices = [{"id": "net1", "mac": "aa:bb:cc:dd:ee:ff"}]
    assert len(ps._topology_inventory(cameras=cameras, sensors=[], network_devices=devices)) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("read_body", [{"data": {"id": "other", "name": "new"}}, {"data": None}])
async def test_carrier_unidentifiable_readback_is_unknown(monkeypatch, read_body):
    raw = {"data": {"id": "other", "name": "new"}}
    monkeypatch.setattr(cf, "_fetch_subscriber", AsyncMock(return_value=read_body))
    body, error = await cf._after_write(object(), "target", None, raw)
    result = cf._written("updated", {}, body, error, raw, lambda after: True)
    assert result["verified"] is None
    assert result["response"] == raw
    assert result["readAfterError"]


def test_ambiguous_network_mac_not_deduplicated():
    cameras = [{"id": "cam1", "mac": "aa:bb:cc:dd:ee:ff"}]
    devices = [
        {"id": "net1", "mac": "aa:bb:cc:dd:ee:ff"},
        {"id": "net2", "mac": "aa:bb:cc:dd:ee:ff"},
    ]
    assert len(ps._topology_inventory(cameras=cameras, sensors=[], network_devices=devices)) == 3
