"""A non-object update body keeps its verdict keys under ``response``."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from unifi_fabric.families.network import network_services_proxy as nsp


def _registry() -> MagicMock:
    reg = MagicMock()
    reg.resolve_key_for_host = AsyncMock(return_value=None)
    reg.resolve_host_id = AsyncMock(return_value="00000000-0000-4000-8000-0000000000a1")
    reg.resolve_site_slug = AsyncMock(return_value="default")
    return reg


async def test_update_setting_keeps_a_non_object_write_body_under_response():
    state = {"_id": "s1", "key": "mgmt", "x": 1}
    reads = [
        {"meta": {"rc": "ok"}, "data": [state]},
        {"meta": {"rc": "ok"}, "data": [{**state, "x": 2}]},
    ]
    api = MagicMock()
    api.get = AsyncMock(side_effect=reads)
    api.put = AsyncMock(return_value=["written"])
    out = await nsp.update_setting(api, _registry(), "h", "s", "mgmt", {"x": 2})
    assert out["response"] == ["written"]
    assert out["_verified"] is True


async def test_update_setting_read_after_failure_keeps_the_body_under_response():
    state = {"_id": "s1", "key": "mgmt", "x": 1}
    api = MagicMock()
    api.get = AsyncMock(
        side_effect=[{"meta": {"rc": "ok"}, "data": [state]}, RuntimeError("read-after 500")]
    )
    api.put = AsyncMock(return_value=["written"])
    out = await nsp.update_setting(api, _registry(), "h", "s", "mgmt", {"x": 2})
    assert out["response"] == ["written"]
    assert out["_verified"] is None
    assert "read-after 500" in out["_readAfterError"]


async def test_annotate_auto_exclusions_wraps_a_non_object_body():
    api = MagicMock()
    api.get = AsyncMock()
    out = await nsp.annotate_auto_exclusions(api, _registry(), "h", "s", ["x"])
    assert out["response"] == ["x"]
    assert out["_warnings"][0]["code"] == "D12_CHECK_FAILED"
    api.get.assert_not_called()
