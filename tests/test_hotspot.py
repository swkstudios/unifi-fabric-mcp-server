"""Tests for hotspot tools — operators and vouchers."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.hotspot import (
    _create_hotspot_operator as create_hotspot_operator,
)
from unifi_fabric.tools.hotspot import (
    _create_vouchers as create_vouchers,
)
from unifi_fabric.tools.hotspot import (
    _delete_hotspot_operator as delete_hotspot_operator,
)
from unifi_fabric.tools.hotspot import (
    _delete_voucher as delete_voucher,
)
from unifi_fabric.tools.hotspot import (
    _list_hotspot_operators as list_hotspot_operators,
)
from unifi_fabric.tools.hotspot import (
    _list_vouchers as list_vouchers,
)
from unifi_fabric.tools.hotspot import (
    _update_hotspot_operator as update_hotspot_operator,
)

HOST_ID = "host-001"
SITE_ID = "site-001"
SITE_SLUG = "default"
CLASSIC_REST_BASE = f"/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/{SITE_SLUG}/rest"


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock()
    c.patch = AsyncMock()
    c.delete = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


# --- Hotspot Operators ---


class TestListHotspotOperators:
    async def test_basic(self, client, registry):
        client.get.return_value = {"data": [{"id": "op-1", "name": "admin"}]}
        result = await list_hotspot_operators(client, registry, "myhost", "mysite")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/hotspotop")
        assert result["count"] == 1
        assert result["operators"][0]["id"] == "op-1"

    async def test_resolves_host_and_site(self, client, registry):
        client.get.return_value = {"data": []}
        await list_hotspot_operators(client, registry, "myhost", "mysite")
        registry.resolve_host_id.assert_called_once_with("myhost")
        registry.resolve_site_slug.assert_called_once_with("mysite", HOST_ID)

    async def test_empty(self, client, registry):
        client.get.return_value = {"data": []}
        result = await list_hotspot_operators(client, registry, "h", "s")
        assert result == {"operators": [], "count": 0}


class TestCreateHotspotOperator:
    async def test_basic(self, client, registry):
        client.post.return_value = {"data": {"id": "op-2"}}
        await create_hotspot_operator(client, registry, "myhost", "mysite", "manager", "pass123")
        call_json = client.post.call_args[1]["json"]
        assert call_json["name"] == "manager"
        assert call_json["password"] == "pass123"
        assert call_json["hostId"] == HOST_ID
        assert call_json["siteId"] == SITE_ID
        assert "note" not in call_json

    async def test_with_note(self, client, registry):
        client.post.return_value = {"data": {}}
        await create_hotspot_operator(client, registry, "h", "s", "staff", "pw", note="Front desk")
        call_json = client.post.call_args[1]["json"]
        assert call_json["note"] == "Front desk"

    async def test_without_note_omits_key(self, client, registry):
        client.post.return_value = {"data": {}}
        await create_hotspot_operator(client, registry, "h", "s", "op", "pw")
        call_json = client.post.call_args[1]["json"]
        assert "note" not in call_json


class TestUpdateHotspotOperator:
    async def test_basic(self, client):
        client.patch.return_value = {"data": {"id": "op-1", "name": "newname"}}
        result = await update_hotspot_operator(client, "op-1", name="newname")
        client.patch.assert_called_once_with("/ea/hotspot-operators/op-1", json={"name": "newname"})
        assert result["name"] == "newname"


class TestDeleteHotspotOperator:
    async def test_basic(self, client):
        client.delete.return_value = None
        result = await delete_hotspot_operator(client, "op-1")
        client.delete.assert_called_once_with("/ea/hotspot-operators/op-1")
        assert result == {"deleted": True, "operatorId": "op-1"}


# --- Vouchers ---


class TestListVouchers:
    async def test_no_filters(self, client, registry):
        client.get.return_value = {"data": [{"id": "v-1", "code": "ABC123"}]}
        result = await list_vouchers(client, registry)
        client.get.assert_called_once_with("/ea/vouchers", params=None)
        assert result["count"] == 1
        assert result["vouchers"][0]["id"] == "v-1"

    async def test_with_host_and_site(self, client, registry):
        client.get.return_value = {"data": []}
        await list_vouchers(client, registry, host="h", site="s")
        client.get.assert_called_once_with(
            "/ea/vouchers", params={"hostId": HOST_ID, "siteId": SITE_ID}
        )

    async def test_pagination(self, client, registry):
        client.get.return_value = {"data": [], "nextToken": "v2"}
        result = await list_vouchers(client, registry, page_token="v1")
        assert result["nextToken"] == "v2"


class TestCreateVouchers:
    async def test_defaults(self, client, registry):
        client.post.return_value = {"data": [{"id": "v-2"}]}
        await create_vouchers(client, registry, "myhost", "mysite")
        call_json = client.post.call_args[1]["json"]
        assert call_json["count"] == 1
        assert call_json["durationMinutes"] == 60
        assert call_json["hostId"] == HOST_ID
        assert call_json["siteId"] == SITE_ID
        assert "quotaMb" not in call_json
        assert "upBandwidthKbps" not in call_json
        assert "downBandwidthKbps" not in call_json
        assert "note" not in call_json

    async def test_with_quota_and_bandwidth(self, client, registry):
        client.post.return_value = {"data": []}
        await create_vouchers(
            client,
            registry,
            "h",
            "s",
            count=5,
            duration_minutes=120,
            quota_mb=500,
            up_bandwidth_kbps=1024,
            down_bandwidth_kbps=2048,
        )
        call_json = client.post.call_args[1]["json"]
        assert call_json["count"] == 5
        assert call_json["durationMinutes"] == 120
        assert call_json["quotaMb"] == 500
        assert call_json["upBandwidthKbps"] == 1024
        assert call_json["downBandwidthKbps"] == 2048

    async def test_with_note(self, client, registry):
        client.post.return_value = {"data": []}
        await create_vouchers(client, registry, "h", "s", note="Event pass")
        call_json = client.post.call_args[1]["json"]
        assert call_json["note"] == "Event pass"

    async def test_quota_zero_included(self, client, registry):
        client.post.return_value = {"data": []}
        await create_vouchers(client, registry, "h", "s", quota_mb=0)
        call_json = client.post.call_args[1]["json"]
        assert call_json["quotaMb"] == 0


class TestDeleteVoucher:
    async def test_basic(self, client):
        client.delete.return_value = None
        result = await delete_voucher(client, "v-1")
        client.delete.assert_called_once_with("/ea/vouchers/v-1")
        assert result == {"deleted": True, "voucherId": "v-1"}
