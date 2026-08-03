"""Tests for hotspot tools — operator accounts.

Hotspot vouchers live in the network-services proxy tools
(``tests/test_network_services_proxy.py``); this module covers only the
Classic-REST operator tools registered from ``tools/hotspot.py``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.tools.hotspot import (
    _create_hotspot_operator as create_hotspot_operator,
)
from unifi_fabric.tools.hotspot import (
    _delete_hotspot_operator as delete_hotspot_operator,
)
from unifi_fabric.tools.hotspot import (
    _list_hotspot_operators as list_hotspot_operators,
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
    c.put = AsyncMock()
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
    """Operators are created via Classic REST (/rest/hotspotop), not the unserved
    Site Manager /ea/hotspot-operators path. Regression guard for the same
    path-asymmetry class as the VPN/RADIUS get tools: the list sibling already
    used Classic REST while create/update/delete pointed at the dead /ea path.
    """

    async def test_basic(self, client, registry):
        client.post.return_value = {"data": {"id": "op-2"}}
        await create_hotspot_operator(client, registry, "myhost", "mysite", "manager", "pass123")
        call_url = client.post.call_args[0][0]
        assert call_url == f"{CLASSIC_REST_BASE}/hotspotop"
        call_json = client.post.call_args[1]["json"]
        assert call_json["name"] == "manager"
        assert call_json["x_password"] == "pass123"
        assert "hostId" not in call_json
        assert "siteId" not in call_json
        assert "note" not in call_json

    async def test_uses_classic_rest_not_ea(self, client, registry):
        client.post.return_value = {"data": {}}
        await create_hotspot_operator(client, registry, "h", "s", "op", "pw")
        call_url = client.post.call_args[0][0]
        assert "/ea/hotspot-operators" not in call_url
        assert "/rest/hotspotop" in call_url

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
    async def test_basic(self, client, registry):
        client.put.return_value = {"data": {"id": "op-1", "name": "newname"}}
        result = await update_hotspot_operator(client, registry, "h", "s", "op-1", name="newname")
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/hotspotop/op-1", json={"name": "newname"}
        )
        assert result["name"] == "newname"

    async def test_uses_classic_rest_not_ea(self, client, registry):
        client.put.return_value = {"data": {}}
        await update_hotspot_operator(client, registry, "h", "s", "op-1", name="x")
        call_url = client.put.call_args[0][0]
        assert "/ea/hotspot-operators" not in call_url


class TestDeleteHotspotOperator:
    async def test_basic(self, client, registry):
        client.delete.return_value = None
        result = await delete_hotspot_operator(client, registry, "h", "s", "op-1")
        client.delete.assert_called_once_with(f"{CLASSIC_REST_BASE}/hotspotop/op-1")
        assert result == {"deleted": True, "operatorId": "op-1"}

    async def test_uses_classic_rest_not_ea(self, client, registry):
        client.delete.return_value = None
        await delete_hotspot_operator(client, registry, "h", "s", "op-1")
        call_url = client.delete.call_args[0][0]
        assert "/ea/hotspot-operators" not in call_url
