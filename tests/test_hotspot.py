"""Tests for hotspot tools — operator accounts.

Hotspot vouchers live in the network-services proxy tools
(``tests/test_network_services_proxy.py``); this module covers only the
Classic-REST operator tools registered from ``tools/hotspot.py``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
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
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


# --- Hotspot Operators ---


class TestListHotspotOperators:
    async def test_basic(self, client, registry):
        body = {"meta": {"rc": "ok"}, "data": [{"id": "op-1", "name": "admin"}]}
        client.get.return_value = body
        result = await list_hotspot_operators(client, registry, "myhost", "mysite")
        client.get.assert_called_once_with(f"{CLASSIC_REST_BASE}/hotspotop", key=None)
        # The Classic envelope verbatim (meta kept, no invented count/operators keys)
        assert result == {"meta": {"rc": "ok"}, "data": [{"id": "op-1", "name": "admin"}]}
        assert "count" not in result

    async def test_resolves_host_and_site(self, client, registry):
        client.get.return_value = {"data": []}
        await list_hotspot_operators(client, registry, "myhost", "mysite")
        registry.resolve_host_id.assert_called_once_with("myhost", key=None)
        registry.resolve_site_slug.assert_called_once_with("mysite", HOST_ID, key=None)

    async def test_empty(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        result = await list_hotspot_operators(client, registry, "h", "s")
        assert result == {"meta": {"rc": "ok"}, "data": []}

    async def test_unexpected_shape_raises(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}}
        with pytest.raises(UniFiConnectionError, match="'data' array"):
            await list_hotspot_operators(client, registry, "h", "s")


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

    async def test_empty_note_is_sent_as_given(self, client, registry):
        client.post.return_value = {"meta": {"rc": "ok"}, "data": []}
        await create_hotspot_operator(client, registry, "h", "s", "op", "pw", note="")
        assert client.post.call_args[1]["json"]["note"] == ""

    async def test_list_valued_data_returned_verbatim(self, client, registry):
        """The controller answers {meta, data: [...]}; the envelope is returned whole
        (it used to be unwrapped to a bare list under a dict return type)."""
        body = {"meta": {"rc": "ok"}, "data": [{"_id": "op-2", "name": "op"}]}
        client.post.return_value = body
        result = await create_hotspot_operator(client, registry, "h", "s", "op", "pw")
        assert result == {"meta": {"rc": "ok"}, "data": [{"_id": "op-2", "name": "op"}]}


class TestUpdateHotspotOperator:
    async def test_basic(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "op-1"}]}
        body = {"meta": {"rc": "ok"}, "data": [{"_id": "op-1", "name": "newname"}]}
        client.put.return_value = body
        result = await update_hotspot_operator(
            client, registry, "h", "s", "op-1", {"name": "newname"}
        )
        client.put.assert_called_once_with(
            f"{CLASSIC_REST_BASE}/hotspotop/op-1", key=None, json={"name": "newname"}
        )
        assert result == {"meta": {"rc": "ok"}, "data": [{"_id": "op-1", "name": "newname"}]}

    async def test_strips_empty_strings_from_list_fields(self, client, registry):
        """Like every other Classic PUT, padded list values are cleaned before writing."""
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "op-1"}]}
        client.put.return_value = {"meta": {"rc": "ok"}, "data": []}
        await update_hotspot_operator(
            client, registry, "h", "s", "op-1", {"note": "n", "sites": ["a", "", ""]}
        )
        assert client.put.call_args.kwargs["json"] == {"note": "n", "sites": ["a"]}

    async def test_uses_classic_rest_not_ea(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "op-1"}]}
        client.put.return_value = {"data": {}}
        await update_hotspot_operator(client, registry, "h", "s", "op-1", {"name": "x"})
        call_url = client.put.call_args[0][0]
        assert "/ea/hotspot-operators" not in call_url


class TestDeleteHotspotOperator:
    async def test_basic(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "op-1"}]}
        client.delete.return_value = None
        result = await delete_hotspot_operator(client, registry, "h", "s", "op-1")
        client.delete.assert_called_once_with(f"{CLASSIC_REST_BASE}/hotspotop/op-1", key=None)
        assert result == {
            "deleted": True,
            "message": "Hotspot operator op-1 deleted.",
            "response": None,
        }

    async def test_uses_classic_rest_not_ea(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"_id": "op-1"}]}
        client.delete.return_value = None
        await delete_hotspot_operator(client, registry, "h", "s", "op-1")
        call_url = client.delete.call_args[0][0]
        assert "/ea/hotspot-operators" not in call_url

    async def test_update_empty_fields_refused(self, client, registry):
        with pytest.raises(ValueError, match="pass at least one"):
            await update_hotspot_operator(client, registry, "h", "s", "op-1", {})
