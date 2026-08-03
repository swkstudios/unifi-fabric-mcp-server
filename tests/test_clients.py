"""Tests for client management tools via connector proxy."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import PaginationAbortedError
from unifi_fabric.tools.clients import _CLASSIC_CMD_BASE
from unifi_fabric.tools.clients import (
    _block_client as block_client,
)
from unifi_fabric.tools.clients import (
    _execute_client_action as execute_client_action,
)
from unifi_fabric.tools.clients import (
    _get_client as get_client,
)
from unifi_fabric.tools.clients import (
    _list_clients as list_clients,
)
from unifi_fabric.tools.clients import (
    _reconnect_client as reconnect_client,
)
from unifi_fabric.tools.clients import (
    _unblock_client as unblock_client,
)
from unifi_fabric.tools.network import PROXY_BASE

HOST_ID = "host-001"
SITE_ID = "11111111-0000-0000-0000-000000000001"
SITE_SLUG = "default"
BASE = PROXY_BASE.format(host_id=HOST_ID)
CLASSIC_CMD_BASE = _CLASSIC_CMD_BASE.format(host_id=HOST_ID, site_slug=SITE_SLUG)
CLIENT_MAC = "aa:bb:cc:dd:ee:ff"


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


class TestListClients:
    async def test_drains_all_by_default(self, client, registry):
        # Default: drain every offset page via paginate_offset — get() unused.
        client.paginate_offset.return_value = [
            {"id": "cl-1", "hostname": "laptop"},
            {"id": "cl-2"},
        ]
        result = await list_clients(client, registry, "h", "s")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients", key=None, params=None, page_size=200
        )
        client.get.assert_not_called()
        assert result == {
            "data": [{"id": "cl-1", "hostname": "laptop"}, {"id": "cl-2"}],
            "totalCount": 2,
        }

    async def test_resolves_names(self, client, registry):
        client.paginate_offset.return_value = []
        await list_clients(client, registry, "UDM-Pro", "Office")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro")
        registry.resolve_site_id.assert_called_once_with("Office", HOST_ID)

    async def test_explicit_offset_and_limit_single_page(self, client, registry):
        # Explicit paging: one page only, API totalCount surfaced for manual paging.
        client.get.return_value = {"data": [{"id": "cl-9"}], "totalCount": 51}
        result = await list_clients(client, registry, "h", "s", offset=25, limit=25)
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients", key=None, params={"offset": 25, "limit": 25}
        )
        client.paginate_offset.assert_not_called()
        assert result == {"data": [{"id": "cl-9"}], "totalCount": 51}

    async def test_client_type_wireless_filter_drains(self, client, registry):
        client.paginate_offset.return_value = []
        await list_clients(client, registry, "h", "s", client_type="WIRELESS")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients",
            key=None,
            params={"type": "WIRELESS"},
            page_size=200,
        )

    async def test_client_type_all_omits_type_param(self, client, registry):
        client.paginate_offset.return_value = []
        await list_clients(client, registry, "h", "s", client_type="ALL")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients", key=None, params=None, page_size=200
        )

    async def test_client_type_lowercase_normalized(self, client, registry):
        client.paginate_offset.return_value = []
        await list_clients(client, registry, "h", "s", client_type="wired")
        client.paginate_offset.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients",
            key=None,
            params={"type": "WIRED"},
            page_size=200,
        )

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        client.paginate_offset.side_effect = PaginationAbortedError(
            f"{BASE}/sites/{SITE_ID}/clients", 5, "page cap of 5 reached", items=[{"id": "cl-1"}]
        )
        result = await list_clients(client, registry, "h", "s")
        assert result["incomplete"] is True
        assert "page cap of 5" in result["incompleteReason"]
        assert result["data"] == [{"id": "cl-1"}]
        assert result["totalCount"] == 1


class TestGetClient:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "cl-1", "hostname": "laptop"}
        result = await get_client(client, registry, "h", "s", "cl-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/clients/cl-1")
        assert result["id"] == "cl-1"


class TestExecuteClientAction:
    async def test_block(self, client, registry):
        action = {"action": "block"}
        client.post.return_value = {"status": "ok"}
        result = await execute_client_action(client, registry, "h", "s", "cl-1", action)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients/cl-1/actions", json=action
        )
        assert result["status"] == "ok"

    async def test_reconnect(self, client, registry):
        action = {"action": "reconnect"}
        client.post.return_value = {"status": "ok"}
        result = await execute_client_action(client, registry, "h", "s", "cl-1", action)
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients/cl-1/actions", json=action
        )
        assert result["status"] == "ok"


class TestBlockClient:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "cl-1", "mac": CLIENT_MAC}
        client.post.return_value = {"status": "ok"}
        result = await block_client(client, registry, "h", "s", "cl-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/clients/cl-1")
        client.post.assert_called_once_with(
            f"{CLASSIC_CMD_BASE}/stamgr", json={"cmd": "block-sta", "mac": CLIENT_MAC}
        )
        assert result["status"] == "ok"

    async def test_mac_from_macAddress_field(self, client, registry):
        client.get.return_value = {"id": "cl-1", "macAddress": CLIENT_MAC}
        client.post.return_value = {"status": "ok"}
        await block_client(client, registry, "h", "s", "cl-1")
        call_json = client.post.call_args[1]["json"]
        assert call_json["mac"] == CLIENT_MAC

    async def test_no_mac_raises(self, client, registry):
        client.get.return_value = {"id": "cl-1"}
        with pytest.raises(ValueError, match="MAC address"):
            await block_client(client, registry, "h", "s", "cl-1")


class TestUnblockClient:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "cl-1", "mac": CLIENT_MAC}
        client.post.return_value = {"status": "ok"}
        result = await unblock_client(client, registry, "h", "s", "cl-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/clients/cl-1")
        client.post.assert_called_once_with(
            f"{CLASSIC_CMD_BASE}/stamgr", json={"cmd": "unblock-sta", "mac": CLIENT_MAC}
        )
        assert result["status"] == "ok"

    async def test_no_mac_raises(self, client, registry):
        client.get.return_value = {"id": "cl-1"}
        with pytest.raises(ValueError, match="MAC address"):
            await unblock_client(client, registry, "h", "s", "cl-1")


class TestReconnectClient:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "cl-1", "mac": CLIENT_MAC}
        client.post.return_value = {"status": "ok"}
        result = await reconnect_client(client, registry, "h", "s", "cl-1")
        client.get.assert_called_once_with(f"{BASE}/sites/{SITE_ID}/clients/cl-1")
        client.post.assert_called_once_with(
            f"{CLASSIC_CMD_BASE}/stamgr", json={"cmd": "kick-sta", "mac": CLIENT_MAC}
        )
        assert result["status"] == "ok"

    async def test_no_mac_raises(self, client, registry):
        client.get.return_value = {"id": "cl-1"}
        with pytest.raises(ValueError, match="MAC address"):
            await reconnect_client(client, registry, "h", "s", "cl-1")
