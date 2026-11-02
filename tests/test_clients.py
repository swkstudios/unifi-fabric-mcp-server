"""Tests for client management tools via connector proxy."""

from __future__ import annotations

from unittest.mock import AsyncMock, call

import pytest

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric.client import UniFiConnectionError
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
    c.paginate_max_pages = None
    c.post = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_site_id = AsyncMock(return_value=SITE_ID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


class TestListClients:
    async def test_drains_all_by_default(self, client, registry):
        # The real GET envelope preserves the upstream total through the shared drain.
        client.get.return_value = {
            "data": [
                {"id": "00000000-0000-4000-8000-0000000000c1", "hostname": "laptop"},
                {"id": "cl-2"},
            ],
            "totalCount": 2,
        }
        result = await list_clients(client, registry, "h", "s")
        client.get.assert_awaited_once_with(
            f"{BASE}/sites/{SITE_ID}/clients", key=None, params={"offset": 0, "limit": 200}
        )
        assert result == {
            "data": [
                {"id": "00000000-0000-4000-8000-0000000000c1", "hostname": "laptop"},
                {"id": "cl-2"},
            ],
            "totalCount": 2,
        }

    async def test_resolves_names(self, client, registry):
        client.get.return_value = []
        await list_clients(client, registry, "UDM-Pro", "Office")
        registry.resolve_host_id.assert_called_once_with("UDM-Pro", key=None)
        registry.resolve_site_id.assert_called_once_with("Office", HOST_ID, key=None)

    async def test_explicit_offset_and_limit_gathers_requested_total(self, client, registry):
        # The old offset+limit batching assertion encoded extra requests for a manual page.
        # Ruling 3 reserves batching for limit alone; keep its exact count and order checks.
        rows = [{"id": f"cl-{index}"} for index in range(51)]

        async def get(path, *, key=None, params):
            offset = params.get("offset", 0)
            size = min(params["limit"], 10)
            return {"data": rows[offset : offset + size], "limit": size, "totalCount": 51}

        client.get.side_effect = get
        result = await list_clients(client, registry, "h", "s", limit=25)
        assert client.get.await_args_list == [
            call(f"{BASE}/sites/{SITE_ID}/clients", key=None, params=params)
            for params in ({"limit": 25}, {"offset": 10, "limit": 10}, {"offset": 20, "limit": 5})
        ]
        client.paginate_offset.assert_not_called()
        assert result == {
            "data": rows[:25],
            "totalCount": 51,
            "_pageSize": {"requested": 25, "sent": [25, 10, 5], "effective": 10, "returned": 25},
            "_nextOffset": 25,
        }
        client.get.reset_mock()
        next_page = await list_clients(
            client, registry, "h", "s", offset=result["_nextOffset"], limit=25
        )
        client.get.assert_awaited_once_with(
            f"{BASE}/sites/{SITE_ID}/clients", key=None, params={"offset": 25, "limit": 25}
        )
        assert next_page == {
            "data": rows[25:35],
            "limit": 10,
            "totalCount": 51,
            "_pageSize": {"requested": 25, "sent": [25], "effective": 10, "returned": 10},
        }
        assert result["data"] + next_page["data"] == rows[:35]

    async def test_client_type_wireless_translated_to_filter(self, client, registry):
        # client_type is translated into the upstream type.eq(...) filter — the raw
        # `type` query param is a no-op upstream, so this is what actually narrows.
        client.get.return_value = []
        await list_clients(client, registry, "h", "s", client_type="WIRELESS")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients",
            key=None,
            params={"filter": "type.eq('WIRELESS')", "offset": 0, "limit": 200},
        )

    async def test_client_type_wired_translated_to_filter(self, client, registry):
        client.get.return_value = []
        await list_clients(client, registry, "h", "s", client_type="WIRED")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients",
            key=None,
            params={"filter": "type.eq('WIRED')", "offset": 0, "limit": 200},
        )

    async def test_client_type_all_omits_type_param(self, client, registry):
        client.get.return_value = []
        await list_clients(client, registry, "h", "s", client_type="ALL")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients", key=None, params={"offset": 0, "limit": 200}
        )

    async def test_client_type_lowercase_normalized(self, client, registry):
        client.get.return_value = []
        await list_clients(client, registry, "h", "s", client_type="wired")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients",
            key=None,
            params={"filter": "type.eq('WIRED')", "offset": 0, "limit": 200},
        )

    async def test_client_type_invalid_raises(self, client, registry):
        with pytest.raises(ValueError, match="client_type must be one of"):
            await list_clients(client, registry, "h", "s", client_type="ETHERNET")
        client.paginate_offset.assert_not_called()
        client.get.assert_not_called()

    async def test_cap_exceeded_marked_incomplete(self, client, registry):
        rows = [{"id": "00000000-0000-4000-8000-0000000000c1"}] + [
            dict({"id": "00000000-0000-4000-8000-0000000000c1"}, id=f"extra-{index}")
            for index in range(1, 5)
        ]
        client.paginate_max_pages = 5
        client.get.side_effect = [{"data": [row], "limit": 1, "totalCount": 40} for row in rows]
        result = await list_clients(client, registry, "h", "s")
        assert result["incomplete"] is True
        assert "page cap of 5" in result["incompleteReason"]
        assert result["data"] == rows
        # The upstream total survives the cap; it is never the gathered count.
        assert result["totalCount"] == 40
        assert client.get.call_count == 5
        assert [call.kwargs["params"]["offset"] for call in client.get.call_args_list] == list(
            range(5)
        )

    async def test_filter_drains_with_exact_param(self, client, registry):
        client.get.return_value = []
        await list_clients(client, registry, "h", "s", filter="ipAddress.eq('10.0.0.5')")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients",
            key=None,
            params={"filter": "ipAddress.eq('10.0.0.5')", "offset": 0, "limit": 200},
        )

    async def test_filter_manual_page_exact_param(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 0}
        await list_clients(
            client, registry, "h", "s", offset=0, limit=25, filter="ipAddress.eq('10.0.0.5')"
        )
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients",
            key=None,
            params={"filter": "ipAddress.eq('10.0.0.5')", "offset": 0, "limit": 25},
        )
        client.paginate_offset.assert_not_called()

    async def test_client_type_and_filter_mutually_exclusive(self, client, registry):
        # Both together cannot compose upstream; must error, never silently drop one.
        with pytest.raises(ValueError, match="mutually exclusive"):
            await list_clients(
                client,
                registry,
                "h",
                "s",
                client_type="WIRED",
                filter="macAddress.eq('aa:bb:cc:dd:ee:ff')",
            )
        client.paginate_offset.assert_not_called()
        client.get.assert_not_called()

    async def test_client_type_all_with_filter_uses_filter(self, client, registry):
        # ALL means "no type restriction", so it composes trivially with an explicit
        # filter rather than erroring.
        client.get.return_value = []
        await list_clients(
            client,
            registry,
            "h",
            "s",
            client_type="ALL",
            filter="macAddress.eq('aa:bb:cc:dd:ee:ff')",
        )
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients",
            key=None,
            params={"filter": "macAddress.eq('aa:bb:cc:dd:ee:ff')", "offset": 0, "limit": 200},
        )

    async def test_filter_none_omits_param_not_string(self, client, registry):
        client.get.return_value = []
        await list_clients(client, registry, "h", "s", filter=None)
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients", key=None, params={"offset": 0, "limit": 200}
        )

    async def test_filter_threads_owning_key(self, client, registry):
        sentinel = object()
        registry.resolve_key_for_host.return_value = sentinel
        client.get.return_value = []
        await list_clients(client, registry, "h", "s", filter="macAddress.eq('aa:bb:cc:dd:ee:ff')")
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients",
            key=sentinel,
            params={"filter": "macAddress.eq('aa:bb:cc:dd:ee:ff')", "offset": 0, "limit": 200},
        )


class TestGetClient:
    async def test_basic(self, client, registry):
        client.get.return_value = {
            "id": "00000000-0000-4000-8000-0000000000c1",
            "hostname": "laptop",
        }
        result = await get_client(
            client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1"
        )
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients/00000000-0000-4000-8000-0000000000c1", key=None
        )
        assert result["id"] == "00000000-0000-4000-8000-0000000000c1"


class TestExecuteClientAction:
    """The published operation accepts AUTHORIZE_GUEST_ACCESS and
    UNAUTHORIZE_GUEST_ACCESS only; anything else fails before any request."""

    async def test_authorize_with_optional_limits(self, client, registry):
        action = {
            "action": "AUTHORIZE_GUEST_ACCESS",
            "timeLimitMinutes": 60,
            "dataUsageLimitMBytes": 1024,
            "rxRateLimitKbps": 5000,
            "txRateLimitKbps": 1000,
        }
        client.post.return_value = {"action": "AUTHORIZE_GUEST_ACCESS"}
        result = await execute_client_action(
            client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1", action
        )
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients/00000000-0000-4000-8000-0000000000c1/actions",
            json=action,
            key=None,
        )
        assert result == {"action": "AUTHORIZE_GUEST_ACCESS"}

    async def test_unauthorize(self, client, registry):
        action = {"action": "UNAUTHORIZE_GUEST_ACCESS"}
        client.post.return_value = {"action": "UNAUTHORIZE_GUEST_ACCESS"}
        await execute_client_action(
            client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1", action
        )
        client.post.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients/00000000-0000-4000-8000-0000000000c1/actions",
            json=action,
            key=None,
        )

    @pytest.mark.parametrize(
        "action",
        [{"action": "block"}, {"action": "reconnect"}, {"action": "UNBLOCK"}, {}, {"x": 1}],
    )
    async def test_unknown_action_fails_before_any_request(self, client, registry, action):
        with pytest.raises(ValueError) as exc:
            await execute_client_action(
                client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1", action
            )
        msg = str(exc.value)
        assert "AUTHORIZE_GUEST_ACCESS" in msg and "UNAUTHORIZE_GUEST_ACCESS" in msg
        assert "block_client" in msg and "reconnect_client" in msg
        client.post.assert_not_called()
        client.get.assert_not_called()
        registry.resolve_key_for_host.assert_not_called()


class TestStamgrReadBeforeShape:
    """A non-object read-before body raises the actionable shape error naming the
    request; nothing is sent to cmd/stamgr."""

    @pytest.mark.parametrize("tool", ["block", "unblock", "reconnect"])
    @pytest.mark.parametrize("body", [None, "text", True, 7, []])
    async def test_non_object_body(self, client, registry, tool, body):
        fn = {"block": block_client, "unblock": unblock_client, "reconnect": reconnect_client}
        client.get.return_value = body
        with pytest.raises(UniFiConnectionError) as exc:
            await fn[tool](client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1")
        msg = str(exc.value)
        assert msg.startswith("Unexpected response shape from GET ")
        assert f"{BASE}/sites/{SITE_ID}/clients/00000000-0000-4000-8000-0000000000c1" in msg
        assert "expected a client object" in msg
        client.post.assert_not_called()


class TestBlockClient:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "00000000-0000-4000-8000-0000000000c1", "mac": CLIENT_MAC}
        client.post.return_value = {"status": "ok"}
        result = await block_client(
            client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1"
        )
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients/00000000-0000-4000-8000-0000000000c1", key=None
        )
        client.post.assert_called_once_with(
            f"{CLASSIC_CMD_BASE}/stamgr", json={"cmd": "block-sta", "mac": CLIENT_MAC}, key=None
        )
        assert result["status"] == "ok"

    async def test_mac_from_macAddress_field(self, client, registry):
        client.get.return_value = {
            "id": "00000000-0000-4000-8000-0000000000c1",
            "macAddress": CLIENT_MAC,
        }
        client.post.return_value = {"status": "ok"}
        await block_client(client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1")
        call_json = client.post.call_args[1]["json"]
        assert call_json["mac"] == CLIENT_MAC

    async def test_no_mac_raises(self, client, registry):
        client.get.return_value = {"id": "00000000-0000-4000-8000-0000000000c1"}
        with pytest.raises(UniFiConnectionError, match="MAC address"):
            await block_client(client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1")


class TestUnblockClient:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "00000000-0000-4000-8000-0000000000c1", "mac": CLIENT_MAC}
        client.post.return_value = {"status": "ok"}
        result = await unblock_client(
            client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1"
        )
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients/00000000-0000-4000-8000-0000000000c1", key=None
        )
        client.post.assert_called_once_with(
            f"{CLASSIC_CMD_BASE}/stamgr", json={"cmd": "unblock-sta", "mac": CLIENT_MAC}, key=None
        )
        assert result["status"] == "ok"

    async def test_no_mac_raises(self, client, registry):
        client.get.return_value = {"id": "00000000-0000-4000-8000-0000000000c1"}
        with pytest.raises(UniFiConnectionError, match="MAC address"):
            await unblock_client(client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1")


class TestReconnectClient:
    async def test_basic(self, client, registry):
        client.get.return_value = {"id": "00000000-0000-4000-8000-0000000000c1", "mac": CLIENT_MAC}
        client.post.return_value = {"status": "ok"}
        result = await reconnect_client(
            client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1"
        )
        client.get.assert_called_once_with(
            f"{BASE}/sites/{SITE_ID}/clients/00000000-0000-4000-8000-0000000000c1", key=None
        )
        client.post.assert_called_once_with(
            f"{CLASSIC_CMD_BASE}/stamgr", json={"cmd": "kick-sta", "mac": CLIENT_MAC}, key=None
        )
        assert result["status"] == "ok"

    async def test_no_mac_raises(self, client, registry):
        client.get.return_value = {"id": "00000000-0000-4000-8000-0000000000c1"}
        with pytest.raises(UniFiConnectionError, match="MAC address"):
            await reconnect_client(
                client, registry, "h", "s", "00000000-0000-4000-8000-0000000000c1"
            )


# --- list_clients: v2 active-client source (additive; Integration stays the default) ---

V2_ACTIVE = f"/v1/connector/consoles/{HOST_ID}/proxy/network/v2/api/site/{SITE_SLUG}/clients/active"


class TestListClientsV2Active:
    async def test_source_v2_returns_body_verbatim(self, client, registry):
        body = [{"mac": "02:00:00:00:00:01", "type": "WIRELESS", "_extra": 1}]
        client.get.return_value = body
        result = await list_clients(client, registry, "h", "s", source="v2")
        client.get.assert_called_once_with(V2_ACTIVE, key=None)
        client.paginate_offset.assert_not_called()
        assert result is body
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key=None)

    async def test_matter_thread_flag_alone_selects_v2(self, client, registry):
        client.get.return_value = []
        await list_clients(client, registry, "h", "s", include_matter_thread_clients=True)
        client.get.assert_called_once_with(
            V2_ACTIVE, key=None, params={"includeMatterThreadClients": "true"}
        )

    async def test_every_flag_is_sent_as_given(self, client, registry):
        client.get.return_value = []
        await list_clients(
            client,
            registry,
            "h",
            "s",
            source=" V2 ",
            include_matter_thread_clients=False,
            include_traffic_usage=True,
            include_unifi_devices=False,
        )
        client.get.assert_called_once_with(
            V2_ACTIVE,
            key=None,
            params={
                "includeMatterThreadClients": "false",
                "includeTrafficUsage": "true",
                "includeUnifiDevices": "false",
            },
        )

    async def test_default_and_blank_source_keep_integration(self, client, registry):
        client.get.return_value = {"data": [], "totalCount": 0}
        await list_clients(client, registry, "h", "s", source="  ")
        await list_clients(client, registry, "h", "s", source="integration")
        assert (
            client.get.await_args_list
            == [
                call(
                    f"{BASE}/sites/{SITE_ID}/clients",
                    key=None,
                    params={"limit": 200, "offset": 0},
                )
            ]
            * 2
        )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"source": "v3"},
            {"source": "integration", "include_traffic_usage": True},
            {"source": "v2", "offset": 0},
            {"source": "v2", "client_type": "WIRED"},
            {"include_unifi_devices": True, "filter": "type.eq('WIRED')"},
            {"include_unifi_devices": True, "limit": 25},
        ],
    )
    async def test_invalid_combinations_refused_before_any_request(self, client, registry, kwargs):
        with pytest.raises(ValueError, match="source must be one of|source conflict"):
            await list_clients(client, registry, "h", "s", **kwargs)
        registry.resolve_key_for_host.assert_not_called()
        registry.resolve_host_id.assert_not_called()
        client.get.assert_not_called()
        client.paginate_offset.assert_not_called()

    async def test_upstream_error_propagates_unchanged(self, client, registry):
        client.get.side_effect = UniFiConnectionError("HTTP 404 Not Found: {'error': 'x'}")
        with pytest.raises(UniFiConnectionError, match="HTTP 404 Not Found"):
            await list_clients(client, registry, "h", "s", source="v2")


async def test_list_clients_v2_routes_to_owning_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    multikey_registry.resolve_site_slug = AsyncMock(return_value="default")
    captured: dict[str, object] = {}

    async def _get(path, *, key=None, params=None):
        captured["key"] = key
        captured["path"] = path
        return []

    multikey_client.get = AsyncMock(side_effect=_get)
    await list_clients(multikey_client, multikey_registry, "Beta-Branch", "Default", source="v2")
    assert captured["key"] is not None and captured["key"].label == "beta"
    assert str(captured["path"]).endswith("/v2/api/site/default/clients/active")
