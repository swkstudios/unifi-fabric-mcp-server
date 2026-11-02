"""Tests for the client-record, system-log, VPN-client and site-administration tools.

Request shapes are the ones proven live on Network 11.0.81 with synthetic objects (an RFC
7042 documentation MAC, a disabled synthetic WireGuard client); see each module docstring.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import read_only
from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools import system_log
from unifi_fabric.tools.client_records import (
    _create_client_reservation,
    _extend_guest,
    _forget_client,
    _list_guests,
    _put_user,
    _set_client_fixed_ip,
)
from unifi_fabric.tools.site_admin import _create_site, _delete_site, _rename_site
from unifi_fabric.tools.system_log import _epoch_hints, _read_system_log, _window
from unifi_fabric.tools.vpn_clients import (
    _create_vpn_client,
    _delete_vpn_client,
    _list_vpn_clients,
    _update_vpn_client,
)

HOST_ID = "host-001"
BASE = f"/v1/connector/consoles/{HOST_ID}/proxy/network/api/s/default"
V2 = f"/v1/connector/consoles/{HOST_ID}/proxy/network/v2/api/site/default"
MAC = "00:00:5e:00:53:42"

USERS = {
    "meta": {"rc": "ok"},
    "data": [
        {"_id": "6523f0c1e4b0a1b2c3d4e5f6", "mac": MAC, "name": "printer"},
        {"_id": "6523f0c1e4b0a1b2c3d4e5f7", "mac": "00:00:5e:00:53:43", "hostname": "tv"},
    ],
}
NETWORKCONF = {
    "meta": {"rc": "ok"},
    "data": [
        {"_id": "c-lan", "external_id": "i-lan", "name": "Default", "purpose": "corporate"},
        {"_id": "c-iot", "external_id": "i-iot", "name": "IoT", "purpose": "corporate"},
        {"_id": "c-vpn", "external_id": "i-vpn", "name": "Remote", "purpose": "remote-user-vpn"},
        {
            "_id": "c-vpnc",
            "external_id": "i-vpnc",
            "name": "Office tunnel",
            "purpose": "vpn-client",
            "vpn_type": "wireguard-client",
            "x_wireguard_private_key": "xxxxxxxx",
        },
    ],
}
GUESTS = {
    "meta": {"rc": "ok"},
    "data": [
        {"_id": "g-old", "mac": MAC, "end": 100, "expired": True},
        {"_id": "g-new", "mac": MAC, "end": 200, "expired": False},
        {"_id": "g-other", "mac": "00:00:5e:00:53:44", "end": 300, "expired": False},
    ],
}
SITES = {
    "meta": {"rc": "ok"},
    "data": [
        {"_id": "s-default", "name": "default", "desc": "Default"},
        {"_id": "s-branch", "name": "ab12cd34", "desc": "Branch office"},
    ],
}


def _routes(table: dict[str, Any]):
    async def get(path: str, **_: Any) -> Any:
        for suffix, body in table.items():
            if path.endswith(suffix):
                return body
        raise AssertionError(f"unexpected GET {path}")

    return get


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock(side_effect=_routes({}))
    c.post = AsyncMock(return_value={"meta": {"rc": "ok"}, "data": []})
    c.put = AsyncMock(return_value={"meta": {"rc": "ok"}, "data": []})
    c.delete = AsyncMock(return_value={"meta": {"rc": "ok"}, "data": []})
    c.paginate_max_pages = None
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_slug = AsyncMock(return_value="default")
    return r


# --------------------------------------------------------------------------- forget_client


async def test_forget_client_one_request_lowercase_colon_duplicates_collapsed(client, registry):
    await _forget_client(
        client, registry, "h", "Default", [MAC, "00-00-5E-00-53-42", "00005e005343"]
    )
    client.post.assert_awaited_once_with(
        f"{BASE}/cmd/stamgr",
        key=None,
        json={"cmd": "forget-sta", "macs": [MAC, "00:00:5e:00:53:43"]},
    )


async def test_forget_client_single_mac_string_uses_the_same_body(client, registry):
    out = await _forget_client(client, registry, "h", "Default", "00005E005342")
    assert out == {"meta": {"rc": "ok"}, "data": []}
    assert client.post.await_args.kwargs["json"] == {"cmd": "forget-sta", "macs": [MAC]}


@pytest.mark.parametrize("bad", [[], ["not-a-mac"], [MAC, "zz"]])
async def test_forget_client_invalid_input_sends_nothing(client, registry, bad):
    with pytest.raises(ValueError, match="mac is empty|Not a MAC address"):
        await _forget_client(client, registry, "h", "Default", bad)
    registry.resolve_key_for_host.assert_not_awaited()
    client.post.assert_not_awaited()


# --------------------------------------------------------------------------- guests


async def test_list_guests_get_without_window_post_with_window(client, registry):
    client.get.side_effect = _routes({"/stat/guest": GUESTS})
    assert await _list_guests(client, registry, "h", "Default", None) == GUESTS
    client.post.return_value = GUESTS
    assert await _list_guests(client, registry, "h", "Default", 24) == GUESTS
    client.post.assert_awaited_once_with(f"{BASE}/stat/guest", key=None, json={"within": 24})


async def test_list_guests_unexpected_shape_raises(client, registry):
    client.get.side_effect = _routes({"/stat/guest": ["no envelope"]})
    with pytest.raises(UniFiConnectionError, match="'data' array"):
        await _list_guests(client, registry, "h", "Default", None)


async def test_extend_guest_by_mac_picks_the_active_authorization(client, registry):
    client.get.side_effect = _routes({"/stat/guest": GUESTS})
    await _extend_guest(client, registry, "h", "Default", "00-00-5E-00-53-42")
    client.post.assert_awaited_once_with(
        f"{BASE}/cmd/hotspot", key=None, json={"cmd": "extend", "_id": "g-new"}
    )


async def test_extend_guest_by_id(client, registry):
    client.get.side_effect = _routes({"/stat/guest": GUESTS})
    await _extend_guest(client, registry, "h", "Default", "g-other")
    assert client.post.await_args.kwargs["json"] == {"cmd": "extend", "_id": "g-other"}


async def test_extend_guest_ambiguous_mac_fails_listing_choices(client, registry):
    two_active = {"data": [{**g, "expired": False} for g in GUESTS["data"]]}
    client.get.side_effect = _routes({"/stat/guest": two_active})
    with pytest.raises(ValueError, match="matches 2 active guest") as exc:
        await _extend_guest(client, registry, "h", "Default", MAC)
    assert "g-old" in str(exc.value) and "g-new" in str(exc.value)
    client.post.assert_not_awaited()


async def test_extend_guest_unknown_fails_listing_guests(client, registry):
    client.get.side_effect = _routes({"/stat/guest": GUESTS})
    with pytest.raises(ValueError, match="not found") as exc:
        await _extend_guest(client, registry, "h", "Default", "nope")
    assert "g-other" in str(exc.value)
    client.post.assert_not_awaited()


# --------------------------------------------------------------------------- known-client record


@pytest.mark.parametrize(
    "ref", [MAC, "00-00-5E-00-53-42", "00005e005342", "6523F0C1E4B0A1B2C3D4E5F6"]
)
async def test_put_user_resolves_mac_or_id_to_the_record(client, registry, ref):
    client.get.side_effect = _routes({"/rest/user": USERS})
    await _put_user(client, registry, "h", "Default", ref, {"name": "x"})
    client.put.assert_awaited_once_with(
        f"{BASE}/rest/user/6523f0c1e4b0a1b2c3d4e5f6", key=None, json={"name": "x"}
    )


async def test_put_user_unknown_mac_fails_listing_records(client, registry):
    client.get.side_effect = _routes({"/rest/user": USERS})
    with pytest.raises(ValueError, match="create_client_reservation") as exc:
        await _put_user(client, registry, "h", "Default", "00:00:5e:00:53:99", {"note": "x"})
    assert "6523f0c1e4b0a1b2c3d4e5f7" in str(exc.value)
    client.put.assert_not_awaited()


async def test_put_user_blank_selector_sends_nothing(client, registry):
    with pytest.raises(ValueError, match="'client'"):
        await _put_user(client, registry, "h", "Default", " ", {"note": "x"})
    client.get.assert_not_awaited()


async def test_fixed_ip_resolves_the_network_by_name_or_integration_id(client, registry):
    client.get.side_effect = _routes({"/rest/user": USERS, "/rest/networkconf": NETWORKCONF})
    await _set_client_fixed_ip(client, registry, "h", "Default", MAC, "192.0.2.50", "iot")
    assert client.put.await_args.kwargs["json"] == {
        "use_fixedip": True,
        "fixed_ip": "192.0.2.50",
        "network_id": "c-iot",
    }
    await _set_client_fixed_ip(client, registry, "h", "Default", MAC, "192.0.2.50", "i-lan")
    assert client.put.await_args.kwargs["json"]["network_id"] == "c-lan"


async def test_fixed_ip_without_network_sends_no_network_id(client, registry):
    client.get.side_effect = _routes({"/rest/user": USERS})
    await _set_client_fixed_ip(client, registry, "h", "Default", MAC, "192.0.2.50", None)
    assert client.put.await_args.kwargs["json"] == {"use_fixedip": True, "fixed_ip": "192.0.2.50"}


async def test_fixed_ip_unknown_network_fails_listing_networks(client, registry):
    client.get.side_effect = _routes({"/rest/user": USERS, "/rest/networkconf": NETWORKCONF})
    with pytest.raises(ValueError, match="not found") as exc:
        await _set_client_fixed_ip(client, registry, "h", "Default", MAC, "192.0.2.50", "Nope")
    assert "'IoT'" in str(exc.value)
    client.put.assert_not_awaited()


@pytest.mark.parametrize("network", ["", "  ", "x\n"])
async def test_fixed_ip_bad_network_fails_before_any_request(client, registry, network):
    with pytest.raises(ValueError, match="'network'"):
        await _set_client_fixed_ip(client, registry, "h", "Default", MAC, "192.0.2.50", network)
    registry.resolve_key_for_host.assert_not_awaited()
    client.get.assert_not_awaited()


async def test_fixed_ip_upstream_error_gets_the_hint(client, registry):
    client.get.side_effect = _routes({"/rest/user": USERS})
    client.put.side_effect = UniFiConnectionError("HTTP 400 from PUT x: api.err.FixedIpOutOfRange")
    with pytest.raises(UniFiConnectionError, match="FixedIpOutOfRange.*network"):
        await _set_client_fixed_ip(client, registry, "h", "Default", MAC, "203.0.113.9", None)


async def test_create_reservation_body(client, registry):
    client.get.side_effect = _routes({"/rest/networkconf": NETWORKCONF})
    await _create_client_reservation(
        client,
        registry,
        "h",
        "Default",
        "00-00-5E-00-53-42",
        name="Printer",
        note=None,
        fixed_ip="192.0.2.60",
        network="Default",
        fields={"mac": "ignored", "usergroup_id": "ug1", "name": "ignored"},
    )
    client.post.assert_awaited_once_with(
        f"{BASE}/rest/user",
        key=None,
        json={
            "mac": MAC,
            "usergroup_id": "ug1",
            "name": "Printer",
            "use_fixedip": True,
            "fixed_ip": "192.0.2.60",
            "network_id": "c-lan",
        },
    )


async def test_create_reservation_minimal_body_and_bad_mac(client, registry):
    kwargs = dict(name=None, note=None, fixed_ip=None, network=None, fields=None)
    await _create_client_reservation(client, registry, "h", "Default", MAC, **kwargs)
    assert client.post.await_args.kwargs["json"] == {"mac": MAC}
    client.post.reset_mock()
    with pytest.raises(ValueError, match="Not a MAC address"):
        await _create_client_reservation(client, registry, "h", "Default", "nope", **kwargs)
    client.post.assert_not_awaited()


# --------------------------------------------------------------------------- system log


def _page(n: int, pages: int, rows: int = 2) -> dict[str, Any]:
    return {
        "data": [{"id": f"e{n}-{i}", "key": "CLIENT_ROAMED_2"} for i in range(rows)],
        "page_number": n,
        "total_element_count": pages * rows,
        "total_page_count": pages,
    }


async def test_drain_reads_every_page_with_the_drain_size(client, registry):
    client.post.side_effect = [_page(0, 3), _page(1, 3), _page(2, 3)]
    out = await _read_system_log(client, registry, "h", "Default", "all", None)
    assert [r["id"] for r in out["data"]] == ["e0-0", "e0-1", "e1-0", "e1-1", "e2-0", "e2-1"]
    assert out["total_element_count"] == 6
    assert "page_number" not in out and "total_page_count" not in out and "incomplete" not in out
    sent = [c.kwargs["json"] for c in client.post.await_args_list]
    assert [s["pageNumber"] for s in sent] == [0, 1, 2]
    assert [s["pageSize"] for s in sent] == [system_log.DRAIN_PAGE_SIZE, 2, 2]
    assert client.post.await_args_list[0].args[0] == f"{V2}/system-log/all"


async def test_single_page_is_verbatim_and_sends_only_what_was_given(client, registry):
    client.post.return_value = _page(4, 9)
    out = await _read_system_log(client, registry, "h", "Default", "all", None, page=4)
    assert out == _page(4, 9)
    assert client.post.await_args.kwargs["json"] == {"pageNumber": 4}


async def test_page_size_alone_is_requested_total_with_effective_size_readback(client, registry):
    client.post.side_effect = [_page(0, 2), _page(1, 2)]
    out = await _read_system_log(client, registry, "h", "Default", "all", None, page_size=9)
    assert len(out["data"]) == 4
    assert [c.kwargs["json"] for c in client.post.await_args_list] == [
        {"pageNumber": 0, "pageSize": 9},
        {"pageNumber": 1, "pageSize": 2},
    ]
    # Old sent=2 hid the requested first wire size; A5 records both requests and the clamp.
    assert out["_pageSize"] == {"requested": 9, "sent": [9, 2], "effective": 2, "returned": 4}


async def test_paging_keys_in_query_are_honoured(client, registry):
    # 18 entries on console pages of 2: pageNumber 1 with pageSize 7 is entries 7 to 13.
    async def post(_path: str, *, key: Any = None, json: dict[str, Any]) -> Any:
        return _page(json["pageNumber"], 9)

    client.post.side_effect = post
    result = await _read_system_log(
        client, registry, "h", "Default", "all", {"pageNumber": 1, "pageSize": 7, "x": 1}
    )

    def entries(first: int, last: int) -> list[dict[str, Any]]:
        return [
            {"id": f"e{index // 2}-{index % 2}", "key": "CLIENT_ROAMED_2"}
            for index in range(first, last)
        ]

    assert [call.kwargs["json"] for call in client.post.await_args_list] == [
        {"x": 1, "pageNumber": number, "pageSize": size}
        for number, size in ((1, 7), (3, 2), (4, 2), (5, 2), (6, 2))
    ]
    assert result["data"] == entries(7, 14)
    assert result["_pageSize"] == {
        "requested": 7,
        "sent": [7, 2, 2, 2, 2],
        "effective": 2,
        "returned": 7,
    }
    assert result["_nextPage"] == 2
    assert "incomplete" not in result
    client.post.reset_mock()
    next_result = await _read_system_log(
        client, registry, "h", "Default", "all", {"x": 1}, page=result["_nextPage"], page_size=7
    )
    assert next_result["data"] == entries(14, 18)
    assert "_nextPage" not in next_result and "incomplete" not in next_result
    assert [call.kwargs["json"] for call in client.post.await_args_list] == [
        {"x": 1, "pageNumber": number, "pageSize": size}
        for number, size in ((2, 7), (7, 2), (8, 2))
    ]


async def test_class_defaults_are_added_unless_the_query_sets_them(client, registry):
    client.post.return_value = _page(0, 1)
    await _read_system_log(client, registry, "h", "Default", "threat-alert", None)
    assert client.post.await_args.kwargs["json"]["threatTypes"] == ["HONEYPOT", "THREAT"]
    await _read_system_log(
        client, registry, "h", "Default", "threat-alert", {"threatTypes": ["THREAT"]}
    )
    assert client.post.await_args.kwargs["json"]["threatTypes"] == ["THREAT"]
    await _read_system_log(client, registry, "h", "Default", "all", None)
    assert "threatTypes" not in client.post.await_args.kwargs["json"]


async def test_unpaged_class_array_is_returned_as_received(client, registry):
    client.post.return_value = [{"id": "c1"}]
    assert await _read_system_log(client, registry, "h", "Default", "critical", None) == [
        {"id": "c1"}
    ]


async def test_repeated_page_stops_incomplete(client, registry):
    client.post.side_effect = [_page(0, 3), _page(0, 3)]
    out = await _read_system_log(client, registry, "h", "Default", "all", None)
    assert out["incomplete"] is True and "page 0" in out["incompleteReason"]
    assert len(out["data"]) == 2


async def test_advancing_page_number_with_repeated_rows_stops_incomplete(client, registry):
    first = {**_page(0, 3, 1), "trace": {"upstream": "unchanged"}}
    second = {**_page(1, 3, 1), "data": first["data"]}
    client.post.side_effect = [first, second]
    out = await _read_system_log(client, registry, "h", "Default", "all", None)
    assert out["data"] == first["data"]
    assert out["incomplete"] is True
    assert "same entries" in out["incompleteReason"]
    assert out["total_element_count"] == 3
    assert out["trace"] == first["trace"]
    assert client.post.await_count == 2
    assert first["data"] == [{"id": "e0-0", "key": "CLIENT_ROAMED_2"}]


async def test_empty_page_before_declared_completion_is_incomplete(client, registry):
    first = _page(0, 3, 1)
    second = {**_page(1, 3, 1), "data": []}
    client.post.side_effect = [first, second]
    out = await _read_system_log(client, registry, "h", "Default", "all", None)
    assert out["data"] == first["data"]
    assert out["total_element_count"] == 3
    assert out["incomplete"] is True
    assert "empty page 1" in out["incompleteReason"]
    assert client.post.await_count == 2


@pytest.mark.parametrize("pages", [None, -1, True, "3"])
async def test_unprovable_page_count_raises_clearly(client, registry, pages):
    response = {"data": [{"id": "one"}], "total_element_count": 3}
    if pages is not None:
        response["total_page_count"] = pages
    client.post.return_value = response
    with pytest.raises(UniFiConnectionError, match="total_page_count.*completeness"):
        await _read_system_log(client, registry, "h", "Default", "all", None)
    client.post.assert_awaited_once()


async def test_missing_page_count_with_complete_total_preserves_envelope(client, registry):
    first = {"data": [{"id": "one"}], "total_element_count": 1, "trace": "raw"}
    client.post.return_value = first
    out = await _read_system_log(client, registry, "h", "Default", "all", None)
    assert out == first
    client.post.assert_awaited_once()


async def test_final_page_count_short_of_declared_total_is_incomplete(client, registry):
    client.post.side_effect = [
        {**_page(0, 2, 1), "total_element_count": 3},
        {**_page(1, 2, 1), "total_element_count": 3},
    ]
    out = await _read_system_log(client, registry, "h", "Default", "all", None)
    assert len(out["data"]) == 2
    assert out["total_element_count"] == 3
    assert out["incomplete"] is True
    assert "declared 3" in out["incompleteReason"]


async def test_opt_in_page_cap_stops_incomplete(client, registry):
    client.paginate_max_pages = 2
    client.post.side_effect = [_page(0, 5), _page(1, 5)]
    out = await _read_system_log(client, registry, "h", "Default", "all", None)
    assert out["incomplete"] is True and "UNIFI_PAGINATE_MAX_PAGES" in out["incompleteReason"]
    assert len(out["data"]) == 4


async def test_unexpected_page_shape_raises(client, registry):
    client.post.return_value = {"unexpected": True}
    with pytest.raises(UniFiConnectionError, match="'data' array"):
        await _read_system_log(client, registry, "h", "Default", "all", None)
    with pytest.raises(UniFiConnectionError, match="'data' array"):
        await _read_system_log(client, registry, "h", "Default", "all", None, page=0)


async def test_class_is_a_path_segment(client, registry):
    with pytest.raises(ValueError, match="log_class"):
        await _read_system_log(client, registry, "h", "Default", "all/../x", None)
    client.post.assert_not_awaited()


def test_window_is_milliseconds_and_only_what_was_given():
    assert _window(None, None) == {}
    assert _window(10, None) == {"timestampFrom": 10_000}
    assert _window(10, 20) == {"timestampFrom": 10_000, "timestampTo": 20_000}


_NET_V2 = "/v1/connector/consoles/h/proxy/network/v2/api/site/default"


@pytest.mark.parametrize(
    "path,is_write",
    [
        ("/v1/connector/consoles/h/proxy/network/v2/api/site/default/system-log/all", True),
        (
            "/v1/connector/consoles/h/proxy/network/v2/api/site/default/system-log/threat-alert/",
            True,
        ),
        ("/v1/connector/consoles/h/proxy/network/v2/api/site/default/system-log/all/x", True),
        ("/v1/connector/consoles/h/proxy/network/v2/api/site/default/system-log", True),
        ("/v1/connector/consoles/h/proxy/network/v2/api/site/default/trafficrules", True),
        ("/v1/connector/consoles/h/proxy/protect/v2/api/site/default/system-log/all", True),
    ],
)
def test_system_log_posts_are_writes(path, is_write):
    assert read_only.is_write_request("POST", path) is is_write


# --------------------------------------------------------------------------- VPN clients


async def test_list_vpn_clients_preserves_envelope_and_exposes_filtered_view(client, registry):
    client.get.side_effect = _routes({"/rest/networkconf": NETWORKCONF})
    out = await _list_vpn_clients(client, registry, "h", "Default")
    assert out == {**NETWORKCONF, "_vpn_clients": [NETWORKCONF["data"][3]]}


@pytest.mark.parametrize(
    "given,sent",
    [("wireguard", "wireguard-client"), ("OpenVPN", "openvpn-client"), ("custom", "custom")],
)
async def test_create_vpn_client_body(client, registry, given, sent):
    await _create_vpn_client(
        client, registry, "h", "Default", "Tunnel", given, enabled=None, fields={"ip_subnet": "x"}
    )
    client.post.assert_awaited_once_with(
        f"{BASE}/rest/networkconf",
        key=None,
        json={"ip_subnet": "x", "purpose": "vpn-client", "name": "Tunnel", "vpn_type": sent},
    )


async def test_create_vpn_client_error_gets_the_field_hint(client, registry):
    client.post.side_effect = UniFiConnectionError(
        "HTTP 400 from POST x: api.err.WireguardMissingInterfaceDns"
    )
    with pytest.raises(UniFiConnectionError, match="dhcpd_dns_1"):
        await _create_vpn_client(
            client, registry, "h", "Default", "T", "wireguard", enabled=False, fields=None
        )


@pytest.mark.parametrize("wanted", ["c-vpnc", "i-vpnc"])
async def test_update_vpn_client_by_either_id(client, registry, wanted):
    client.get.side_effect = _routes({"/rest/networkconf": NETWORKCONF})
    await _update_vpn_client(client, registry, "h", "Default", wanted, {"enabled": True})
    client.put.assert_awaited_once_with(
        f"{BASE}/rest/networkconf/c-vpnc",
        key=None,
        json={"enabled": True, "purpose": "vpn-client"},
    )


async def test_vpn_client_writes_never_address_another_purpose(client, registry):
    client.get.side_effect = _routes({"/rest/networkconf": NETWORKCONF})
    with pytest.raises(ValueError, match="VPN client 'c-vpn' not found"):
        await _update_vpn_client(client, registry, "h", "Default", "c-vpn", {"enabled": True})
    with pytest.raises(ValueError, match="not found"):
        await _delete_vpn_client(client, registry, "h", "Default", "c-lan")
    client.put.assert_not_awaited()
    client.delete.assert_not_awaited()


async def test_delete_vpn_client(client, registry):
    client.get.side_effect = _routes({"/rest/networkconf": NETWORKCONF})
    out = await _delete_vpn_client(client, registry, "h", "Default", "i-vpnc")
    client.delete.assert_awaited_once_with(f"{BASE}/rest/networkconf/c-vpnc", key=None)
    assert out["deleted"] is True


# --------------------------------------------------------------------------- sites


async def test_create_and_rename_site_send_the_sitemgr_commands(client, registry):
    await _create_site(client, registry, "h", "Default", "Branch office")
    client.post.assert_awaited_with(
        f"{BASE}/cmd/sitemgr", key=None, json={"cmd": "add-site", "desc": "Branch office"}
    )
    await _rename_site(client, registry, "h", "Default", "Head office")
    client.post.assert_awaited_with(
        f"{BASE}/cmd/sitemgr", key=None, json={"cmd": "update-site", "desc": "Head office"}
    )


async def test_create_site_not_implemented_gets_the_multi_site_hint(client, registry):
    client.post.side_effect = UniFiConnectionError("HTTP 400 from POST x: api.err.NotImplemented")
    with pytest.raises(UniFiConnectionError, match="several Network sites"):
        await _create_site(client, registry, "h", "Default", "Branch office")


@pytest.mark.parametrize("target", ["s-branch", "ab12cd34", "Branch office", "branch office"])
async def test_delete_site_resolves_the_target(client, registry, target):
    client.get.side_effect = _routes({"/api/self/sites": SITES})
    out = await _delete_site(client, registry, "h", "Default", target)
    client.post.assert_awaited_once_with(
        f"{BASE}/cmd/sitemgr", key=None, json={"cmd": "delete-site", "site": "s-branch"}
    )
    assert out["deleted"] is True


async def test_delete_site_unknown_target_fails_listing_sites(client, registry):
    client.get.side_effect = _routes({"/api/self/sites": SITES})
    with pytest.raises(ValueError, match="not found") as exc:
        await _delete_site(client, registry, "h", "Default", "Nope")
    assert "s-branch" in str(exc.value)
    client.post.assert_not_awaited()


@pytest.mark.parametrize("desc", [" Edge spaces ", "Café ☕"])
async def test_site_names_are_values_sent_as_given(client, registry, desc):
    await _create_site(client, registry, "h", "Default", desc)
    assert client.post.await_args.kwargs["json"] == {"cmd": "add-site", "desc": desc}
    await _rename_site(client, registry, "h", "Default", desc)
    assert client.post.await_args.kwargs["json"] == {"cmd": "update-site", "desc": desc}


def test_epoch_hints_warn_and_never_change_the_value():
    assert _window(-1, 100_000_000_000) == {
        "timestampFrom": -1000,
        "timestampTo": 100_000_000_000_000,
    }
    out = _epoch_hints({"data": []}, -1, 100_000_000_000)
    assert out["data"] == []
    assert [(w["argument"], w["code"]) for w in out["_warnings"]] == [
        ("start", "EPOCH_SECONDS_NEGATIVE"),
        ("end", "EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"),
    ]
    assert _epoch_hints({"data": []}, 1_760_000_000, None) == {"data": []}


def test_epoch_must_be_an_integer():
    with pytest.raises(ValueError, match="integer epoch-seconds"):
        _window(True, None)  # type: ignore[arg-type]


# ------------------------------------------- additive v2 sources (Classic stays the default)


async def test_list_guests_v2_source_returns_hotspot_clients_verbatim(client, registry):
    body = [{"mac": MAC, "authorized": True, "_extra": 1}]
    client.get.side_effect = _routes({"/hotspot/clients": body})
    out = await _list_guests(client, registry, "h", "Default", None, source=" V2 ")
    assert out is body
    client.get.assert_awaited_once_with(f"{V2}/hotspot/clients", key=None)
    client.post.assert_not_awaited()


async def test_list_guests_blank_or_classic_source_keeps_stat_guest(client, registry):
    client.get.side_effect = _routes({"/stat/guest": GUESTS})
    assert await _list_guests(client, registry, "h", "Default", None, source="") == GUESTS
    assert await _list_guests(client, registry, "h", "Default", None, source="classic") == GUESTS
    assert all(c.args[0] == f"{BASE}/stat/guest" for c in client.get.await_args_list)


@pytest.mark.parametrize(
    ("source", "within", "match"),
    [("v3", None, "source must be one of"), ("v2", 24, "source conflict")],
)
async def test_list_guests_bad_source_sends_nothing(client, registry, source, within, match):
    with pytest.raises(ValueError, match=match):
        await _list_guests(client, registry, "h", "Default", within, source=source)
    registry.resolve_key_for_host.assert_not_awaited()
    client.get.assert_not_awaited()
    client.post.assert_not_awaited()


async def test_list_guests_v2_upstream_error_keeps_reason(client, registry):
    client.get.side_effect = UniFiConnectionError("HTTP 404 Not Found: {'code': 'x'}")
    with pytest.raises(UniFiConnectionError, match="HTTP 404 Not Found"):
        await _list_guests(client, registry, "h", "Default", None, source="v2")


async def test_list_guests_v2_source_routes_to_owning_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    multikey_registry.resolve_site_slug = AsyncMock(return_value="default")
    keys: list[Any] = []

    async def _get(path: str, *, key: Any = None, params: Any = None) -> Any:
        keys.append(key)
        return []

    multikey_client.get = AsyncMock(side_effect=_get)
    await _list_guests(multikey_client, multikey_registry, "Beta-Branch", "Default", None, "v2")
    assert [k.label for k in keys] == ["beta"]
