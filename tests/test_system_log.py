"""Tests for list_network_events' additive view and VPN-user scope (system_log module).

The class drain itself is covered in test_client_records_system_log_and_sites.py; these
tests cover the optional arguments added on top of it.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric.tools import system_log

HOST_ID = "host-001"
V2 = f"/v1/connector/consoles/{HOST_ID}/proxy/network/v2/api/site/default"


def _page(n: int, pages: int, rows: int = 2) -> dict[str, Any]:
    return {
        "data": [{"id": f"e{n}-{i}", "key": "CLIENT_ROAMED_2"} for i in range(rows)],
        "page_number": n,
        "total_element_count": pages * rows,
        "total_page_count": pages,
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
    c.paginate_max_pages = None
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_slug = AsyncMock(return_value="default")
    return r


async def test_list_network_events_view_reads_that_class(client, registry):
    client.post.side_effect = [_page(0, 1)]
    out = await system_log._list_network_events(
        client, registry, "h", "Default", 1_760_140_800, None, view="device-alert"
    )
    assert client.post.await_args.args[0] == f"{V2}/system-log/device-alert"
    assert client.post.await_args.kwargs["json"]["timestampFrom"] == 1_760_140_800_000
    assert [r["id"] for r in out["data"]] == ["e0-0", "e0-1"]


async def test_list_network_events_blank_view_is_all(client, registry):
    client.post.side_effect = [_page(0, 1)]
    await system_log._list_network_events(client, registry, "h", "Default", None, None, view=" ")
    assert client.post.await_args.args[0] == f"{V2}/system-log/all"


async def test_list_network_events_vpn_user_scope_is_a_get_verbatim(client, registry):
    body = {"data": [{"key": "VPN_CLIENT_CONNECTED"}], "extra": 1}
    client.get.side_effect = _routes({"/system-log/vpn-user-connection": body})
    out = await system_log._list_network_events(
        client, registry, "h", "Default", None, None, vpn_user_id="65f1c0ffee0123456789abcd"
    )
    assert out is body
    client.get.assert_awaited_once_with(
        f"{V2}/system-log/vpn-user-connection",
        key=None,
        params={"vpnUserId": "65f1c0ffee0123456789abcd"},
    )
    client.post.assert_not_awaited()


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"vpn_user_id": ""}, "vpn_user_id"),
        ({"vpn_user_id": "u1", "view": "all"}, "scope conflict: view"),
        ({"vpn_user_id": "u1", "start": 1_760_140_800}, "scope conflict: start"),
    ],
)
async def test_list_network_events_vpn_scope_refusals_send_nothing(client, registry, kwargs, match):
    args = {"start": None, "end": None, **kwargs}
    start, end = args.pop("start"), args.pop("end")
    with pytest.raises(ValueError, match=match):
        await system_log._list_network_events(client, registry, "h", "Default", start, end, **args)
    registry.resolve_key_for_host.assert_not_awaited()
    client.get.assert_not_awaited()
    client.post.assert_not_awaited()


async def test_list_network_events_default_is_class_all_unchanged(client, registry):
    client.post.side_effect = [_page(0, 1)]
    await system_log._list_network_events(client, registry, "h", "Default", None, None)
    assert client.post.await_args.args[0] == f"{V2}/system-log/all"
    assert client.post.await_args.kwargs["json"] == {"pageNumber": 0, "pageSize": 1000}


async def test_list_network_events_vpn_scope_routes_to_owning_key(
    multikey_client, multikey_registry
):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    multikey_registry.resolve_site_slug = AsyncMock(return_value="default")
    keys: list[Any] = []

    async def _get(path: str, *, key: Any = None, params: Any = None) -> Any:
        keys.append(key)
        return []

    multikey_client.get = AsyncMock(side_effect=_get)
    await system_log._list_network_events(
        multikey_client, multikey_registry, "Beta-Branch", "Default", None, None, vpn_user_id="u1"
    )
    assert [k.label for k in keys] == ["beta"]


# --- get_scoped_system_log (GET system-log/{scope}/{identifier}) ---------------------------

SCOPES = {
    "device": "aa:bb:cc:dd:ee:01",
    "client-connection": "aa:bb:cc:dd:ee:02",
    "admin-activity": "65f1c0ffee0123456789abcd",
    "by-external-id": "ext-0001",
}
#: A device-scope list shaped like the live 200 (a bare list of events), synthetic values.
DEVICE_EVENTS = [
    {"id": "e1", "key": "DEVICE_RESTARTED", "category": "DEVICES", "timestamp": 1760140800000},
    {"id": "e2", "key": "DEVICE_UPGRADED", "category": "DEVICES", "timestamp": 1760140900000},
]


@pytest.mark.parametrize(("scope", "identifier"), list(SCOPES.items()))
async def test_scoped_log_is_a_plain_get_on_the_scope_route(client, registry, scope, identifier):
    body = DEVICE_EVENTS if scope == "device" else []
    client.get.side_effect = _routes({f"/system-log/{scope}/{identifier}": body})
    out = await system_log._get_scoped_system_log(
        client, registry, "h", "Default", scope, identifier
    )
    assert out is body
    client.get.assert_awaited_once_with(f"{V2}/system-log/{scope}/{identifier}", key=None)
    client.post.assert_not_awaited()


@pytest.mark.parametrize(
    "body",
    [
        {"data": {"id": "x"}, "httpStatusCode": 200, "traceId": "t"},
        [{"id": f"e{i}"} for i in range(301)],
        None,
        [],
    ],
)
async def test_scoped_log_returns_the_upstream_body_verbatim(client, registry, body):
    client.get.side_effect = _routes({"/system-log/device/aa:bb:cc:dd:ee:01": body})
    out = await system_log._get_scoped_system_log(
        client, registry, "h", "Default", "device", "aa:bb:cc:dd:ee:01"
    )
    assert out is body


async def test_scoped_log_sends_the_query_only_when_given(client, registry):
    client.get.side_effect = _routes({"/system-log/device/aa": []})
    await system_log._get_scoped_system_log(
        client, registry, "h", "Default", "device", "aa", {"limit": 5}
    )
    client.get.assert_awaited_once_with(f"{V2}/system-log/device/aa", key=None, params={"limit": 5})
    client.get.reset_mock()
    await system_log._get_scoped_system_log(client, registry, "h", "Default", "device", "aa", {})
    client.get.assert_awaited_once_with(f"{V2}/system-log/device/aa", key=None)


@pytest.mark.parametrize(
    ("scope", "identifier", "match"),
    [
        ("all", "aa", "scope must be one of device, client-connection, admin-activity"),
        ("", "aa", "scope.* must not be empty"),
        ("Device", "aa", "scope must be one of"),
        ("device", "", "must not be empty"),
        ("device", "a\nb", "control character"),
        ("device", "..", "path traversal"),
    ],
)
async def test_scoped_log_refusals_send_nothing(client, registry, scope, identifier, match):
    with pytest.raises(ValueError, match=match):
        await system_log._get_scoped_system_log(client, registry, "h", "Default", scope, identifier)
    registry.resolve_key_for_host.assert_not_awaited()
    client.get.assert_not_awaited()
    client.post.assert_not_awaited()


async def test_scoped_log_identifier_is_one_path_segment(client, registry):
    client.get.side_effect = _routes({"": []})
    await system_log._get_scoped_system_log(
        client, registry, "h", "Default", "by-external-id", "a/b?c#d"
    )
    sent = client.get.await_args.args[0]
    assert sent == f"{V2}/system-log/by-external-id/a%2Fb%3Fc%23d"


async def test_scoped_log_routes_to_owning_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    multikey_registry.resolve_site_slug = AsyncMock(return_value="default")
    keys: list[Any] = []

    async def _get(path: str, *, key: Any = None, params: Any = None) -> Any:
        keys.append(key)
        return []

    multikey_client.get = AsyncMock(side_effect=_get)
    await system_log._get_scoped_system_log(
        multikey_client, multikey_registry, "Beta-Branch", "Default", "device", "aa"
    )
    assert [k.label for k in keys] == ["beta"]


async def test_invalid_batch_control_fails_before_site_resolution(client, registry):
    # PAGING-VALIDATION-A1 rule 3: the count template naming the query field.
    with pytest.raises(ValueError, match=r"^query_body\.pageSize must be a positive integer"):
        await system_log._read_system_log(
            client, registry, "h", "Default", "all", {"pageSize": "zz-conflict"}
        )
    registry.resolve_key_for_host.assert_not_awaited()
    registry.resolve_host_id.assert_not_awaited()
    registry.resolve_site_slug.assert_not_awaited()
    client.get.assert_not_awaited()
    client.post.assert_not_awaited()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"page": 2, "page_size": 4},
        {"query": {"pageNumber": 2, "pageSize": 4}},
        {"query": {"pageNumber": 1, "pageSize": 3}, "page": 2, "page_size": 4},
    ],
)
async def test_explicit_page_and_size_return_the_logical_window(client, registry, kwargs):
    # The console serves pages of 2 entries whatever pageSize asks for; the window
    # page=2, page_size=4 is entries 8 to 11, which are console pages 4 and 5.
    pages = {number: _page(number, 8) for number in range(8)}
    pages[2]["future"] = {"verbatim": True}

    async def post(_path: str, *, key: Any = None, json: dict[str, Any]) -> Any:
        return pages[json["pageNumber"]]

    client.post.side_effect = post
    query = kwargs.get("query")
    paging = {key: value for key, value in kwargs.items() if key != "query"}
    result = await system_log._read_system_log(
        client, registry, "host", "Default", "all", query, **paging
    )
    assert result["data"] == pages[4]["data"] + pages[5]["data"]
    assert result["future"] == {"verbatim": True}
    assert result["total_element_count"] == 16
    assert "page_number" not in result and "total_page_count" not in result
    assert result["_nextPage"] == 3
    assert result["_pageSize"] == {"requested": 4, "sent": [4, 2, 2], "effective": 2, "returned": 4}
    assert "incomplete" not in result
    assert [call.kwargs["json"] for call in client.post.await_args_list] == [
        {"pageNumber": 2, "pageSize": 4},
        {"pageNumber": 4, "pageSize": 2},
        {"pageNumber": 5, "pageSize": 2},
    ]
    assert {call.args[0] for call in client.post.await_args_list} == {f"{V2}/system-log/all"}
