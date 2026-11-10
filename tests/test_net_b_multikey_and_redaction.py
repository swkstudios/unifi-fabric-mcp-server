"""NET-B tools: non-first-key routing, VPN-client credential redaction, read-POST routes.

Multi-key: every one of the 18 NET-B tools, called through the MCP layer with a registry
that resolves the target console to the SECOND configured key, sends every request (the
tool's own selector GETs included) with that key and never the first one.

Redaction: ``x_wireguard_private_key`` and ``x_openvpn_password`` are credential fields.
They are returned verbatim by default and masked only under the ``UNIFI_REDACT_SECRETS``
opt-in, in a list_vpn_clients result and in a create_vpn_client dry-run preview.

Read-only: every system-log POST is a write pending a separate allowlist PR.
UNIFI_WRITE_POLICY refuses all three tools before any upstream request; dry-run previews
the first POST without sending it.
"""

from __future__ import annotations

import copy
import json
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from fastmcp.exceptions import ToolError

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric import read_only, server
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.families.statistics import system_log
from unifi_fabric.redaction import REDACTION_MASK, is_credential_field

NET_B_TOOLS = (
    "create_client_reservation",
    "create_site",
    "create_vpn_client",
    "delete_site",
    "delete_vpn_client",
    "extend_guest",
    "forget_client",
    "get_system_log",
    "list_guests",
    "list_ips_events",
    "list_network_events",
    "list_vpn_clients",
    "remove_client_fixed_ip",
    "rename_site",
    "set_client_fixed_ip",
    "set_client_name",
    "set_client_note",
    "update_vpn_client",
)

# Synthetic placeholders, never deployed credentials.
FIRST = APIKeyConfig(key="synthetic-first-key", label="first")
SECOND = APIKeyConfig(key="synthetic-second-key", label="second")
WG_SECRET = "synthetic-wireguard-private-key-value"
OVPN_SECRET = "synthetic-openvpn-password-value"

HOST_ID = "host-002"
MAC = "00:00:5e:00:53:42"

USERS = {
    "meta": {"rc": "ok"},
    "data": [{"_id": "6523f0c1e4b0a1b2c3d4e5f6", "mac": MAC, "name": "printer"}],
}
NETWORKCONF = {
    "meta": {"rc": "ok"},
    "data": [
        {"_id": "c-lan", "external_id": "i-lan", "name": "Default", "purpose": "corporate"},
        {
            "_id": "c-vpnc",
            "external_id": "i-vpnc",
            "name": "Office tunnel",
            "purpose": "vpn-client",
            "vpn_type": "wireguard-client",
            "x_wireguard_private_key": WG_SECRET,
        },
        {
            "_id": "c-ovpn",
            "external_id": "i-ovpn",
            "name": "Branch tunnel",
            "purpose": "vpn-client",
            "vpn_type": "openvpn-client",
            "openvpn_username": "branch",
            "x_openvpn_password": OVPN_SECRET,
        },
    ],
}
GUESTS = {"meta": {"rc": "ok"}, "data": [{"_id": "g-1", "mac": MAC, "end": 200}]}
SITES = {
    "meta": {"rc": "ok"},
    "data": [
        {"_id": "s-default", "name": "default", "desc": "Default"},
        {"_id": "s-branch", "name": "ab12cd34", "desc": "Branch office"},
    ],
}
LOG_PAGE = {
    "data": [{"id": "e0", "key": "CLIENT_ROAMED_2"}],
    "page_number": 0,
    "total_element_count": 1,
    "total_page_count": 1,
}

ARGS: dict[str, dict[str, Any]] = {
    "create_client_reservation": {"mac": MAC, "name": "printer", "network": "Default"},
    "create_site": {"description": "Branch office"},
    "create_vpn_client": {"name": "Tunnel", "vpn_type": "wireguard"},
    "delete_site": {"site_to_delete": "Branch office"},
    "delete_vpn_client": {"vpn_client_id": "c-vpnc"},
    "extend_guest": {"guest": MAC},
    "forget_client": {"mac": MAC},
    "get_system_log": {"log_class": "all"},
    "list_guests": {},
    "list_ips_events": {},
    "list_network_events": {},
    "list_vpn_clients": {},
    "remove_client_fixed_ip": {"client": MAC},
    "rename_site": {"description": "Main office"},
    "set_client_fixed_ip": {"client": MAC, "fixed_ip": "192.0.2.50", "network": "Default"},
    "set_client_name": {"client": MAC, "name": "printer"},
    "set_client_note": {"client": MAC, "note": "lab"},
    "update_vpn_client": {"vpn_client_id": "i-vpnc", "fields": {"enabled": True}},
}

_GETS = {
    "/rest/user": USERS,
    "/rest/networkconf": NETWORKCONF,
    "/stat/guest": GUESTS,
    "/self/sites": SITES,
}


def test_the_table_covers_exactly_the_net_b_tools():
    assert set(ARGS) == set(NET_B_TOOLS)
    assert set(NET_B_TOOLS) <= set(cti.TOOLS)
    # The catalog-wide owning-key invariant runs these tools too.
    assert set(NET_B_TOOLS) <= set(cti.HOST_TOOLS)


async def _get(path: str, **_: Any) -> Any:
    for suffix, body in _GETS.items():
        if path.endswith(suffix):
            return copy.deepcopy(body)
    raise AssertionError(f"unexpected GET {path}")


async def _post(path: str, **_: Any) -> Any:
    if "/system-log/" in path:
        return copy.deepcopy(LOG_PAGE)
    return {"meta": {"rc": "ok"}, "data": [{"_id": "new"}]}


def _mocks() -> tuple[AsyncMock, AsyncMock]:
    client = AsyncMock()
    client.get = AsyncMock(side_effect=_get)
    client.post = AsyncMock(side_effect=_post)
    client.put = AsyncMock(return_value={"meta": {"rc": "ok"}, "data": [{"_id": "x"}]})
    client.delete = AsyncMock(return_value={"meta": {"rc": "ok"}, "data": []})
    client.paginate_max_pages = None
    # The attributes the server's call path reads synchronously stay plain values, not
    # auto-created coroutine mocks: the client's settings (the environment credentials) and
    # no audit stream.
    client._settings = Settings(api_key="synthetic-unit-key")
    client.audit_stream = None
    registry = AsyncMock()
    registry.resolve_key_for_host = AsyncMock(return_value=SECOND)
    registry.resolve_host_id = AsyncMock(return_value=HOST_ID)
    registry.resolve_site_slug = AsyncMock(return_value="default")
    return client, registry


@pytest.fixture(scope="module", autouse=True)
def _tool_catalog_ready() -> Any:
    """Build the lazy catalog before an asynchronous test enters its event loop."""
    return cti.TOOLS["list_vpn_clients"]


@pytest.mark.parametrize("name", NET_B_TOOLS)
async def test_every_request_rides_the_resolved_second_key(monkeypatch, name):
    client, registry = _mocks()
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    await server.mcp.call_tool(name, {"host": "branch-console", "site": "Default", **ARGS[name]})

    registry.resolve_key_for_host.assert_awaited_with("branch-console")
    for call in registry.resolve_host_id.await_args_list:
        assert call.kwargs.get("key") is SECOND, (name, call)
    for call in registry.resolve_site_slug.await_args_list:
        assert call.kwargs.get("key") is SECOND, (name, call)
    calls = [
        (verb, call)
        for verb in ("get", "post", "put", "delete")
        for call in getattr(client, verb).await_args_list
    ]
    assert calls, f"{name}: no upstream call made"
    wrong = [
        (verb, c.args, c.kwargs.get("key"))
        for verb, c in calls
        if c.kwargs.get("key") is not SECOND
    ]
    assert wrong == [], f"{name}: requests not on the resolved second key: {wrong}"


# ----------------------------------------------------------------- credential redaction
def test_vpn_client_credentials_are_credential_fields():
    for field in ("x_wireguard_private_key", "x_openvpn_password", "X_WIREGUARD_PRIVATE_KEY"):
        assert is_credential_field(field), field


class VpnUpstream(uh.FakeUpstream):
    """Answers the Classic networkconf list with VPN-client records carrying credentials."""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        response = super().__call__(req)
        if req.method == "GET" and req.url.path.endswith("/rest/networkconf"):
            body = copy.deepcopy(NETWORKCONF)
            self.served[-1].body = body
            return httpx.Response(200, json=body)
        return response


def _vpn_records(payload: Any) -> list[dict[str, Any]]:
    data = payload.get("data") if isinstance(payload, dict) else None
    assert isinstance(data, list), payload
    return data


@pytest.mark.parametrize("enabled", [False, True], ids=["redaction-off", "redaction-on"])
@pytest.mark.parametrize("collision", [False, True], ids=["no-collision", "collision"])
async def test_list_vpn_clients_masks_vpn_credentials_only_under_the_opt_in(
    monkeypatch, enabled, collision
):
    if collision:
        monkeypatch.setitem(NETWORKCONF, "_vpn_clients", {"upstream": "preserved"})
    up = VpnUpstream()
    args = tool_args.generated_args(cti.TOOLS["list_vpn_clients"])
    res = await cti._call(
        monkeypatch,
        "list_vpn_clients",
        up,
        args=args,
        env={"UNIFI_REDACT_SECRETS": "1" if enabled else "0"},
    )
    payload = uh.result_payload(res)
    expected = copy.deepcopy(NETWORKCONF)
    if enabled:
        expected["data"][1]["x_wireguard_private_key"] = REDACTION_MASK
        expected["data"][2]["x_openvpn_password"] = REDACTION_MASK
    assert all(payload[key] == value for key, value in expected.items()), payload
    assert {r["_id"] for r in _vpn_records(payload)} == {"c-lan", "c-vpnc", "c-ovpn"}
    view = payload["_wrapperFields"]["_vpn_clients"] if collision else payload["_vpn_clients"]
    assert view == expected["data"][1:]
    records = {r["_id"]: r for r in view}
    assert set(records) == {"c-vpnc", "c-ovpn"}, records
    text = json.dumps(payload) + "".join(getattr(b, "text", "") or "" for b in res.content)
    if enabled:
        assert records["c-vpnc"]["x_wireguard_private_key"] == REDACTION_MASK
        assert records["c-ovpn"]["x_openvpn_password"] == REDACTION_MASK
        assert records["c-ovpn"]["openvpn_username"] == "branch"
        assert WG_SECRET not in text and OVPN_SECRET not in text
    else:
        assert records["c-vpnc"]["x_wireguard_private_key"] == WG_SECRET
        assert records["c-ovpn"]["x_openvpn_password"] == OVPN_SECRET
        assert REDACTION_MASK not in text


@pytest.mark.parametrize("enabled", [False, True], ids=["redaction-off", "redaction-on"])
async def test_create_vpn_client_dry_run_preview_masks_only_under_the_opt_in(monkeypatch, enabled):
    up = uh.FakeUpstream()
    fields = {
        "wireguard_client_mode": "manual",
        "x_wireguard_private_key": WG_SECRET,
        "openvpn_username": "branch",
        "x_openvpn_password": OVPN_SECRET,
    }
    args = {
        **tool_args.generated_args(cti.TOOLS["create_vpn_client"]),
        "name": "Tunnel",
        "vpn_type": "wireguard",
        "fields": fields,
    }
    res = await cti._call(
        monkeypatch,
        "create_vpn_client",
        up,
        args=args,
        env={"UNIFI_WRITE_POLICY": "dry-run", "UNIFI_REDACT_SECRETS": "1" if enabled else "0"},
    )
    payload = uh.result_payload(res)
    assert payload.get("status") == "dry_run", payload
    assert up.writes() == [], "a dry run sent a write"
    body = payload["preview"]["body"]
    assert payload["preview"]["method"] == "POST"
    assert body["purpose"] == "vpn-client" and body["openvpn_username"] == "branch"
    text = json.dumps(payload) + "".join(getattr(b, "text", "") or "" for b in res.content)
    if enabled:
        assert body["x_wireguard_private_key"] == REDACTION_MASK
        assert body["x_openvpn_password"] == REDACTION_MASK
        assert WG_SECRET not in text and OVPN_SECRET not in text
    else:
        assert body["x_wireguard_private_key"] == WG_SECRET
        assert body["x_openvpn_password"] == OVPN_SECRET


# ----------------------------------------------------------------- system-log writes
_SYSLOG = "/v1/connector/consoles/h/proxy/network/v2/api/site/default/system-log/"
SYSTEM_LOG_TOOLS = ("get_system_log", "list_network_events", "list_ips_events")


@pytest.mark.parametrize("log_class", system_log.KNOWN_CLASSES)
@pytest.mark.parametrize("suffix", ["", "/", "?pageNumber=0"])
def test_documented_system_log_posts_are_writes(log_class, suffix):
    # `all` is the one read-allowlisted route (its query string is not part of the route): the
    # native readers keep it a write with always_write, every other class is a write by route
    is_read = log_class == "all" and suffix in ("", "?pageNumber=0")
    assert read_only.is_write_request("POST", _SYSLOG + log_class + suffix) is not is_read


@pytest.mark.parametrize(
    "log_class",
    [
        "%61ll",
        "%2561ll",
        "all/",
        "ALL",
        "unknown-class",
        "all-x",
        "xall",
        "critical2",
        "all%2Fx",
        "all%252Fx",
        "delete",
        "count",
    ],
)
def test_alternate_or_unapproved_system_log_posts_are_writes(log_class):
    assert read_only.is_write_request("POST", _SYSLOG + log_class) is True


async def test_system_log_tools_are_advertised_as_writes():
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    assert set(SYSTEM_LOG_TOOLS) == {"get_system_log", "list_network_events", "list_ips_events"}
    for name in SYSTEM_LOG_TOOLS:
        assert tools[name].annotations.read_only_hint is not True, name
        assert name in cti.WRITE_TOOLS, name


@pytest.mark.parametrize(
    "name,extra",
    [
        ("get_system_log", {"log_class": log_class})
        for log_class in (*system_log.KNOWN_CLASSES, "%61ll", "%2561ll", "all/", "unknown-class")
    ]
    + [("list_network_events", {}), ("list_ips_events", {})],
)
@pytest.mark.parametrize("exceptions", [None, "family:network=dry-run"])
async def test_system_log_tools_refused_before_any_request(monkeypatch, name, extra, exceptions):
    up = uh.FakeUpstream()
    args = {**tool_args.generated_args(cti.TOOLS[name]), **extra}
    with pytest.raises(ToolError, match="UNIFI_WRITE_POLICY|read-only"):
        await cti._call(
            monkeypatch,
            name,
            up,
            args=args,
            env={"UNIFI_WRITE_POLICY": "deny"}
            | ({"UNIFI_WRITE_EXCEPTIONS": exceptions} if exceptions else {}),
        )
    assert up.served == [], f"{name} made an upstream request before refusal"


@pytest.mark.parametrize(
    "name,extra,log_class",
    [
        ("get_system_log", {"page": 0, "page_size": 5}, "all"),
        ("get_system_log", {"page_size": 5}, "all"),
        ("get_system_log", {"log_class": "critical"}, "critical"),
        ("list_network_events", {}, "all"),
        ("list_ips_events", {}, "threat-alert"),
    ],
)
async def test_system_log_dry_run_returns_first_post_preview(monkeypatch, name, extra, log_class):
    up = uh.FakeUpstream()
    # the class is passed explicitly: the generated defaults (tool_args) use device-alert, so
    # without it the `all` cases would never exercise the read-allowlisted route
    chosen = {"get_system_log": "log_class", "list_network_events": "view"}.get(name)
    extra = {**extra, **({chosen: log_class} if chosen else {})}
    args = {**tool_args.generated_args(cti.TOOLS[name]), **extra}
    res = await cti._call(monkeypatch, name, up, args=args, env={"UNIFI_WRITE_POLICY": "dry-run"})
    payload = uh.result_payload(res)
    assert payload["status"] == "dry_run", payload
    assert payload["preview"]["method"] == "POST"
    assert payload["preview"]["path"].endswith("/system-log/" + log_class)
    assert payload["preview"]["body"]["pageNumber"] == 0
    if "page_size" in extra:
        assert payload["preview"]["body"]["pageSize"] == extra["page_size"]
    if log_class == "threat-alert":
        assert payload["preview"]["body"]["threatTypes"] == ["HONEYPOT", "THREAT"]
    assert up.writes() == [], "a dry run sent a POST"


@pytest.mark.asyncio
async def test_guest_window_post_dry_run_returns_preview(monkeypatch):
    up = uh.FakeUpstream()
    res = await cti._call(
        monkeypatch,
        "list_guests",
        up,
        args={"host": tool_args.HOST, "site": tool_args.SITE, "within_hours": 24},
        env={"UNIFI_WRITE_POLICY": "dry-run"},
    )
    payload = uh.result_payload(res)
    assert payload["status"] == "dry_run"
    assert payload["preview"]["method"] == "POST"
    assert payload["preview"]["body"] == {"within": 24}
    assert up.writes() == []
