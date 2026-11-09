"""Network clients, guests, DHCP and hotspot tools.

Every tool runs against the real ``UniFiClient`` with only the HTTP transport mocked:
the route chosen (official / v2 / Classic) and why, query parameters and bodies sent,
verbatim pass-through, dry-run previews, read-only mode, zero-request input validation,
the Classic affirmative-rc rule, the read-merge-write Classic PUT, and the registration
contract (annotations derived from source, every property described). Response bodies
carry the key names of live Network 11.0.81 answers; every value is synthetic.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from unifi_fabric import server
from unifi_fabric._read_only_audit import classify_tool_verbs
from unifi_fabric.client import ClassicApiError, UniFiClient, UniFiConnectionError, _key_fingerprint
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.registry import Registry
from unifi_fabric.tools import network_clients_guests as ncg

HOST = "console-n05"
SITE_ID = "00000000-0000-4000-8000-0000000000a1"
NET = f"/v1/connector/consoles/{HOST}/proxy/network"
OFFICIAL = f"{NET}/integration/v1/sites/{SITE_ID}"
CLASSIC = f"{NET}/api/s/default"
V2 = f"{NET}/v2/api/site/default"
MAC = "02:00:00:00:05:01"
MAC_DASH = "02-00-00-00-05-01"
MAC_PATH = "02%3A00%3A00%3A00%3A05%3A01"
AP_PATH = "02%3A00%3A00%3A00%3A0a%3A01"
CLIENT_UUID = "00000000-0000-4000-8000-0000000000c1"
SESSION_ID = "00000000-0000-4000-8000-0000000000d1"
OPTION_ID = "00000000-0000-4000-8000-0000000000e1"
PACKAGE_ID = "00000000-0000-4000-8000-0000000000f1"
FILE_ID = "00000000-0000-4000-8000-0000000000b1"
OK = {"meta": {"rc": "ok"}, "data": []}

READ_TOOLS = {
    "get_local_client",
    "list_client_traffic_controls",
    "get_client_insights",
    "get_client_observability",
    "list_dhcp_leases",
    "list_dhcp_excluded_ips",
    "list_dhcp_options",
    "get_hotspot_settings",
    "list_hotspot_payments",
    "list_hotspot_authorizations",
}
WRITE_TOOLS = {
    "authorize_guest",
    "revoke_guest_access",
    "set_client_icon",
    "set_client_fingerprint_override",
    "report_incorrect_wifi_experience",
    "create_dhcp_option",
    "update_dhcp_option",
    "delete_dhcp_option",
    "create_hotspot_package",
    "update_hotspot_package",
    "delete_hotspot_package",
    "delete_guest_portal_file",
    "reset_guest_access_settings",
}

# Live-shaped records (key names as recorded on Network 11.0.81; synthetic values).
DHCP_OPTION = {
    "_id": OPTION_ID,
    "code": 224,
    "name": "tftp",
    "signed": False,
    "site_id": "000000000000000000000001",
    "type": "text",
}
PACKAGE = {
    "_id": PACKAGE_ID,
    "amount": 0.0,
    "currency": "USD",
    "index": 0,
    "limit_overwrite": False,
    "name": "Trial",
    "site_id": "000000000000000000000001",
    "trial_duration_minutes": 30,
    "trial_reset": "24",
}
GUEST_AUTH = {
    "meta": {"rc": "ok"},
    "data": [
        {
            "_id": SESSION_ID,
            "authorized_by": "api",
            "end": 1760000300,
            "mac": MAC,
            "qos_overwrite": False,
            "site_id": "000000000000000000000001",
            "start": 1760000000,
        }
    ],
}


def registry(c: UniFiClient, key: APIKeyConfig | None = None) -> Registry:
    """A real registry with complete synthetic discovery records in its cache."""
    r = Registry(c)
    label = (key or APIKeyConfig(key="test-key", label="beta")).label
    r._hosts[None] = r._hosts[label] = [{"id": HOST, "reportedState": {"hostname": HOST}}]
    r._sites[(None, HOST)] = r._sites[(label, HOST)] = [
        {"id": SITE_ID, "name": "Default", "internalReference": "default"}
    ]
    return r


@pytest.fixture(autouse=True)
def _write_policy_env_reset(monkeypatch):
    """Start every test without a write policy; ``_modes`` sets one for a client's modes."""
    # setenv first so the teardown removes a value a helper set directly in os.environ
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "allow")
    monkeypatch.delenv("UNIFI_WRITE_POLICY")


def _modes(settings: dict) -> dict:
    """Express the retired ``dry_run`` / ``read_only`` client modes as the write policy."""
    settings = dict(settings)
    dry = settings.pop("dry_run", False)
    deny = settings.pop("read_only", False)
    if deny:
        os.environ["UNIFI_WRITE_POLICY"] = "deny"
    elif dry:
        os.environ["UNIFI_WRITE_POLICY"] = "dry-run"
    return settings


def client(handler, **settings: Any) -> UniFiClient:
    settings = _modes(settings)
    c = UniFiClient(Settings(api_keys=[APIKeyConfig(key="test-key", label="beta")], **settings))
    c._clients[("beta", _key_fingerprint("test-key"))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(handler)
    )
    return c


def page(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"offset": 0, "limit": 200, "count": len(rows), "totalCount": len(rows), "data": rows}


class Upstream:
    """Route table: (method, raw path) -> response; records every request."""

    def __init__(self, routes: dict[tuple[str, str], Any] | None = None):
        self.routes = routes or {}
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        path = req.url.raw_path.decode().split("?")[0]
        entry = self.routes.get((req.method, path))
        if entry is None and req.method == "GET":
            if path == f"{OFFICIAL}/clients":
                entry = page(ONLINE)
            elif path == f"{CLASSIC}/stat/alluser":
                entry = {"meta": {"rc": "ok"}, "data": [{"mac": MAC, "name": "known-guest"}]}
            elif path == f"{CLASSIC}/stat/authorization":
                entry = GUEST_AUTH
        if entry is None:
            return httpx.Response(404, json={"error": "no route in test", "path": path})
        if callable(entry):
            entry = entry(req)
        if isinstance(entry, httpx.Response):
            return entry
        return httpx.Response(200, json=entry)

    def writes(self) -> list[httpx.Request]:
        return [r for r in self.seen if r.method != "GET"]


def body_of(req: httpx.Request) -> Any:
    return json.loads(req.content) if req.content else None


def path_of(req: httpx.Request) -> str:
    return req.url.raw_path.decode().split("?")[0]


async def run(handler, fn, *args, settings: dict[str, Any] | None = None, **kwargs):
    c = client(handler, **(settings or {}))
    try:
        return await fn(c, registry(c), HOST, "Default", *args, **kwargs)
    finally:
        await c.close()


def connected(rows: list[dict[str, Any]]) -> dict[tuple[str, str], Any]:
    return {("GET", f"{OFFICIAL}/clients"): page(rows)}


ONLINE = [{"id": CLIENT_UUID, "macAddress": MAC, "type": "WIRELESS", "name": "guest-phone"}]


# --------------------------------------------------------------------------- guests


async def test_authorize_connected_mac_uses_the_official_action_with_mapped_limits():
    up = Upstream(
        {
            **connected(ONLINE),
            ("POST", f"{OFFICIAL}/clients/{CLIENT_UUID}/actions"): {"action": "ok"},
        }
    )
    result = await run(
        up,
        ncg.authorize_guest,
        MAC_DASH,
        time_limit_minutes=60,
        data_limit_mbytes=1024,
        rx_rate_limit_kbps=10000,
        tx_rate_limit_kbps=2000,
    )
    assert result == {"action": "ok", "_route": "official", "_reason": "the client is connected"}
    lookup, write = up.seen
    assert lookup.method == "GET"
    assert body_of(write) == {
        "action": "AUTHORIZE_GUEST_ACCESS",
        "timeLimitMinutes": 60,
        "dataUsageLimitMBytes": 1024,
        "rxRateLimitKbps": 10000,
        "txRateLimitKbps": 2000,
    }


async def test_authorize_unconnected_mac_falls_back_to_classic_stamgr():
    up = Upstream({**connected([]), ("POST", f"{CLASSIC}/cmd/stamgr"): GUEST_AUTH})
    result = await run(
        up, ncg.authorize_guest, MAC, time_limit_minutes=5, data_limit_mbytes=10,
        rx_rate_limit_kbps=512, tx_rate_limit_kbps=256,
    )  # fmt: skip
    assert result["_route"] == "classic" and "not a connected client" in result["_reason"]
    assert {k: v for k, v in result.items() if not k.startswith("_")} == GUEST_AUTH
    assert body_of(up.writes()[0]) == {
        "cmd": "authorize-guest",
        "mac": MAC,
        "minutes": 5,
        "bytes": 10,
        "down": 512,
        "up": 256,
    }


async def test_authorize_sends_only_given_limits():
    up = Upstream({**connected([]), ("POST", f"{CLASSIC}/cmd/stamgr"): GUEST_AUTH})
    await run(up, ncg.authorize_guest, MAC)
    assert body_of(up.writes()[0]) == {"cmd": "authorize-guest", "mac": MAC}


async def test_authorize_by_uuid_resolves_before_the_official_action():
    up = Upstream({("POST", f"{OFFICIAL}/clients/{CLIENT_UUID}/actions"): {}})
    result = await run(up, ncg.authorize_guest, CLIENT_UUID)
    assert result["_route"] == "official"
    assert up.seen[0].method == "GET"
    assert len(up.writes()) == 1
    assert body_of(up.writes()[0]) == {"action": "AUTHORIZE_GUEST_ACCESS"}


async def test_authorize_with_ap_mac_resolves_then_uses_classic():
    up = Upstream({("POST", f"{CLASSIC}/cmd/stamgr"): GUEST_AUTH})
    result = await run(up, ncg.authorize_guest, MAC, ap_mac="02-00-00-00-0A-01")
    assert result["_route"] == "classic" and "ap_mac" in result["_reason"]
    assert up.seen[0].method == "GET"
    assert body_of(up.writes()[0])["ap_mac"] == "02:00:00:00:0a:01"


async def test_authorize_uuid_with_ap_mac_reads_the_mac_then_uses_classic():
    up = Upstream(
        {
            ("GET", f"{OFFICIAL}/clients/{CLIENT_UUID}"): {"id": CLIENT_UUID, "macAddress": MAC},
            ("POST", f"{CLASSIC}/cmd/stamgr"): GUEST_AUTH,
        }
    )
    result = await run(up, ncg.authorize_guest, CLIENT_UUID, ap_mac="02:00:00:00:0a:01")
    assert result["_route"] == "classic"
    assert body_of(up.writes()[0])["mac"] == MAC


async def test_authorize_classic_rc_error_raises_with_the_full_body():
    rejected = {"meta": {"rc": "error", "msg": "api.err.InvalidMac"}, "data": []}
    up = Upstream({**connected([]), ("POST", f"{CLASSIC}/cmd/stamgr"): rejected})
    # The client chokepoint raises the shared Classic error first; the Wave 0 helper
    # names the command and keeps the full upstream body (rc and msg) in the message.
    with pytest.raises(ClassicApiError) as exc:
        await run(up, ncg.authorize_guest, MAC)
    text = str(exc.value)
    assert "Classic command 'authorize-guest'" in text
    assert '"rc":"error"' in text and "api.err.InvalidMac" in text


async def test_official_not_guest_answer_is_raised_with_the_full_reason():
    reason = {
        "statusCode": 422,
        "statusName": "UNPROCESSABLE_ENTITY",
        "code": "api.client.not-guest",
        "message": "Client is not a guest",
    }
    up = Upstream(
        {
            **connected(ONLINE),
            ("POST", f"{OFFICIAL}/clients/{CLIENT_UUID}/actions"): httpx.Response(422, json=reason),
        }
    )
    with pytest.raises(UniFiConnectionError) as exc:
        await run(up, ncg.authorize_guest, MAC)
    assert "api.client.not-guest" in str(exc.value) and "Client is not a guest" in str(exc.value)


async def test_revoke_connected_mac_uses_the_official_action():
    up = Upstream({**connected(ONLINE), ("POST", f"{OFFICIAL}/clients/{CLIENT_UUID}/actions"): {}})
    result = await run(up, ncg.revoke_guest_access, MAC)
    assert result["deleted"] is True
    assert result["response"] == {}
    assert body_of(up.writes()[0]) == {"action": "UNAUTHORIZE_GUEST_ACCESS"}


async def test_revoke_offline_mac_uses_classic_unauthorize():
    up = Upstream({**connected([]), ("POST", f"{CLASSIC}/cmd/stamgr"): OK})
    result = await run(up, ncg.revoke_guest_access, MAC)
    assert result["deleted"] is True
    assert result["response"] == OK
    assert body_of(up.writes()[0]) == {"cmd": "unauthorize-guest", "mac": MAC}


async def test_revoke_guest_session_terminates_it_by_id():
    up = Upstream({("POST", f"{CLASSIC}/cmd/hotspot"): GUEST_AUTH})
    result = await run(up, ncg.revoke_guest_access, SESSION_ID, "guest_session")
    assert result["deleted"] is True and result["response"] == GUEST_AUTH
    assert up.seen[0].method == "GET"
    assert len(up.writes()) == 1
    assert body_of(up.writes()[0]) == {"cmd": "terminate", "_id": SESSION_ID}


async def test_revoke_uuid_client_resolves_then_uses_the_official_action():
    up = Upstream({("POST", f"{OFFICIAL}/clients/{CLIENT_UUID}/actions"): {}})
    result = await run(up, ncg.revoke_guest_access, CLIENT_UUID)
    assert result["deleted"] is True and result["response"] == {} and len(up.writes()) == 1


async def test_a_mac_matching_several_ids_uses_the_unambiguous_classic_route():
    rows = [
        {"id": CLIENT_UUID, "macAddress": MAC},
        {"id": "00000000-0000-4000-8000-0000000000c2", "macAddress": MAC},
    ]
    up = Upstream({**connected(rows), ("POST", f"{CLASSIC}/cmd/stamgr"): OK})
    result = await run(up, ncg.revoke_guest_access, MAC)
    assert result["deleted"] is True and result["response"] == OK


# --------------------------------------------------------------------------- v2 clients


async def test_get_local_client_encodes_the_mac_and_sends_only_given_flags():
    record = {"mac": MAC, "fingerprint": {"has_override": False}, "id": "x"}
    up = Upstream({("GET", f"{V2}/clients/local/{MAC_PATH}"): record})
    assert await run(up, ncg.get_local_client, MAC_DASH) == record
    assert not up.seen[0].url.query
    up = Upstream({("GET", f"{V2}/clients/local/{MAC_PATH}"): record})
    await run(
        up, ncg.get_local_client, MAC, include_traffic_usage=True, include_unifi_devices=False
    )
    assert dict(up.seen[0].url.params) == {
        "includeTrafficUsage": "true",
        "includeUnifiDevices": "false",
    }


async def test_get_local_client_by_uuid_reads_the_mac_first():
    up = Upstream(
        {
            ("GET", f"{OFFICIAL}/clients/{CLIENT_UUID}"): {"macAddress": MAC},
            ("GET", f"{V2}/clients/local/{MAC_PATH}"): {"mac": MAC},
        }
    )
    assert await run(up, ncg.get_local_client, CLIENT_UUID) == {"mac": MAC}


async def test_traffic_controls_verbatim():
    body = {"applied_traffic_rule_count": {MAC: 2}}
    up = Upstream({("GET", f"{V2}/clients/traffic-control"): body})
    assert await run(up, ncg.list_client_traffic_controls) == body


@pytest.mark.parametrize("view", ["24hr-activity", "24hr-satisfaction", "traffic-insights"])
async def test_insight_views_send_the_mac_query(view):
    body = {"historical_activity": [{"activity_seconds": 30, "timestamp": 1760000000000}]}
    up = Upstream({("GET", f"{V2}/client/{MAC_PATH}/{view}"): body})
    assert await run(up, ncg.get_client_insights, MAC, view) == body
    assert dict(up.seen[0].url.params) == {"mac": MAC}


async def test_ap_stats_sends_the_window_in_milliseconds():
    body = {"ap_stats": [], "total_session_time_seconds": 0}
    up = Upstream({("GET", f"{V2}/client/{MAC_PATH}/ap-stats"): body})
    await run(up, ncg.get_client_insights, MAC, "ap-stats", start=1760000000, end=1760003600)
    assert dict(up.seen[0].url.params) == {
        "mac": MAC,
        "start": "1760000000000",
        "end": "1760003600000",
    }


async def test_insight_millisecond_input_warns_and_is_sent_scaled():
    up = Upstream({("GET", f"{V2}/client/{MAC_PATH}/ap-stats"): {"ap_stats": []}})
    result = await run(
        up, ncg.get_client_insights, MAC, "ap-stats", start=1760000000000, end=1760003600000
    )
    assert {w["code"] for w in result["_warnings"]} == {"EPOCH_SECONDS_LOOKS_LIKE_MILLISECONDS"}


async def test_observability_timeline_list_is_verbatim_with_ms_window():
    body = [{"id": "e1", "mac": MAC, "timestamp": 1760000000000, "type": "CONNECTED"}]
    up = Upstream({("GET", f"{V2}/observability/client/{MAC_PATH}/timeline"): body})
    assert await run(up, ncg.get_client_observability, MAC, "timeline", start=1, end=2) == body
    assert dict(up.seen[0].url.params) == {"start": "1000", "end": "2000"}


async def test_observability_topology_puts_the_time_in_the_path():
    body = {"client": {}, "hops": [], "isp": {}, "timestamp": 1760003000000}
    up = Upstream(
        {("GET", f"{V2}/observability/client/{MAC_PATH}/topology/at/1760003000000"): body}
    )
    assert (
        await run(up, ncg.get_client_observability, MAC, "topology", timestamp=1760003000) == body
    )
    assert not up.seen[0].url.query


async def test_observability_topology_without_timestamp_fails_before_any_request():
    up = Upstream()
    with pytest.raises(ValueError, match="integer epoch-seconds"):
        await run(up, ncg.get_client_observability, MAC, "topology")
    assert up.seen == []


async def test_logs_all_multi_page_answer_carries_a_warning():
    body = {"data": [], "page_number": 0, "total_element_count": 300, "total_page_count": 3}
    up = Upstream({("GET", f"{V2}/observability/client/{MAC_PATH}/logs-all"): body})
    result = await run(up, ncg.get_client_observability, MAC, "logs-all", start=1, end=2)
    assert result["_warnings"][0]["code"] == "MORE_PAGES_NOT_REQUESTABLE"
    assert {k: v for k, v in result.items() if k != "_warnings"} == body
    single = {**body, "total_page_count": 1}
    up = Upstream({("GET", f"{V2}/observability/client/{MAC_PATH}/logs-all"): single})
    assert await run(up, ncg.get_client_observability, MAC, "logs-all", start=1, end=2) == single


@pytest.mark.parametrize("view", ["logs-all", "timeline", "timestamps"])
@pytest.mark.parametrize(
    "window", [{}, {"start": 1793188385}, {"end": 1793191985}], ids=["none", "start", "end"]
)
async def test_window_views_without_complete_window_pass_upstream_400_verbatim(view, window):
    """E2E 0.7.0 bug 18: logs-all (and timeline, timestamps) without the window was sent
    and answered HTTP 400 (live, Network 11.0.89: neither or only one of start / end)."""
    path = f"{V2}/observability/client/{MAC_PATH}/{view}"
    up = Upstream({("GET", path): httpx.Response(400, json={"message": "window required"})})
    with pytest.raises(UniFiConnectionError) as info:
        await run(up, ncg.get_client_observability, MAC, view, **window)
    assert info.value.status == 400
    assert len(up.seen) == 1
    assert dict(up.seen[0].url.params) == {k: str(v * 1000) for k, v in window.items()}


async def test_window_views_send_the_window_in_milliseconds():
    body = {"data": [], "page_number": 0, "total_element_count": 0, "total_page_count": 1}
    up = Upstream({("GET", f"{V2}/observability/client/{MAC_PATH}/logs-all"): body})
    result = await run(
        up, ncg.get_client_observability, MAC, "logs-all", start=1793188385, end=1793191985
    )
    assert result == body
    assert dict(up.seen[-1].url.params) == {"start": "1793188385000", "end": "1793191985000"}


async def test_icon_put_and_restore_routes():
    icon = {"icon_id": "i", "icon_set_id": "s", "request_id": "r", "assets": []}
    up = Upstream(
        {
            ("PUT", f"{V2}/clients/{MAC_PATH}/ai-icon"): {"ok": True},
            ("DELETE", f"{V2}/clients/{MAC_PATH}/ai-icon"): httpx.Response(200),
        }
    )
    assert await run(up, ncg.set_client_icon, MAC, icon) == {"ok": True}
    assert body_of(up.seen[-1]) == icon
    result = await run(up, ncg.set_client_icon, MAC, None)
    assert result["deleted"] is True and result["response"] is None


async def test_icon_matter_node_route():
    up = Upstream({("DELETE", f"{V2}/matter/nodes/node-7/ai-icon"): httpx.Response(200)})
    result = await run(up, ncg.set_client_icon, "node-7", None, "matter_node")
    assert result["deleted"] is True and result["response"] is None


async def test_fingerprint_override_adds_the_mac_and_restores_with_delete():
    route = f"{V2}/station/{MAC_PATH}/fingerprint_override"
    answer = {"dev_id_override": 4, "fp_ml_version": 1, "mac": MAC}
    up = Upstream({("PUT", route): answer, ("DELETE", route): httpx.Response(200)})
    assert await run(up, ncg.set_client_fingerprint_override, MAC, {"dev_id_override": 4}) == answer
    assert body_of(up.seen[-1]) == {"dev_id_override": 4, "mac": MAC}
    await run(up, ncg.set_client_fingerprint_override, MAC, {"dev_id_override": 4, "mac": "x"})
    assert body_of(up.seen[-1])["mac"] == "x"
    result = await run(up, ncg.set_client_fingerprint_override, MAC, None)
    assert result["deleted"] is True and result["response"] is None


@pytest.mark.parametrize(
    "target_type,target,route",
    [
        ("client", MAC, f"{V2}/station/{MAC_PATH}/wifi_experience/incorrect"),
        ("ap", "02-00-00-00-0a-01", f"{V2}/device/{AP_PATH}/wifi_experience/incorrect"),
    ],
)  # fmt: skip
async def test_wifi_experience_report_route_and_body(target_type, target, route):
    up = Upstream({("POST", route): {}})
    await run(up, ncg.report_incorrect_wifi_experience, target_type, target, "POOR_LATENCY", "slow")
    assert body_of(up.seen[-1]) == {"reason": "POOR_LATENCY", "comment": "slow"}


# --------------------------------------------------------------------------- DHCP


@pytest.mark.parametrize("fn,route", [
    (ncg.list_dhcp_leases, "active-leases"),
    (ncg.list_dhcp_excluded_ips, "excluded-ips"),
])  # fmt: skip
async def test_dhcp_reads_site_wide_and_per_network(fn, route):
    body = {"dhcp_lease_info": []}
    up = Upstream({("GET", f"{V2}/{route}"): body, ("GET", f"{V2}/{route}/net-1"): body})
    assert await run(up, fn) == body
    assert await run(up, fn, "net-1") == body


async def test_list_dhcp_options_verbatim():
    body = {"meta": {"rc": "ok"}, "data": [DHCP_OPTION]}
    up = Upstream({("GET", f"{CLASSIC}/rest/dhcpoption"): body})
    assert await run(up, ncg.list_dhcp_options) == body


async def test_create_dhcp_option_sends_the_body_as_given():
    option = {"name": "tftp", "code": "224", "type": "text"}
    up = Upstream({("POST", f"{CLASSIC}/rest/dhcpoption"): {"meta": {"rc": "ok"}, "data": []}})
    await run(up, ncg.create_dhcp_option, option)
    assert body_of(up.seen[0]) == option


async def test_update_dhcp_option_lays_fields_over_the_listed_record():
    listing = {"meta": {"rc": "ok"}, "data": [DHCP_OPTION]}
    up = Upstream(
        {
            ("GET", f"{CLASSIC}/rest/dhcpoption"): listing,
            ("PUT", f"{CLASSIC}/rest/dhcpoption/{OPTION_ID}"): listing,
        }
    )
    assert await run(up, ncg.update_dhcp_option, OPTION_ID.upper(), {"name": "tftp2"}) == {
        **listing,
        "_verified": False,
        "_unverifiedFields": ["name"],
    }
    assert body_of(up.writes()[0]) == {**DHCP_OPTION, "name": "tftp2"}
    assert path_of(up.writes()[0]).endswith(OPTION_ID)  # the upstream spelling, not the input


async def test_update_dhcp_option_unknown_id_sends_no_write():
    up = Upstream({("GET", f"{CLASSIC}/rest/dhcpoption"): {"meta": {"rc": "ok"}, "data": []}})
    with pytest.raises(ValueError, match="not found; valid: \\(none\\)"):
        await run(up, ncg.update_dhcp_option, OPTION_ID, {"name": "x"})
    assert up.writes() == []


@pytest.mark.parametrize("fn", [ncg.update_dhcp_option, ncg.update_hotspot_package])
async def test_empty_update_fails_before_any_request(fn):
    up = Upstream()
    with pytest.raises(ValueError, match="^No fields provided"):
        await run(up, fn, OPTION_ID, {})
    assert up.seen == []


async def test_delete_dhcp_option_returns_the_deletion_result():
    up = Upstream(
        {
            ("GET", f"{CLASSIC}/rest/dhcpoption"): {"meta": {"rc": "ok"}, "data": [DHCP_OPTION]},
            ("DELETE", f"{CLASSIC}/rest/dhcpoption/{OPTION_ID}"): OK,
        }
    )
    result = await run(up, ncg.delete_dhcp_option, OPTION_ID)
    assert result == {
        "deleted": True,
        "message": f"DHCP option {OPTION_ID} deleted.",
        "response": OK,
    }


# --------------------------------------------------------------------------- hotspot


async def test_hotspot_settings_route_is_the_stat_s_layout():
    body = {"meta": {"rc": "ok"}, "data": [{"auth": "none", "payment_enabled": False}]}
    up = Upstream({("GET", f"{NET}/api/stat/s/default/hotspotconfig"): body})
    assert await run(up, ncg.get_hotspot_settings) == body


async def test_payments_window_in_milliseconds_and_within_as_given():
    body = {"meta": {"rc": "ok"}, "data": []}
    up = Upstream({("GET", f"{CLASSIC}/stat/payment"): body})
    assert await run(up, ncg.list_hotspot_payments, start=10, end=20, within=720) == body
    assert dict(up.seen[0].url.params) == {"start": "10000", "end": "20000", "within": "720"}
    await run(up, ncg.list_hotspot_payments)
    assert not up.seen[-1].url.query


async def test_authorizations_window_in_seconds():
    up = Upstream({("GET", f"{CLASSIC}/stat/authorization"): {"meta": {"rc": "ok"}, "data": []}})
    await run(up, ncg.list_hotspot_authorizations, start=10, end=20)
    assert dict(up.seen[0].url.params) == {"start": "10", "end": "20"}


async def test_package_lifecycle_routes_and_merged_update():
    listing = {"meta": {"rc": "ok"}, "data": [PACKAGE]}
    up = Upstream(
        {
            ("POST", f"{CLASSIC}/rest/hotspotpackage"): listing,
            ("GET", f"{CLASSIC}/rest/hotspotpackage"): listing,
            ("PUT", f"{CLASSIC}/rest/hotspotpackage/{PACKAGE_ID}"): listing,
            ("DELETE", f"{CLASSIC}/rest/hotspotpackage/{PACKAGE_ID}"): OK,
        }
    )
    create = {"name": "Trial", "amount": 0, "trial_duration_minutes": 30}
    assert await run(up, ncg.create_hotspot_package, create) == listing
    assert body_of(up.writes()[-1]) == create
    await run(up, ncg.update_hotspot_package, PACKAGE_ID, {"name": "Trial 2"})
    assert body_of(up.writes()[-1]) == {**PACKAGE, "name": "Trial 2"}
    assert (await run(up, ncg.delete_hotspot_package, PACKAGE_ID))["deleted"] is True


async def test_portal_file_unknown_id_sends_no_delete():
    up = Upstream({("GET", f"{CLASSIC}/rest/portalfile"): {"meta": {"rc": "ok"}, "data": []}})
    with pytest.raises(ValueError, match="Guest portal file .* not found"):
        await run(up, ncg.delete_guest_portal_file, FILE_ID)
    assert up.writes() == []


async def test_portal_file_delete_resolves_then_deletes():
    up = Upstream(
        {
            ("GET", f"{CLASSIC}/rest/portalfile"): {
                "meta": {"rc": "ok"},
                "data": [{"_id": FILE_ID}],
            },
            ("DELETE", f"{CLASSIC}/rest/portalfile/{FILE_ID}"): OK,
        }
    )
    assert (await run(up, ncg.delete_guest_portal_file, FILE_ID))["deleted"] is True


async def test_reset_guest_access_sends_an_empty_object_by_default():
    up = Upstream({("POST", f"{V2}/settings/guest-access/reset"): {}})
    await run(up, ncg.reset_guest_access_settings)
    assert body_of(up.seen[0]) == {}
    await run(up, ncg.reset_guest_access_settings, {"keep": True})
    assert body_of(up.seen[-1]) == {"keep": True}


# --------------------------------------------------------------- whole-module sweeps

CALLS: dict[str, tuple[Any, tuple, dict]] = {
    "authorize_guest": (ncg.authorize_guest, (MAC,), {"time_limit_minutes": 5}),
    "revoke_guest_access": (ncg.revoke_guest_access, (MAC,), {}),
    "get_local_client": (ncg.get_local_client, (MAC,), {}),
    "list_client_traffic_controls": (ncg.list_client_traffic_controls, (), {}),
    "get_client_insights": (ncg.get_client_insights, (MAC, "24hr-activity"), {}),
    "get_client_observability": (
        ncg.get_client_observability,
        (MAC, "timeline"),
        {"start": 1, "end": 2},
    ),
    "set_client_icon": (ncg.set_client_icon, (MAC, None), {}),
    "set_client_fingerprint_override": (
        ncg.set_client_fingerprint_override,
        (MAC, {"dev_id_override": 4}),
        {},
    ),
    "report_incorrect_wifi_experience": (
        ncg.report_incorrect_wifi_experience,
        ("client", MAC, "POOR_LATENCY"),
        {},
    ),
    "list_dhcp_leases": (ncg.list_dhcp_leases, (), {}),
    "list_dhcp_excluded_ips": (ncg.list_dhcp_excluded_ips, (), {}),
    "list_dhcp_options": (ncg.list_dhcp_options, (), {}),
    "create_dhcp_option": (ncg.create_dhcp_option, ({"name": "o", "code": "224"},), {}),
    "update_dhcp_option": (ncg.update_dhcp_option, (OPTION_ID, {"name": "p"}), {}),
    "delete_dhcp_option": (ncg.delete_dhcp_option, (OPTION_ID,), {}),
    "get_hotspot_settings": (ncg.get_hotspot_settings, (), {}),
    "list_hotspot_payments": (ncg.list_hotspot_payments, (), {}),
    "list_hotspot_authorizations": (ncg.list_hotspot_authorizations, (), {}),
    "create_hotspot_package": (ncg.create_hotspot_package, ({"name": "t"},), {}),
    "update_hotspot_package": (ncg.update_hotspot_package, (PACKAGE_ID, {"name": "u"}), {}),
    "delete_hotspot_package": (ncg.delete_hotspot_package, (PACKAGE_ID,), {}),
    "delete_guest_portal_file": (ncg.delete_guest_portal_file, (FILE_ID,), {}),
    "reset_guest_access_settings": (ncg.reset_guest_access_settings, (), {}),
}


class GenericUpstream(Upstream):
    """Answers every route the module calls, shaped like the live console."""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        path = path_of(req)
        if req.method != "GET":
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": []})
        if path == f"{OFFICIAL}/clients":
            return httpx.Response(200, json=page([]))
        for collection, record in (
            ("dhcpoption", DHCP_OPTION),
            ("hotspotpackage", PACKAGE),
            ("portalfile", {"_id": FILE_ID}),
        ):
            if path.endswith(f"/rest/{collection}"):
                return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [record]})
        if path.endswith("/stat/alluser"):
            return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [{"mac": MAC}]})
        if path.endswith("/stat/guest"):
            return httpx.Response(200, json=GUEST_AUTH)
        return httpx.Response(200, json={"meta": {"rc": "ok"}, "data": []})


def test_calls_cover_every_tool():
    assert set(CALLS) == READ_TOOLS | WRITE_TOOLS


@pytest.mark.parametrize("name", sorted(CALLS))
async def test_every_tool_valid_call_reaches_upstream(name):
    fn, args, kwargs = CALLS[name]
    up = GenericUpstream()
    await run(up, fn, *args, **kwargs)
    assert up.seen, name
    if name in WRITE_TOOLS:
        assert up.writes(), f"{name} sent no write"
    else:
        assert not up.writes(), f"read tool {name} sent a write"


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_dry_run_previews_every_write_and_sends_none(name):
    fn, args, kwargs = CALLS[name]
    up = GenericUpstream()
    result = await run(up, fn, *args, settings={"dry_run": True}, **kwargs)
    assert up.writes() == [], name
    assert result["status"] == "dry_run", result
    assert result.get("deleted") in (None, False)
    assert "verified" not in result


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
async def test_read_only_mode_refuses_every_write(name, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    fn, args, kwargs = CALLS[name]
    up = GenericUpstream()
    with pytest.raises(Exception, match="read-only mode"):
        await run(up, fn, *args, **kwargs)
    assert up.writes() == []


@pytest.mark.parametrize("name", sorted(READ_TOOLS))
async def test_read_only_mode_leaves_reads_working(name, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    fn, args, kwargs = CALLS[name]
    up = GenericUpstream()
    await run(up, fn, *args, **kwargs)
    assert up.seen


@pytest.mark.parametrize("bad", ["", "not-a-mac", "../etc", "aa:bb"])
@pytest.mark.parametrize("name", sorted(n for n, (_, a, _k) in CALLS.items() if MAC in a))
async def test_bad_client_refs_fail_before_any_request(name, bad):
    fn, args, kwargs = CALLS[name]
    broken = tuple(bad if a == MAC else a for a in args)
    up = GenericUpstream()
    with pytest.raises(ValueError, match="neither a client id"):
        await run(up, fn, *broken, **kwargs)
    assert up.seen == [], name


@pytest.mark.parametrize("bad", ["", "../etc", "a/b", "x y"])
@pytest.mark.parametrize(
    "name",
    ["update_dhcp_option", "delete_dhcp_option", "update_hotspot_package",
     "delete_hotspot_package", "delete_guest_portal_file"],
)  # fmt: skip
async def test_unsafe_record_ids_fail_before_any_request(name, bad):
    fn, args, kwargs = CALLS[name]
    up = GenericUpstream()
    with pytest.raises(ValueError):
        await run(up, fn, bad, *args[1:], **kwargs)
    assert up.seen == [], name


@pytest.mark.parametrize(
    "fn,args",
    [
        (ncg.get_client_insights, (MAC, "24hr")),
        (ncg.get_client_observability, (MAC, "logs")),
        (ncg.set_client_icon, (MAC, None, "device")),
        (ncg.report_incorrect_wifi_experience, ("station", MAC, "POOR_LATENCY")),
        (ncg.revoke_guest_access, (MAC, "session")),
    ],
)
async def test_closed_choices_fail_before_any_request(fn, args):
    up = GenericUpstream()
    with pytest.raises(ValidationError, match="Input should be"):
        await run(up, fn, *args)
    assert up.seen == []


@pytest.mark.parametrize("value", [True, 1.5, "5"])
async def test_limits_must_be_integers_before_any_request(value):
    up = GenericUpstream()
    with pytest.raises(ValidationError):
        await run(up, ncg.authorize_guest, MAC, time_limit_minutes=value)
    assert up.seen == []


async def test_requests_ride_the_resolved_key():
    """Every request goes out on the key the registry resolved for the host: the only
    mocked transport is the resolved key's, so another key would fail to connect."""
    alpha = APIKeyConfig(key="synthetic-alpha", label="alpha")
    beta = APIKeyConfig(key="synthetic-beta", label="beta")
    assert "authorize_guest" in CALLS
    for name, (fn, args, kwargs) in sorted(CALLS.items()):
        up = GenericUpstream()
        c = UniFiClient(Settings(api_keys=[alpha, beta]))
        c._clients[("beta", _key_fingerprint(beta.key))] = httpx.AsyncClient(
            base_url="https://api.ui.com",
            headers={"X-API-KEY": beta.key},
            transport=httpx.MockTransport(up),
        )

        def wrong_key(request: httpx.Request) -> httpx.Response:
            raise AssertionError(f"request used the non-owning key: {request.method}")

        c._clients[("alpha", _key_fingerprint(alpha.key))] = httpx.AsyncClient(
            base_url="https://api.ui.com", transport=httpx.MockTransport(wrong_key)
        )
        r = registry(c, beta)
        r._hosts["alpha"] = []
        try:
            await fn(c, r, HOST, "Default", *args, **kwargs)
        finally:
            await c.close()
        assert up.seen, name
        assert all(request.headers["X-API-KEY"] == beta.key for request in up.seen), name


# --------------------------------------------------------------- registration contract


def _registered() -> dict[str, Any]:
    res = server.mcp.list_tools()
    tools = asyncio.run(res) if inspect.isawaitable(res) else res
    return {t.name: t for t in tools if t.name in READ_TOOLS | WRITE_TOOLS}


def test_register_adds_exactly_the_23_tools():
    assert set(_registered()) == READ_TOOLS | WRITE_TOOLS
    assert len(READ_TOOLS | WRITE_TOOLS) == 23


def test_annotations_match_the_source_derived_write_set():
    tools = _registered()
    verbs = classify_tool_verbs(list(tools.values()))
    assert {name for name, v in verbs.items() if v} == WRITE_TOOLS
    for name, tool in tools.items():
        writes = name in WRITE_TOOLS
        hints = tool.annotations.model_dump(by_alias=True)
        assert hints["readOnlyHint"] is (not writes), name
        assert hints["destructiveHint"] is writes, name


def test_every_property_is_described_and_descriptions_fit():
    tools = _registered()
    assert set(tools) == READ_TOOLS | WRITE_TOOLS
    for name, tool in tools.items():
        assert tool.description and len(tool.description) <= 2048, name
        assert "Route" in tool.description or "route" in tool.description, name
        props = (tool.parameters or {}).get("properties", {})
        assert props, name
        for prop, schema in props.items():
            assert schema.get("description"), f"{name}.{prop} has no description"


def test_closed_choices_are_schema_enums():
    tools = _registered()
    assert tools["get_client_insights"].parameters["properties"]["view"]["enum"] == [
        "24hr-activity",
        "24hr-satisfaction",
        "ap-stats",
        "traffic-insights",
    ]
    assert tools["revoke_guest_access"].parameters["properties"]["target_type"]["enum"] == [
        "client",
        "guest_session",
    ]


def test_write_tools_accept_and_ignore_confirm():
    tools = _registered()
    for name in WRITE_TOOLS:
        assert "confirm" in tools[name].parameters["properties"], name
    for name in READ_TOOLS:
        assert "confirm" not in tools[name].parameters["properties"], name


def test_module_raise_sites_are_registered():
    from unifi_fabric.refusals import registered_sites

    tree = ast.parse(Path(ncg.__file__).read_text())
    sites = registered_sites()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(isinstance(child, ast.Raise) for child in ast.walk(node)):
                assert f"tools/network_clients_guests.py:{node.name}" in sites


# --------------------------------------------------------------------------- NO-GO classes
# Each Wave-2 NO-GO finding class is proved over all 23 tools, not per instance.


class ProbeUpstream(GenericUpstream):
    """GenericUpstream whose every object body carries a per-request probe value."""

    def __init__(self) -> None:
        super().__init__()
        self.bodies: list[tuple[httpx.Request, Any]] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        response = super().__call__(req)
        body = json.loads(response.content)
        if isinstance(body, dict):
            body = {**body, "probe": f"{req.method} {len(self.bodies)}"}
        self.bodies.append((req, body))
        return httpx.Response(response.status_code, json=body)


@pytest.mark.parametrize("name", sorted(CALLS))
async def test_every_tool_returns_its_upstream_body_verbatim(name):
    """Class: wrapped (non-verbatim) bodies. The tool's own request (the last write, or
    the last read for a read tool) comes back unchanged; only ``_``-prefixed keys added."""
    fn, args, kwargs = CALLS[name]
    up = ProbeUpstream()
    result = await run(up, fn, *args, **kwargs)
    writes = [(r, b) for r, b in up.bodies if r.method != "GET"]
    _, primary = (writes or up.bodies)[-1]
    delete_tools = {
        "delete_dhcp_option",
        "delete_guest_portal_file",
        "delete_hotspot_package",
        "revoke_guest_access",
        "set_client_icon",
    }
    if name in delete_tools:
        assert result["deleted"] is True
        assert result["response"] == primary
        assert set(result) == {"deleted", "message", "response"}
    elif isinstance(result, dict):
        assert {k: v for k, v in result.items() if not k.startswith("_")} == primary, name
    else:
        assert result == primary, name


def test_every_tool_is_a_typed_named_function_with_typed_schemas():
    """Class: untyped lambda registration and ``{}`` schemas, over all 23 tools."""

    def empty_schemas(node: Any, path: str) -> list[str]:
        if not isinstance(node, dict):
            return []
        if node == {}:
            return [path]
        found: list[str] = []
        for key, value in node.items():
            if key in ("properties", "$defs") and isinstance(value, dict):
                for sub, schema in value.items():
                    found += empty_schemas(schema, f"{path}.{key}.{sub}")
            elif key in ("items", "additionalProperties") and isinstance(value, dict):
                found += empty_schemas(value, f"{path}.{key}")
        return found

    def typed(schema: dict[str, Any]) -> bool:
        return bool(schema.get("type") or schema.get("$ref")) or any(
            all(isinstance(b, dict) and typed(b) for b in schema.get(k, [])) and schema.get(k)
            for k in ("anyOf", "oneOf", "allOf")
        )

    tools = _registered()
    assert len(tools) == 23
    for name, tool in tools.items():
        fn = inspect.unwrap(tool.fn)
        assert fn.__code__.co_name != "<lambda>", name
        assert fn.__code__.co_name == f"_{name}", name
        for param in inspect.signature(fn).parameters.values():
            assert param.kind is not param.VAR_KEYWORD, f"{name} takes **kwargs"
            assert param.annotation is not param.empty, f"{name}.{param.name} is untyped"
        assert empty_schemas(tool.parameters, name) == [], name
        for prop, schema in tool.parameters["properties"].items():
            assert typed(schema), f"{name}.{prop} has no type"
    src = Path(ncg.__file__).read_text()
    assert "lambda" not in src.split("def register(", 1)[1]


def test_every_argument_description_carries_a_real_example():
    """Class: missing ``Args:`` descriptions. Every parameter of all 23 tools has a
    description with an ``e.g.`` example (``confirm`` is the fixed ignored flag)."""
    missing = [
        f"{name}.{prop}"
        for name, tool in _registered().items()
        for prop, schema in tool.parameters["properties"].items()
        if prop != "confirm" and "e.g." not in str(schema.get("description", ""))
    ]
    assert missing == []


def test_registry_names_no_stale_site_in_this_module():
    """Class: unregistered refusals, inverse direction. Every registry entry naming this
    module points at a function that still raises (no dead or renamed site)."""
    from unifi_fabric.refusals import registered_sites

    tree = ast.parse(Path(ncg.__file__).read_text())
    raising = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(isinstance(child, ast.Raise) for child in ast.walk(node))
    }
    prefix = "tools/network_clients_guests.py:"
    named = {site[len(prefix) :] for site in registered_sites() if site.startswith(prefix)}
    assert named <= raising, named - raising
    assert raising <= named, raising - named


def test_module_tests_exist_for_every_tool():
    """Class: missing module test file. tests/test_network_clients_guests.py exercises
    every registered tool by name."""
    text = Path(__file__).read_text()
    for name in READ_TOOLS | WRITE_TOOLS:
        assert f"ncg.{name}" in text, name
