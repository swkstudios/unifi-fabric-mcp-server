"""Network mobile broadband (LTE / MBB / eSIM) and WAN tools (tools/network_mobile_wan.py).

Hermetic: a real ``UniFiClient`` with the HTTP layer mocked by respx and a stub registry
that records every resolution call (so "zero requests on invalid input" covers the
resolution reads too). Every MAC, id, PIN, password and activation code is synthetic.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest
import respx
from httpx import Response

from tests._tool_catalog import LazyCatalog
from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
from unifi_fabric import refusals, route_secrets
from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.tools import network_mobile_wan as nmw

BASE = "https://api.ui.com"
HOST = "A1B2C3:12345"
CONSOLE = f"{BASE}/v1/connector/consoles/{HOST}/proxy/network"
CMD_LTE = f"{CONSOLE}/api/s/default/cmd/lte"
CMD_MBB = f"{CONSOLE}/api/s/default/cmd/mbb"
DEVICES = f"{CONSOLE}/api/s/default/stat/device-basic"
V2 = f"{CONSOLE}/v2/api/site/default"

MAC = "02:00:5e:00:53:01"
OTHER_MAC = "02:00:5e:00:53:02"
PIN = "4821"
PASSWORD = "synthetic-pass-0000"
TOKEN = "552190"
ACTIVATION = "LPA:1$smdp.example.com$SYNTHETIC-CODE-0001"
SLA_ID = "0000000000000000000000c1"
OK = {"meta": {"rc": "ok"}, "data": [{"probe": 1}]}
DEVICE_LIST = {
    "meta": {"rc": "ok"},
    "data": [{"mac": MAC, "name": "lte-backup", "model": "ULTE"}],
}

TOOLS = LazyCatalog()
LANE_TOOLS = (
    "get_lte_subscription_status",
    "activate_lte_trial",
    "authorize_lte_device",
    "set_lte_apn_profile",
    "verify_sim_pin",
    "update_lte_device",
    "manage_esim_profile",
    "get_inactive_sim_slot",
    "reset_mobile_data_usage",
    "set_lte_failover",
    "get_wan_load_balancing",
    "update_wan_load_balancing",
    "list_wan_network_groups",
    "get_wan_insights",
    "list_wan_slas",
    "create_wan_sla",
    "update_wan_sla",
    "delete_wan_sla",
    "get_enriched_configuration",
    "list_gateway_routes",
)
READS = {
    "get_wan_load_balancing",
    "list_wan_network_groups",
    "get_wan_insights",
    "list_wan_slas",
    "get_enriched_configuration",
    "list_gateway_routes",
}


class StubRegistry:
    """Resolves every console to HOST and every site to ``default``; records each call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def resolve_key_for_host(self, host: str) -> None:
        self.calls.append(("key", host))

    async def resolve_host_id(self, host: str, *, key: Any = None) -> str:
        self.calls.append(("host", host))
        return HOST

    async def resolve_site_slug(self, site: str, host_id: str, *, key: Any = None) -> str:
        self.calls.append(("site", site))
        return "default"


@pytest.fixture
def registry() -> StubRegistry:
    return StubRegistry()


def _client(monkeypatch, *, dry_run: bool = False, redact: bool = False) -> UniFiClient:
    for var in ("UNIFI_DRY_RUN", "UNIFI_READ_ONLY", "UNIFI_REDACT_SECRETS"):
        monkeypatch.delenv(var, raising=False)
    if dry_run:
        monkeypatch.setenv("UNIFI_DRY_RUN", "1")
    if redact:
        monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    return UniFiClient(Settings(api_key="sk-test"))


@pytest.fixture
def client(monkeypatch) -> UniFiClient:
    return _client(monkeypatch)


def _sent(route: respx.Route, index: int = -1) -> Any:
    return json.loads(route.calls[index].request.content)


# --------------------------------------------------------------------------- catalog


def test_all_twenty_tools_registered_with_derived_annotations():
    assert set(LANE_TOOLS) <= set(TOOLS)
    for name in LANE_TOOLS:
        ann = TOOLS[name].annotations
        assert ann.read_only_hint is (name in READS), name
        assert ann.destructive_hint is (name not in READS), name


@pytest.mark.parametrize("name", LANE_TOOLS)
def test_descriptions_fit_and_name_required_args_with_examples(name):
    tool = TOOLS[name]
    assert len(tool.description) <= 2048
    for arg in tool.parameters.get("required", []):
        assert arg in tool.description, (name, arg)
    for arg, spec in tool.parameters["properties"].items():
        assert "for example" in spec["description"], (name, arg)
    assert "simulat" not in tool.description.lower()


def test_route_choice_recorded_for_every_tool():
    assert set(nmw.ROUTE_CHOICES) == set(LANE_TOOLS)
    for source, route, reason in nmw.ROUTE_CHOICES.values():
        assert source in {"classic", "v2"} and route and reason


def test_physical_and_irreversible_writes_carry_a_consequence_line():
    for name in (
        "activate_lte_trial",
        "authorize_lte_device",
        "set_lte_apn_profile",
        "verify_sim_pin",
        "update_lte_device",
        "manage_esim_profile",
        "reset_mobile_data_usage",
        "set_lte_failover",
        "update_wan_load_balancing",
        "delete_wan_sla",
    ):
        assert "Consequence:" in TOOLS[name].description, name


def test_confirm_is_accepted_on_every_write():
    writes = set(LANE_TOOLS) - READS
    assert "activate_lte_trial" in writes
    for name in writes:
        props = TOOLS[name].parameters["properties"]
        assert "confirm" in props and props["confirm"]["default"] is False, name


# --------------------------------------------------------------------------- Classic commands


CLASSIC_CASES = [
    (
        "get_lte_subscription_status",
        nmw.get_lte_subscription_status,
        ([MAC],),
        {"ubic_username": "admin@example.com", "ubic_password": PASSWORD, "ubic_2fa_token": TOKEN},
        CMD_LTE,
        {
            "cmd": "check-subscription",
            "macs": [MAC],
            "ubic_username": "admin@example.com",
            "x_ubic_password": PASSWORD,
            "ubic_2fa_token": TOKEN,
        },
        True,
    ),
    (
        "activate_lte_trial",
        nmw.activate_lte_trial,
        (),
        {},
        CMD_LTE,
        {"cmd": "activate-trial"},
        False,
    ),
    (
        "authorize_lte_device",
        nmw.authorize_lte_device,
        ("02-00-5E-00-53-01",),
        {"ubic_username": "admin@example.com", "ubic_password": PASSWORD},
        CMD_LTE,
        {
            "cmd": "auth-device",
            "mac": MAC,
            "ubic_username": "admin@example.com",
            "x_ubic_password": PASSWORD,
        },
        True,
    ),
    (
        "set_lte_apn_profile",
        nmw.set_lte_apn_profile,
        (MAC, {"apn": "internet"}),
        {},
        CMD_LTE,
        {"cmd": "lte-set-profile", "apn": "internet", "mac": MAC},
        True,
    ),
    (
        "verify_sim_pin",
        nmw.verify_sim_pin,
        (PIN,),
        {"mac": MAC},
        CMD_LTE,
        {"cmd": "lte-verify-pin", "mac": MAC, "pin": PIN},
        True,
    ),
    (
        "verify_sim_pin mbb",
        nmw.verify_sim_pin,
        (PIN,),
        {"manager": "mbb", "params": {"slot": 2}},
        CMD_MBB,
        {"cmd": "verify-pin", "slot": 2, "pin": PIN},
        False,
    ),
    (
        "update_lte_device",
        nmw.update_lte_device,
        ({"mac": MAC, "roaming": True},),
        {},
        CMD_LTE,
        {"cmd": "update-device", "mac": MAC, "roaming": True},
        False,
    ),
    (
        "manage_esim_profile add",
        nmw.manage_esim_profile,
        ("add", {"activation_code": ACTIVATION}),
        {},
        CMD_MBB,
        {"cmd": "esim-add", "activation_code": ACTIVATION},
        False,
    ),
    (
        "manage_esim_profile delete",
        nmw.manage_esim_profile,
        ("delete", {"profile_ref": "profile-1"}),
        {},
        CMD_MBB,
        {"cmd": "esim-delete", "profile_ref": "profile-1"},
        False,
    ),
    (
        "get_inactive_sim_slot",
        nmw.get_inactive_sim_slot,
        (),
        {"params": {"mac": MAC}},
        CMD_MBB,
        {"cmd": "read-inactive-slot-sim-card", "mac": MAC},
        False,
    ),
    (
        "reset_mobile_data_usage",
        nmw.reset_mobile_data_usage,
        (),
        {},
        CMD_MBB,
        {"cmd": "reset-usage"},
        False,
    ),
]
CLASSIC_IDS = [case[0] for case in CLASSIC_CASES]


@respx.mock
@pytest.mark.parametrize(
    ("label", "fn", "args", "kwargs", "url", "body", "reads_devices"),
    CLASSIC_CASES,
    ids=CLASSIC_IDS,
)
async def test_classic_command_sends_the_bundle_body_and_returns_it_verbatim(
    client, registry, label, fn, args, kwargs, url, body, reads_devices
):
    devices = respx.get(DEVICES).mock(return_value=Response(200, json=DEVICE_LIST))
    route = respx.post(url).mock(return_value=Response(200, json=OK))
    out = await fn(client, registry, "Home UDM", "Default", *args, **kwargs)
    assert out == OK
    assert _sent(route) == body
    assert devices.called is reads_devices
    assert ("host", "Home UDM") in registry.calls


@respx.mock
@pytest.mark.parametrize(
    ("label", "fn", "args", "kwargs", "url", "body", "reads_devices"),
    CLASSIC_CASES,
    ids=CLASSIC_IDS,
)
async def test_classic_rc_error_is_an_error_with_the_full_body(
    client, registry, label, fn, args, kwargs, url, body, reads_devices
):
    rejected = {"meta": {"rc": "error", "msg": "api.err.LteNotSupported"}, "data": []}
    respx.get(DEVICES).mock(return_value=Response(200, json=DEVICE_LIST))
    respx.post(url).mock(return_value=Response(200, json=rejected))
    with pytest.raises(UniFiConnectionError) as exc:
        await fn(client, registry, "Home UDM", "Default", *args, **kwargs)
    assert "api.err.LteNotSupported" in str(exc.value)


@respx.mock
@pytest.mark.parametrize(
    ("label", "fn", "args", "kwargs", "url", "body", "reads_devices"),
    CLASSIC_CASES,
    ids=CLASSIC_IDS,
)
async def test_classic_dry_run_returns_the_preview_and_sends_nothing(
    monkeypatch, registry, label, fn, args, kwargs, url, body, reads_devices
):
    client = _client(monkeypatch, dry_run=True)
    respx.get(DEVICES).mock(return_value=Response(200, json=DEVICE_LIST))
    route = respx.post(url).mock(return_value=Response(200, json=OK))
    out = await fn(client, registry, "Home UDM", "Default", *args, **kwargs)
    assert not route.called
    assert out["status"] == "dry_run" and out["dryRun"] is True
    assert set(out) == {"status", "dryRun", "sent", "message", "preview"}
    assert out["preview"]["body"] == body  # verbatim without UNIFI_REDACT_SECRETS
    assert out["preview"]["params"] is None


@respx.mock
async def test_unknown_device_mac_fails_listing_devices_and_sends_no_command(client, registry):
    respx.get(DEVICES).mock(return_value=Response(200, json=DEVICE_LIST))
    route = respx.post(CMD_LTE).mock(return_value=Response(200, json=OK))
    with pytest.raises(ValueError) as exc:
        await nmw.authorize_lte_device(client, registry, "Home UDM", "Default", OTHER_MAC)
    text = str(exc.value)
    assert "not found" in text and MAC in text and "lte-backup" in text
    assert refusals.classify(text).id == "lookup-miss"
    assert not route.called


@respx.mock
async def test_device_list_with_a_non_object_row_is_a_shape_error(client, registry):
    respx.get(DEVICES).mock(return_value=Response(200, json={"meta": {"rc": "ok"}, "data": [7]}))
    route = respx.post(CMD_LTE).mock(return_value=Response(200, json=OK))
    with pytest.raises(UniFiConnectionError, match="Unexpected response shape"):
        await nmw.authorize_lte_device(client, registry, "Home UDM", "Default", MAC)
    assert not route.called


# --------------------------------------------------------------------------- secrets


@pytest.mark.parametrize("redact", [False, True])
@respx.mock
async def test_sim_pin_and_account_password_in_errors_follow_the_redaction_opt_in(
    monkeypatch, registry, redact
):
    # Error text is masked of the sent credentials only under UNIFI_REDACT_SECRETS;
    # otherwise the upstream error is passed through verbatim, the value included.
    client = _client(monkeypatch, redact=redact)
    echoed = {"meta": {"rc": "error", "msg": f"bad pin {PIN}"}, "data": [{"pin": PIN}]}
    respx.get(DEVICES).mock(return_value=Response(200, json=DEVICE_LIST))
    respx.post(CMD_LTE).mock(return_value=Response(200, json=echoed))
    with pytest.raises(UniFiConnectionError) as exc:
        await nmw.verify_sim_pin(client, registry, "Home UDM", "Default", PIN, mac=MAC)
    assert (PIN in str(exc.value)) is (not redact)
    assert "bad pin" in str(exc.value)
    respx.post(CMD_LTE).mock(return_value=Response(500, text=f"echo {PASSWORD} {TOKEN}"))
    with pytest.raises(UniFiConnectionError) as exc:
        await nmw.authorize_lte_device(
            client,
            registry,
            "Home UDM",
            "Default",
            MAC,
            ubic_password=PASSWORD,
            ubic_2fa_token=TOKEN,
        )
    assert (PASSWORD in str(exc.value)) is (not redact)
    assert (TOKEN in str(exc.value)) is (not redact)
    assert "HTTP 500" in str(exc.value)
    if not redact:
        assert f"echo {PASSWORD} {TOKEN}" in str(exc.value)


@pytest.mark.parametrize("redact", [False, True])
@respx.mock
async def test_esim_activation_code_in_a_transport_error_follows_the_redaction_opt_in(
    monkeypatch, registry, redact
):
    client = _client(monkeypatch, redact=redact)
    respx.post(CMD_MBB).mock(return_value=Response(400, text=f"invalid code {ACTIVATION}"))
    with pytest.raises(UniFiConnectionError) as exc:
        await nmw.manage_esim_profile(
            client, registry, "Home UDM", "Default", "add", {"activation_code": ACTIVATION}
        )
    assert (ACTIVATION in str(exc.value)) is (not redact)
    assert "HTTP 400" in str(exc.value) and "invalid code" in str(exc.value)
    if not redact:
        assert f"invalid code {ACTIVATION}" in str(exc.value)


@respx.mock
async def test_redact_secrets_masks_the_pin_in_the_preview_only_when_opted_in(
    monkeypatch, registry
):
    client = _client(monkeypatch, dry_run=True, redact=True)
    out = await nmw.verify_sim_pin(client, registry, "Home UDM", "Default", PIN)
    assert out["preview"]["body"]["pin"] == route_secrets.MASK
    out = await nmw.manage_esim_profile(
        client, registry, "Home UDM", "Default", "add", {"activation_code": ACTIVATION}
    )
    assert ACTIVATION not in json.dumps(out)


def test_route_secret_entries_cover_the_lane_credentials():
    lte = f"/v1/connector/consoles/{HOST}/proxy/network/api/s/default/cmd/lte"
    mbb = f"/v1/connector/consoles/{HOST}/proxy/network/api/s/default/cmd/mbb"
    body = {"cmd": "auth-device", "x_ubic_password": PASSWORD, "ubic_2fa_token": TOKEN}
    assert set(route_secrets.request_secrets("POST", lte, body)) == {PASSWORD, TOKEN}
    assert route_secrets.request_secrets("POST", lte, {"pin": PIN}) == (PIN,)
    assert route_secrets.request_secrets("POST", mbb, {"pin": PIN}) == (PIN,)
    assert route_secrets.request_secrets("POST", mbb, {"activation_code": ACTIVATION}) == (
        ACTIVATION,
    )
    assert route_secrets.request_secrets("POST", lte, {"apn_password": PASSWORD}) == (PASSWORD,)
    assert PIN in route_secrets.tool_call_secrets("verify_sim_pin", {"pin": PIN})
    assert PASSWORD in route_secrets.tool_call_secrets(
        "authorize_lte_device", {"ubic_password": PASSWORD}
    )


# --------------------------------------------------------------------------- zero requests


INVALID_CALLS = [
    (nmw.get_lte_subscription_status, ("Home UDM", "Default", ["not-a-mac"]), {}),
    (nmw.get_lte_subscription_status, ("Home UDM", "Default", [""]), {}),
    (nmw.authorize_lte_device, ("Home UDM", "Default", "zz:zz"), {}),
    (nmw.authorize_lte_device, (" Home UDM", "Default", MAC), {}),
    (nmw.set_lte_apn_profile, ("Home UDM", "Default", MAC, {"cmd": "restart"}), {}),
    (nmw.verify_sim_pin, ("Home UDM", "Default", PIN), {"mac": "bad"}),
    (nmw.verify_sim_pin, ("Home UDM", "Default", PIN), {"manager": "other"}),
    (nmw.update_lte_device, ("Home UDM", "", {"a": 1}), {}),
    (nmw.manage_esim_profile, ("Home UDM", "Default", "wipe", {"a": 1}), {}),
    (nmw.activate_lte_trial, ("Home UDM", "Default"), {"params": {"x": float("nan")}}),
    (nmw.get_inactive_sim_slot, ("Home UDM", "Default"), {"params": ["x"]}),
    (nmw.reset_mobile_data_usage, ("", "Default"), {}),
    (nmw.set_lte_failover, ("Home UDM", "Default\n", {"enabled": True}), {}),
    (nmw.get_wan_load_balancing, ("Home UDM", "Default"), {"view": "both"}),
    (nmw.update_wan_load_balancing, ("Home UDM", "Default", {}), {}),
    (nmw.update_wan_load_balancing, ("Home UDM", "Default", {"_keyLabel": "x"}), {}),
    (nmw.list_wan_network_groups, ("Home UDM", "Default"), {"uptime": 1}),
    (nmw.get_wan_insights, ("Home UDM", "Default", ".."), {}),
    (nmw.get_wan_insights, ("Home UDM", "Default", "WAN"), {"view": "graph"}),
    (nmw.list_wan_slas, ("Home UDM", " "), {}),
    (nmw.create_wan_sla, ("", "Default", {"name": "x"}), {}),
    (nmw.update_wan_sla, ("Home UDM", "Default", SLA_ID, {}), {}),
    (nmw.update_wan_sla, ("Home UDM", "Default", "", {"name": "x"}), {}),
    (nmw.delete_wan_sla, ("Home UDM", "Default", " x"), {}),
    (nmw.get_enriched_configuration, ("Home UDM", "Default"), {"kind": "vpn"}),
    (nmw.list_gateway_routes, ("Home UDM", ""), {}),
]


@respx.mock
@pytest.mark.parametrize(("fn", "args", "kwargs"), INVALID_CALLS)
async def test_invalid_input_makes_zero_requests(client, registry, fn, args, kwargs):
    route = respx.route().mock(return_value=Response(200, json=OK))
    with pytest.raises(ValueError):
        await fn(client, registry, *args, **kwargs)
    assert not route.called
    assert registry.calls == []


# --------------------------------------------------------------------------- v2 reads


@respx.mock
@pytest.mark.parametrize(
    ("fn", "args", "kwargs", "url", "query"),
    [
        (nmw.get_wan_load_balancing, (), {}, f"{V2}/wan/load-balancing/configuration", ""),
        (nmw.get_wan_load_balancing, (), {"view": "status"}, f"{V2}/wan/load-balancing/status", ""),
        (nmw.list_wan_network_groups, (), {}, f"{V2}/wan/networkgroups", ""),
        (
            nmw.list_wan_network_groups,
            (),
            {"uptime": True},
            f"{V2}/wan/networkgroups",
            "uptime=true",
        ),
        (nmw.get_wan_insights, ("WAN",), {}, f"{V2}/wan/WAN/insights/overview", ""),
        (
            nmw.get_wan_insights,
            ("WAN2",),
            {"view": "history", "period": "DAY"},
            f"{V2}/wan/WAN2/insights/history",
            "period=DAY",
        ),
        (
            nmw.get_wan_insights,
            ("WAN",),
            {"view": "speed_tests", "period": "WEEK"},
            f"{V2}/wan/WAN/insights/speed-tests",
            "period=WEEK",
        ),
        (nmw.list_wan_slas, (), {}, f"{V2}/wan-slas", ""),
        (nmw.get_enriched_configuration, (), {}, f"{V2}/wan/enriched-configuration", ""),
        (nmw.get_enriched_configuration, ("lan",), {}, f"{V2}/lan/enriched-configuration", ""),
        (nmw.get_enriched_configuration, ("wlan",), {}, f"{V2}/wlan/enriched-configuration", ""),
        (nmw.list_gateway_routes, (), {}, f"{V2}/routes", ""),
    ],
)
async def test_v2_reads_return_the_body_verbatim(client, registry, fn, args, kwargs, url, query):
    body = [{"_id": "0000000000000000000000d1", "name": "WAN", "nested": {"x": [1, None]}}]
    route = respx.get(url).mock(return_value=Response(200, json=body))
    out = await fn(client, registry, "Home UDM", "Default", *args, **kwargs)
    assert out == body
    assert route.calls[0].request.url.query.decode() == query


@respx.mock
async def test_read_error_carries_the_full_upstream_body(client, registry):
    long_reason = "x" * 5000
    respx.get(f"{V2}/routes").mock(return_value=Response(404, json={"message": long_reason}))
    with pytest.raises(UniFiConnectionError) as exc:
        await nmw.list_gateway_routes(client, registry, "Home UDM", "Default")
    assert long_reason in str(exc.value) and "/v2/api/site/default/routes" in str(exc.value)


@respx.mock
async def test_redirect_raises_with_status_and_location(client, registry):
    respx.get(f"{V2}/wan-slas").mock(
        return_value=Response(302, headers={"location": "https://elsewhere.example/login"})
    )
    with pytest.raises(UniFiConnectionError) as exc:
        await nmw.list_wan_slas(client, registry, "Home UDM", "Default")
    assert "HTTP 302" in str(exc.value) and "elsewhere.example" in str(exc.value)


# --------------------------------------------------------------------------- v2 writes


@respx.mock
async def test_set_lte_failover_puts_the_body_verbatim(client, registry):
    route = respx.put(f"{V2}/lan/enable-lte-failover").mock(
        return_value=Response(200, json={"ok": True})
    )
    out = await nmw.set_lte_failover(client, registry, "Home UDM", "Default", {"enabled": True})
    assert out == {"ok": True}
    assert _sent(route) == {"enabled": True}


@respx.mock
async def test_create_wan_sla_posts_the_body_verbatim(client, registry):
    created = {"_id": SLA_ID, "name": "Branch SLA", "latency_ms": 80}
    route = respx.post(f"{V2}/wan-slas").mock(return_value=Response(200, json=created))
    out = await nmw.create_wan_sla(
        client, registry, "Home UDM", "Default", {"name": "Branch SLA", "latency_ms": 80}
    )
    assert out == created
    assert _sent(route) == {"name": "Branch SLA", "latency_ms": 80}


LB_CURRENT = {"mode": "weighted", "wans": {"WAN": {"weight": 50}, "WAN2": {"weight": 50}}}


@respx.mock
async def test_update_wan_load_balancing_reads_merges_writes_and_verifies(client, registry):
    url = f"{V2}/wan/load-balancing/configuration"
    merged = {"mode": "weighted", "wans": {"WAN": {"weight": 80}, "WAN2": {"weight": 50}}}
    respx.get(url).mock(side_effect=[Response(200, json=LB_CURRENT), Response(200, json=merged)])
    put = respx.put(url).mock(return_value=Response(200, json={"result": "saved"}))
    out = await nmw.update_wan_load_balancing(
        client,
        registry,
        "Home UDM",
        "Default",
        {"wans": {"WAN": {"weight": 80}}},
        test_config_id="cfg-1",
    )
    assert _sent(put) == merged
    assert put.calls[0].request.url.query.decode() == "testConfigId=cfg-1"
    assert out == {"result": "saved", "_verified": True}


@respx.mock
async def test_update_wan_load_balancing_type_strict_mismatch_is_unverified(client, registry):
    url = f"{V2}/wan/load-balancing/configuration"
    after = {"mode": "weighted", "sticky": 1}
    respx.get(url).mock(side_effect=[Response(200, json=LB_CURRENT), Response(200, json=after)])
    respx.put(url).mock(return_value=Response(200, json={}))
    out = await nmw.update_wan_load_balancing(
        client, registry, "Home UDM", "Default", {"sticky": True}
    )
    assert out["_verified"] is False
    assert out["_unverifiedFields"] == ["sticky"]


@respx.mock
async def test_update_wan_load_balancing_failed_read_back_is_unknown_not_an_error(client, registry):
    url = f"{V2}/wan/load-balancing/configuration"
    respx.get(url).mock(side_effect=[Response(200, json=LB_CURRENT), Response(503, text="busy")])
    respx.put(url).mock(return_value=Response(204))
    out = await nmw.update_wan_load_balancing(
        client, registry, "Home UDM", "Default", {"mode": "x"}
    )
    assert out["_verified"] is None
    assert "HTTP 503" in out["_readAfterError"]
    assert out["response"] is None


@respx.mock
async def test_update_wan_load_balancing_dry_run_reads_but_never_puts(monkeypatch, registry):
    client = _client(monkeypatch, dry_run=True)
    url = f"{V2}/wan/load-balancing/configuration"
    respx.get(url).mock(return_value=Response(200, json=LB_CURRENT))
    put = respx.put(url).mock(return_value=Response(200, json={}))
    out = await nmw.update_wan_load_balancing(
        client, registry, "Home UDM", "Default", {"mode": "x"}
    )
    assert not put.called
    assert out["status"] == "dry_run"
    assert out["preview"]["body"] == {**LB_CURRENT, "mode": "x"}
    assert "_verified" not in out


SLAS = [
    {"_id": SLA_ID, "name": "Branch SLA", "thresholds": {"latency": 80, "loss": 2}},
    {"_id": "0000000000000000000000c2", "name": "HQ SLA", "thresholds": {"latency": 40}},
]


@respx.mock
async def test_update_wan_sla_reads_merges_writes_and_verifies(client, registry):
    after = [{**SLAS[0], "thresholds": {"latency": 60, "loss": 2}}, SLAS[1]]
    respx.get(f"{V2}/wan-slas").mock(
        side_effect=[Response(200, json=SLAS), Response(200, json=after)]
    )
    put = respx.put(f"{V2}/wan-slas/{SLA_ID}").mock(return_value=Response(200, json=after[0]))
    out = await nmw.update_wan_sla(
        client, registry, "Home UDM", "Default", SLA_ID, {"thresholds": {"latency": 60}}
    )
    assert _sent(put) == after[0]
    assert out == {**after[0], "_verified": True}


@respx.mock
async def test_update_wan_sla_ignored_change_is_reported_false(client, registry):
    respx.get(f"{V2}/wan-slas").mock(return_value=Response(200, json=SLAS))
    respx.put(f"{V2}/wan-slas/{SLA_ID}").mock(return_value=Response(200, json={}))
    out = await nmw.update_wan_sla(
        client, registry, "Home UDM", "Default", SLA_ID, {"name": "Renamed"}
    )
    assert out["_verified"] is False and out["_unverifiedFields"] == ["name"]


@respx.mock
async def test_update_wan_sla_unknown_id_fails_listing_the_slas(client, registry):
    respx.get(f"{V2}/wan-slas").mock(return_value=Response(200, json={"data": SLAS}))
    put = respx.put(url__startswith=f"{V2}/wan-slas/").mock(return_value=Response(200))
    with pytest.raises(ValueError) as exc:
        await nmw.update_wan_sla(
            client, registry, "Home UDM", "Default", "0000000000000000000000ff", {"name": "x"}
        )
    assert "Branch SLA" in str(exc.value) and "HQ SLA" in str(exc.value)
    assert refusals.classify(str(exc.value)).id == "lookup-miss"
    assert not put.called


@respx.mock
async def test_delete_wan_sla_deletes_the_listed_record(client, registry):
    respx.get(f"{V2}/wan-slas").mock(return_value=Response(200, json=SLAS))
    delete = respx.delete(f"{V2}/wan-slas/{SLA_ID}").mock(return_value=Response(204))
    out = await nmw.delete_wan_sla(client, registry, "Home UDM", "Default", SLA_ID)
    assert delete.called
    assert out == {"deleted": True, "message": f"WAN SLA {SLA_ID!r} deleted.", "response": None}


@respx.mock
async def test_delete_wan_sla_unknown_id_sends_no_delete(client, registry):
    respx.get(f"{V2}/wan-slas").mock(return_value=Response(200, json=[]))
    delete = respx.delete(url__startswith=f"{V2}/wan-slas/").mock(return_value=Response(204))
    with pytest.raises(ValueError, match=r"not found; valid: \(none\)"):
        await nmw.delete_wan_sla(client, registry, "Home UDM", "Default", SLA_ID)
    assert not delete.called


@respx.mock
@pytest.mark.parametrize(
    ("fn", "args", "method", "url"),
    [
        (nmw.update_wan_sla, (SLA_ID, {"name": "x"}), "PUT", f"{V2}/wan-slas/{SLA_ID}"),
        (nmw.create_wan_sla, ({"name": "x"},), "POST", f"{V2}/wan-slas"),
        (nmw.set_lte_failover, ({"enabled": True},), "PUT", f"{V2}/lan/enable-lte-failover"),
    ],
)
async def test_v2_writes_return_the_bare_dry_run_preview(
    monkeypatch, registry, fn, args, method, url
):
    client = _client(monkeypatch, dry_run=True)
    respx.get(f"{V2}/wan-slas").mock(return_value=Response(200, json=SLAS))
    write = respx.route(method=method, url=url).mock(return_value=Response(200, json={}))
    out = await fn(client, registry, "Home UDM", "Default", *args)
    assert not write.called
    assert set(out) == {"status", "dryRun", "sent", "message", "preview"}
    assert out["preview"]["method"] == method and out["preview"]["path"].endswith(
        url.removeprefix(BASE).split("/proxy/network", 1)[1]
    )


@respx.mock
async def test_delete_wan_sla_dry_run_is_the_deletion_result_shape(monkeypatch, registry):
    client = _client(monkeypatch, dry_run=True)
    respx.get(f"{V2}/wan-slas").mock(return_value=Response(200, json=SLAS))
    write = respx.delete(f"{V2}/wan-slas/{SLA_ID}").mock(return_value=Response(200, json={}))
    out = await nmw.delete_wan_sla(client, registry, "Home UDM", "Default", SLA_ID)
    assert not write.called
    assert set(out) == {"status", "deleted", "message", "response"}
    assert out["status"] == "dry_run" and out["deleted"] is False and out["message"]
    assert set(out["response"]) == {"status", "dryRun", "sent", "message", "preview"}
    assert out["response"]["preview"]["method"] == "DELETE"


# --------------------------------------------------------------------------- multi-key


async def _beta_setup(multikey_client, multikey_registry) -> None:
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    multikey_registry.resolve_site_slug = AsyncMock(return_value="default")


@respx.mock
async def test_multikey_v2_read_and_write_ride_the_owning_beta_key(
    multikey_client, multikey_registry
):
    await _beta_setup(multikey_client, multikey_registry)
    v2 = f"{BASE}/v1/connector/consoles/console-beta-1/proxy/network/v2/api/site/default"
    read = respx.get(f"{v2}/routes").mock(return_value=Response(200, json=[]))
    write = respx.post(f"{v2}/wan-slas").mock(return_value=Response(200, json={}))
    await nmw.list_gateway_routes(multikey_client, multikey_registry, "Beta-Branch", "Default")
    await nmw.create_wan_sla(
        multikey_client, multikey_registry, "Beta-Branch", "Default", {"name": "x"}
    )
    assert read.calls[0].request.headers["x-api-key"] == "k-beta"
    assert write.calls[0].request.headers["x-api-key"] == "k-beta"


@respx.mock
async def test_multikey_classic_command_rides_the_owning_beta_key(
    multikey_client, multikey_registry
):
    await _beta_setup(multikey_client, multikey_registry)
    api = f"{BASE}/v1/connector/consoles/console-beta-1/proxy/network/api/s/default"
    devices = respx.get(f"{api}/stat/device-basic").mock(
        return_value=Response(200, json=DEVICE_LIST)
    )
    cmd = respx.post(f"{api}/cmd/lte").mock(return_value=Response(200, json=OK))
    await nmw.verify_sim_pin(
        multikey_client, multikey_registry, "Beta-Branch", "Default", PIN, mac=MAC
    )
    assert devices.calls[0].request.headers["x-api-key"] == "k-beta"
    assert cmd.calls[0].request.headers["x-api-key"] == "k-beta"


async def test_multikey_unknown_host_fails_before_any_data_request(
    multikey_client, multikey_registry
):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    with respx.mock(assert_all_called=False) as mock:
        data = mock.route(path__regex=r".*/proxy/network/.*").mock(return_value=Response(200))
        with pytest.raises(ValueError):
            await nmw.list_wan_slas(
                multikey_client, multikey_registry, "Nowhere-Console", "Default"
            )
        assert not data.called
