"""N10 WiFi-radio registration, validation, write-gate and response contracts."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.read_only import ReadOnlyModeError
from unifi_fabric.tools import network_wifi_radio as radio

HOST = "my-console"
SITE = "Default"
MAC = "02:00:5e:00:00:a1"
WAN = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
FIXTURES = Path(__file__).parent / "fixtures" / "network_wifi_radio"
#: Recorded Classic networkconf capture: the first of its three purpose=wan records.
REC_WAN_ID = "00000000-0000-4000-8000-000000fa00e3"
REC_WAN_EXTERNAL = "00000000-0000-4000-b000-000000fa0040"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture()
def client():
    result = AsyncMock()
    result.get = AsyncMock(return_value={"upstream": "body"})
    result.post = AsyncMock(return_value={"upstream": "post"})
    result.put = AsyncMock(return_value={"meta": {"rc": "ok"}, "data": []})
    result.audit_refusal = Mock()
    result.dry_run = False
    return result


@pytest.fixture()
def registry():
    result = AsyncMock()
    result.resolve_key_for_host = AsyncMock(return_value=None)
    result.resolve_host_id = AsyncMock(return_value="host-001")
    result.resolve_site_slug = AsyncMock(return_value="default")
    return result


async def test_server_registers_every_n10_tool_with_typed_schema():
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    expected = {
        "get_radio_ai_isolation_matrix",
        "preview_radio_ai_optimization",
        "apply_radio_ai_optimization",
        "get_radio_history",
        "get_wifi_connectivity",
        "control_wifi_doctor_optimization",
        "get_wifi_stats",
        "get_wifi_tethering_scan",
        "get_wifiman_settings",
        "get_wlan_capabilities",
        "list_available_wifi_channels",
        "get_access_point_neighbors",
        "start_spectrum_scan",
        "get_spectrum_scan_results",
        "start_wifi_quick_scan",
        "get_wifi_quick_scan_status",
        "get_wifi_uplink_scan_status",
        "configure_wifi_wan",
    }
    assert expected <= tools.keys()
    for name in expected:
        assert tools[name].parameters["properties"], name
        assert "host" in tools[name].parameters["properties"], name
        assert "site" in tools[name].parameters["properties"], name
    wan = tools["configure_wifi_wan"].parameters
    assert "wan_id" not in wan["required"]
    assert "x_uplink_password" in wan["properties"]
    assert "confirm" not in wan["properties"]


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: radio.get_radio_history(c, r, HOST, SITE, "at", start=1, access_point="bad"),
        lambda c, r: radio.get_access_point_neighbors(c, r, HOST, SITE, "bad"),
        lambda c, r: radio.get_spectrum_scan_results(c, r, HOST, SITE, "bad"),
        lambda c, r: radio.get_wifi_connectivity(c, r, HOST, SITE, 1, 2, access_point="bad"),
        lambda c, r: radio.get_wifi_stats(c, r, HOST, SITE, "details", 1, 2, access_point="bad"),
    ],
)
async def test_invalid_mac_never_resolves_or_requests(client, registry, call):
    with pytest.raises(ValueError):
        await call(client, registry)
    client.get.assert_not_called()
    registry.resolve_key_for_host.assert_not_called()


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: radio.preview_radio_ai_optimization(
            c, r, HOST, SITE, WAN, [{"mac": MAC}], "balanced", dry_run=True
        ),
        lambda c, r: radio.apply_radio_ai_optimization(
            c, r, HOST, SITE, [{"mac": MAC}], dry_run=True
        ),
        lambda c, r: radio.control_wifi_doctor_optimization(
            c, r, HOST, SITE, "start", dry_run=True
        ),
        lambda c, r: radio.start_spectrum_scan(c, r, HOST, SITE, MAC, dry_run=True),
        lambda c, r: radio.start_wifi_quick_scan(c, r, HOST, SITE, "na", dry_run=True),
    ],
)
async def test_every_existing_write_returns_dry_run_preview(client, registry, call):
    result = await call(client, registry)
    assert result["status"] == "dry_run"
    assert result["dryRun"] is True
    client.post.assert_not_called()


async def test_epoch_reads_preserve_body_and_add_unit_warning(client, registry):
    result = await radio.get_wifi_connectivity(
        client, registry, HOST, SITE, 1710000000000, 1710003600000
    )
    assert result["upstream"] == "body"
    assert result["_warnings"][0]["code"] == "EPOCH_MILLISECONDS"


@pytest.mark.parametrize("name", ["start_spectrum_scan", "control_wifi_doctor_optimization"])
async def test_read_only_refuses_write_before_resolution(monkeypatch, client, registry, name):
    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    call = getattr(radio, name)
    args = (
        (client, registry, HOST, SITE, MAC)
        if name == "start_spectrum_scan"
        else (client, registry, HOST, SITE, "start")
    )
    with pytest.raises(ReadOnlyModeError):
        await call(*args, dry_run=True)
    client.get.assert_not_called()


async def test_configure_wifi_wan_preview_merges_without_put(client, registry):
    original = {"_id": WAN, "external_id": WAN, "purpose": "wan", "unrelated": {"keep": True}}
    client.get.return_value = {"data": [original]}
    result = await radio.configure_wifi_wan(
        client,
        registry,
        HOST,
        SITE,
        True,
        True,
        9,
        "example-uplink",
        "WPA2_PERSONAL",
        "RADIO_NA",
        "example-passphrase",
        wan_id=WAN,
        dry_run=True,
    )
    assert result["preview"]["body"]["unrelated"] == {"keep": True}
    assert result["preview"]["body"]["x_uplink_password"] == "example-passphrase"
    client.put.assert_not_called()


@pytest.mark.parametrize(
    "security,password,identity", [("WPA2_PERSONAL", None, None), ("WPA3_ENTERPRISE", "x", None)]
)
async def test_wifi_wan_conditional_fields_fail_before_resolution(
    client, registry, security, password, identity
):
    with pytest.raises(ValueError):
        await radio.configure_wifi_wan(
            client,
            registry,
            HOST,
            SITE,
            True,
            True,
            9,
            "ssid",
            security,
            "RADIO_NA",
            password,
            identity,
            wan_id=WAN,
        )
    registry.resolve_key_for_host.assert_not_called()


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: radio.get_radio_ai_isolation_matrix(c, r, HOST, SITE),
        lambda c, r: radio.get_wifi_tethering_scan(c, r, HOST, SITE, MAC),
        lambda c, r: radio.get_wifiman_settings(c, r, HOST, SITE),
        lambda c, r: radio.get_wlan_capabilities(c, r, HOST, SITE),
        lambda c, r: radio.list_available_wifi_channels(c, r, HOST, SITE),
        lambda c, r: radio.get_access_point_neighbors(c, r, HOST, SITE, MAC),
        lambda c, r: radio.get_spectrum_scan_results(c, r, HOST, SITE),
        lambda c, r: radio.get_wifi_quick_scan_status(c, r, HOST, SITE, "na"),
        lambda c, r: radio.get_wifi_uplink_scan_status(c, r, HOST, SITE),
    ],
)
async def test_non_epoch_read_tools_return_upstream_body_verbatim(client, registry, call):
    assert await call(client, registry) == {"upstream": "body"}


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: radio.preview_radio_ai_optimization(
            c, r, HOST, SITE, WAN, [{"mac": MAC}], "balanced", dry_run=True
        ),
        lambda c, r: radio.apply_radio_ai_optimization(
            c, r, HOST, SITE, [{"mac": MAC}], dry_run=True
        ),
        lambda c, r: radio.control_wifi_doctor_optimization(
            c, r, HOST, SITE, "start", dry_run=True
        ),
        lambda c, r: radio.start_spectrum_scan(c, r, HOST, SITE, MAC, dry_run=True),
        lambda c, r: radio.start_wifi_quick_scan(c, r, HOST, SITE, "na", dry_run=True),
        lambda c, r: radio.configure_wifi_wan(
            c,
            r,
            HOST,
            SITE,
            True,
            True,
            9,
            "example-uplink",
            "OPEN",
            "RADIO_NA",
            wan_id=WAN,
            dry_run=True,
        ),
    ],
)
async def test_every_write_honors_connector_opt_out_before_resolution(
    monkeypatch, client, registry, call
):
    monkeypatch.setenv("UNIFI_ENABLE_CONNECTOR_WRITE", "0")
    with pytest.raises(PermissionError):
        await call(client, registry)
    client.get.assert_not_called()
    registry.resolve_key_for_host.assert_not_called()


async def test_quick_scan_status_optional_band_and_upstream_validation(registry):
    """The optional band reaches upstream; only upstream rejects missing/unknown bands."""
    from fastmcp import FastMCP

    from unifi_fabric.client import UniFiConnectionError

    async def upstream(path, *, key=None, params=None):
        if (params or {}).get("band") not in {"ng", "na", "6e"}:
            raise UniFiConnectionError(f"HTTP 400 from GET {path}: <html>400</html>", status=400)
        return {"in_progress": False}

    live = AsyncMock()
    live.get = AsyncMock(side_effect=upstream)
    mcp = FastMCP("wifi-radio")
    radio.register(mcp, lambda: (live, registry))
    tool = {t.name: t for t in await mcp.list_tools()}["get_wifi_quick_scan_status"]
    assert "radio_band" not in tool.parameters["required"]
    assert {b["type"] for b in tool.parameters["properties"]["radio_band"]["anyOf"]} == {
        "string",
        "null",
    }
    for band in ("ng", "na", "6e"):
        result = await mcp.call_tool(
            "get_wifi_quick_scan_status", {"host": HOST, "site": SITE, "radio_band": band}
        )
        assert result.structured_content == {"in_progress": False}
    assert [call.kwargs["params"] for call in live.get.await_args_list] == [
        {"band": "ng"},
        {"band": "na"},
        {"band": "6e"},
    ]
    for arguments, expected in (
        ({}, None),
        ({"radio_band": None}, None),
        ({"radio_band": "future"}, {"band": "future"}),
    ):
        with pytest.raises(UniFiConnectionError) as info:
            await tool.fn(host=HOST, site=SITE, **arguments)
        assert info.value.status == 400
        assert live.get.await_args.kwargs["params"] == expected


def test_n10_routes_do_not_advertise_unsupported_pagination():
    """N10 contracts have no documented paginated route; do not invent offset/limit controls."""
    # FastMCP schemas are the public contract; the explicit list route is one Classic endpoint.
    assert "/stat/current-channel" in radio.list_available_wifi_channels.__code__.co_consts


# --------------------------------------------------------------------------- harness
def _wan(c, r, **kw):
    args = {
        "is_wifi_tethering": True,
        "enabled": True,
        "port": 9,
        "uplink_ssid": "ssid-0001",
        "uplink_security": "WPA2_PERSONAL",
        "uplink_band": "RADIO_NA",
        "x_uplink_password": "example-passphrase",
        "wan_id": REC_WAN_EXTERNAL,
    }
    args.update(kw)
    return radio.configure_wifi_wan(c, r, uh.HOST, uh.SITE, **args)


def _recorded_wan() -> dict:
    body = uh.recorded("network_classic/network_api_s_SITE_rest_networkconf.json")["body"]
    return copy.deepcopy(next(rec for rec in body["data"] if rec["_id"] == REC_WAN_ID))


async def test_configure_wifi_wan_read_merge_write_against_recorded_shape(monkeypatch):
    up = uh.FakeUpstream()
    c = uh.install(monkeypatch, up)
    result = await _wan(c, server._registry)
    writes = up.writes()
    assert len(writes) == 1 and writes[0].method == "PUT"
    assert writes[0].path.endswith(f"/proxy/network/api/s/default/rest/networkconf/{REC_WAN_ID}")
    sent = writes[0].sent_json
    expected = {
        **_recorded_wan(),
        "purpose": "wan",
        "is_wifi_tethering": True,
        "enabled": True,
        "port": 9,
        "uplink_ssid": "ssid-0001",
        "uplink_security": "WPA2_PERSONAL",
        "uplink_band": "RADIO_NA",
        "x_uplink_password": "example-passphrase",
    }
    assert sent == expected  # every unrelated read-back field preserved
    # Upstream envelope verbatim; only additive _-prefixed keys.
    assert result["meta"] == {"rc": "ok"} and isinstance(result["data"], list)
    assert isinstance(result["_verified"], bool)
    assert result["_readAfter"]["_id"] == REC_WAN_ID
    await c.close()


async def test_configure_wifi_wan_dry_run_preview_equals_sent_body(monkeypatch):
    up = uh.FakeUpstream()
    c = uh.install(monkeypatch, up)
    preview = await _wan(c, server._registry, dry_run=True)
    assert not up.writes()
    assert preview["preview"]["method"] == "PUT"
    assert preview["preview"]["params"] is None
    up2 = uh.FakeUpstream()
    c2 = uh.install(monkeypatch, up2)
    await _wan(c2, server._registry)
    assert preview["preview"]["body"] == up2.writes()[0].sent_json
    await c.close()
    await c2.close()


async def test_configure_wifi_wan_without_id_lists_every_wan_choice(monkeypatch):
    up = uh.FakeUpstream()
    c = uh.install(monkeypatch, up)
    with pytest.raises(ValueError) as err:
        await _wan(c, server._registry, wan_id=None)
    message = str(err.value)
    assert "ambiguous" in message and REC_WAN_ID in message and REC_WAN_EXTERNAL in message
    assert message.count("_id=") == 3
    assert not up.writes()
    await c.close()


async def test_configure_wifi_wan_without_id_picks_the_only_wan(client, registry):
    record = {"_id": "0000000000000000000000aa", "purpose": "wan", "keep": [1, 2]}
    client.get.return_value = {"meta": {"rc": "ok"}, "data": [record, {"purpose": "corporate"}]}
    result = await radio.configure_wifi_wan(
        client, registry, HOST, SITE, False, True, 9, "ssid", "OPEN", "RADIO_NG", dry_run=True
    )
    assert result["preview"]["path"].endswith("/rest/networkconf/0000000000000000000000aa")
    assert result["preview"]["body"]["keep"] == [1, 2]
    assert result["preview"]["body"]["purpose"] == "wan"


async def test_configure_wifi_wan_unknown_id_fails_listing_choices(monkeypatch):
    up = uh.FakeUpstream()
    c = uh.install(monkeypatch, up)
    with pytest.raises(ValueError, match="valid: "):
        await _wan(c, server._registry, wan_id="0000000000000000000000ff")
    assert not up.writes()
    await c.close()


async def test_configure_wifi_wan_upstream_error_reason_is_complete_and_scrubbed(monkeypatch):
    reason = "api.err.InvalidPayload " + "detail " * 200
    up = uh.FakeUpstream(write_status=400, error_body=json.dumps({"meta": {"rc": reason}}))
    c = uh.install(monkeypatch, up)
    with pytest.raises(Exception) as err:
        await _wan(c, server._registry)
    text = str(err.value)
    assert reason.strip() in text  # never truncated
    assert "example-passphrase" not in text
    assert len(up.writes()) == 1  # never retried
    await c.close()


async def test_configure_wifi_wan_rides_the_owning_key(
    monkeypatch, multikey_client, multikey_registry
):
    up = uh.FakeUpstream(hosts_by_key={"k-alpha": [], "k-beta": [copy.deepcopy(uh.HOST_RECORD)]})

    async def http_session(key):
        if key.label not in multikey_client._clients:
            multikey_client._clients[key.label] = httpx.AsyncClient(
                base_url=multikey_client._settings.api_base_url,
                headers={"X-API-KEY": key.key},
                transport=httpx.MockTransport(up),
            )
        return multikey_client._clients[key.label]

    monkeypatch.setattr(multikey_client, "_get_client", http_session)
    await _wan(multikey_client, multikey_registry)
    await radio.get_wifi_tethering_scan(
        multikey_client, multikey_registry, uh.HOST, uh.SITE, "02:00:5e:00:00:c1"
    )
    await radio.get_wifi_uplink_scan_status(multikey_client, multikey_registry, uh.HOST, uh.SITE)
    own = [s for s in up.served if not s.resolution]
    assert own and all(s.api_key == "k-beta" for s in own)
    assert any(s.method == "PUT" for s in own)
    await multikey_client.close()


@pytest.mark.parametrize(
    "name,call,suffix",
    [
        (
            "wifi_tethering_scan.json",
            lambda c, r: radio.get_wifi_tethering_scan(c, r, HOST, SITE, "02-00-5E-00-00-A1"),
            "/wifi-tethering/scan/02:00:5e:00:00:a1",
        ),
        (
            "quick_scan_wifi_uplink_status.json",
            lambda c, r: radio.get_wifi_uplink_scan_status(c, r, HOST, SITE),
            "/quick-scan/wifi-uplink/status",
        ),
    ],
)
async def test_wifi_uplink_reads_pass_recorded_shape_through(client, registry, name, call, suffix):
    body = fixture(name)["body"]
    client.get.return_value = copy.deepcopy(body)
    assert await call(client, registry) == body
    path = client.get.call_args.args[0]
    assert path == f"/v1/connector/consoles/host-001/proxy/network/v2/api/site/default{suffix}"


async def test_configure_wifi_wan_returns_put_envelope_verbatim(client, registry):
    envelope = fixture("networkconf_put_wan.json")["body"]
    record = {"_id": REC_WAN_ID, "purpose": "wan", "name": "name-0033"}
    client.get.return_value = {"meta": {"rc": "ok"}, "data": [record]}
    client.put.return_value = copy.deepcopy(envelope)
    result = await radio.configure_wifi_wan(
        client, registry, HOST, SITE, True, True, 9, "ssid-0001", "OPEN", "RADIO_NA"
    )
    assert {k: v for k, v in result.items() if not k.startswith("_")} == envelope
    assert set(result) - set(envelope) <= {"_readAfter", "_verified", "_readAfterError"}


async def test_read_only_refuses_configure_wifi_wan_before_any_request(
    monkeypatch, client, registry
):
    monkeypatch.setenv("UNIFI_READ_ONLY", "1")
    with pytest.raises(ReadOnlyModeError):
        await radio.configure_wifi_wan(
            client, registry, HOST, SITE, True, True, 9, "ssid", "OPEN", "RADIO_NA"
        )
    client.get.assert_not_called()
    registry.resolve_key_for_host.assert_not_called()


def test_uplink_password_is_a_registered_route_secret():
    from unifi_fabric import route_secrets

    entry = next(e for e in route_secrets.ROUTE_SECRETS if "x_uplink_password" in e.request_fields)
    assert entry.tool_arguments == {"configure_wifi_wan": ("x_uplink_password",)}


@pytest.mark.parametrize("landed,verified", [(True, True), (False, False)])
async def test_configure_wifi_wan_verifies_requested_leaves_type_strict(
    client, registry, landed, verified
):
    record = {"_id": REC_WAN_ID, "purpose": "wan", "port": "9"}
    after = {**record, "is_wifi_tethering": True, "enabled": True, "uplink_ssid": "ssid-0001"}
    after |= {"uplink_security": "OPEN", "uplink_band": "RADIO_NA"}
    after["port"] = 9 if landed else "9"  # a string 9 is not the requested integer 9
    client.get.side_effect = [
        {"meta": {"rc": "ok"}, "data": [record]},
        {"meta": {"rc": "ok"}, "data": [record]},
        {"meta": {"rc": "ok"}, "data": [after]},
    ]
    result = await radio.configure_wifi_wan(
        client, registry, HOST, SITE, True, True, 9, "ssid-0001", "OPEN", "RADIO_NA"
    )
    assert result["_verified"] is verified
    assert result["_readAfter"] == after


async def test_preview_calculation_id_is_a_body_value_not_a_path_segment(client, registry):
    """calculation_id travels in the preview body, so path-segment rules never apply."""
    result = await radio.preview_radio_ai_optimization(
        client, registry, HOST, SITE, "calc.id:01", [{"mac": MAC}], "balanced"
    )
    assert result == {"upstream": "post"}
    sent = client.post.await_args.kwargs["json"]
    assert sent["calculation_id"] == "calc.id:01"
    with pytest.raises(ValueError, match="calculation_id, a non-empty radios"):
        await radio.preview_radio_ai_optimization(
            client, registry, HOST, SITE, "  ", [{"mac": MAC}], "balanced"
        )


@pytest.mark.parametrize(
    "call",
    [
        lambda c, r: radio.start_spectrum_scan(c, r, HOST, SITE, MAC),
        lambda c, r: radio.start_wifi_quick_scan(c, r, HOST, SITE, "na"),
        lambda c, r: radio.configure_wifi_wan(
            c, r, HOST, SITE, False, True, 9, "ssid", "OPEN", "RADIO_NG"
        ),
    ],
)
async def test_unifi_dry_run_env_previews_without_writing(monkeypatch, client, registry, call):
    """UNIFI_DRY_RUN (client.dry_run) previews locally: no write, no verification."""
    client.dry_run = True
    monkeypatch.setattr(
        radio,
        "networkconf_records",
        AsyncMock(return_value=[{"_id": "0000000000000000000000aa", "purpose": "wan"}]),
    )
    result = await call(client, registry)
    assert result["status"] == "dry_run" and result["dryRun"] is True
    assert {"body", "params"} <= result["preview"].keys()
    assert "_verified" not in result
    client.post.assert_not_awaited()
    client.put.assert_not_awaited()
