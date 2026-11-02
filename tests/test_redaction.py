"""Opt-in credential redaction (public #26, UNIFI_REDACT_SECRETS).

Redaction is installed at ONE shared point (``install_response_redaction``) that
wraps every registered tool handler, so when the flag is on EVERY tool response is
masked and when off the output is byte-identical. Covers:

* pure ``redact_credentials`` behaviour (explicit field list, nesting, no mutation),
* the shared installer wraps every registered tool (full coverage) and is idempotent,
* an exhaustive payload carrying every documented credential field: nothing escapes
  when enabled, identity when disabled,
* end-to-end through real registered read tools (settings, connector GET, WLAN, WiFi
  broadcast, Dynamic DNS, RADIUS accounts/profiles): nothing escapes on, byte-identity off,
* the suffix and ``x_`` rules across Classic, v2 and integration shapes (nested, in
  lists), non-secret look-alikes, and a classification of every recorded ``x_`` key.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp.tools.function_tool import FunctionTool

from unifi_fabric import server
from unifi_fabric.config import Settings
from unifi_fabric.redaction import (
    CREDENTIAL_FIELDS,
    CREDENTIAL_SUFFIXES,
    REDACTION_MASK,
    X_FIELD_CREDENTIAL_ENDINGS,
    install_response_redaction,
    is_credential_field,
    redact_credentials,
)

SEEDED_WLAN = {
    "data": [
        {
            "_id": "wlan-1",
            "name": "Corp-SSID",
            "enabled": True,
            "security": "wpapsk",
            "x_passphrase": "super-secret-wifi-pw",
            "wpa_mode": "wpa2",
            "vlan": 20,
            "radius_profile": {
                "name": "corp-radius",
                "x_secret": "radius-shared-secret",
                "auth_servers": [{"ip": "10.0.0.5", "x_secret": "server-secret", "port": 1812}],
            },
        }
    ]
}

SEEDED_BROADCAST = {
    "name": "Guest",
    "enabled": True,
    "securityConfiguration": {"securityProtocol": "WPA2", "passphrase": "guest-pass"},
    "broadcastingFrequenciesGHz": [2.4, 5.0],
}


# --------------------------------------------------------------------------- #
# pure redact_credentials
# --------------------------------------------------------------------------- #
def test_redact_masks_documented_fields_and_keeps_others():
    out = redact_credentials(SEEDED_WLAN)
    row = out["data"][0]
    assert row["x_passphrase"] == REDACTION_MASK
    assert row["radius_profile"]["x_secret"] == REDACTION_MASK
    assert row["radius_profile"]["auth_servers"][0]["x_secret"] == REDACTION_MASK
    assert row["name"] == "Corp-SSID"
    assert row["enabled"] is True
    assert row["vlan"] == 20
    assert row["radius_profile"]["auth_servers"][0]["ip"] == "10.0.0.5"
    assert row["radius_profile"]["auth_servers"][0]["port"] == 1812


def test_redact_is_case_insensitive_on_key_name():
    out = redact_credentials({"Password": "pw", "PASSPHRASE": "pp", "Other": "x"})
    assert out["Password"] == REDACTION_MASK
    assert out["PASSPHRASE"] == REDACTION_MASK
    assert out["Other"] == "x"


def test_redact_handles_lists_and_leaves_scalars():
    assert redact_credentials([{"secret": "s"}, {"ok": 1}]) == [
        {"secret": REDACTION_MASK},
        {"ok": 1},
    ]
    assert redact_credentials("plain") == "plain"
    assert redact_credentials(42) == 42


def test_redact_does_not_mutate_input():
    original = json.dumps(SEEDED_WLAN, sort_keys=True)
    _ = redact_credentials(SEEDED_WLAN)
    assert json.dumps(SEEDED_WLAN, sort_keys=True) == original


def test_credential_field_list_is_explicit_and_documented():
    for name in (
        "x_passphrase",
        "x_password",
        "passphrase",
        "password",
        "secret",
        "token",
        "x_private_key",
        "ssh_password",
        "pre_shared_key",
        "api_token",
    ):
        assert name in CREDENTIAL_FIELDS
    # Deliberately NOT in the list — too broad / not inherently a credential.
    assert "key" not in CREDENTIAL_FIELDS
    assert "name" not in CREDENTIAL_FIELDS
    assert "username" not in CREDENTIAL_FIELDS


def test_settings_default_off_and_env_read(monkeypatch):
    assert Settings().redact_secrets is False
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    assert Settings().redact_secrets is True


# --------------------------------------------------------------------------- #
# the shared installer covers EVERY registered tool
# --------------------------------------------------------------------------- #
def _registered_function_tools():
    return [
        c for c in server.mcp._local_provider._components.values() if isinstance(c, FunctionTool)
    ]


def test_every_registered_tool_handler_is_wrapped():
    tools = _registered_function_tools()
    assert len(tools) > 0
    unwrapped = [t.name for t in tools if not getattr(t.fn, "_unifi_redaction_wrapped", False)]
    assert unwrapped == [], f"tools not covered by the shared redaction point: {unwrapped}"


def test_install_is_idempotent():
    # Everything is already wrapped at import, so re-installing wraps nothing new.
    added = install_response_redaction(server.mcp, lambda: False)
    assert added == 0
    assert install_response_redaction(server.mcp, lambda: True) == 0


# --------------------------------------------------------------------------- #
# exhaustive: a payload carrying EVERY documented credential field
# --------------------------------------------------------------------------- #
def _all_fields_payload():
    # Each credential field gets a unique sentinel value; add non-credential fields too.
    secrets = {f: f"example-{f}-value" for f in sorted(CREDENTIAL_FIELDS)}
    return {
        "meta": {"name": "keepme", "count": 7, "nested": {"flag": True}},
        "list": [dict(secrets), {"ok": "stays", **secrets}],
        **secrets,
    }


def test_nothing_escapes_when_enabled():
    payload = _all_fields_payload()
    masked = redact_credentials(payload)
    blob = json.dumps(masked)
    # Not a single sentinel secret value survives anywhere in the output.
    assert "example-" not in blob
    # Every documented field present is masked.
    for f in CREDENTIAL_FIELDS:
        assert masked[f] == REDACTION_MASK
    # Non-credential fields preserved.
    assert masked["meta"] == {"name": "keepme", "count": 7, "nested": {"flag": True}}
    assert masked["list"][1]["ok"] == "stays"


# --------------------------------------------------------------------------- #
# end-to-end through real registered read tools
# --------------------------------------------------------------------------- #
# name, delegate module attr on `server`, delegate function name, run-args
E2E_READ_TOOLS = [
    (
        "get_wlan_config",
        "network_services_proxy",
        "get_wlan_config",
        {"host": "h", "site": "s", "wlan_id": "w"},
    ),
    (
        "get_wifi_broadcast",
        "network",
        "get_wifi_broadcast",
        {"host": "h", "site": "s", "broadcast_id": "b"},
    ),
    (
        "get_dynamic_dns",
        "network_services_proxy",
        "get_dynamic_dns",
        {"host": "h", "site": "s", "ddns_id": "d"},
    ),
    (
        "get_account",
        "network_services_proxy",
        "get_account",
        {"host": "h", "site": "s", "account_id": "a"},
    ),
    (
        "list_radius_profiles",
        "network_services_proxy",
        "list_radius_profiles",
        {"host": "h", "site": "s"},
    ),
    (
        "get_setting",
        "network_services_proxy",
        "get_setting",
        {"host": "h", "site": "s", "setting_key": "mgmt"},
    ),
    ("fabric_connector_get", "connector", "connector_get", {"host": "h", "path": "/stat/health"}),
]

_SECRETFUL = {
    "data": [
        {
            "name": "obj",
            "id": "x1",
            "x_passphrase": "example-pass-value",
            "x_password": "example-pw-value",
            "x_secret": "example-radius-value",
            "ssh_password": "example-ssh-value",
            "private_key": "example-pk-value",
            "pre_shared_key": "example-psk-value",
            "api_token": "example-token-value",
            "vlan": 42,
        }
    ]
}


@pytest.fixture
def _stub_require(monkeypatch):
    monkeypatch.setattr(server, "_require", lambda: (MagicMock(), MagicMock()))


@pytest.mark.parametrize("name,modattr,fnname,args", E2E_READ_TOOLS)
async def test_read_tool_nothing_escapes_when_enabled(
    monkeypatch, _stub_require, name, modattr, fnname, args
):
    monkeypatch.setattr(
        getattr(server, modattr), fnname, AsyncMock(return_value=json.loads(json.dumps(_SECRETFUL)))
    )
    monkeypatch.setattr(server, "_settings", Settings(redact_secrets=True))
    tool = await server.mcp.get_tool(name)
    result = await tool.run(args)
    blob = json.dumps(result.structured_content) + "".join(
        getattr(b, "text", "") for b in result.content
    )
    assert "example-" not in blob, f"{name} leaked a secret when redaction was enabled"
    assert REDACTION_MASK in blob


@pytest.mark.parametrize("name,modattr,fnname,args", E2E_READ_TOOLS)
async def test_read_tool_byte_identical_when_disabled(
    monkeypatch, _stub_require, name, modattr, fnname, args
):
    baseline = json.loads(json.dumps(_SECRETFUL))
    monkeypatch.setattr(
        getattr(server, modattr), fnname, AsyncMock(return_value=json.loads(json.dumps(_SECRETFUL)))
    )
    monkeypatch.setattr(server, "_settings", Settings())  # default OFF
    tool = await server.mcp.get_tool(name)
    result = await tool.run(args)
    assert json.dumps(result.structured_content, sort_keys=True) == json.dumps(
        baseline, sort_keys=True
    )


@pytest.mark.parametrize(
    "name,args",
    [
        ("list_wlan_configs", {"host": "h", "site": "s"}),
        ("get_wlan_config", {"host": "h", "site": "s", "wlan_id": "w"}),
    ],
)
@pytest.mark.parametrize("enabled", [False, True])
async def test_wlan_empty_password_suffix_contract(monkeypatch, _stub_require, name, args, enabled):
    key = "radius_macacl_empty_password"
    payload = {"data": [{key: False}, {key: "synthetic-value"}]}
    assert is_credential_field(key)
    monkeypatch.setattr(server.network_services_proxy, name, AsyncMock(return_value=payload))
    monkeypatch.setattr(server, "_settings", Settings(redact_secrets=enabled))
    result = await (await server.mcp.get_tool(name)).run(args)
    assert result.structured_content == {
        "data": [{key: False}, {key: REDACTION_MASK if enabled else "synthetic-value"}]
    }
    assert payload == {"data": [{key: False}, {key: "synthetic-value"}]}


# --------------------------------------------------------------------------- #
# wrapper internals: sync handler path + tuple recursion + defensive install
# --------------------------------------------------------------------------- #
def test_make_redacting_fn_sync_handler():
    from unifi_fabric.redaction import _make_redacting_fn

    calls = {"n": 0}

    def handler(x):
        calls["n"] += 1
        return {"password": "pw", "keep": x}

    on = _make_redacting_fn(handler, lambda: True)
    off = _make_redacting_fn(handler, lambda: False)
    assert on(5) == {"password": REDACTION_MASK, "keep": 5}
    assert off(7) == {"password": "pw", "keep": 7}
    assert getattr(on, "_unifi_redaction_wrapped", False) is True


def test_redact_tuple_recurses():
    assert redact_credentials(({"secret": "s"}, "keep")) == ({"secret": REDACTION_MASK}, "keep")


def test_install_without_components_refuses_enabled_redaction():
    class Dummy:
        pass

    assert install_response_redaction(Dummy(), lambda: False) == 0
    with pytest.raises(RuntimeError, match="UNIFI_REDACT_SECRETS"):
        install_response_redaction(Dummy(), lambda: True)


# --------------------------------------------------------------------------- #
# Real relay path (no module mock): the connector returns upstream bodies verbatim
# by default and is masked only by the opt-in wrapper. Regression for the relay's
# former unconditional "[REDACTED]" masking.
# --------------------------------------------------------------------------- #
class _Resp:
    def __init__(self, body):
        self.status_code = 200
        self._body = body
        self.text = json.dumps(body)
        self.content = self.text.encode()
        self.headers = {"content-type": "application/json"}

    def json(self):
        return self._body


_RELAY_BODY = {"data": [{"name": "ssid", "x_passphrase": "example-pass-value", "vlan": 7}]}


@pytest.fixture
def _relay(monkeypatch):
    client = MagicMock()
    client.request = AsyncMock(
        side_effect=lambda *a, **k: _Resp(json.loads(json.dumps(_RELAY_BODY)))
    )
    registry = MagicMock()
    registry.resolve_key_for_host = AsyncMock(return_value=None)
    registry.resolve_host_id = AsyncMock(return_value="aabbccddeeff0000:12345")
    registry.resolve_site_slug = AsyncMock(return_value="default")
    registry.resolve_site_id = AsyncMock(return_value="a1b2c3d4-e5f6-7890-abcd-ef1234567890")
    monkeypatch.setattr(server, "_client", client)
    monkeypatch.setattr(server, "_registry", registry)
    return client


_RELAY_CALLS = [
    (
        "fabric_connector_get",
        {"host": "h", "path": "network/api/s/{site}/rest/wlanconf", "site": "s"},
    ),
    (
        "fabric_connector_post",
        {"host": "h", "path": "network/integration/v1/sites/x/wifi/broadcasts", "body": {}},
    ),
]


@pytest.mark.parametrize("name,args", _RELAY_CALLS)
async def test_relay_body_verbatim_when_redaction_unset(monkeypatch, _relay, name, args):
    monkeypatch.setattr(server, "_settings", Settings())  # UNIFI_REDACT_SECRETS unset
    result = await server.mcp.call_tool(name, args)
    assert result.structured_content["body"] == _RELAY_BODY


@pytest.mark.parametrize("name,args", _RELAY_CALLS)
async def test_relay_body_masked_only_when_redaction_enabled(monkeypatch, _relay, name, args):
    monkeypatch.setattr(server, "_settings", Settings(redact_secrets=True))
    result = await server.mcp.call_tool(name, args)
    body = result.structured_content["body"]
    assert body["data"][0]["x_passphrase"] == REDACTION_MASK
    assert body["data"][0]["vlan"] == 7


# --------------------------------------------------------------------------- #
# A masked value fed back into a write is never sent upstream
# --------------------------------------------------------------------------- #


class TestDropMaskedFields:
    @pytest.fixture(autouse=True)
    def enable_write_redaction(self, monkeypatch):
        monkeypatch.setenv("UNIFI_REDACT_SECRETS", "true")

    def test_drops_top_level_nested_and_list_fields(self):
        from unifi_fabric.redaction import drop_masked_fields

        body = {
            "name": "Corp",
            "x_passphrase": REDACTION_MASK,
            "radius_profile": {"x_secret": REDACTION_MASK, "port": 1812},
            "peers": [{"private_key": REDACTION_MASK, "peer": "a"}, "plain"],
        }
        clean, dropped = drop_masked_fields(body)
        assert clean == {
            "name": "Corp",
            "radius_profile": {"port": 1812},
            "peers": [{"peer": "a"}, "plain"],
        }
        assert dropped == ["x_passphrase", "radius_profile.x_secret", "peers[0].private_key"]
        assert body["x_passphrase"] == REDACTION_MASK, "input must not be mutated"

    def test_any_field_with_exact_mask_is_dropped_but_not_lookalikes(self):
        from unifi_fabric.redaction import drop_masked_fields

        body = {"note": REDACTION_MASK, "other": REDACTION_MASK + " ", "x": "***"}
        clean, dropped = drop_masked_fields(body)
        assert clean == {"other": REDACTION_MASK + " ", "x": "***"}
        assert dropped == ["note"]

    def test_body_without_mask_is_returned_unchanged(self):
        from unifi_fabric.redaction import drop_masked_fields

        body = {"a": [1, {"b": "c"}], "d": {"e": None}}
        clean, dropped = drop_masked_fields(body)
        assert clean is body
        assert dropped == []


class TestMaskedFieldsReport:
    @pytest.mark.parametrize("redact", [False, True])
    async def test_wrapper_reports_dropped_paths_on_dict_and_list_results(self, redact):
        from unifi_fabric.redaction import (
            MASKED_FIELDS_KEY,
            _make_redacting_fn,
            drop_and_note_masked_fields,
        )

        async def dict_tool():
            drop_and_note_masked_fields({"x_passphrase": REDACTION_MASK})
            return {"ok": True}

        async def list_tool():
            drop_and_note_masked_fields({"a": {"psk": REDACTION_MASK}})
            return [1, 2]

        async def clean_tool():
            drop_and_note_masked_fields({"name": "n"})
            return {"ok": True}

        enabled = lambda: redact  # noqa: E731
        expected = {"ok": True}
        if redact:
            expected[MASKED_FIELDS_KEY] = ["x_passphrase"]
        assert await _make_redacting_fn(dict_tool, enabled)() == expected
        # Scalar array entries cannot carry additive keys; the array shape is preserved.
        assert await _make_redacting_fn(list_tool, enabled)() == [1, 2]
        assert await _make_redacting_fn(clean_tool, enabled)() == {"ok": True}

    async def test_client_write_path_drops_mask_and_dry_run_preview_shows_clean_body(self):
        from unifi_fabric.client import UniFiClient, is_dry_run_preview

        client = UniFiClient(Settings(api_key="sk-test", dry_run=True, redact_secrets=True))
        body = {"name": "n", "x_passphrase": REDACTION_MASK, "nested": {"psk": REDACTION_MASK}}
        out = await client.put("/v1/connector/consoles/H/proxy/network/x", json=body)
        assert is_dry_run_preview(out)
        assert out["preview"]["body"] == {"name": "n", "nested": {}}
        await client.close()

    def test_mask_drop_is_documented(self):
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        readme = (root / "docs" / "CONFIGURATION.md").read_text()
        assert "_redactedFieldsNotSent" in readme
        changelog = (root / "CHANGELOG.md").read_text()
        section = changelog.split("## [0.7.0]", 1)[1].split("\n## [", 1)[0]
        assert "_redactedFieldsNotSent" in section


# --------------------------------------------------------------------------- #
# Opt-in suffix and x_ rules (rules 2 and 3): google_maps_api_key and every other
# suffix / x_ credential is verbatim by default and masked only when opted in, in
# Classic, v2 and integration shapes, nested and in lists. Look-alikes stay verbatim.
# --------------------------------------------------------------------------- #

#: Keys matched only by the suffix rule or the x_ rule (none is in CREDENTIAL_FIELDS).
PATTERN_SECRETS = {
    "google_maps_api_key": "example-gmaps-key-value",
    "Openweather_API_KEY": "example-weather-key-value",
    "utm_token": "example-utm-token-value",
    "guest_token": "example-guest-token-value",
    "ddns_password": "example-ddns-pw-value",
    "client_secret": "example-client-secret-value",
    "hotspot_passphrase": "example-hotspot-pp-value",
    "x_authkey": "example-authkey-value",
    "x_inform_authkey": "example-inform-authkey-value",
    "x_vwirekey": "example-vwire-value",
    "x_mgmt_key": "example-mgmt-key-value",
    "x_pregenerated_dh_key": "example-dh-value",
    "x_stripe_api_key": "example-stripe-value",
    "x_quickpay_apikey": "example-quickpay-value",
    "x_merchantwarrior_apikey": "example-mw-key-value",
    "x_merchantwarrior_apipassphrase": "example-mw-pp-value",
    "x_authorize_transactionkey": "example-authorize-value",
    "x_element_psk": "example-element-psk-value",
    "x_paypal_password": "example-paypal-pw-value",
    "x_paypal_signature": "example-paypal-sig-value",
    "x_ssh_sha512passwd": "example-sha512-value",
    "x_sso_token": "example-sso-value",
    # VPN clients (r18 list_vpn_clients / create_vpn_client dry-run)
    "wireguard_private_key": "example-wg-plain-pk-value",
    "Peer_Private_Key": "example-peer-plain-pk-value",
}

#: The VPN-client credentials c0a512ef also lists explicitly in CREDENTIAL_FIELDS (so
#: they are masked whichever rule matches): kept out of PATTERN_SECRETS, which proves the
#: pattern rules alone.
EXPLICIT_VPN_SECRETS = {
    "x_wireguard_private_key": "example-wg-pk-value",
    "x_openvpn_password": "example-openvpn-pw-value",
}

#: Non-secret look-alikes: never masked, with or without the opt-in.
LOOKALIKES = {
    "token_count": 3,
    "token_count_label": "three",
    "key_id": "kid-1",
    "api_key_id": "akid-1",
    "secret_santa_mode": True,
    "secret_santa_mode_label": "on",
    "password_enabled": True,
    "passphrase_autogenerated": False,
    "profileToken": "profile-token-0",
    "digitalInputTokens": ["digital-input-0"],
    "regularAdminLongTermToken": True,
    "supportAPIKeysMigration": True,
    "public_key": "public-key-material",
    # suffix match but not a string: a setting flag, never a credential
    "radius_macacl_empty_password": False,
    "session_token": None,
    "max_password": 64,
    # x_ fields that are identifiers, flags or public material
    "x_ssh_username": "admin",
    "x_paypal_username": "merchant@example.invalid",
    "x_quickpay_merchantid": "m-1",
    "x_authorize_loginid": "login-1",
    "x_mesh_essid": "mesh-ssid",
    "x_ssh_enabled": True,
    "x_ssh_auth_password_enabled": True,
    "x_aes_gcm": False,
    "x_has_ssh_hostkey": True,
    "x_ssh_hostkey_fingerprint": "aa:bb:cc",
    "x_certificate_pem": "-----BEGIN CERTIFICATE-----",
    "x_certificate_arn": "arn:aws:iot:example",
    "x_ssh_keys": ["ssh-ed25519 AAAA public"],
}


def _record(i: int) -> dict:
    return {
        "_id": f"obj-{i}",
        "name": f"obj-{i}",
        "server_certificate_key": "example-server-cert-key",
        "sso_app_id": "sso-app-id-0001",
        "syslog_key": "example-syslog-key",
        **PATTERN_SECRETS,
        **EXPLICIT_VPN_SECRETS,
        **LOOKALIKES,
        # a pattern key holding an object is recursed into, not masked wholesale
        "portal_token": {"ttl": 60, "x_secret": "example-nested-x-secret"},
        "nested": {"peers": [{"x_wireguard_private_key": "example-peer-pk", "port": 51820}]},
    }


# The three upstream response shapes the server relays.
SHAPES = {
    "classic": {"meta": {"rc": "ok"}, "data": [_record(0), _record(1)]},
    "v2": [_record(0), _record(1)],
    "integration": {
        "offset": 0,
        "limit": 25,
        "count": 2,
        "totalCount": 2,
        "data": [_record(0), _record(1)],
    },
}


def _records_of(shape):
    return shape if isinstance(shape, list) else shape["data"]


def _assert_masked(shape):
    blob = json.dumps(shape)
    assert "example-" not in blob, blob
    for row in _records_of(shape):
        assert row["server_certificate_key"] == REDACTION_MASK
        assert row["syslog_key"] == REDACTION_MASK
        assert row["sso_app_id"] == "sso-app-id-0001"
        for key in (*PATTERN_SECRETS, *EXPLICIT_VPN_SECRETS):
            assert row[key] == REDACTION_MASK, key
        for key, value in LOOKALIKES.items():
            assert row[key] == value, key
        assert row["portal_token"] == {"ttl": 60, "x_secret": REDACTION_MASK}
        assert row["nested"]["peers"][0] == {
            "x_wireguard_private_key": REDACTION_MASK,
            "port": 51820,
        }


def test_pattern_keys_are_not_in_the_explicit_list():
    # Proves the suffix and x_ rules (not the explicit list) are what mask these keys.
    assert not {k.lower() for k in PATTERN_SECRETS} & CREDENTIAL_FIELDS
    assert all(is_credential_field(k) for k in PATTERN_SECRETS)
    assert set(CREDENTIAL_SUFFIXES) == {
        "_api_key",
        "_private_key",
        "_secret",
        "_token",
        "_password",
        "_passphrase",
    }
    assert "key" in X_FIELD_CREDENTIAL_ENDINGS


@pytest.mark.parametrize("shape_name", sorted(SHAPES))
def test_pattern_rules_mask_every_shape_when_enabled(shape_name):
    shape = SHAPES[shape_name]
    before = json.dumps(shape, sort_keys=True)
    _assert_masked(redact_credentials(shape))
    assert json.dumps(shape, sort_keys=True) == before, "input must not be mutated"


@pytest.mark.parametrize("shape_name", sorted(SHAPES))
@pytest.mark.parametrize("env", [None, "0", "false"], ids=["unset", "zero", "false"])
async def test_pattern_fields_verbatim_by_default(monkeypatch, _relay, shape_name, env):
    """Default mode through the real relay: google_maps_api_key and every look-alike."""
    if env is None:
        monkeypatch.delenv("UNIFI_REDACT_SECRETS", raising=False)
    else:
        monkeypatch.setenv("UNIFI_REDACT_SECRETS", env)
    shape = SHAPES[shape_name]
    _relay.request = AsyncMock(side_effect=lambda *a, **k: _Resp(json.loads(json.dumps(shape))))
    monkeypatch.setattr(server, "_settings", Settings())
    result = await server.mcp.call_tool(
        "fabric_connector_get",
        {"host": "h", "path": "network/api/s/{site}/rest/setting", "site": "s"},
    )
    body = result.structured_content["body"]
    assert body == shape
    first_record = _records_of(body)[0]
    assert first_record["google_maps_api_key"] == "example-gmaps-key-value"
    assert first_record["server_certificate_key"] == "example-server-cert-key"
    assert first_record["syslog_key"] == "example-syslog-key"
    assert first_record["sso_app_id"] == "sso-app-id-0001"


@pytest.mark.parametrize("shape_name", sorted(SHAPES))
async def test_pattern_fields_masked_through_relay_when_opted_in(monkeypatch, _relay, shape_name):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    shape = SHAPES[shape_name]
    _relay.request = AsyncMock(side_effect=lambda *a, **k: _Resp(json.loads(json.dumps(shape))))
    monkeypatch.setattr(server, "_settings", Settings())
    result = await server.mcp.call_tool(
        "fabric_connector_get",
        {"host": "h", "path": "network/api/s/{site}/rest/setting", "site": "s"},
    )
    body = result.structured_content["body"]
    _assert_masked(body)
    first_record = _records_of(body)[0]
    assert first_record["server_certificate_key"] == REDACTION_MASK
    assert first_record["syslog_key"] == REDACTION_MASK
    assert first_record["sso_app_id"] == "sso-app-id-0001"
    text = "".join(getattr(b, "text", "") for b in result.content)
    assert "example-" not in text


@pytest.mark.parametrize("name,modattr,fnname,args", E2E_READ_TOOLS)
@pytest.mark.parametrize("enabled", [False, True], ids=["off", "on"])
async def test_pattern_fields_through_typed_read_tools(
    monkeypatch, _stub_require, name, modattr, fnname, args, enabled
):
    payload = SHAPES["classic"]
    monkeypatch.setattr(
        getattr(server, modattr), fnname, AsyncMock(return_value=json.loads(json.dumps(payload)))
    )
    monkeypatch.setattr(server, "_settings", Settings(redact_secrets=enabled))
    result = await (await server.mcp.get_tool(name)).run(args)
    if enabled:
        _assert_masked(result.structured_content)
    else:
        assert json.dumps(result.structured_content, sort_keys=True) == json.dumps(
            payload, sort_keys=True
        )


# Every x_ key in the recorded real-response fixtures, classified. A new recorded x_
# key fails here until it is placed in one of the two sets (with a reason in the
# redaction module docstring for X_FIELD_CREDENTIAL_ENDINGS).
RECORDED_X_MASKED = {
    "x_api_token",
    "x_authkey",
    "x_authorize_transactionkey",
    "x_element_psk",
    "x_iapp_key",
    "x_inform_authkey",
    "x_merchantwarrior_apikey",
    "x_merchantwarrior_apipassphrase",
    "x_mesh_psk",
    "x_mgmt_key",
    "x_passphrase",
    "x_password",
    "x_paypal_password",
    "x_paypal_signature",
    "x_pregenerated_dh_key",
    "x_private_key",
    "x_quickpay_apikey",
    "x_secret",
    "x_ssh_password",
    "x_ssh_sha512passwd",
    "x_sso_token",
    "x_stripe_api_key",
    "x_vwirekey",
    "x_wireguard_private_key",
}
RECORDED_X_VERBATIM = {
    "x_aes_gcm",
    "x_authorize_loginid",
    "x_certificate_arn",
    "x_certificate_pem",
    "x_element_essid",
    "x_has_ssh_hostkey",
    "x_ippay_terminalid",
    "x_merchantwarrior_merchantuuid",
    "x_mesh_essid",
    "x_paypal_username",
    "x_quickpay_agreementid",
    "x_quickpay_merchantid",
    "x_ssh_auth_password_enabled",
    "x_ssh_bind_wildcard",
    "x_ssh_enabled",
    "x_ssh_hostkey_fingerprint",
    "x_ssh_keys",
    "x_ssh_username",
}

_RECORDED = Path(__file__).resolve().parent / "fixtures" / "recorded"


def _recorded_bodies():
    for path in sorted(_RECORDED.rglob("*.json")):
        doc = json.loads(path.read_text())
        if isinstance(doc, dict) and "body" in doc:
            yield path, doc["body"]


def _walk_keys(node, out):
    if isinstance(node, dict):
        for key, value in node.items():
            out.append((key, value))
            _walk_keys(value, out)
    elif isinstance(node, list):
        for item in node:
            _walk_keys(item, out)


def test_every_recorded_x_key_is_classified():
    pairs: list = []
    for _path, body in _recorded_bodies():
        _walk_keys(body, pairs)
    seen = {k for k, _v in pairs if isinstance(k, str) and k.lower().startswith("x_")}
    assert seen, "recorded fixtures must contain x_ keys"
    assert RECORDED_X_MASKED.isdisjoint(RECORDED_X_VERBATIM)
    assert seen <= RECORDED_X_MASKED | RECORDED_X_VERBATIM, sorted(
        seen - RECORDED_X_MASKED - RECORDED_X_VERBATIM
    )
    assert {k for k in RECORDED_X_MASKED if is_credential_field(k)} == RECORDED_X_MASKED
    assert {k for k in RECORDED_X_VERBATIM if is_credential_field(k)} == set()


def test_recorded_fixtures_masked_only_on_classified_keys():
    """Real recorded bodies: opt-in masks exactly the credential keys, nothing else."""
    bodies = list(_recorded_bodies())
    assert bodies
    for path, body in bodies:
        masked = redact_credentials(body)
        before: list = []
        after: list = []
        _walk_keys(body, before)
        _walk_keys(masked, after)
        assert len(before) == len(after), path
        for (key, value), (key2, value2) in zip(before, after, strict=True):
            assert key == key2
            lowered = key.lower() if isinstance(key, str) else key
            empty = value is None or value == ""
            if lowered in CREDENTIAL_FIELDS and empty:
                # an exact-name field with nothing in it is left as is
                assert value2 == value, (path.name, key)
            elif lowered in CREDENTIAL_FIELDS or (
                isinstance(value, str) and lowered in RECORDED_X_MASKED
            ):
                assert value2 == REDACTION_MASK, (path.name, key)
            elif lowered in RECORDED_X_VERBATIM or lowered in {
                "google_maps_api_key",
                "utm_token",
                "guest_token",
            }:
                if lowered in RECORDED_X_VERBATIM:
                    assert value2 == value, (path.name, key)
                else:
                    assert value2 == (REDACTION_MASK if isinstance(value, str) else value)
            elif not isinstance(value, dict | list):
                assert value2 == value, (path.name, key)


def test_recorded_google_maps_api_key_default_verbatim_and_opt_in_masked():
    body = json.loads(
        (_RECORDED / "network_classic" / "network_api_s_SITE_stat_sysinfo.json").read_text()
    )["body"]
    pairs: list = []
    _walk_keys(body, pairs)
    values = [v for k, v in pairs if k == "google_maps_api_key"]
    assert values and all(isinstance(v, str) for v in values)
    masked: list = []
    _walk_keys(redact_credentials(body), masked)
    assert [v for k, v in masked if k == "google_maps_api_key"] == [REDACTION_MASK] * len(values)


def test_server_certificate_key_opt_in_masked_and_default_verbatim_unit():
    raw = {"server_certificate_key": "private-key-material-xxxx"}
    assert is_credential_field("server_certificate_key") is True
    # Default (pass-through / verbatim)
    assert raw["server_certificate_key"] == "private-key-material-xxxx"
    # Opt-in masked
    masked = redact_credentials(raw)
    assert masked == {"server_certificate_key": REDACTION_MASK}


def test_recorded_radius_server_certificate_key_default_verbatim_and_opt_in_masked():
    path = _RECORDED / "network_classic" / "network_api_s_SITE_rest_setting.json"
    doc = json.loads(path.read_text())
    body = doc["body"]
    pairs: list = []
    _walk_keys(body, pairs)
    # Find the radius record entries
    key_values = [v for k, v in pairs if k == "server_certificate_key"]
    assert key_values and all(isinstance(v, str) for v in key_values)
    # Verify default verbatim on recorded body
    assert all(v == "xxxxxxxx" for v in key_values)
    # Verify opt-in masked
    masked: list = []
    _walk_keys(redact_credentials(body), masked)
    masked_key_values = [v for k, v in masked if k == "server_certificate_key"]
    assert masked_key_values == [REDACTION_MASK] * len(key_values)


def test_sso_app_id_canary_allowlist_verbatim_in_both_modes():
    assert is_credential_field("sso_app_id") is False
    data = {"sso_app_id": "sso-app-id-0001"}
    # Verbatim in default mode
    assert data["sso_app_id"] == "sso-app-id-0001"
    # Verbatim under opt-in redaction
    assert redact_credentials(data) == {"sso_app_id": "sso-app-id-0001"}
    # Also verify in recorded sysinfo fixture
    path = _RECORDED / "network_classic" / "network_api_s_SITE_stat_sysinfo.json"
    doc = json.loads(path.read_text())
    body = doc["body"]
    pairs: list = []
    _walk_keys(body, pairs)
    sso_values = [v for k, v in pairs if k == "sso_app_id"]
    assert sso_values == ["sso-app-id-0001"]
    masked_pairs: list = []
    _walk_keys(redact_credentials(body), masked_pairs)
    assert [v for k, v in masked_pairs if k == "sso_app_id"] == ["sso-app-id-0001"]


# --------------------------------------------------------------------------- #
# VPN client credentials (NET-B list_vpn_clients / create_vpn_client): the WireGuard
# private key and OpenVPN password are verbatim by default and masked under the
# opt-in, in list results and in a write's dry-run preview.
# --------------------------------------------------------------------------- #
_VPN_CLIENTS = {
    "meta": {"rc": "ok"},
    "data": [
        {
            "_id": "vpnc-1",
            "name": "wg-client",
            "vpn_type": "wireguard-client",
            "x_wireguard_private_key": "example-wg-client-pk",
            "wireguard_private_key": "example-wg-client-plain-pk",
            "wireguard_public_key": "public-key-stays",
            "peers": [{"x_wireguard_private_key": "example-wg-peer-pk", "port": 51820}],
        },
        {
            "_id": "vpnc-2",
            "name": "ovpn-client",
            "vpn_type": "openvpn-client",
            "x_openvpn_password": "example-ovpn-pw",
            "openvpn_username": "ovpn-user",
        },
    ],
}
_VPN_SECRET_KEYS = ("x_wireguard_private_key", "wireguard_private_key", "x_openvpn_password")


def _vpn_secret_values(node, out):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _VPN_SECRET_KEYS:
                out.append(value)
            _vpn_secret_values(value, out)
    elif isinstance(node, list):
        for item in node:
            _vpn_secret_values(item, out)
    return out


@pytest.mark.parametrize("enabled", [False, True], ids=["off", "on"])
async def test_vpn_client_list_credentials_follow_opt_in(monkeypatch, _relay, enabled):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1" if enabled else "0")
    _relay.request = AsyncMock(
        side_effect=lambda *a, **k: _Resp(json.loads(json.dumps(_VPN_CLIENTS)))
    )
    monkeypatch.setattr(server, "_settings", Settings())
    result = await server.mcp.call_tool(
        "fabric_connector_get",
        {"host": "h", "path": "network/api/s/{site}/rest/networkconf", "site": "s"},
    )
    body = result.structured_content["body"]
    values = _vpn_secret_values(body, [])
    assert len(values) == 4
    if enabled:
        assert values == [REDACTION_MASK] * 4
        assert "example-" not in json.dumps(body)
        assert body["data"][0]["wireguard_public_key"] == "public-key-stays"
        assert body["data"][1]["openvpn_username"] == "ovpn-user"
        assert body["data"][0]["peers"][0]["port"] == 51820
    else:
        assert body == _VPN_CLIENTS


@pytest.mark.parametrize("enabled", [False, True], ids=["off", "on"])
async def test_vpn_client_create_dry_run_preview_follows_opt_in(enabled):
    from unifi_fabric.client import UniFiClient, is_dry_run_preview

    client = UniFiClient(Settings(api_key="sk-test", dry_run=True, redact_secrets=enabled))
    body = {
        "name": "wg-client",
        "x_wireguard_private_key": "example-wg-create-pk",
        "x_openvpn_password": "example-ovpn-create-pw",
        "wireguard_private_key": "example-wg-create-plain-pk",
        "wireguard_public_key": "public-key-stays",
    }
    out = await client.post(
        "/v1/connector/consoles/H/proxy/network/api/s/default/rest/networkconf", json=body
    )
    await client.close()
    assert is_dry_run_preview(out)
    preview = out["preview"]["body"]
    if enabled:
        assert _vpn_secret_values(preview, []) == [REDACTION_MASK] * 3
        assert preview["wireguard_public_key"] == "public-key-stays"
        assert "example-" not in json.dumps(out)
    else:
        assert preview == body


def test_camel_case_credential_fields_are_opt_in_masked() -> None:
    names = (
        "sharedSecret",
        "authServerSecret",
        "wanPassword",
        "wireguardPrivateKey",
        "clientSecret",
        "bearerToken",
        "apiToken",
        "accessToken",
        "refreshToken",
        "radiusSecret",
        "pppoePassword",
        "sshPassword",
    )
    original = {name: "secret-value" for name in names}
    assert redact_credentials(original) == {name: REDACTION_MASK for name in names}
    assert original == {name: "secret-value" for name in names}


def test_camelcase_and_x_alias_credential_fields_are_masked() -> None:
    keys = (
        "sharedSecret",
        "authServerSecret",
        "wanPassword",
        "wireguardPrivateKey",
        "clientSecret",
        "bearerToken",
        "apiToken",
        "accessToken",
        "refreshToken",
        "radiusSecret",
        "pppoePassword",
        "sshPassword",
        "x_bearer_token",
        "x_shared_secret",
        "x_client_secret",
    )
    payload = {key: key for key in keys} | {"x_has_password": True}
    masked = redact_credentials(payload)
    assert all(masked[key] == REDACTION_MASK for key in keys)
    assert masked["x_has_password"] is True


# --------------------------------------------------------------------------- #
# Code review of swkstudios/unifi-fabric-mcp-server#37 and swkstudios/unifi-fabric-mcp-server#38:
# camelCase credential names (string values only),
# pagination cursors exempt from the _token suffix rule, null/empty exact-name values
# left as is, and x_ identifiers that are never masked.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "key", ["acctServerSecret", "authToken", "hashedPassword", "wpaPsk", "wpa_psk"]
)
def test_camel_case_credential_names_mask_string_values(key):
    masked = redact_credentials({key: "s3cret-value", "name": "kept"})
    assert masked == {key: REDACTION_MASK, "name": "kept"}
    assert is_credential_field(key)


@pytest.mark.parametrize("key", ["acctServerSecret", "authToken", "hashedPassword", "wpaPsk"])
@pytest.mark.parametrize("value", [True, 7, {"nested": "x"}, ["x"]])
def test_camel_case_credential_names_leave_non_string_values(key, value):
    assert redact_credentials({key: value}) == {key: value}


@pytest.mark.parametrize(
    "key",
    [
        "nextToken",
        "next_token",
        "pageToken",
        "page_token",
        "continuation_token",
        "continuationToken",
    ],
)
def test_pagination_cursors_are_never_masked(key):
    payload = {key: "page-cursor-not-a-secret", "data": [{"id": 1}]}
    assert redact_credentials(payload) == payload
    assert not is_credential_field(key)
    # other _token keys still follow the suffix rule
    assert redact_credentials({"utm_token": "abc"}) == {"utm_token": REDACTION_MASK}


@pytest.mark.parametrize("key", ["x_passphrase", "password", "token", "psk", "wpa_psk", "secret"])
@pytest.mark.parametrize("value", [None, ""])
def test_exact_name_with_null_or_empty_value_is_left_as_is(key, value):
    assert redact_credentials({key: value}) == {key: value}


@pytest.mark.parametrize("key", ["x_passphrase", "password", "psk"])
@pytest.mark.parametrize("value", ["v", 0, False, ["x"], {"a": 1}, [], {}])
def test_exact_name_with_a_value_is_still_masked_whatever_its_type(key, value):
    assert redact_credentials({key: value}) == {key: REDACTION_MASK}


@pytest.mark.parametrize(
    "key", ["x_ssh_username", "x_certificate_pem", "x_wan_ip", "x_mac", "x_name"]
)
def test_x_identifier_fields_are_never_masked(key):
    payload = {key: "value-kept-verbatim"}
    assert redact_credentials(payload) == payload
    assert not is_credential_field(key)


async def test_dry_run_preview_says_nothing_was_sent_and_keeps_the_key_label():
    from unifi_fabric.client import DRY_RUN_MESSAGE, UniFiClient, is_dry_run_preview
    from unifi_fabric.config import APIKeyConfig

    key = APIKeyConfig(key="sk-alpha", label="alpha")
    client = UniFiClient(Settings(api_keys=[key], dry_run=True))
    out = await client.put("/v1/connector/consoles/H/proxy/network/x", key=key, json={"a": 1})
    assert is_dry_run_preview(out)
    assert out["status"] == "dry_run" and out["dryRun"] is True and out["sent"] is False
    assert out["message"] == DRY_RUN_MESSAGE
    assert out["preview"]["keyLabel"] == "alpha"
    assert out["preview"]["body"] == {"a": 1}
    await client.close()


@pytest.mark.parametrize("enabled", [False, True])
def test_mask_literal_is_a_value_unless_redaction_is_explicitly_enabled(monkeypatch, enabled):
    from unifi_fabric.redaction import drop_masked_fields

    monkeypatch.setenv("UNIFI_REDACT_SECRETS", str(enabled))
    body = {"note": REDACTION_MASK, "nested": [{"password": REDACTION_MASK}]}
    clean, dropped = drop_masked_fields(body)
    assert clean == ({"nested": [{}]} if enabled else body)
    assert dropped == (["note", "nested[0].password"] if enabled else [])
    if not enabled:
        assert clean is body


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("async_handler", [False, True])
async def test_tool_setting_controls_write_masks_and_restores_context(
    monkeypatch, enabled, async_handler
):
    from unifi_fabric.redaction import (
        MASKED_FIELDS_KEY,
        _make_redacting_fn,
        drop_and_note_masked_fields,
        write_redaction_enabled,
    )

    monkeypatch.setenv("UNIFI_REDACT_SECRETS", str(not enabled))
    body = {"note": REDACTION_MASK}

    def sync_tool():
        return drop_and_note_masked_fields(body)

    async def async_tool():
        return sync_tool()

    result = _make_redacting_fn(async_tool if async_handler else sync_tool, lambda: enabled)()
    if async_handler:
        result = await result
    assert result == ({MASKED_FIELDS_KEY: ["note"]} if enabled else body)
    assert write_redaction_enabled() is not enabled


@pytest.mark.parametrize("enabled", [False, True])
async def test_redaction_middleware_binds_setting_before_handler_and_restores_it(
    monkeypatch, enabled
):
    from types import SimpleNamespace

    from unifi_fabric.redaction import RedactionScopeMiddleware, write_redaction_enabled

    monkeypatch.setenv("UNIFI_REDACT_SECRETS", str(not enabled))

    async def next_call(context):
        assert write_redaction_enabled() is enabled
        raise RuntimeError("synthetic handler failure")

    middleware = RedactionScopeMiddleware(lambda: enabled)
    with pytest.raises(RuntimeError, match="synthetic handler failure"):
        await middleware.on_call_tool(SimpleNamespace(), next_call)
    assert write_redaction_enabled() is not enabled
