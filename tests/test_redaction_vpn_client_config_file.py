"""Public issue #46: the embedded WireGuard client configuration is a credential field.

``list_vpn_clients`` returns the Classic networkconf records. A WireGuard client record
carries its whole ``wireguard_client_configuration_file`` (an ``[Interface]`` block with an
inline ``PrivateKey =`` line and ``[Peer]`` ``PresharedKey =``) under a key no credential
rule matched, so ``UNIFI_REDACT_SECRETS`` left the private key in the text and structured
output. Redaction disabled stays a byte-identical pass-through. Fixtures are synthetic.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import httpx
import pytest

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric import redaction
from unifi_fabric.redaction import REDACTION_MASK, drop_masked_fields, is_credential_field

# Obviously fake values, never a real key.
FAKE_PRIVATE = "SYNTHETIC_PRIVATE_KEY_DO_NOT_USE"
FAKE_PRESHARED = "SYNTHETIC_PRESHARED_KEY_DO_NOT_USE"
CONFIG_FILE = (
    f"[Interface]\nPrivateKey = {FAKE_PRIVATE}\nAddress = 192.0.2.2/32\n"
    f"[Peer]\nPresharedKey = {FAKE_PRESHARED}\nEndpoint = 198.51.100.7:51820\n"
)
CLASSIC = {
    "meta": {"rc": "ok"},
    "data": [
        {
            "_id": "6523f0c1e4b0a1b2c3d4e5f6",
            "name": "Synthetic tunnel",
            "purpose": "vpn-client",
            "vpn_type": "wireguard-client",
            "wireguard_client_configuration_file": CONFIG_FILE,
            "openvpn_configuration": "<key>SYNTHETIC_OPENVPN_KEY</key>",
            "password": "SYNTHETIC_PASSWORD",
            "wireguard_client_private_key": "SYNTHETIC_KEY_CONTROL",
        }
    ],
}


class _Upstream(uh.FakeUpstream):
    def __call__(self, req: httpx.Request) -> httpx.Response:
        response = super().__call__(req)
        if req.method == "GET" and req.url.path.endswith("/rest/networkconf"):
            body = copy.deepcopy(CLASSIC)
            self.served[-1].body = body
            return httpx.Response(200, json=body)
        return response


async def _list(monkeypatch, enabled: bool):
    res = await cti._call(
        monkeypatch,
        "list_vpn_clients",
        _Upstream(),
        args=tool_args.generated_args(cti.TOOLS["list_vpn_clients"]),
        env={"UNIFI_REDACT_SECRETS": "1" if enabled else "0"},
    )
    payload = uh.result_payload(res)
    text = json.dumps(payload) + "".join(getattr(b, "text", "") or "" for b in res.content)
    return payload, text


def test_the_configuration_file_is_a_credential_field():
    for name in ("wireguard_client_configuration_file", "WireGuard_Client_Configuration_File"):
        assert is_credential_field(name), name
    masked = redaction.redact_credentials(copy.deepcopy(CLASSIC))
    row = masked["data"][0]
    assert row["wireguard_client_configuration_file"] == REDACTION_MASK
    assert row["name"] == "Synthetic tunnel" and row["vpn_type"] == "wireguard-client"


@pytest.fixture(scope="module", autouse=True)
def _tool_catalog_ready() -> Any:
    return cti.TOOLS["list_vpn_clients"]


async def test_list_vpn_clients_masks_the_embedded_config_in_every_copy(monkeypatch):
    payload, text = await _list(monkeypatch, True)
    assert FAKE_PRIVATE not in text and FAKE_PRESHARED not in text
    assert "PrivateKey" not in text
    for row in (payload["data"][0], payload["_vpn_clients"][0]):
        assert row["wireguard_client_configuration_file"] == REDACTION_MASK
        # Controls and non-secret fields keep their documented behaviour.
        assert row["openvpn_configuration"] == REDACTION_MASK
        assert row["password"] == REDACTION_MASK
        assert row["wireguard_client_private_key"] == REDACTION_MASK
        assert row["name"] == "Synthetic tunnel" and row["_id"] == "6523f0c1e4b0a1b2c3d4e5f6"


async def test_list_vpn_clients_is_a_verbatim_pass_through_when_redaction_is_off(monkeypatch):
    payload, text = await _list(monkeypatch, False)
    assert payload["data"] == CLASSIC["data"]
    assert payload["_vpn_clients"] == CLASSIC["data"]
    assert REDACTION_MASK not in text and FAKE_PRIVATE in text


def test_a_masked_config_round_tripped_into_a_write_body_is_dropped(monkeypatch):
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    body = {"name": "renamed", "wireguard_client_configuration_file": REDACTION_MASK}
    sent, dropped = drop_masked_fields(body)
    assert sent == {"name": "renamed"}
    assert dropped == ["wireguard_client_configuration_file"]
    monkeypatch.setenv("UNIFI_REDACT_SECRETS", "0")
    assert drop_masked_fields(body) == (body, [])


@pytest.mark.parametrize(
    "name",
    [
        spelling
        for field in ("wireguard_client_configuration_file", "wireguard_client_preshared_key")
        for spelling in (
            field,
            field.upper(),
            field.split("_")[0] + "".join(part.title() for part in field.split("_")[1:]),
            field.replace("_", ""),
        )
    ],
)
def test_every_spelling_of_the_wireguard_client_fields_is_masked(name):
    assert is_credential_field(name)
    body = {"name": "synthetic", name: CONFIG_FILE}
    masked = redaction.redact_credentials(body)
    assert masked[name] == REDACTION_MASK
    assert masked["name"] == "synthetic"


def test_the_configuration_file_is_a_bound_networkconf_route_secret():
    """Logs and the audit log scrub the .conf whatever UNIFI_REDACT_SECRETS says."""
    from unifi_fabric import route_secrets as rs

    path = "network/api/s/default/rest/networkconf/0000000000000000000000aa"
    body = {"name": "synthetic", "wireguard_client_configuration_file": CONFIG_FILE}
    raw = json.dumps(body).encode()
    assert CONFIG_FILE in rs.response_secrets(
        "GET", path, raw, [("content-type", "application/json")]
    )
    assert CONFIG_FILE in rs.request_secrets("PUT", path, body)
