"""Dry-run preview and the redaction opt-in.

The preview shows the caller's own input verbatim; credential fields in it (body and
query) are masked only when ``UNIFI_REDACT_SECRETS`` is on, the same opt-in as every
response and upstream error body. Checked at the client chokepoint for every write verb
and through the MCP layer.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from tests import test_cross_tool_invariants as cti
from tests import tool_args
from tests import upstream_harness as uh
from unifi_fabric.client import UniFiClient, is_dry_run_preview
from unifi_fabric.config import Settings
from unifi_fabric.redaction import REDACTION_MASK

TOOLS = cti.TOOLS
_call = cti._call


@pytest.fixture(autouse=True)
def _quiet_logs():
    logging.disable(logging.CRITICAL)
    yield
    logging.disable(logging.NOTSET)


def _payload(res: Any) -> Any:
    """What a client receives, with FastMCP's ``{"result": ...}`` list wrapper undone."""
    body = uh.result_payload(res)
    if isinstance(body, dict) and set(body) == {"result"}:
        return body["result"]
    return body


# =========================================================================== dry-run preview
_SECRET_BODY = {
    "name": "guest",
    "securityConfiguration": {"type": "WPA2_PERSONAL", "passphrase": "hunter2hunter2"},
    "token": "probe-token-value",
    "x_password": "probe-password",
}
_SECRET_PARAMS = {"password": "probe-query-secret", "force": "true"}
_PATH = "/v1/connector/consoles/H/proxy/network/integration/v1/sites/S/wifi/broadcasts"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_preview_shows_input_verbatim_when_redaction_is_off(method, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = UniFiClient(Settings(api_key="sk-test"))
    body = None if method == "DELETE" else json.loads(json.dumps(_SECRET_BODY))
    resp = await client.request(method, _PATH, json=body, params=dict(_SECRET_PARAMS))
    await client.close()
    out = resp.json()
    assert is_dry_run_preview(out)
    assert out["preview"]["body"] == (None if method == "DELETE" else _SECRET_BODY)
    assert out["preview"]["params"] == _SECRET_PARAMS
    assert REDACTION_MASK not in json.dumps(out)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_preview_masks_credentials_when_redaction_is_on(method, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = UniFiClient(Settings(api_key="sk-test", redact_secrets=True))
    body = None if method == "DELETE" else json.loads(json.dumps(_SECRET_BODY))
    resp = await client.request(method, _PATH, json=body, params=dict(_SECRET_PARAMS))
    await client.close()
    out = resp.json()
    assert out["preview"]["params"] == {"password": REDACTION_MASK, "force": "true"}
    if method != "DELETE":
        sent = out["preview"]["body"]
        assert sent["securityConfiguration"]["passphrase"] == REDACTION_MASK
        assert sent["token"] == REDACTION_MASK and sent["x_password"] == REDACTION_MASK
        assert sent["name"] == "guest"
    for secret in ("hunter2hunter2", "probe-token-value", "probe-password", "probe-query"):
        assert secret not in json.dumps(out)


@pytest.mark.parametrize("redact", [None, "1"], ids=["redaction-unset", "redaction-on"])
async def test_tool_preview_follows_the_redaction_opt_in(monkeypatch, redact):
    """Through the MCP layer: a write tool carrying a credential argument."""
    name = "update_mobility_device_wireless"
    env = {"UNIFI_WRITE_POLICY": "dry-run"}
    if redact is None:
        monkeypatch.delenv("UNIFI_REDACT_SECRETS", raising=False)
    else:
        env["UNIFI_REDACT_SECRETS"] = redact
    args = {**tool_args.generated_args(TOOLS[name]), "ssid": "probe", "password": "pw-12345678"}
    up = uh.FakeUpstream()
    res = await _call(monkeypatch, name, up, args=args, env=env)
    text = json.dumps(uh.result_payload(res))
    assert not up.writes(), "dry-run sent a write"
    if redact is None:
        assert "pw-12345678" in text and REDACTION_MASK not in text
    else:
        assert "pw-12345678" not in text and REDACTION_MASK in text
