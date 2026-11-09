"""Shared Classic command helper: local validation first, affirmative meta.rc success."""

from __future__ import annotations

import json
import math

import pytest
import respx
from httpx import Response

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings
from unifi_fabric.tools import _classic_cmd as cc

BASE = "https://api.ui.com"
HOST = "A1B2C3:12345"
URL = f"{BASE}/v1/connector/consoles/{HOST}/proxy/network/api/s/default/cmd/devmgr"


@pytest.fixture
def client(monkeypatch) -> UniFiClient:
    for var in ("UNIFI_WRITE_POLICY", "UNIFI_WRITE_EXCEPTIONS", "UNIFI_REDACT_SECRETS"):
        monkeypatch.delenv(var, raising=False)
    return UniFiClient(Settings(api_key="sk-test"))


def test_body_is_cmd_plus_params():
    assert cc.classic_command_body("set-locate", {"mac": "00:00:00:00:00:00"}) == {
        "cmd": "set-locate",
        "mac": "00:00:00:00:00:00",
    }
    assert cc.classic_command_body("list-backups") == {"cmd": "list-backups"}


@pytest.mark.parametrize(
    ("cmd", "params"),
    [
        ("", None),
        ("Set-Locate", None),
        ("set locate", None),
        (None, None),
        ("set-locate", {"cmd": "restart"}),
        ("set-locate", ["mac"]),
        ("set-locate", {"x": math.nan}),
        ("set-locate", {"x": [math.inf]}),
        ("set-locate", {"x": {1: "a"}}),
        ("set-locate", {"x": object()}),
    ],
)
def test_invalid_body_raises(cmd, params):
    with pytest.raises(ValueError):
        cc.classic_command_body(cmd, params)


@pytest.mark.parametrize("manager", ["", "DEVMGR", "dev mgr", "devmgr/", "a/b/c", "../x", None])
def test_invalid_manager_raises(manager):
    with pytest.raises(ValueError):
        cc.validate_manager(manager)


@pytest.mark.parametrize(
    "manager", ["devmgr", "stamgr", "devmgr/port-locate", "productinfo/refresh-sso"]
)
def test_valid_managers(manager):
    assert cc.validate_manager(manager) == manager


@respx.mock
@pytest.mark.parametrize(
    ("host", "site", "manager", "cmd", "params"),
    [
        ("bad/host", "default", "devmgr", "set-locate", None),
        (HOST, "..", "devmgr", "set-locate", None),
        (HOST, "default", "Dev", "set-locate", None),
        (HOST, "default", "devmgr", "", None),
        (HOST, "default", "devmgr", "set-locate", {"cmd": "x"}),
    ],
)
async def test_invalid_input_makes_no_request(client, host, site, manager, cmd, params):
    route = respx.route().mock(return_value=Response(200, json={"meta": {"rc": "ok"}}))
    with pytest.raises(ValueError):
        await cc.classic_command(client, host, site, manager, cmd, params)
    assert not route.called


@respx.mock
async def test_success_requires_rc_ok(client):
    route = respx.post(URL).mock(
        return_value=Response(200, json={"meta": {"rc": "ok"}, "data": [{"a": 1}]})
    )
    out = await cc.classic_command(client, HOST, "default", "devmgr", "set-locate", {"mac": "m"})
    assert out == {"meta": {"rc": "ok"}, "data": [{"a": 1}]}
    assert json.loads(route.calls[0].request.content) == {"cmd": "set-locate", "mac": "m"}
    assert cc.command_data(out) == [{"a": 1}]


@respx.mock
@pytest.mark.parametrize(
    "body",
    [
        {"meta": {"rc": "error", "msg": "api.err.UnknownDevice"}, "data": []},
        {"meta": {"msg": "api.err.X"}, "data": []},
        {"data": []},
        ["not", "an", "object"],
        {"meta": "ok"},
    ],
)
async def test_http_200_without_rc_ok_raises_with_full_meta(client, body):
    respx.post(URL).mock(return_value=Response(200, json=body))
    with pytest.raises(UniFiConnectionError) as exc:
        await cc.classic_command(client, HOST, "default", "devmgr", "set-locate", {"mac": "m"})
    text = str(exc.value)
    assert isinstance(exc.value, cc._SHARED_ERROR)
    assert "set-locate" in text
    assert Response(200, json=body).text in text  # the complete upstream body, verbatim


@respx.mock
async def test_http_error_status_raises(client):
    respx.post(URL).mock(return_value=Response(400, json={"meta": {"rc": "error", "msg": "m"}}))
    with pytest.raises(UniFiConnectionError) as exc:
        await cc.classic_command(client, HOST, "default", "devmgr", "set-locate")
    assert "HTTP 400" in str(exc.value)


@respx.mock
async def test_dry_run_returns_the_preview(monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    client = UniFiClient(Settings(api_key="sk-test"))
    route = respx.route().mock(return_value=Response(200, json={"meta": {"rc": "error"}}))
    out = await cc.classic_command(client, HOST, "default", "devmgr", "set-locate", {"mac": "m"})
    assert not route.called
    assert out["status"] == "dry_run"
    assert out["preview"]["body"] == {"cmd": "set-locate", "mac": "m"}


@pytest.mark.parametrize(
    ("status", "body", "ok"),
    [
        (200, {"meta": {"rc": "ok"}}, True),
        (204, {"meta": {"rc": "ok"}, "data": []}, True),
        (200, {"meta": {"rc": "error"}}, False),
        (200, None, False),
        (404, {"meta": {"rc": "error"}}, True),  # non-2xx: the client raises it already
    ],
)
def test_rc_rule(status, body, ok):
    assert (cc.classic_rc_failure(status, body) is None) is ok


def test_command_data_requires_array():
    with pytest.raises(UniFiConnectionError):
        cc.command_data({"meta": {"rc": "ok"}})


@pytest.mark.parametrize(
    "pattern,value", [(cc.MANAGER_RE, "devmgr\n"), (cc.COMMAND_RE, "set-locate\n")]
)
def test_token_patterns_reject_final_newline(pattern, value):
    assert pattern.match(value) is None


@pytest.mark.parametrize("body", [{"data": []}, {"meta": {}}, {"meta": {"rc": "other"}}])
def test_command_local_rc_rule_remains_strict_with_shared_rule(monkeypatch, body):
    monkeypatch.setattr(cc, "_SHARED_RC_RULE", lambda *_: None)
    assert cc.classic_rc_failure(200, body) is not None


@pytest.mark.parametrize(
    "host,site", [(None, "default"), ("", "default"), ("host", None), ("host", "")]
)
async def test_site_selectors_validate_before_resolution(monkeypatch, client, host, site):
    from unittest.mock import AsyncMock

    resolve = AsyncMock(side_effect=AssertionError("resolution makes requests"))
    monkeypatch.setattr(cc, "resolve_site_slug", resolve)
    with pytest.raises(ValueError):
        await cc.classic_command_for_site(client, object(), host, site, "devmgr", "set-locate")
    resolve.assert_not_awaited()


def test_upstream_error_credential_fields_use_shared_formatter():
    from unifi_fabric.client import UniFiConnectionError
    from unifi_fabric.redaction import write_redaction_scope
    from unifi_fabric.tools._classic_cmd import command_data

    body = {"data": {"password": "CLASSIC_SHAPE_SENTINEL"}}
    with write_redaction_scope(True), pytest.raises(UniFiConnectionError) as exc:
        command_data(body)
    assert "CLASSIC_SHAPE_SENTINEL" not in str(exc.value)
