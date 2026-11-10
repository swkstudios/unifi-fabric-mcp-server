"""Protect camera-object and webhook credentials under UNIFI_REDACT_SECRETS.

A Protect camera object carries credentials under keys that the name-based redaction
does not recognise: each channel's RTSP stream alias (``channels[].rtspAlias``), the
share link (``streamSharing.shareLink`` / ``token``) and webhook shortcut credentials
(``shortcuts[].shortcut.headers`` / ``auth``). The same object is returned by the camera
list, one camera (GET and PATCH) and the bootstrap ``cameras`` array, so every one of
those routes must list every one of those fields. Webhook shortcut credentials are sent
by every write method of the shortcuts route (create POST, update PATCH), not only by one.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from unifi_fabric import route_secrets as rs
from unifi_fabric.client import UniFiClient, _key_fingerprint
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.families.protect import protect_ptz_doorbell

CONSOLE = "/v1/connector/consoles/HOST:1/proxy/"
CAMERA_ID = "0000000000000000000000aa"

_token = st.text(alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", min_size=12)


def _camera(alias: str, share: str, token: str, bearer: str, password: str) -> dict[str, Any]:
    return {
        "id": CAMERA_ID,
        "name": "Front door",
        "channels": [
            {"id": 0, "name": "High", "rtspAlias": alias, "isRtspEnabled": True},
            {"id": 1, "name": "Medium", "rtspAlias": alias[::-1], "isRtspEnabled": True},
        ],
        "streamSharing": {"enabled": True, "shareLink": share, "token": token},
        "shortcuts": [
            {
                "id": "shortcut-1",
                "shortcut": {
                    "type": "webhook",
                    "name": "Open gate",
                    "url": "http://192.0.2.1/hook",
                    "method": "POST",
                    "headers": {"Authorization": f"Bearer {bearer}"},
                    "auth": {"user": "gate", "pass": password},
                },
            }
        ],
    }


#: (method, application route, wrap(camera) -> response body) for every route that
#: returns a Protect camera object.
CAMERA_OBJECT_ROUTES = [
    ("GET", "protect/api/cameras", lambda cam: [cam]),
    ("GET", f"protect/api/cameras/{CAMERA_ID}", lambda cam: cam),
    ("PATCH", f"protect/api/cameras/{CAMERA_ID}", lambda cam: cam),
    ("GET", "protect/api/bootstrap", lambda cam: {"nvr": {"id": "nvr"}, "cameras": [cam]}),
]


@settings(max_examples=60, deadline=None)
@given(
    route=st.sampled_from(CAMERA_OBJECT_ROUTES),
    console=st.booleans(),
    values=st.lists(_token, min_size=5, max_size=5, unique=True),
)
def test_camera_object_credentials_masked_on_every_camera_route(route, console, values):
    method, app_route, wrap = route
    path = CONSOLE + app_route if console else app_route
    alias, share, token, bearer, password = values
    body = wrap(_camera(alias, share, token, bearer, password))
    secrets = [alias, alias[::-1], share, token, f"Bearer {bearer}", password]

    found = rs.response_secrets(method, path, json.dumps(body).encode(), [])
    assert set(secrets) <= set(found), (method, app_route)

    # Default pass-through: the body is returned itself, unchanged.
    assert rs.mask_response_body(method, path, body, redact_secrets=False) is body
    masked = json.dumps(rs.mask_response_body(method, path, body, redact_secrets=True))
    for secret in secrets:
        assert secret not in masked, (method, app_route)
    # Non-credential siblings survive.
    assert "Front door" in masked and "isRtspEnabled" in masked and CAMERA_ID in masked


def _shortcut_body(bearer: str, password: str) -> list[dict[str, Any]]:
    return [
        {
            "shortcut": {
                "type": "webhook",
                "name": "n",
                "url": "http://192.0.2.1/",
                "method": "POST",
                "headers": {"Authorization": f"Bearer {bearer}", "X-Api-Key": bearer[::-1]},
                "auth": {"user": "u", "pass": password},
            }
        }
    ]


@pytest.mark.parametrize("method", ["POST", "PATCH"])
@pytest.mark.parametrize("console", [False, True])
def test_shortcut_webhook_credentials_on_every_write_method(method, console):
    path = (CONSOLE if console else "") + f"protect/api/cameras/{CAMERA_ID}/shortcuts"
    bearer, password = "b3arer-" + "0123456789abcdef", "pw-" + "0123456789abcdef"  # split: gitleaks
    body = _shortcut_body(bearer, password)
    secrets = {f"Bearer {bearer}", bearer[::-1], password}

    assert secrets <= set(rs.request_secrets(method, path, body))
    assert rs.mask_request_body(method, path, body, redact_secrets=False) is body
    masked = json.dumps(rs.mask_request_body(method, path, body, redact_secrets=True))
    assert not any(secret in masked for secret in secrets)
    # The response hands the shortcut list back.
    assert secrets <= set(rs.response_secrets(method, path, json.dumps(body).encode(), []))


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        (
            "create_camera_shortcut",
            {"shortcut": _shortcut_body("tok-create-0123456789", "pw-c")[0]},
        ),
        ("update_camera_shortcut", {"body": _shortcut_body("tok-update-0123456789", "pw-u")[0]}),
    ],
)
def test_shortcut_tool_arguments_bind_webhook_credentials(tool, arguments):
    found = set(rs.tool_call_secrets(tool, arguments))
    inner = arguments.get("shortcut") or arguments["body"]
    assert inner["shortcut"]["headers"]["Authorization"] in found
    assert inner["shortcut"]["auth"]["pass"] in found


def _client(redact: bool, upstream) -> tuple[UniFiClient, APIKeyConfig]:
    key = APIKeyConfig(key="fixture-key", label="fixture")
    client = UniFiClient(Settings(api_keys=[key], redact_secrets=redact))
    client._clients[(key.label, _key_fingerprint(key.key))] = httpx.AsyncClient(
        base_url="https://api.ui.com", transport=httpx.MockTransport(upstream)
    )
    return client, key


@pytest.mark.parametrize("redact", [False, True])
@pytest.mark.parametrize("route", CAMERA_OBJECT_ROUTES[:2] + CAMERA_OBJECT_ROUTES[3:])
def test_client_chokepoint_masks_rtsp_alias_only_under_opt_in(redact, route):
    method, app_route, wrap = route
    alias = "AbCdEfGh12345678"
    body = wrap(_camera(alias, "share-0123456789", "tok-0123456789", "b-0123456789", "p-0123"))

    def upstream(request):
        return httpx.Response(200, json=body)

    client, key = _client(redact, upstream)

    async def run():
        try:
            return await client.get(CONSOLE + app_route, key=key)
        finally:
            await client.close()

    text = json.dumps(asyncio.run(run()))
    assert (alias in text) is not redact
    assert "isRtspEnabled" in text


def test_create_camera_shortcut_dry_run_preview_masks_webhook_credentials(monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    monkeypatch.setattr(protect_ptz_doorbell, "_start_write", lambda method: None)
    requests: list[httpx.Request] = []

    def upstream(request):
        requests.append(request)
        raise AssertionError("dry-run must not contact upstream")

    client, key = _client(True, upstream)
    registry = AsyncMock()
    registry.resolve_key_for_host.return_value = key
    registry.resolve_host_id.return_value = "fixture-host-id"
    bearer, password = "b3arer-" + "0123456789abcdef", "pw-" + "0123456789abcdef"  # split: gitleaks
    shortcut = _shortcut_body(bearer, password)[0]

    async def run():
        try:
            return await protect_ptz_doorbell.create_camera_shortcut(
                client, registry, "fixture", CAMERA_ID, shortcut
            )
        finally:
            await client.close()

    text = json.dumps(asyncio.run(run()))
    assert not requests
    assert "dry_run" in text
    assert bearer not in text and password not in text
    assert "http://192.0.2.1/" in text
    # The caller's own argument is never mutated.
    assert shortcut["shortcut"]["auth"]["pass"] == password
