"""Closure regression checks: transport uncertainty and relay argument secrets."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import Settings

PATH = "/v1/connector/consoles/test/proxy/network/api/s/default/cmd/devmgr"


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize(
    "error_type,sent",
    [
        (httpx.ReadTimeout, True),
        (httpx.WriteTimeout, True),
        (httpx.ConnectTimeout, False),
        (httpx.PoolTimeout, False),
        (httpx.ReadError, True),
        (httpx.RemoteProtocolError, True),
        (httpx.ConnectError, False),
    ],
)
async def test_transport_error_has_one_write_notice_and_send_tag(method, error_type, sent):
    client = UniFiClient(Settings(api_key="synthetic-closure-api-key"))
    transport = MagicMock(request=AsyncMock(side_effect=error_type("synthetic failure")))
    client._get_client = AsyncMock(return_value=transport)
    try:
        with pytest.raises(UniFiConnectionError) as raised:
            await client.request(method, PATH)
        message = str(raised.value).lower()
        # A failure before the request left (connect or pool timeout, connect error) never
        # reached the controller, so it carries no "outcome unknown" notice.
        expected = method == "POST" and sent
        assert message.count("outcome unknown") == int(expected)
        assert raised.value.request_sent is sent
        transport.request.assert_awaited_once()
    finally:
        await client.close()


@pytest.mark.parametrize("redact", [False, True])
async def test_adv_adopt_relay_error_follows_explicit_redaction_choice(redact, caplog):
    password = "synthetic-adopt-password-closure-sentinel"
    client = UniFiClient(Settings(api_key="synthetic-closure-api-key", redact_secrets=redact))
    transport = MagicMock(request=AsyncMock(side_effect=httpx.ReadError(password)))
    client._get_client = AsyncMock(return_value=transport)
    try:
        with pytest.raises(UniFiConnectionError) as raised:
            await client.request(
                "POST", PATH, json={"cmd": "adv-adopt", "password": password}, always_write=True
            )
        error = str(raised.value)
        assert (password not in error) is redact
        if redact:
            assert "***" in error
        else:
            assert password in error
        # Logging remains an unconditional sink: the opt-in changes the surfaced error,
        # never a record emitted by the client.
        assert password not in caplog.text
    finally:
        await client.close()


async def test_device_config_preserves_single_write_notice_and_send_tag():
    from unifi_fabric.families.devices._device_config import update_device_config

    client = UniFiClient(Settings(api_key="synthetic-closure-api-key"))
    error = UniFiConnectionError(
        "read timed out; outcome unknown; read back before retrying", request_sent=True
    )
    client.put = AsyncMock(side_effect=error)
    read_after = AsyncMock()
    try:
        with pytest.raises(UniFiConnectionError) as raised:
            await update_device_config(
                client,
                PATH,
                {"name": "before"},
                {"name": "after"},
                {},
                read_after,
                lambda before, after: {},
                key=None,
            )
        assert str(raised.value).count("outcome unknown") == 1
        assert raised.value is error
        assert raised.value.request_sent is True
        client.put.assert_awaited_once()
        read_after.assert_not_awaited()
    finally:
        await client.close()


@pytest.mark.parametrize("changed", [False, True])
async def test_device_config_read_after_failure_has_no_write_notice(changed):
    from unifi_fabric.families.devices._device_config import update_device_config

    client = UniFiClient(Settings(api_key="synthetic-closure-api-key"))
    client.put = AsyncMock(return_value={"meta": {"rc": "ok"}, "data": []})
    read_after = AsyncMock(side_effect=UniFiConnectionError("read timed out"))
    before = {"name": "before"}
    desired = {"name": "after"} if changed else before
    try:
        out = await update_device_config(
            client,
            PATH,
            before,
            desired,
            {},
            read_after,
            lambda before, after: {},
            key=None,
        )
        assert out["readAfterError"] == "read timed out"
        assert out["_verified"] is None
        assert client.put.await_count == int(changed)
        read_after.assert_awaited_once()
    finally:
        await client.close()


@pytest.mark.parametrize("redact", [False, True])
async def test_adv_adopt_relay_preview_preserves_explicit_redaction_choice(redact, monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "dry-run")
    password = "synthetic-preview-adopt-password"
    client = UniFiClient(Settings(api_key="synthetic-closure-api-key", redact_secrets=redact))
    client._get_client = AsyncMock()
    try:
        response = await client.request(
            "POST", PATH, json={"cmd": "adv-adopt", "password": password}
        )
        body = response.json()["preview"]["body"]
        assert (body["password"] == password) is (not redact)
        if redact:
            assert password not in str(body)
        client._get_client.assert_not_awaited()
    finally:
        await client.close()
