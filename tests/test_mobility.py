"""Tests for the UniFi Mobility tools (workspace-scoped, api.ui.com/v1/mobility).

Hermetic: every request is mocked with respx against a real ``UniFiClient`` so the
exact paths, query/pagination behavior, selected-key routing, PUT bodies, and the
read-before / write / read-after write flow are all asserted directly. The three
PUT writes are mocked only — no live write is ever issued.

The write gate (``UNIFI_ENABLE_MOBILITY_WRITE``) is fail-closed / OFF by default
pending live verification of the PUT replace-vs-merge semantics (issue #186 comment
gate); tests that exercise the actual PUT path opt in via the ``enable_writes``
fixture. Wireless passwords must never be logged or retained — that is asserted
explicitly. All ids/secrets are synthetic and no real value appears here.
"""

from __future__ import annotations

import json as _json
import logging

import httpx
import pytest
import respx
from httpx import Response

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.tools import mobility
from unifi_fabric.tools.mobility import (
    MOBILITY_BASE,
    WRITE_ENABLED_ENV,
    get_mobility_device,
    list_mobility_admins,
    list_mobility_clients,
    list_mobility_devices,
    list_mobility_workspaces,
    update_mobility_device_name,
    update_mobility_device_network,
    update_mobility_device_wireless,
)

BASE = "https://api.ui.com"
WID = "11111111-1111-4111-8111-111111111111"
DID = "22222222-2222-4222-8222-222222222222"
WS = f"{BASE}{MOBILITY_BASE}/workspaces"
DEV = f"{WS}/{WID}/devices/{DID}"


@pytest.fixture()
def client():
    return UniFiClient(Settings(api_key="sk-single"))


@pytest.fixture()
def enable_writes(monkeypatch):
    """Opt in to the fail-closed write gate for tests that exercise a real PUT."""
    monkeypatch.setenv(WRITE_ENABLED_ENV, "1")


@pytest.fixture()
def multikey():
    return UniFiClient(
        Settings(
            api_keys=[
                APIKeyConfig(key="sk-alpha", label="alpha", is_org_key=False),
                APIKeyConfig(key="sk-beta", label="beta", is_org_key=True),
            ]
        )
    )


def _detail(**over):
    base = {
        "id": DID,
        "name": "Office Router",
        "model": "UMR",
        "state": "CONNECTED",
        "firmware_version": "3.1.14",
        "mac_address": "00:1A:2B:3C:4D:5E",
        "host_address": "192.168.1.1",
        "wifi_ssid": "UniFi-LTE",
    }
    base.update(over)
    return {"data": base, "httpStatusCode": 200, "traceId": "t-1"}


# --- Reads: exact paths + envelopes -----------------------------------------


class TestReads:
    @respx.mock
    async def test_list_workspaces_path_and_no_pagination_params(self, client):
        route = respx.get(WS).mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        {
                            "workspace_id": WID,
                            "workspace_name": "John's Cloud",
                            "is_owner": True,
                            "status": "ACTIVE",
                            "surprise_field": "kept",
                        }
                    ],
                    "total": 1,
                    "httpStatusCode": 200,
                    "traceId": "t",
                },
            )
        )
        result = await list_mobility_workspaces(client)
        assert route.called
        assert "limit" not in route.calls[0].request.url.params
        assert "offset" not in route.calls[0].request.url.params
        assert result["count"] == 1
        assert result["total"] == 1
        assert result["workspaces"][0]["surprise_field"] == "kept"

    @respx.mock
    async def test_list_admins_path(self, client):
        route = respx.get(f"{WS}/{WID}/admins").mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        {
                            "name": "John Doe",
                            "email": "john@example.com",
                            "status": "ACTIVE",
                            "is_owner": True,
                            "permissions": {"umr": "ALL"},
                        }
                    ],
                    "httpStatusCode": 200,
                    "traceId": "t",
                },
            )
        )
        result = await list_mobility_admins(client, WID)
        assert route.called
        assert result["admins"][0]["permissions"]["umr"] == "ALL"
        assert result["count"] == 1

    @respx.mock
    async def test_get_device_unwraps_data_envelope(self, client):
        respx.get(DEV).mock(return_value=Response(200, json=_detail(client_count=5)))
        result = await get_mobility_device(client, WID, DID)
        assert result["device"]["id"] == DID
        assert result["device"]["client_count"] == 5

    @respx.mock
    async def test_list_devices_offset_pagination_drains(self, client):
        path = f"{WS}/{WID}/devices"
        full_page = [{"id": f"d-{i}", "name": f"n{i}"} for i in range(200)]
        route = respx.get(path)
        route.side_effect = [
            Response(
                200, json={"data": full_page, "total": 201, "httpStatusCode": 200, "traceId": "t"}
            ),
            Response(
                200,
                json={
                    "data": [{"id": "d-200", "name": "n200"}],
                    "total": 201,
                    "httpStatusCode": 200,
                    "traceId": "t",
                },
            ),
        ]
        result = await list_mobility_devices(client, WID)
        assert result["count"] == 201
        assert route.call_count == 2
        assert route.calls[0].request.url.params["limit"] == "200"
        assert route.calls[0].request.url.params["offset"] == "0"
        assert route.calls[1].request.url.params["offset"] == "200"

    @respx.mock
    async def test_list_clients_path_and_params(self, client):
        path = f"{DEV}/clients"
        route = respx.get(path).mock(
            return_value=Response(
                200,
                json={
                    "data": [
                        {
                            "mac": "AA:BB:CC:DD:EE:FF",
                            "name": "John's iPhone",
                            "type": "WIRELESS",
                            "connection_status": "ONLINE",
                            "ip_address": "192.168.1.100",
                            "is_blocked": False,
                            "wifi_experience": 85,
                        }
                    ],
                    "total": 1,
                    "httpStatusCode": 200,
                    "traceId": "t",
                },
            )
        )
        result = await list_mobility_clients(client, WID, DID)
        assert route.called
        assert route.calls[0].request.url.params["limit"] == "200"
        assert route.calls[0].request.url.params["offset"] == "0"
        assert result["clients"][0]["wifi_experience"] == 85


# --- Selected-key routing ----------------------------------------------------


class TestKeyRouting:
    @respx.mock
    async def test_key_label_routes_on_that_key(self, multikey):
        route = respx.get(WS).mock(return_value=Response(200, json={"data": []}))
        await list_mobility_workspaces(multikey, key_label="beta")
        assert route.calls[0].request.headers["x-api-key"] == "sk-beta"

    @respx.mock
    async def test_default_key_used_when_label_omitted(self, multikey):
        route = respx.get(WS).mock(return_value=Response(200, json={"data": []}))
        await list_mobility_workspaces(multikey)
        assert route.calls[0].request.headers["x-api-key"] == "sk-alpha"

    async def test_unknown_key_label_raises(self, multikey):
        with pytest.raises(KeyError):
            await list_mobility_workspaces(multikey, key_label="nope")


# --- Validation --------------------------------------------------------------


class TestValidation:
    async def test_bad_workspace_id_rejected(self, client):
        with pytest.raises(ValueError):
            await list_mobility_admins(client, "bad/../id")

    @pytest.mark.parametrize("name", ["", "x" * 33])
    async def test_device_name_length(self, client, name):
        with pytest.raises(ValueError):
            await update_mobility_device_name(client, WID, DID, name, confirm=True)

    async def test_wireless_lengths(self, client):
        with pytest.raises(ValueError):
            await update_mobility_device_wireless(client, WID, DID, "s", "short", confirm=True)

    async def test_network_bad_dhcp_mode(self, client):
        with pytest.raises(ValueError):
            await update_mobility_device_network(client, WID, DID, dhcp_mode="on", confirm=True)

    async def test_network_bad_ipv4(self, client):
        with pytest.raises(ValueError):
            await update_mobility_device_network(
                client, WID, DID, host_address="999.1.1.1", confirm=True
            )

    async def test_network_negative_lease(self, client):
        with pytest.raises(ValueError):
            await update_mobility_device_network(client, WID, DID, dhcp_lease_time=-1, confirm=True)

    async def test_network_empty_body_rejected(self, client):
        with pytest.raises(ValueError):
            await update_mobility_device_network(client, WID, DID, confirm=True)


# --- Write gate is fail-closed (OFF by default) ------------------------------


class TestWriteGate:
    def test_writes_gated_off_by_default(self):
        # The hermetic fixture strips UNIFI_* env, so the gate is unset here → OFF.
        assert mobility._writes_enabled() is False

    @pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
    def test_truthy_values_enable(self, monkeypatch, val):
        monkeypatch.setenv(WRITE_ENABLED_ENV, val)
        assert mobility._writes_enabled() is True

    @pytest.mark.parametrize("val", ["0", "false", "no", "off", ""])
    def test_falsey_values_keep_disabled(self, monkeypatch, val):
        monkeypatch.setenv(WRITE_ENABLED_ENV, val)
        assert mobility._writes_enabled() is False

    @respx.mock
    async def test_confirmed_write_blocked_when_gate_unset(self, client):
        # Default OFF: a fully-confirmed rename still returns disabled and issues no PUT.
        respx.get(DEV).mock(return_value=Response(200, json=_detail(name="Old")))
        put = respx.put(DEV).mock(return_value=Response(204))
        result = await update_mobility_device_name(client, WID, DID, "New", confirm=True)
        assert result["status"] == "disabled"
        assert not put.called

    @respx.mock
    async def test_explicit_off_blocks_write(self, client, monkeypatch):
        monkeypatch.setenv(WRITE_ENABLED_ENV, "0")
        respx.get(DEV).mock(return_value=Response(200, json=_detail(name="Old")))
        put = respx.put(DEV).mock(return_value=Response(204))
        result = await update_mobility_device_name(client, WID, DID, "New", confirm=True)
        assert result["status"] == "disabled"
        assert not put.called


# --- Device name write: read-before / no-op / confirm / read-after ----------


class TestUpdateName:
    @respx.mock
    async def test_no_op_when_name_matches(self, client):
        respx.get(DEV).mock(return_value=Response(200, json=_detail(name="Keep")))
        put = respx.put(DEV).mock(return_value=Response(204))
        result = await update_mobility_device_name(client, WID, DID, "Keep", confirm=True)
        assert result["status"] == "no_op"
        assert not put.called

    @respx.mock
    async def test_unconfirmed_does_not_write(self, client):
        respx.get(DEV).mock(return_value=Response(200, json=_detail(name="Old")))
        put = respx.put(DEV).mock(return_value=Response(204))
        result = await update_mobility_device_name(client, WID, DID, "New")
        assert result["status"] == "unconfirmed"
        assert result["current_name"] == "Old"
        assert result["proposed_name"] == "New"
        assert not put.called

    @respx.mock
    async def test_updated_read_before_write_read_after(self, client, enable_writes):
        get = respx.get(DEV)
        get.side_effect = [
            Response(200, json=_detail(name="Old")),
            Response(200, json=_detail(name="New")),
        ]
        put = respx.put(DEV).mock(return_value=Response(204))
        result = await update_mobility_device_name(client, WID, DID, "New", confirm=True)
        # read-before + read-after == two GETs; exactly one PUT between them.
        assert get.call_count == 2
        assert put.call_count == 1
        assert _json.loads(put.calls[0].request.content) == {"name": "New"}
        assert result["status"] == "updated"
        assert result["changed"] == {"name": {"from": "Old", "to": "New"}}
        assert result["verified"] is True


# --- Network write -----------------------------------------------------------


class TestUpdateNetwork:
    @respx.mock
    async def test_no_op_when_only_host_address_matches(self, client):
        respx.get(DEV).mock(return_value=Response(200, json=_detail(host_address="192.168.1.1")))
        put = respx.put(f"{DEV}/network").mock(return_value=Response(204))
        result = await update_mobility_device_network(
            client, WID, DID, host_address="192.168.1.1", confirm=True
        )
        assert result["status"] == "no_op"
        assert not put.called

    @respx.mock
    async def test_partial_body_read_before_write_read_after(self, client, enable_writes):
        get = respx.get(DEV)
        get.side_effect = [
            Response(200, json=_detail(host_address="192.168.1.1")),
            Response(200, json=_detail(host_address="192.168.10.1")),
        ]
        put = respx.put(f"{DEV}/network").mock(return_value=Response(204))
        result = await update_mobility_device_network(
            client,
            WID,
            DID,
            host_address="192.168.10.1",
            dhcp_mode="dhcp",
            dhcp_lease_time=86400,
            confirm=True,
        )
        assert get.call_count == 2
        assert put.call_count == 1
        body = _json.loads(put.calls[0].request.content)
        assert body == {
            "host_address": "192.168.10.1",
            "dhcp_mode": "dhcp",
            "dhcp_lease_time": 86400,
        }
        # only the provided fields are sent — never the full record.
        assert "dhcp_range_start" not in body
        assert result["status"] == "updated"
        assert result["verified"] == {"host_address": True}

    @respx.mock
    async def test_unconfirmed_preview(self, client):
        respx.get(DEV).mock(return_value=Response(200, json=_detail(host_address="192.168.1.1")))
        put = respx.put(f"{DEV}/network").mock(return_value=Response(204))
        result = await update_mobility_device_network(client, WID, DID, dhcp_mode="none")
        assert result["status"] == "unconfirmed"
        assert result["proposed"] == {"dhcp_mode": "none"}
        assert not put.called


# --- Wireless write ----------------------------------------------------------


class TestUpdateWireless:
    @respx.mock
    async def test_unconfirmed_preview(self, client):
        respx.get(DEV).mock(return_value=Response(200, json=_detail(wifi_ssid="Old-SSID")))
        put = respx.put(f"{DEV}/wireless").mock(return_value=Response(204))
        result = await update_mobility_device_wireless(client, WID, DID, "New-SSID", "password123")
        assert result["status"] == "unconfirmed"
        assert result["current_ssid"] == "Old-SSID"
        assert not put.called

    @respx.mock
    async def test_updated_read_before_write_read_after(self, client, enable_writes):
        get = respx.get(DEV)
        get.side_effect = [
            Response(200, json=_detail(wifi_ssid="Old-SSID")),
            Response(200, json=_detail(wifi_ssid="New-SSID")),
        ]
        put = respx.put(f"{DEV}/wireless").mock(return_value=Response(204))
        result = await update_mobility_device_wireless(
            client, WID, DID, "New-SSID", "s3cr3tpass", confirm=True
        )
        assert get.call_count == 2
        assert put.call_count == 1
        body = _json.loads(put.calls[0].request.content)
        assert body == {"ssid": "New-SSID", "password": "s3cr3tpass"}
        assert result["changed"]["password"] == "updated"
        assert result["verified"] == {"ssid": True}

    @respx.mock
    async def test_password_never_logged_or_retained(self, client, enable_writes, caplog):
        """Comment-gate requirement: never log or retain wireless passwords."""
        secret = "not-a-real-password"
        get = respx.get(DEV)
        get.side_effect = [
            Response(200, json=_detail(wifi_ssid="Old-SSID")),
            Response(200, json=_detail(wifi_ssid="New-SSID")),
        ]
        put = respx.put(f"{DEV}/wireless").mock(return_value=Response(204))
        with caplog.at_level(logging.DEBUG):
            result = await update_mobility_device_wireless(
                client, WID, DID, "New-SSID", secret, confirm=True
            )
        # Retained nowhere in the returned payload (only the SSID + a redaction marker).
        assert secret not in _json.dumps(result)
        assert result["changed"]["password"] == "updated"
        # Not emitted to any log record.
        assert secret not in caplog.text
        # The secret leaves the process ONLY as the request body to the upstream API.
        assert secret in put.calls[0].request.content.decode()


# --- Preflight / upstream error mapping (all three writes) -------------------
#
# The Mobility writes need the write:mobility scope, workspace Admin permission, and
# an active device subscription. Any of those failing is answered by the gateway as a
# 401/403 (or a 404 for an unavailable subscription); the tools surface it verbatim
# via UniFiConnectionError rather than masking it. These tests exercise both the
# read-before leg (where a scope/permission failure lands first) and the PUT leg.

_WRITE_CALLS = {
    "name": (lambda c: update_mobility_device_name(c, WID, DID, "New", confirm=True), DEV),
    "network": (
        lambda c: update_mobility_device_network(
            c, WID, DID, host_address="192.168.10.1", confirm=True
        ),
        f"{DEV}/network",
    ),
    "wireless": (
        lambda c: update_mobility_device_wireless(
            c, WID, DID, "New-SSID", "password123", confirm=True
        ),
        f"{DEV}/wireless",
    ),
}


class TestPreflightErrors:
    @pytest.mark.parametrize("kind", list(_WRITE_CALLS))
    @respx.mock
    async def test_read_before_forbidden_surfaces_and_skips_put(self, client, enable_writes, kind):
        call, put_path = _WRITE_CALLS[kind]
        # Missing write:mobility scope / non-Admin → 403 on the read-before GET.
        respx.get(DEV).mock(
            return_value=Response(
                403,
                json={
                    "code": "forbidden",
                    "httpStatusCode": 403,
                    "message": "missing write:mobility scope or not workspace Admin",
                    "traceId": "t",
                },
            )
        )
        put = respx.put(put_path).mock(return_value=Response(204))
        with pytest.raises(UniFiConnectionError) as exc:
            await call(client)
        assert "403" in str(exc.value)
        assert not put.called

    @pytest.mark.parametrize("kind", list(_WRITE_CALLS))
    @respx.mock
    async def test_put_forbidden_surfaces(self, client, enable_writes, kind):
        call, put_path = _WRITE_CALLS[kind]
        # read-before OK, but the write itself is rejected (e.g. VIEW_ONLY admin).
        respx.get(DEV).mock(
            return_value=Response(
                200, json=_detail(name="Old", host_address="192.168.1.1", wifi_ssid="Old-SSID")
            )
        )
        respx.put(put_path).mock(
            return_value=Response(
                403,
                json={
                    "code": "forbidden",
                    "httpStatusCode": 403,
                    "message": "write not permitted",
                    "traceId": "t",
                },
            )
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await call(client)
        assert "403" in str(exc.value)

    @respx.mock
    async def test_no_active_subscription_surfaces(self, client, enable_writes):
        # An unavailable Mobility subscription on the device → upstream 404 on read-before.
        respx.get(DEV).mock(
            return_value=Response(
                404,
                json={
                    "code": "bad_request",
                    "httpStatusCode": 404,
                    "message": "device has no active subscription",
                    "traceId": "t",
                },
            )
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await update_mobility_device_name(client, WID, DID, "New", confirm=True)
        assert "404" in str(exc.value)
        assert "subscription" in str(exc.value)


# --- 204 handling ------------------------------------------------------------


class TestUpstreamErrors:
    @respx.mock
    async def test_forbidden_read_surfaces_verbatim(self, client):
        respx.get(WS).mock(
            return_value=Response(
                403,
                json={
                    "code": "forbidden",
                    "httpStatusCode": 403,
                    "message": "no mobility scope",
                    "traceId": "t",
                },
            )
        )
        with pytest.raises(UniFiConnectionError) as exc:
            await list_mobility_workspaces(client)
        assert "403" in str(exc.value)

    @respx.mock
    async def test_204_put_not_treated_as_json_error(self, client, enable_writes):
        # A 204 No Content PUT must not raise a "Non-JSON response" decode error.
        get = respx.get(DEV)
        get.side_effect = [
            Response(200, json=_detail(name="Old")),
            Response(200, json=_detail(name="New")),
        ]
        respx.put(DEV).mock(return_value=Response(204))
        result = await update_mobility_device_name(client, WID, DID, "New", confirm=True)
        assert result["status"] == "updated"


def test_module_imports_httpx_client_symbol():
    # Guard: mobility depends only on the shared client, no second auth path.
    assert isinstance(UniFiClient(Settings(api_key="x")), UniFiClient)
    assert httpx is not None
