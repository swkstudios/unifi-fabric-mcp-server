"""Tests for the UniFi Mobility tools (workspace-scoped, api.ui.com/v1/mobility).

Hermetic: every request is mocked with respx against a real ``UniFiClient`` so the
exact paths, query/pagination behavior, selected-key routing, PUT bodies, and the
read-before / write / read-after write flow are all asserted directly. The three
PUT writes are mocked only — no live write is ever issued.

Mobility writes are enabled by default (opt out with the ``UNIFI_WRITE_EXCEPTIONS``
entry ``family:mobility=deny``); the hermetic fixture strips ``UNIFI_*``, so tests
that exercise the actual PUT path re-assert the default via the ``enable_writes`` fixture.
Wireless passwords must never be logged or retained — that is asserted
explicitly. All ids/secrets are synthetic and no real value appears here.
"""

from __future__ import annotations

import json as _json
import logging

import pytest
import respx
from httpx import Response

from unifi_fabric.client import UniFiClient, UniFiConnectionError
from unifi_fabric.config import APIKeyConfig, Settings
from unifi_fabric.families.mobility import mobility
from unifi_fabric.families.mobility.mobility import (
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
    """Re-assert the default (no family:mobility=deny entry) for tests that exercise a real PUT."""
    monkeypatch.delenv("UNIFI_WRITE_EXCEPTIONS", raising=False)


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
        assert result["_count"] == 1
        assert result["total"] == 1
        assert result["data"][0]["surprise_field"] == "kept"

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
        assert result["data"][0]["permissions"]["umr"] == "ALL"
        assert result["_count"] == 1

    @respx.mock
    async def test_get_device_returns_envelope_verbatim(self, client):
        body = _detail(client_count=5)
        respx.get(DEV).mock(return_value=Response(200, json=body))
        result = await get_mobility_device(client, WID, DID)
        assert result == body
        assert result["data"]["id"] == DID
        assert result["data"]["client_count"] == 5

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
        assert result["_count"] == 201
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
        assert result["data"][0]["wifi_experience"] == 85


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
        with pytest.raises(ValueError, match="valid labels"):
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


# --- Writes are enabled by default (opt out: family:mobility=deny) -----


class TestWriteGate:
    def test_writes_enabled_by_default(self):
        # The hermetic fixture strips UNIFI_* env, so the gate is unset here → ON.
        assert mobility.writes_enabled() is True

    @pytest.mark.parametrize(
        "val", [WRITE_ENABLED_ENV.replace("=deny", "=dry-run"), "family:network=deny"]
    )
    def test_other_exceptions_leave_writes_enabled(self, monkeypatch, val):
        monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", val)
        assert mobility.writes_enabled() is True

    @pytest.mark.parametrize(
        "val", [WRITE_ENABLED_ENV, f"family:network=dry-run;{WRITE_ENABLED_ENV}"]
    )
    def test_area_deny_exception_disables(self, monkeypatch, val):
        monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", val)
        assert mobility.writes_enabled() is False

    @respx.mock
    async def test_write_runs_when_gate_unset(self, client):
        # Default ON: a rename proceeds and issues the PUT without an explicit opt-in.
        get = respx.get(DEV)
        get.side_effect = [
            Response(200, json=_detail(name="Old")),
            Response(200, json=_detail(name="New")),
        ]
        put = respx.put(DEV).mock(return_value=Response(204))
        result = await update_mobility_device_name(client, WID, DID, "New", confirm=True)
        assert result["status"] == "updated"
        assert put.call_count == 1

    @respx.mock
    async def test_explicit_off_blocks_write(self, client, monkeypatch):
        monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", WRITE_ENABLED_ENV)
        respx.get(DEV).mock(return_value=Response(200, json=_detail(name="Old")))
        put = respx.put(DEV).mock(return_value=Response(204))
        with pytest.raises(ValueError, match="(?i)writes|mutation|disabled|opted"):
            await update_mobility_device_name(client, WID, DID, "New", confirm=True)
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
    async def test_runs_without_confirm(self, client):
        get = respx.get(DEV)
        get.side_effect = [
            Response(200, json=_detail(name="Old")),
            Response(200, json=_detail(name="New")),
        ]
        put = respx.put(DEV).mock(return_value=Response(204))
        result = await update_mobility_device_name(client, WID, DID, "New")
        assert result["status"] == "updated"
        assert put.call_count == 1

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
        assert result["verified"] == {"name": True}
        assert result["response"] is None


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
        assert result["verified"] == {
            "host_address": True,
            "dhcp_mode": None,
            "dhcp_lease_time": None,
        }
        assert result["changed"] == {
            "host_address": {"from": "192.168.1.1", "to": "192.168.10.1"},
            "dhcp_mode": {"from": None, "to": "dhcp"},
            "dhcp_lease_time": {"from": None, "to": 86400},
        }

    @respx.mock
    async def test_runs_without_confirm(self, client):
        get = respx.get(DEV)
        get.side_effect = [
            Response(200, json=_detail(host_address="192.168.1.1")),
            Response(200, json=_detail(host_address="192.168.1.1")),
        ]
        put = respx.put(f"{DEV}/network").mock(return_value=Response(204))
        result = await update_mobility_device_network(client, WID, DID, dhcp_mode="none")
        assert result["status"] == "updated"
        assert put.call_count == 1


# --- Wireless write ----------------------------------------------------------


class TestUpdateWireless:
    @respx.mock
    async def test_runs_without_confirm(self, client):
        get = respx.get(DEV)
        get.side_effect = [
            Response(200, json=_detail(wifi_ssid="Old-SSID")),
            Response(200, json=_detail(wifi_ssid="New-SSID")),
        ]
        put = respx.put(f"{DEV}/wireless").mock(return_value=Response(204))
        result = await update_mobility_device_wireless(client, WID, DID, "New-SSID", "password123")
        assert result["status"] == "updated"
        assert put.call_count == 1

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
        assert result["changed"] == {"ssid": {"from": "Old-SSID", "to": "New-SSID"}}
        assert result["verified"] == {"ssid": True, "password": None}

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
        # Retained nowhere in the returned payload (only the SSID is reported).
        assert secret not in _json.dumps(result)
        assert "password" not in result["changed"]
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


# --- Device-detail envelope shape ---------------------------------------------


class TestDetailEnvelope:
    @pytest.mark.parametrize("inner", [None, [1], "text", 3])
    @respx.mock
    async def test_non_object_data_raises(self, client, inner):
        respx.get(DEV).mock(return_value=Response(200, json={"data": inner, "traceId": "t"}))
        with pytest.raises(UniFiConnectionError, match="expected 'data' to be a device object"):
            await get_mobility_device(client, WID, DID)

    @respx.mock
    async def test_non_object_data_on_read_before_skips_put(self, client):
        respx.get(DEV).mock(return_value=Response(200, json={"data": ["x"]}))
        put = respx.put(DEV)
        with pytest.raises(UniFiConnectionError, match="expected 'data' to be a device object"):
            await update_mobility_device_name(client, WID, DID, "New")
        assert not put.called

    @respx.mock
    async def test_object_without_data_key_is_the_device(self, client):
        respx.get(DEV).mock(return_value=Response(200, json={"id": DID, "name": "Bare"}))
        result = await get_mobility_device(client, WID, DID)
        assert result == {"id": DID, "name": "Bare"}


# --- Uniform write results and gate first -------------------------------------


class TestUniformWriteResults:
    @respx.mock
    async def test_every_write_has_the_same_result_keys(self, client):
        respx.get(DEV).mock(return_value=Response(200, json=_detail(name="Old", wifi_ssid="Old")))
        respx.put(DEV).mock(return_value=Response(204))
        respx.put(f"{DEV}/network").mock(return_value=Response(204))
        respx.put(f"{DEV}/wireless").mock(return_value=Response(200, text="accepted"))
        results = [
            await update_mobility_device_name(client, WID, DID, "New"),
            await update_mobility_device_network(client, WID, DID, dhcp_mode="none"),
            await update_mobility_device_wireless(client, WID, DID, "New", "password-1"),
        ]
        for result in results:
            assert set(result) == {"status", "changed", "verified", "device", "response"}
            assert isinstance(result["verified"], dict)
            for change in result["changed"].values():
                assert set(change) == {"from", "to"}
        assert results[1]["verified"] == {"dhcp_mode": None}  # requested field is unobservable
        assert results[2]["response"] == "accepted"  # a text body is returned verbatim

    @pytest.mark.parametrize(
        "fn,args,kwargs",
        [
            (update_mobility_device_name, ("../bad", DID, ""), {}),
            (update_mobility_device_network, ("../bad", DID), {}),
            (update_mobility_device_wireless, ("../bad", DID, "", "short"), {}),
        ],
    )
    async def test_gate_is_checked_before_field_validation(
        self, client, monkeypatch, fn, args, kwargs
    ):
        monkeypatch.setenv("UNIFI_WRITE_EXCEPTIONS", WRITE_ENABLED_ENV)
        with respx.mock(assert_all_called=False) as router:
            with pytest.raises(ValueError, match=WRITE_ENABLED_ENV):
                await fn(client, *args, **kwargs)
            assert not router.calls


# --- Drained Mobility lists keep the upstream total (complete or capped) ---------


def _page(items, total=None):
    body = {"data": items, "httpStatusCode": 200, "traceId": "t"}
    if total is not None:
        body["total"] = total
    return Response(200, json=body)


_DRAINED = [
    (list_mobility_devices, (WID,), f"{WS}/{WID}/devices", "devices"),
    (list_mobility_clients, (WID, DID), f"{DEV}/clients", "clients"),
]


class TestDrainedTotal:
    @pytest.mark.parametrize("fn,args,path,name", _DRAINED)
    @respx.mock
    async def test_complete_drain_reports_upstream_total(self, client, fn, args, path, name):
        respx.get(path).mock(return_value=_page([{"id": "a"}, {"id": "b"}], total=2))
        result = await fn(client, *args)
        # The first page's envelope fields (httpStatusCode, traceId) are kept beside the records.
        assert result == {
            "data": [{"id": "a"}, {"id": "b"}],
            "_count": 2,
            "total": 2,
            "httpStatusCode": 200,
            "traceId": "t",
        }

    @pytest.mark.parametrize("fn,args,path,name", _DRAINED)
    @respx.mock
    async def test_later_total_keeps_first_page_total(self, client, fn, args, path, name):
        respx.get(path).mock(
            side_effect=[
                _page([{"id": "a"}], total=2),
                _page([{"id": "b"}, {"id": "c"}], total=3),
            ]
        )
        result = await fn(client, *args)
        assert result["data"] == [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        assert result["total"] == 2
        assert result["_wrapperFields"] == {"total": 3}

    @pytest.mark.parametrize("fn,args,path,name", _DRAINED)
    @pytest.mark.parametrize("upstream_total", [None, 7, 1], ids=["null", "different", "equal"])
    @respx.mock
    async def test_total_and_total_count_are_preserved(
        self, client, fn, args, path, name, upstream_total
    ):
        respx.get(path).mock(
            return_value=Response(
                200, json={"data": [{"id": "a"}], "total": upstream_total, "totalCount": 1}
            )
        )
        result = await fn(client, *args)
        assert result["data"] == [{"id": "a"}]
        assert result["total"] == upstream_total
        assert result["totalCount"] == 1
        assert result["_count"] == 1
        if upstream_total == 1:
            assert "_wrapperFields" not in result
        else:
            assert result["_wrapperFields"] == {"total": 1}

    @pytest.mark.parametrize("fn,args,path,name", _DRAINED)
    @respx.mock
    async def test_no_upstream_total_is_never_invented(self, client, fn, args, path, name):
        respx.get(path).mock(side_effect=[_page([{"id": "a"}]), _page([])])
        result = await fn(client, *args)
        assert "total" not in result
        assert result["_count"] == 1

    @pytest.mark.parametrize("fn,args,path,name", _DRAINED)
    @respx.mock
    async def test_capped_drain_keeps_total_and_says_incomplete(self, fn, args, path, name):
        capped = UniFiClient(Settings(api_key="sk-single", paginate_max_pages=1))
        full = [{"id": f"x{i}"} for i in range(200)]
        respx.get(path).mock(return_value=_page(full, total=450))
        result = await fn(capped, *args)
        assert result["incomplete"] is True
        assert result["total"] == 450
        assert result["_count"] == 200

    @pytest.mark.parametrize("fn,args,path,name", _DRAINED)
    @respx.mock
    async def test_multi_key_owning_key_total(self, multikey, fn, args, path, name):
        def answer(request):
            if request.headers["x-api-key"] == "sk-beta":
                return _page([{"id": "b"}], total=1)
            return Response(404, json={"error": "not_found"})

        respx.get(path).mock(side_effect=answer)
        result = await fn(multikey, *args)
        assert result["total"] == 1
        assert result["data"] == [{"id": "b"}]

    @pytest.mark.parametrize("fn,args,path,name", _DRAINED)
    @respx.mock
    async def test_multi_key_all_fail_is_an_error(self, multikey, fn, args, path, name):
        respx.get(path).mock(return_value=Response(403, json={"error": "boom-probe"}))
        with pytest.raises(RuntimeError, match="boom-probe"):
            await fn(multikey, *args)


# --- Write results embed the device-detail GET body verbatim (nothing unwrapped) -----


class TestWriteResultEnvelope:
    @respx.mock
    async def test_name_update_embeds_full_read_after_body(self, client, enable_writes):
        after = _detail(name="New")
        respx.get(DEV).side_effect = [
            Response(200, json=_detail(name="Old")),
            Response(200, json=after),
        ]
        respx.put(DEV).mock(return_value=Response(204))
        result = await update_mobility_device_name(client, WID, DID, "New")
        assert result["device"] == after  # httpStatusCode / traceId kept beside data
        assert result["response"] is None

    @respx.mock
    async def test_no_op_embeds_full_read_before_body(self, client):
        before = _detail(name="Keep")
        respx.get(DEV).mock(return_value=Response(200, json=before))
        result = await update_mobility_device_name(client, WID, DID, "Keep")
        assert result["status"] == "no_op"
        assert result["device"] == before

    @respx.mock
    async def test_network_update_embeds_full_read_after_body(self, client, enable_writes):
        after = _detail(host_address="10.0.0.1")
        respx.get(DEV).side_effect = [Response(200, json=_detail()), Response(200, json=after)]
        respx.put(f"{DEV}/network").mock(return_value=Response(204))
        result = await update_mobility_device_network(client, WID, DID, host_address="10.0.0.1")
        assert result["device"] == after
        assert result["verified"] == {"host_address": True}

    @respx.mock
    async def test_wireless_update_embeds_full_read_after_body(self, client, enable_writes):
        after = _detail(wifi_ssid="New-SSID")
        respx.get(DEV).side_effect = [Response(200, json=_detail()), Response(200, json=after)]
        respx.put(f"{DEV}/wireless").mock(return_value=Response(200, json={"ok": True}))
        result = await update_mobility_device_wireless(client, WID, DID, "New-SSID", "pass-1234")
        assert result["device"] == after
        assert result["response"] == {"ok": True}
        assert result["verified"] == {"ssid": True, "password": None}


@pytest.mark.parametrize("controls", [{"offset": -1}, {"limit": 0}, {"limit": True}])
async def test_drain_rejects_invalid_controls_before_request(controls):
    from unittest.mock import AsyncMock

    client = AsyncMock()
    with pytest.raises(ValueError):
        await mobility._drain(client, "/synthetic", None, **controls)
    client.get.assert_not_called()


async def test_drain_offset_only_is_forwarded_once():
    from unittest.mock import AsyncMock

    client = AsyncMock()
    client.get.return_value = {"data": []}
    assert await mobility._drain(client, "/synthetic", None, offset=3) == {"data": []}
    client.get.assert_awaited_once_with("/synthetic", key=None, params={"offset": 3})


@respx.mock
async def test_wireless_password_echo_scrubbed_on_error(client, enable_writes, monkeypatch):
    monkeypatch.setattr(client._settings, "redact_secrets", True)
    secret = "synthetic-wireless-secret"
    respx.get(DEV).mock(return_value=Response(200, json=_detail()))
    respx.put(f"{DEV}/wireless").mock(return_value=Response(400, json={"echo": secret}))
    with pytest.raises(UniFiConnectionError) as error:
        await update_mobility_device_wireless(client, WID, DID, "New-SSID", secret, confirm=True)
    assert secret not in str(error.value)


@respx.mock
async def test_wireless_error_retains_body_when_redaction_disabled(client, enable_writes):
    secret = "synthetic-wireless-secret"
    respx.get(DEV).mock(return_value=Response(200, json=_detail()))
    respx.put(f"{DEV}/wireless").mock(return_value=Response(400, json={"echo": secret}))
    with pytest.raises(UniFiConnectionError) as error:
        await update_mobility_device_wireless(client, WID, DID, "New-SSID", secret, confirm=True)
    assert secret in str(error.value)


async def test_limited_drain_reports_count():
    from unittest.mock import AsyncMock

    client = AsyncMock()
    client.paginate_max_pages = None
    client.get.return_value = {"data": [{"id": "one"}], "total": 1}
    result = await mobility._drain(client, "/synthetic", None, limit=5)
    assert result["_count"] == 1


@respx.mock
async def test_list_devices_limit_mode_carries_the_documented_count(client):
    # The description promises {data, _count} in every mode; limit mode once omitted _count.
    respx.get(f"{WS}/{WID}/devices").mock(
        return_value=Response(
            200,
            json={
                "data": [{"id": "d-0"}, {"id": "d-1"}],
                "total": 5,
                "httpStatusCode": 200,
                "traceId": "t",
            },
        )
    )
    result = await list_mobility_devices(client, WID, limit=2)
    assert result["_count"] == 2
    assert [d["id"] for d in result["data"]] == ["d-0", "d-1"]
