"""Hermetic regressions for tool audit, request and verification contracts."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.families.network import network_device_operations as devices
from unifi_fabric.families.network import network_nat_qos_traffic as nat
from unifi_fabric.families.network import network_routing_topology as routing
from unifi_fabric.families.network import network_security_diagnostics as security
from unifi_fabric.families.network import network_switching_power as switching
from unifi_fabric.families.network import site_admin
from unifi_fabric.families.protect import protect
from unifi_fabric.families.protect import protect_camera_recording as recording
from unifi_fabric.families.protect import protect_private as private
from unifi_fabric.families.protect import protect_users_assets as assets
from unifi_fabric.families.site_manager import site_manager
from unifi_fabric.families.statistics import system_log
from unifi_fabric.families.vpn import network_vpn_dns as vpn
from unifi_fabric.shared_shapes import _classic_objects as classic

ID = "000000000000000000000001"


async def test_malformed_device_row_is_not_dropped():
    client = SimpleNamespace(
        request=AsyncMock(
            return_value=httpx.Response(200, json={"meta": {"rc": "ok"}, "data": [{"_id": ID}, 4]})
        )
    )
    with pytest.raises(UniFiConnectionError, match="row 1"):
        await devices._site_devices(client, None, "console", "default")


@pytest.mark.parametrize("family", ["nat", "routing", "classic"])
async def test_read_after_missing_record_never_claims_no_write(family):
    client = SimpleNamespace(get=AsyncMock(return_value=[]))
    with pytest.raises(ValueError) as exc:
        if family == "nat":
            await nat._nc_listed(
                client, "/list", None, ID, "NAT rule", "list_nat_rules", read_after=True
            )
        elif family == "routing":
            await routing._listed_record(client, "/list", None, ID, "Router", read_after=True)
        else:
            await classic.require_listed_record(
                client,
                "/list",
                ID,
                key=None,
                kind="Object",
                list_tool="list_objects",
                read_after=True,
            )
    assert "No write was sent" not in str(exc.value)
    assert "write was sent" in str(exc.value)


@pytest.mark.parametrize("family", ["routing", "vpn", "site", "switching", "camera", "arm"])
async def test_upstream_error_fields_use_client_scrubber(monkeypatch, family):
    # A sentinel scrubber checks that structured upstream fields reach the existing policy.
    seen = []
    client = SimpleNamespace(
        get=AsyncMock(return_value=[{"_id": ID, "name": {"password": "synthetic"}}])
    )

    def scrub(value, supplied_client=None):
        assert supplied_client is client
        seen.append(value)
        return "scrubbed"

    module = {
        "routing": routing,
        "vpn": vpn,
        "site": site_admin,
        "switching": switching,
        "camera": protect,
        "arm": protect,
    }[family]
    monkeypatch.setattr(module, "upstream_error_value", scrub)
    with pytest.raises(ValueError) as exc:
        if family == "routing":
            await routing._listed_record(client, "/list", None, "missing", "Router")
        elif family == "vpn":
            vpn._select_users(
                [{"_id": ID, "name": {"password": "synthetic"}}], "/list", ["missing"], client
            )
        elif family == "switching":
            await switching._listed_record(client, "/list", None, "missing", "Switch")
        elif family == "camera":
            client.get.return_value = [{"id": ID, "name": "Door"}]
            await protect._resolve_camera_refs(client, "console", "missing")
        elif family == "arm":
            raise protect._unknown_arm_profile("missing", "console", [ID], client)
        else:
            site_admin._select_site(
                [{"_id": ID, "name": "default", "desc": {"password": "synthetic"}}],
                "missing",
                "site",
                client,
            )
    assert "synthetic" not in str(exc.value)
    assert "scrubbed" in str(exc.value)
    assert seen


async def test_camera_not_found_handles_non_string_names():
    client = SimpleNamespace(
        get=AsyncMock(return_value=[{"id": ID, "name": "Door"}, {"id": "two", "name": 4}])
    )
    with pytest.raises(ValueError, match="not found"):
        await protect._resolve_camera_refs(client, "console", "missing-camera")


def test_refusal_reports_http_verb_and_audits_policy(monkeypatch):
    monkeypatch.setenv("UNIFI_WRITE_POLICY", "deny")
    client = SimpleNamespace(audit_refusal=Mock())
    with pytest.raises(security.ReadOnlyModeError, match="POST refused"):
        security._write_gate(client, "update_ssl_inspection")
    client.audit_refusal.assert_called_once_with(
        tool="update_ssl_inspection", reason="UNIFI_WRITE_POLICY"
    )


async def test_export_prepare_disables_retries(monkeypatch):
    monkeypatch.setattr(recording, "_resolve", AsyncMock(return_value=(None, "console")))
    client = SimpleNamespace(
        request=AsyncMock(return_value=httpx.Response(200, json={"filename": "export.mp4"}))
    )
    await recording.export_edge_recording(
        client, None, "console", ID, "prepare", "export.mp4", 1700000000, 1700000001
    )
    assert client.request.await_args.kwargs["max_retries"] == 0


async def test_unadopt_still_present_cannot_keep_success_verdict(monkeypatch):
    monkeypatch.setattr(private, "_guard", lambda _: None)
    monkeypatch.setattr(
        private, "_device_path", AsyncMock(return_value="protect/api/cameras/" + ID)
    )
    monkeypatch.setattr(
        private,
        "_action",
        AsyncMock(
            return_value={
                "status": 200,
                "_verified": True,
                "_noOp": True,
                "changed": False,
                "readAfter": {"status": 200, "body": {"id": ID}},
            }
        ),
    )
    result = await private.unadopt_protect_device(None, None, "console", "camera", ID)
    assert result["_verified"] is False
    assert result["_noOp"] is None
    assert "changed" not in result


@pytest.mark.parametrize(
    "after,expected", [({}, True), ({"validUntil": 1893456000000}, True), (None, False)]
)
async def test_indefinite_mute_verifies_object_not_null_timestamp(monkeypatch, after, expected):
    monkeypatch.setattr(assets, "_require_mutations", lambda: None)
    monkeypatch.setattr(assets, "_resolve", AsyncMock(return_value=(None, "console")))
    monkeypatch.setattr(
        assets,
        "_bootstrap_record",
        AsyncMock(side_effect=[{"id": ID}, {"id": ID, "notificationSnoozeSettings": after}]),
    )
    result = await assets.set_protect_notifications_muted(
        SimpleNamespace(post=AsyncMock(return_value={})), None, "console", ID, True
    )
    assert result["_verified"] is expected


async def test_isp_query_preserves_non_timestamp_nulls(monkeypatch):
    sent = []

    async def post(client, path, **kwargs):
        sent.append(kwargs["json"])
        return {"data": {"metrics": []}}

    monkeypatch.setattr(site_manager, "post_read", post)
    sites = [{"hostId": "console", "siteId": "site", "extension": None, "beginTimestamp": None}]
    await site_manager.query_isp_metrics(None, "1h", sites=sites)
    assert sent[0]["sites"] == [{"hostId": "console", "siteId": "site", "extension": None}]
    assert sites[0]["beginTimestamp"] is None


def test_system_log_warning_records_converted_value():
    result = system_log._epoch_hints({}, 1700000000000, None)
    warning = result["_warnings"][0]
    assert warning["sent_as"] == 1700000000000000
    assert "multiplied by 1000" in warning["message"]
    assert "sent as given" not in warning["message"]
