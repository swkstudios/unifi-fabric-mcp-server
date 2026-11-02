"""Captured read failures retain upstream errors and offer source-backed guidance."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools import network_clients_guests as cg
from unifi_fabric.tools import network_controller_insights as ci
from unifi_fabric.tools import network_nat_qos_traffic as nt
from unifi_fabric.tools import network_vpn_dns as vd
from unifi_fabric.tools import network_wifi_radio as wr


@pytest.mark.parametrize("kind", ["traffic", "poe", "scan", "stats", "logs", "openvpn"])
async def test_missing_context_hints_preserve_error(monkeypatch, kind):
    error = UniFiConnectionError("upstream body", status=404 if kind == "openvpn" else 400)
    client = AsyncMock()
    client.get.side_effect = error
    client.request.side_effect = error
    monkeypatch.setattr(nt, "_nc_site", AsyncMock(return_value=(None, "host", "default")))
    monkeypatch.setattr(wr, "_get", AsyncMock(side_effect=error))
    monkeypatch.setattr(ci, "_resolve_host", AsyncMock(return_value=(None, "host")))
    monkeypatch.setattr(cg, "resolve_site_slug", AsyncMock(return_value=(None, "host", "default")))
    monkeypatch.setattr(cg, "_client_mac_for", AsyncMock(return_value="02:00:5e:00:00:a1"))
    monkeypatch.setattr(vd, "_vpn_server", AsyncMock(return_value=(None, "host", "default", "id")))
    calls = {
        "traffic": lambda: nt.get_traffic_stats(client, None, "host", "site"),
        "poe": lambda: nt.get_poe_info(client, None, "host", "site"),
        "scan": lambda: wr.get_wifi_quick_scan_status(client, None, "host", "site"),
        "stats": lambda: ci.get_controller_stats(client, None, "host"),
        "logs": lambda: cg.get_client_observability(
            client, None, "host", "site", "02:00:5e:00:00:a1", "logs-all"
        ),
        "openvpn": lambda: vd.get_openvpn_client_config(client, None, "host", "site", "id"),
    }
    expected = {
        "traffic": "start",
        "poe": "mac",
        "scan": "band",
        "stats": "schema",
        "logs": "start",
        "openvpn": "OpenVPN",
    }
    with pytest.raises(UniFiConnectionError) as caught:
        await calls[kind]()
    assert caught.value is error
    assert str(caught.value).startswith("upstream body -- Hint: ")
    assert "Hint:" in str(caught.value) and expected[kind] in str(caught.value)
    assert caught.value.status == error.status
