"""Tests for statistics — read-only stat endpoints via Classic REST."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools.statistics import (
    _CLASSIC_STAT_BASE,
    _get_client_link_diagnostics,
    _get_device_port_state,
    _get_device_stp_state,
    _get_historical_stats,
    _get_site_statistics,
    _get_system_info,
    _list_active_clients_stats,
    _list_client_sessions,
    _list_device_stats,
    _list_known_clients,
)

HOST_ID = "host-001"
SITE_SLUG = "default"
STAT_BASE = _CLASSIC_STAT_BASE.format(host_id=HOST_ID, site_slug=SITE_SLUG)


@pytest.fixture()
def client():
    c = AsyncMock()
    c.get = AsyncMock()
    c.post = AsyncMock()
    return c


@pytest.fixture()
def registry():
    r = AsyncMock()
    r.resolve_key_for_host = AsyncMock(return_value=None)
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


# --- get_site_statistics ---


class TestGetSiteStatistics:
    async def test_uses_stat_health_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"subsystem": "wlan"}]}
        result = await _get_site_statistics(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/health", key=None)
        assert result == [{"subsystem": "wlan"}]

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        await _get_site_statistics(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key=None)

    async def test_extracts_data_list(self, client, registry):
        items = [{"subsystem": "wan"}, {"subsystem": "lan"}]
        client.get.return_value = {"meta": {"rc": "ok"}, "data": items}
        result = await _get_site_statistics(client, registry, "h", "s")
        assert result == items


# --- get_system_info ---


class TestGetSystemInfo:
    async def test_uses_stat_sysinfo_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"version": "8.0.0"}]}
        result = await _get_system_info(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/sysinfo", key=None)
        assert result == [{"version": "8.0.0"}]

    async def test_extracts_data(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"uptime": 123456}]}
        result = await _get_system_info(client, registry, "h", "s")
        assert result[0]["uptime"] == 123456


# --- list_active_clients_stats ---


class TestListActiveClientsStats:
    async def test_uses_stat_sta_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"mac": "aa:bb:cc:dd:ee:ff"}]}
        result = await _list_active_clients_stats(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/sta", key=None)
        assert result == [{"mac": "aa:bb:cc:dd:ee:ff"}]

    async def test_extracts_data(self, client, registry):
        items = [{"mac": "aa:bb:cc:dd:ee:ff", "signal": -65}]
        client.get.return_value = {"meta": {"rc": "ok"}, "data": items}
        result = await _list_active_clients_stats(client, registry, "h", "s")
        assert result == items


# --- list_device_stats ---


class TestListDeviceStats:
    async def test_uses_stat_device_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"mac": "11:22:33:44:55:66"}]}
        result = await _list_device_stats(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/device", key=None)
        assert result == [{"mac": "11:22:33:44:55:66"}]

    async def test_extracts_data(self, client, registry):
        items = [{"mac": "11:22:33:44:55:66", "uptime": 9999}]
        client.get.return_value = {"meta": {"rc": "ok"}, "data": items}
        result = await _list_device_stats(client, registry, "h", "s")
        assert result == items

    async def test_passthrough_when_no_data_key(self, client, registry):
        raw = [{"mac": "11:22:33:44:55:66"}]
        client.get.return_value = raw
        result = await _list_device_stats(client, registry, "h", "s")
        assert result == raw


# --- list_client_sessions (/stat/session — epoch SECONDS) ---

# All identifiers below are synthetic (documentation ranges / placeholder MACs).
_START_S = 1_735_000_000
_END_S = 1_735_600_000


class TestListClientSessions:
    async def test_posts_to_session_url_with_default_slug(self, client, registry):
        client.post.return_value = {"data": []}
        await _list_client_sessions(client, registry, "h", "s", _START_S, _END_S)
        # The classic path site segment must be the slug 'default', never a display name.
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key=None)
        path = client.post.call_args.args[0]
        assert path == f"{STAT_BASE}/session"
        assert "/s/default/" in path

    async def test_body_uses_epoch_seconds_verbatim(self, client, registry):
        client.post.return_value = {"data": []}
        await _list_client_sessions(client, registry, "h", "s", _START_S, _END_S)
        body = client.post.call_args.kwargs["json"]
        # /stat/session takes SECONDS — the values must be passed through unchanged.
        assert body == {"type": "all", "start": _START_S, "end": _END_S}

    async def test_rejects_millisecond_magnitude_start(self, client, registry):
        # Milliseconds sent to /stat/session return HTTP 200 + empty array; reject them loudly.
        with pytest.raises(ValueError, match="milliseconds"):
            await _list_client_sessions(client, registry, "h", "s", _START_S * 1000, _END_S)
        client.post.assert_not_called()

    async def test_identifiers_survive(self, client, registry):
        # Data-survival: the server is a faithful pass-through. Identifier fields
        # supplied upstream must come back unchanged, not withheld.
        client.post.return_value = {
            "data": [
                {
                    "mac": "0a:00:00:00:00:01",
                    "ap_mac": "0a:00:00:00:00:02",
                    "ip": "203.0.113.5",
                    "hostname": "synthetic-laptop",
                    "duration": 3600,
                    "is_wired": False,
                }
            ]
        }
        result = await _list_client_sessions(client, registry, "h", "s", _START_S, _END_S)
        session = result[0]
        assert session["mac"] == "0a:00:00:00:00:01"
        assert session["ap_mac"] == "0a:00:00:00:00:02"
        assert session["ip"] == "203.0.113.5"
        assert session["hostname"] == "synthetic-laptop"
        # Non-identifier fields survive too.
        assert session["duration"] == 3600
        assert session["is_wired"] is False

    async def test_wired_session_null_ap_mac_preserved(self, client, registry):
        client.post.return_value = {"data": [{"is_wired": True, "ap_mac": None, "sw_port": 5}]}
        result = await _list_client_sessions(client, registry, "h", "s", _START_S, _END_S)
        # null ap_mac must stay null (signals wired) rather than being redacted.
        assert result[0]["ap_mac"] is None
        assert result[0]["sw_port"] == 5

    async def test_truncated_host_id_raises_host_error(self, client, registry):
        client.post.side_effect = UniFiConnectionError(
            "HTTP 403 from POST /v1/connector/...: forbidden: host not found"
        )
        with pytest.raises(UniFiConnectionError, match="host id"):
            await _list_client_sessions(client, registry, "h", "s", _START_S, _END_S)


# --- get_historical_stats (/stat/report — epoch MILLISECONDS) ---


class TestGetHistoricalStats:
    async def test_body_converts_seconds_to_milliseconds(self, client, registry):
        client.post.return_value = {"data": []}
        await _get_historical_stats(client, registry, "h", "s", "hourly", "ap", _START_S, _END_S)
        body = client.post.call_args.kwargs["json"]
        # /stat/report takes MILLISECONDS — the sibling of /stat/session uses the opposite unit.
        assert body["start"] == _START_S * 1000
        assert body["end"] == _END_S * 1000

    async def test_path_encodes_interval_and_scope(self, client, registry):
        client.post.return_value = {"data": []}
        await _get_historical_stats(client, registry, "h", "s", "daily", "ap", _START_S, _END_S)
        assert client.post.call_args.args[0] == f"{STAT_BASE}/report/daily.ap"

    async def test_default_attrs_used_when_omitted(self, client, registry):
        client.post.return_value = {"data": []}
        await _get_historical_stats(client, registry, "h", "s", "hourly", "ap", _START_S, _END_S)
        assert client.post.call_args.kwargs["json"]["attrs"] == ["num_sta", "rx_bytes", "tx_bytes"]

    async def test_scientific_notation_bytes_preserved_as_float(self, client, registry):
        client.post.return_value = {
            "data": [{"time": 1_735_000_000_000, "num_sta": 12, "rx_bytes": 5.275171266916667e9}]
        }
        result = await _get_historical_stats(
            client, registry, "h", "s", "hourly", "ap", _START_S, _END_S
        )
        assert isinstance(result[0]["rx_bytes"], float)
        assert result[0]["num_sta"] == 12

    async def test_invalid_interval_rejected(self, client, registry):
        with pytest.raises(ValueError, match="interval"):
            await _get_historical_stats(
                client, registry, "h", "s", "weekly", "ap", _START_S, _END_S
            )
        client.post.assert_not_called()

    async def test_invalid_scope_rejected(self, client, registry):
        with pytest.raises(ValueError, match="scope"):
            await _get_historical_stats(
                client, registry, "h", "s", "hourly", "switch", _START_S, _END_S
            )

    async def test_rejects_millisecond_magnitude(self, client, registry):
        with pytest.raises(ValueError, match="milliseconds"):
            await _get_historical_stats(
                client, registry, "h", "s", "hourly", "ap", _START_S * 1000, _END_S
            )


# --- list_all_clients (/stat/alluser — GET) ---


class TestListAllClients:
    async def test_uses_get_on_alluser_url(self, client, registry):
        client.get.return_value = {"data": []}
        await _list_known_clients(client, registry, "h", "s")
        # /stat/alluser accepts GET (it is not POST-only).
        client.get.assert_called_once_with(f"{STAT_BASE}/alluser", key=None)
        client.post.assert_not_called()

    async def test_roster_identifiers_survive(self, client, registry):
        # Data-survival: roster identifiers (mac/ip/hostname/name) are the
        # human-meaningful keys a caller joins on; they must pass through verbatim.
        client.get.return_value = {
            "data": [
                {
                    "mac": "0a:00:00:00:00:03",
                    "last_ip": "203.0.113.9",
                    "hostname": "synthetic-phone",
                    "name": "Alias Device",
                    "first_seen": 1_700_000_000,
                    "is_wired": False,
                }
            ]
        }
        result = await _list_known_clients(client, registry, "h", "s")
        entry = result[0]
        assert entry["mac"] == "0a:00:00:00:00:03"
        assert entry["last_ip"] == "203.0.113.9"
        assert entry["hostname"] == "synthetic-phone"
        assert entry["name"] == "Alias Device"
        assert entry["first_seen"] == 1_700_000_000

    async def test_truncated_host_id_raises_host_error(self, client, registry):
        client.get.side_effect = UniFiConnectionError("HTTP 403 forbidden: host not found")
        with pytest.raises(UniFiConnectionError, match="host id"):
            await _list_known_clients(client, registry, "h", "s")


# ===========================================================================
# Focused convenience reads (#183 / #184 / #188) — same /stat/* payloads,
# in-memory selection, verbatim field survival. All identifiers below are
# synthetic (documentation-range IPs, placeholder MACs).
# ===========================================================================


def _sta_payload():
    """A minimal /stat/sta response mixing a wireless and a wired client."""
    return {
        "meta": {"rc": "ok"},
        "data": [
            {
                "_id": "clientdoc0000000000000001",
                "mac": "0a:00:00:00:00:11",
                "is_wired": False,
                "rssi": 42,
                "signal": -58,
                "noise": -96,
                "channel": 36,
                "radio_name": "wifi1",
                "rx_rate": 866000,
                "tx_rate": 780000,
                "wifi_tx_attempts": 1200,
                "tx_retries": 37,
                "satisfaction_reason": 1,
                "network_id": "netdoc00000000000000aa11",
                "vlan": 20,
                "qos_policy_applied": True,
                "use_fixedip": True,
                "fixed_ip": "203.0.113.11",
                "virtual_network_override_enabled": False,
                # An unknown/future field the server must not drop:
                "some_future_diag_field": {"nested": "survives"},
            },
            {
                "_id": "clientdoc0000000000000002",
                "mac": "0a:00:00:00:00:22",
                "is_wired": True,
                "sw_mac": "00:00:5e:00:53:01",
                "sw_port": 22,
                "network_id": "netdoc00000000000000aa11",
                "satisfaction_reason": 2,
            },
        ],
    }


class TestGetClientLinkDiagnostics:
    async def test_uses_stat_sta_url_and_returns_record_unchanged(self, client, registry):
        client.get.return_value = _sta_payload()
        result = await _get_client_link_diagnostics(
            client, registry, "h", "s", client_id="0a:00:00:00:00:11"
        )
        # Exact Fabric route, reusing the same /stat/sta request as the list tool.
        client.get.assert_called_once_with(f"{STAT_BASE}/sta", key=None)
        # The matching upstream record is returned unchanged (single-select).
        assert result["_id"] == "clientdoc0000000000000001"
        assert result["rssi"] == 42
        assert result["satisfaction_reason"] == 1

    async def test_selects_wireless_client_by_id(self, client, registry):
        client.get.return_value = _sta_payload()
        result = await _get_client_link_diagnostics(
            client, registry, "h", "s", client_id="clientdoc0000000000000001"
        )
        assert result["mac"] == "0a:00:00:00:00:11"
        assert result["is_wired"] is False
        assert result["radio_name"] == "wifi1"

    async def test_selects_wired_client(self, client, registry):
        client.get.return_value = _sta_payload()
        result = await _get_client_link_diagnostics(
            client, registry, "h", "s", client_id="0a:00:00:00:00:22"
        )
        assert result["is_wired"] is True
        assert result["sw_port"] == 22

    async def test_unknown_future_fields_survive(self, client, registry):
        client.get.return_value = _sta_payload()
        result = await _get_client_link_diagnostics(
            client, registry, "h", "s", client_id="0a:00:00:00:00:11"
        )
        # Data-survival: a field the server has never heard of must pass through verbatim.
        assert result["some_future_diag_field"] == {"nested": "survives"}
        # Policy/link fields are all present unchanged.
        assert result["qos_policy_applied"] is True
        assert result["fixed_ip"] == "203.0.113.11"
        assert result["vlan"] == 20

    async def test_mac_separator_insensitive(self, client, registry):
        client.get.return_value = _sta_payload()
        # bare 12-hex form of 0a:00:00:00:00:11
        result = await _get_client_link_diagnostics(
            client, registry, "h", "s", client_id="0A0000000011"
        )
        assert result["_id"] == "clientdoc0000000000000001"

    async def test_missing_client_fails_clearly(self, client, registry):
        client.get.return_value = _sta_payload()
        with pytest.raises(ValueError, match="No client matching"):
            await _get_client_link_diagnostics(
                client, registry, "h", "s", client_id="0a:00:00:00:00:ff"
            )

    async def test_requires_exactly_one_selector(self, client, registry):
        client.get.return_value = _sta_payload()
        with pytest.raises(ValueError, match="exactly one"):
            await _get_client_link_diagnostics(client, registry, "h", "s")
        with pytest.raises(ValueError, match="exactly one"):
            await _get_client_link_diagnostics(
                client, registry, "h", "s", client_id="x", client_ids=["y"]
            )

    async def test_multi_client_bounded_selection_returns_list_in_order(self, client, registry):
        client.get.return_value = _sta_payload()
        result = await _get_client_link_diagnostics(
            client,
            registry,
            "h",
            "s",
            client_ids=["0a:00:00:00:00:22", "clientdoc0000000000000001"],
        )
        assert isinstance(result, list)
        assert [r["_id"] for r in result] == [
            "clientdoc0000000000000002",
            "clientdoc0000000000000001",
        ]

    async def test_multi_client_missing_fails_clearly(self, client, registry):
        client.get.return_value = _sta_payload()
        with pytest.raises(ValueError, match="0a:00:00:00:00:ee"):
            await _get_client_link_diagnostics(
                client,
                registry,
                "h",
                "s",
                client_ids=["0a:00:00:00:00:11", "0a:00:00:00:00:ee"],
            )

    async def test_multi_client_exceeds_bound_rejected(self, client, registry):
        client.get.return_value = _sta_payload()
        too_many = [f"0a:00:00:00:00:{i:02x}" for i in range(65)]
        with pytest.raises(ValueError, match="bounded maximum"):
            await _get_client_link_diagnostics(client, registry, "h", "s", client_ids=too_many)
        # Selection is in-memory over one fetch — it must never fan out per identifier.
        client.get.assert_called_once()

    async def test_threads_owning_key_for_host(self, client, registry):
        # Multi-key routing: the resolved key must be threaded through every registry call
        # and the client GET, so the request rides the console-owning key.
        registry.resolve_key_for_host = AsyncMock(return_value="KEY-B")
        registry.resolve_host_id = AsyncMock(return_value=HOST_ID)
        registry.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
        client.get.return_value = _sta_payload()
        await _get_client_link_diagnostics(
            client, registry, "h", "s", client_id="0a:00:00:00:00:11"
        )
        registry.resolve_host_id.assert_called_once_with("h", key="KEY-B")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key="KEY-B")
        client.get.assert_called_once_with(f"{STAT_BASE}/sta", key="KEY-B")


def _device_payload():
    """A /stat/device response for one PoE switch with copper, SFP, and down ports."""
    return {
        "meta": {"rc": "ok"},
        "data": [
            {
                "_id": "devicedoc000000000000aa01",
                "mac": "00:00:5e:00:53:01",
                "name": "USW Pro 24 PoE",
                "model": "US24PRO",
                # device-level STP + thermal/power
                "stp_version": "rstp",
                "stp_priority": "4096",
                "root_switch": "00:00:5e:00:53:01",
                "stp_experimental_future": "carried",
                "general_temperature": 46,
                "fan_level": 30,
                "overheating": False,
                "total_used_power": "12.5",
                "total_max_power": "95.0",
                "lldp_table": [
                    {
                        "local_port_idx": 22,
                        "chassis_id": "0a:00:00:00:0a:22",
                        "port_id": "eth0",
                        "is_wired": True,
                    }
                ],
                "port_table": [
                    {
                        "port_idx": 1,
                        "name": "PoE AP",
                        "up": True,
                        "speed": 1000,
                        "full_duplex": True,
                        "media": "GE",
                        "rx_bytes": 123456789,
                        "tx_bytes": 987654321,
                        "rx_errors": 0,
                        "tx_dropped": 3,
                        "poe_enable": True,
                        "poe_good": True,
                        "poe_power": "5.20",
                        "poe_voltage": "53.5",
                        "poe_current": 97,
                        "poe_class": "Class 4",
                        "poe_mode": "auto",
                        "portconf_id": "portconfdoc0000000000a1",
                        "stp_state": "forwarding",
                        "stp_role": "designated",
                        "stp_pathcost": 20000,
                        "unknown_port_field": "kept",
                    },
                    {
                        "port_idx": 10,
                        "name": "Empty",
                        "up": False,
                        "speed": 0,
                        "full_duplex": False,
                        "poe_enable": False,
                        "poe_power": "0.00",
                        "stp_state": "disabled",
                    },
                    {
                        "port_idx": 22,
                        "name": "test-uplink-22",
                        "up": True,
                        "speed": 1000,
                        "full_duplex": True,
                        "poe_enable": False,
                        "stp_state": "forwarding",
                        "stp_role": "root",
                        "stp_pathcost": 20000,
                    },
                    {
                        "port_idx": 25,
                        "name": "SFP+ 1",
                        "up": True,
                        "speed": 10000,
                        "full_duplex": True,
                        "media": "SFP+",
                        "sfp_found": True,
                        "sfp_part": "FTLX8574D3BCL",
                        "sfp_vendor": "UBIQUITI",
                        "sfp_serial": "SYN0000000001",
                        "sfp_rxfault": False,
                        "sfp_txfault": False,
                        "stp_state": "forwarding",
                    },
                ],
            }
        ],
    }


class TestGetDevicePortState:
    async def test_device_view_uses_stat_device_url(self, client, registry):
        client.get.return_value = _device_payload()
        await _get_device_port_state(client, registry, "h", "s", "00:00:5e:00:53:01")
        # Reuses the same /stat/device request as list_device_stats — no new route.
        client.get.assert_called_once_with(f"{STAT_BASE}/device", key=None)

    async def test_device_view_lists_all_ports_active_and_inactive(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_port_state(client, registry, "h", "s", "00:00:5e:00:53:01")
        idxs = [p["port_idx"] for p in result["port_table"]]
        assert idxs == [1, 10, 22, 25]
        up_states = {p["port_idx"]: p["up"] for p in result["port_table"]}
        assert up_states[1] is True and up_states[10] is False

    async def test_device_view_carries_lldp_and_thermal_power(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_port_state(client, registry, "h", "s", "00:00:5e:00:53:01")
        assert result["lldp_table"][0]["chassis_id"] == "0a:00:00:00:0a:22"
        tp = result["thermal_power"]
        assert tp["general_temperature"] == 46
        assert tp["fan_level"] == 30
        assert tp["overheating"] is False
        assert tp["total_used_power"] == "12.5"
        assert tp["total_max_power"] == "95.0"

    async def test_port_view_returns_row_verbatim_with_envelope(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_port_state(
            client, registry, "h", "s", "00:00:5e:00:53:01", port_idx=1
        )
        assert result["device"] == "00:00:5e:00:53:01"
        assert result["port_idx"] == 1
        assert result["source"] == "/stat/device"
        port = result["port"]
        # PoE numeric / string / zero values all preserved with their upstream types.
        assert port["poe_enable"] is True
        assert port["poe_power"] == "5.20"
        assert port["poe_current"] == 97
        assert port["poe_class"] == "Class 4"
        # Counters and link speed/duplex preserved.
        assert port["rx_bytes"] == 123456789
        assert port["tx_dropped"] == 3
        assert port["speed"] == 1000
        assert port["full_duplex"] is True
        # No field dropped: an unknown port field survives.
        assert port["unknown_port_field"] == "kept"

    async def test_zero_poe_value_preserved_on_disabled_port(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_port_state(
            client, registry, "h", "s", "00:00:5e:00:53:01", port_idx=10
        )
        port = result["port"]
        assert port["up"] is False
        assert port["poe_enable"] is False
        assert port["poe_power"] == "0.00"
        assert port["speed"] == 0

    async def test_sfp_fields_absent_on_copper_present_on_sfp(self, client, registry):
        client.get.return_value = _device_payload()
        copper = await _get_device_port_state(
            client, registry, "h", "s", "00:00:5e:00:53:01", port_idx=22
        )
        assert "sfp_found" not in copper["port"]
        sfp = await _get_device_port_state(
            client, registry, "h", "s", "00:00:5e:00:53:01", port_idx=25
        )
        assert sfp["port"]["sfp_found"] is True
        assert sfp["port"]["sfp_serial"] == "SYN0000000001"
        assert sfp["port"]["speed"] == 10000

    async def test_select_device_by_id(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_port_state(
            client, registry, "h", "s", "devicedoc000000000000aa01", port_idx=1
        )
        assert result["port"]["name"] == "PoE AP"

    async def test_unknown_port_idx_fails_clearly(self, client, registry):
        client.get.return_value = _device_payload()
        with pytest.raises(ValueError, match="no port_idx=99"):
            await _get_device_port_state(
                client, registry, "h", "s", "00:00:5e:00:53:01", port_idx=99
            )

    async def test_unknown_device_fails_clearly(self, client, registry):
        client.get.return_value = _device_payload()
        with pytest.raises(ValueError, match="No device matching"):
            await _get_device_port_state(client, registry, "h", "s", "00:00:00:00:00:00")

    async def test_threads_owning_key_for_host(self, client, registry):
        registry.resolve_key_for_host = AsyncMock(return_value="KEY-B")
        registry.resolve_host_id = AsyncMock(return_value=HOST_ID)
        registry.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
        client.get.return_value = _device_payload()
        await _get_device_port_state(client, registry, "h", "s", "00:00:5e:00:53:01")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key="KEY-B")
        client.get.assert_called_once_with(f"{STAT_BASE}/device", key="KEY-B")


class TestGetDeviceStpState:
    async def test_uses_stat_device_url_fabric_only(self, client, registry):
        client.get.return_value = _device_payload()
        await _get_device_stp_state(client, registry, "h", "s", "00:00:5e:00:53:01")
        client.get.assert_called_once_with(f"{STAT_BASE}/device", key=None)
        client.post.assert_not_called()

    async def test_returns_device_level_stp_fields(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_stp_state(client, registry, "h", "s", "00:00:5e:00:53:01")
        stp = result["stp"]
        assert stp["stp_version"] == "rstp"
        assert stp["stp_priority"] == "4096"
        assert stp["root_switch"] == "00:00:5e:00:53:01"

    async def test_unknown_stp_field_survives(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_stp_state(client, registry, "h", "s", "00:00:5e:00:53:01")
        # Any stp_* key present upstream is carried through, not just the known floor set.
        assert result["stp"]["stp_experimental_future"] == "carried"

    async def test_per_port_stp_role_state_path_cost(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_stp_state(client, registry, "h", "s", "00:00:5e:00:53:01")
        by_idx = {p["port_idx"]: p for p in result["ports"]}
        assert by_idx[1]["stp_state"] == "forwarding"
        assert by_idx[1]["stp_role"] == "designated"
        assert by_idx[1]["stp_pathcost"] == 20000
        assert by_idx[22]["stp_role"] == "root"
        # A disabled port still reports its verbatim stp_state.
        assert by_idx[10]["stp_state"] == "disabled"

    async def test_select_by_id_and_not_found(self, client, registry):
        client.get.return_value = _device_payload()
        ok = await _get_device_stp_state(client, registry, "h", "s", "devicedoc000000000000aa01")
        assert ok["stp"]["stp_version"] == "rstp"
        with pytest.raises(ValueError, match="No device matching"):
            await _get_device_stp_state(client, registry, "h", "s", "ff:ff:ff:ff:ff:ff")
