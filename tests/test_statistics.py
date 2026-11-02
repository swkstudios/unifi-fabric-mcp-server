"""Tests for statistics — read-only stat endpoints via Classic REST."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from tests.conftest import MULTIKEY_HOSTS_BY_LABEL
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
        assert result["data"] == [{"subsystem": "wlan"}]

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        await _get_site_statistics(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID, key=None)

    async def test_extracts_data_list(self, client, registry):
        items = [{"subsystem": "wan"}, {"subsystem": "lan"}]
        client.get.return_value = {"meta": {"rc": "ok"}, "data": items}
        result = await _get_site_statistics(client, registry, "h", "s")
        assert result["data"] == items


# --- get_system_info ---


class TestGetSystemInfo:
    async def test_uses_stat_sysinfo_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"version": "8.0.0"}]}
        result = await _get_system_info(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/sysinfo", key=None)
        assert result["data"] == [{"version": "8.0.0"}]

    async def test_extracts_data(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"uptime": 123456}]}
        result = await _get_system_info(client, registry, "h", "s")
        assert result["data"][0]["uptime"] == 123456


# --- list_active_clients_stats ---


class TestListActiveClientsStats:
    async def test_uses_stat_sta_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"mac": "aa:bb:cc:dd:ee:ff"}]}
        result = await _list_active_clients_stats(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/sta", key=None)
        assert result["data"] == [{"mac": "aa:bb:cc:dd:ee:ff"}]

    async def test_extracts_data(self, client, registry):
        items = [{"mac": "aa:bb:cc:dd:ee:ff", "signal": -65}]
        client.get.return_value = {"meta": {"rc": "ok"}, "data": items}
        result = await _list_active_clients_stats(client, registry, "h", "s")
        assert result["data"] == items


# --- list_device_stats ---


class TestListDeviceStats:
    async def test_uses_stat_device_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"mac": "11:22:33:44:55:66"}]}
        result = await _list_device_stats(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/device", key=None)
        assert result["data"] == [{"mac": "11:22:33:44:55:66"}]

    async def test_extracts_data(self, client, registry):
        items = [{"mac": "11:22:33:44:55:66", "uptime": 9999}]
        client.get.return_value = {"meta": {"rc": "ok"}, "data": items}
        result = await _list_device_stats(client, registry, "h", "s")
        assert result["data"] == items

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
        session = result["data"][0]
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
        assert result["data"][0]["ap_mac"] is None
        assert result["data"][0]["sw_port"] == 5

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

    async def test_attrs_omitted_when_caller_passes_none(self, client, registry):
        client.post.return_value = {"data": []}
        await _get_historical_stats(client, registry, "h", "s", "hourly", "ap", _START_S, _END_S)
        assert client.post.call_args.kwargs["json"] == {
            "start": _START_S * 1000,
            "end": _END_S * 1000,
        }

    async def test_caller_attrs_sent_exactly_as_given(self, client, registry):
        client.post.return_value = {"data": []}
        await _get_historical_stats(
            client, registry, "h", "s", "hourly", "ap", _START_S, _END_S, ["wan-tx_bytes"]
        )
        assert client.post.call_args.kwargs["json"]["attrs"] == ["wan-tx_bytes"]

    async def test_empty_attrs_list_is_forwarded_not_replaced(self, client, registry):
        client.post.return_value = {"data": []}
        await _get_historical_stats(
            client, registry, "h", "s", "hourly", "ap", _START_S, _END_S, []
        )
        assert client.post.call_args.kwargs["json"]["attrs"] == []

    async def test_tool_level_call_sends_no_default_attrs(self, client, registry):
        from fastmcp import FastMCP

        from unifi_fabric.tools import statistics

        client.post.return_value = {"meta": {"rc": "ok"}, "data": []}
        mcp = FastMCP("test")
        statistics.register(mcp, lambda: (client, registry))
        await mcp.call_tool(
            "get_historical_stats",
            {
                "host": "h",
                "site": "s",
                "interval": "hourly",
                "scope": "site",
                "start": _START_S,
                "end": _END_S,
            },
        )
        assert "attrs" not in client.post.call_args.kwargs["json"]

    async def test_scientific_notation_bytes_preserved_as_float(self, client, registry):
        client.post.return_value = {
            "data": [{"time": 1_735_000_000_000, "num_sta": 12, "rx_bytes": 5.275171266916667e9}]
        }
        result = await _get_historical_stats(
            client, registry, "h", "s", "hourly", "ap", _START_S, _END_S
        )
        assert isinstance(result["data"][0]["rx_bytes"], float)
        assert result["data"][0]["num_sta"] == 12

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
        entry = result["data"][0]
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
# Focused convenience reads — same /stat/* payloads,
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
        # the /stat/sta envelope, data narrowed to the one selected record
        assert result["meta"] == {"rc": "ok"} and len(result["data"]) == 1
        result = result["data"][0]
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
        # the /stat/sta envelope, data narrowed to the one selected record
        assert result["meta"] == {"rc": "ok"} and len(result["data"]) == 1
        result = result["data"][0]
        assert result["mac"] == "0a:00:00:00:00:11"
        assert result["is_wired"] is False
        assert result["radio_name"] == "wifi1"

    async def test_selects_wired_client(self, client, registry):
        client.get.return_value = _sta_payload()
        result = await _get_client_link_diagnostics(
            client, registry, "h", "s", client_id="0a:00:00:00:00:22"
        )
        # the /stat/sta envelope, data narrowed to the one selected record
        assert result["meta"] == {"rc": "ok"} and len(result["data"]) == 1
        result = result["data"][0]
        assert result["is_wired"] is True
        assert result["sw_port"] == 22

    async def test_unknown_future_fields_survive(self, client, registry):
        client.get.return_value = _sta_payload()
        result = await _get_client_link_diagnostics(
            client, registry, "h", "s", client_id="0a:00:00:00:00:11"
        )
        # the /stat/sta envelope, data narrowed to the one selected record
        assert result["meta"] == {"rc": "ok"} and len(result["data"]) == 1
        result = result["data"][0]
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
        # the /stat/sta envelope, data narrowed to the one selected record
        assert result["meta"] == {"rc": "ok"} and len(result["data"]) == 1
        result = result["data"][0]
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
        assert result["meta"] == {"rc": "ok"}
        assert [r["_id"] for r in result["data"]] == [
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

    async def test_multi_client_has_no_selector_limit(self, client, registry):
        records = [
            {"_id": f"c{i}", "mac": f"0a:00:00:00:{i // 256:02x}:{i % 256:02x}"} for i in range(200)
        ]
        client.get.return_value = {"meta": {"rc": "ok"}, "data": records}
        result = await _get_client_link_diagnostics(
            client, registry, "h", "s", client_ids=[r["_id"] for r in records]
        )
        assert len(result["data"]) == 200
        # Selection is in-memory over one fetch — it never fans out per identifier.
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
        tp = result["_thermal_power"]
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
        assert result["_device"] == "00:00:5e:00:53:01"
        assert result["_port_idx"] == 1
        assert result["_source"] == "/stat/device"
        port = result["_port"]
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

    async def test_negative_port_idx_fails_before_any_request(self, client, registry):
        with pytest.raises(ValueError, match="non-negative port number"):
            await _get_device_port_state(
                client, registry, "h", "s", "00:00:5e:00:53:01", port_idx=-1
            )

        registry.resolve_key_for_host.assert_not_awaited()
        registry.resolve_host_id.assert_not_awaited()
        registry.resolve_site_slug.assert_not_awaited()
        client.get.assert_not_awaited()

    async def test_zero_port_idx_remains_valid(self, client, registry):
        payload = _device_payload()
        zero_port = {"port_idx": 0, "name": "synthetic-zero"}
        payload["data"][0]["port_table"].append(zero_port)
        client.get.return_value = payload

        result = await _get_device_port_state(
            client, registry, "h", "s", "00:00:5e:00:53:01", port_idx=0
        )

        assert result["_port_idx"] == 0
        assert result["_port"] is zero_port
        client.get.assert_awaited_once_with(f"{STAT_BASE}/device", key=None)

    async def test_zero_poe_value_preserved_on_disabled_port(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_port_state(
            client, registry, "h", "s", "00:00:5e:00:53:01", port_idx=10
        )
        port = result["_port"]
        assert port["up"] is False
        assert port["poe_enable"] is False
        assert port["poe_power"] == "0.00"
        assert port["speed"] == 0

    async def test_sfp_fields_absent_on_copper_present_on_sfp(self, client, registry):
        client.get.return_value = _device_payload()
        copper = await _get_device_port_state(
            client, registry, "h", "s", "00:00:5e:00:53:01", port_idx=22
        )
        assert "sfp_found" not in copper["_port"]
        sfp = await _get_device_port_state(
            client, registry, "h", "s", "00:00:5e:00:53:01", port_idx=25
        )
        assert sfp["_port"]["sfp_found"] is True
        assert sfp["_port"]["sfp_serial"] == "SYN0000000001"
        assert sfp["_port"]["speed"] == 10000

    @pytest.mark.parametrize("damage", [None, "drop-field", "change-value", "drop-port"])
    async def test_integration_sfp_check_uses_raw_hardware_and_exact_values(
        self, client, registry, monkeypatch, damage
    ):
        from tests import test_statistics_integration as integration

        client.get.return_value = _device_payload()
        monkeypatch.setattr(integration, "_TEST_HOST", "h")
        monkeypatch.setattr(integration, "_TEST_SITE", "s")

        async def projection(*args, **kwargs):
            import copy

            result = copy.deepcopy(await _get_device_port_state(*args, **kwargs))
            sfp = next(row for row in result["port_table"] if row["port_idx"] == 25)
            if damage == "drop-field":
                del sfp["sfp_serial"]
            elif damage == "change-value":
                sfp["sfp_serial"] = "SYN0000000002"
            elif damage == "drop-port":
                result["port_table"].remove(sfp)
            return result

        monkeypatch.setattr(integration, "_get_device_port_state", projection)
        check = integration.TestDevicePortStateIntegration().test_sfp_fields_projected_when_present
        if damage is None:
            await check(client, registry)
        else:
            with pytest.raises(AssertionError):
                await check(client, registry)

    async def test_select_device_by_id(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_port_state(
            client, registry, "h", "s", "devicedoc000000000000aa01", port_idx=1
        )
        assert result["_port"]["name"] == "PoE AP"

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
        stp = result["_stp"]
        assert stp["stp_version"] == "rstp"
        assert stp["stp_priority"] == "4096"
        assert stp["root_switch"] == "00:00:5e:00:53:01"

    async def test_unknown_stp_field_survives(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_stp_state(client, registry, "h", "s", "00:00:5e:00:53:01")
        # Any stp_* key present upstream is carried through, not just the known floor set.
        assert result["_stp"]["stp_experimental_future"] == "carried"

    async def test_per_port_stp_role_state_path_cost(self, client, registry):
        client.get.return_value = _device_payload()
        result = await _get_device_stp_state(client, registry, "h", "s", "00:00:5e:00:53:01")
        by_idx = {p["port_idx"]: p for p in result["_ports"]}
        assert by_idx[1]["stp_state"] == "forwarding"
        assert by_idx[1]["stp_role"] == "designated"
        assert by_idx[1]["stp_pathcost"] == 20000
        assert by_idx[22]["stp_role"] == "root"
        # A disabled port still reports its verbatim stp_state.
        assert by_idx[10]["stp_state"] == "disabled"

    async def test_select_by_id_and_not_found(self, client, registry):
        client.get.return_value = _device_payload()
        ok = await _get_device_stp_state(client, registry, "h", "s", "devicedoc000000000000aa01")
        assert ok["_stp"]["stp_version"] == "rstp"
        with pytest.raises(ValueError, match="No device matching"):
            await _get_device_stp_state(client, registry, "h", "s", "ff:ff:ff:ff:ff:ff")


# --- identifier descriptions + not-found hints (MAC / classic _id, not Integration ids) ---

_INTEGRATION_DEVICE_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa7"


class TestClassicSelectorIdentifiers:
    """These tools select from classic /stat/device and /stat/sta payloads, which carry the
    MAC and a classic _id but never the Integration API id that list_site_devices /
    list_clients return in data[].id. Descriptions and errors must say so."""

    async def test_device_not_found_names_accepted_identifiers(self, client, registry):
        client.get.return_value = {
            "meta": {"rc": "ok"},
            "data": [{"_id": "classic-dev-1", "mac": "0a:00:00:00:00:01", "port_table": []}],
        }
        with pytest.raises(ValueError) as exc:
            await _get_device_port_state(client, registry, "h", "s", _INTEGRATION_DEVICE_ID)
        msg = str(exc.value)
        assert "No device matching" in msg
        assert "list_device_stats" in msg
        assert "list_site_devices data[].id) is a different identifier" in msg

    async def test_client_not_found_names_accepted_identifiers(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        with pytest.raises(ValueError) as exc:
            await _get_client_link_diagnostics(client, registry, "h", "s", client_id="x-1")
        assert "list_active_clients_stats" in str(exc.value)
        assert "list_clients data[].id) is a different identifier" in str(exc.value)

    async def test_multi_client_not_found_names_accepted_identifiers(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        with pytest.raises(ValueError) as exc:
            await _get_client_link_diagnostics(client, registry, "h", "s", client_ids=["x-1"])
        assert "list_active_clients_stats" in str(exc.value)

    @pytest.mark.parametrize(
        "tool,param,classic_source,integration_source",
        [
            ("get_device_port_state", "device_id", "list_device_stats", "list_site_devices"),
            ("get_device_stp_state", "device_id", "list_device_stats", "list_site_devices"),
            (
                "get_client_link_diagnostics",
                "client_id",
                "list_active_clients_stats",
                "list_clients",
            ),
        ],
    )
    async def test_param_description_states_mac_or_classic_id(
        self, tool, param, classic_source, integration_source
    ):
        from unifi_fabric import server

        desc = (await server.mcp.get_tool(tool)).parameters["properties"][param]["description"]
        assert "MAC" in desc
        assert "_id" in desc and classic_source in desc
        assert f"{integration_source} data[].id" in desc
        assert "does not match" in desc

    async def test_historical_stats_description_explains_empty_report(self):
        from unifi_fabric import server

        desc = (await server.mcp.get_tool("get_historical_stats")).description or ""
        assert "An empty data array means the controller has no report rows" in desc
        assert "aggregated-dashboard" in desc


# --- list_known_clients: v2 client-history source (additive; Classic stays the default) ---

V2_HISTORY = (
    f"/v1/connector/consoles/{HOST_ID}/proxy/network/v2/api/site/{SITE_SLUG}/clients/history"
)


class TestListKnownClientsV2History:
    async def test_default_stays_classic_alluser(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        await _list_known_clients(client, registry, "h", "s", source="classic")
        await _list_known_clients(client, registry, "h", "s", source="")
        assert [c.args[0] for c in client.get.call_args_list] == [f"{STAT_BASE}/alluser"] * 2

    async def test_source_v2_returns_body_verbatim(self, client, registry):
        body = [{"mac": "02:00:00:00:00:09", "last_seen": 1_700_000_000}]
        client.get.return_value = body
        result = await _list_known_clients(client, registry, "h", "s", source="v2")
        client.get.assert_called_once_with(V2_HISTORY, key=None)
        assert result is body

    async def test_v2_arguments_select_v2_and_are_sent_as_given(self, client, registry):
        client.get.return_value = []
        await _list_known_clients(
            client,
            registry,
            "h",
            "s",
            within_hours=24,
            only_blocked=False,
            only_non_blocked=True,
            include_matter_thread_clients=True,
            include_traffic_usage=False,
            include_unifi_devices=True,
        )
        client.get.assert_called_once_with(
            V2_HISTORY,
            key=None,
            params={
                "onlyBlocked": "false",
                "onlyNonBlocked": "true",
                "includeMatterThreadClients": "true",
                "includeTrafficUsage": "false",
                "includeUnifiDevices": "true",
                "withinHours": "24",
            },
        )

    @pytest.mark.parametrize(
        "kwargs",
        [{"source": "history"}, {"source": "classic", "within_hours": 1}],
    )
    async def test_invalid_source_refused_before_any_request(self, client, registry, kwargs):
        with pytest.raises(ValueError, match="source must be one of|source conflict"):
            await _list_known_clients(client, registry, "h", "s", **kwargs)
        registry.resolve_key_for_host.assert_not_called()
        client.get.assert_not_called()

    async def test_upstream_error_keeps_reason(self, client, registry):
        client.get.side_effect = UniFiConnectionError("HTTP 500 Internal: {'msg': 'boom'}")
        with pytest.raises(UniFiConnectionError, match="boom"):
            await _list_known_clients(client, registry, "h", "s", source="v2")


async def test_list_known_clients_v2_routes_to_owning_key(multikey_client, multikey_registry):
    for label, hosts in MULTIKEY_HOSTS_BY_LABEL.items():
        await multikey_registry.set_hosts(hosts, key=multikey_client.get_key_by_label(label))
    multikey_registry.resolve_host_id = AsyncMock(return_value="console-beta-1")
    multikey_registry.resolve_site_slug = AsyncMock(return_value="default")
    captured: dict[str, object] = {}

    async def _get(path, *, key=None, params=None):
        captured["key"] = key
        return []

    multikey_client.get = AsyncMock(side_effect=_get)
    await _list_known_clients(
        multikey_client, multikey_registry, "Beta-Branch", "Default", within_hours=1
    )
    assert captured["key"] is not None and captured["key"].label == "beta"


class TestHealthSummary:
    async def test_site_statistics_adds_summary_beside_verbatim_body(self, client, registry):
        body = {
            "meta": {"rc": "ok"},
            "data": [
                {"subsystem": "wan", "status": "ok", "latency": 7},
                {"subsystem": "wlan", "status": "warning"},
                {"subsystem": "vpn", "status": "unknown"},
                "not-a-record",
            ],
        }
        client.get.return_value = body
        result = await _get_site_statistics(client, registry, "h", "s")
        assert {k: v for k, v in result.items() if k != "_healthSummary"} == body
        assert result["_healthSummary"] == {
            "subsystems": {"wan": "ok", "wlan": "warning", "vpn": "unknown"},
            "notOk": ["wlan", "vpn"],
            "allOk": False,
        }

    @pytest.mark.parametrize(
        "body",
        [
            {"meta": {"rc": "ok"}, "data": []},
            {"meta": {"rc": "ok"}, "data": {"numSta": 1}},
            {"meta": {"rc": "ok"}, "data": [{"status": "ok"}]},
        ],
    )
    async def test_no_summary_without_subsystem_records(self, client, registry, body):
        client.get.return_value = body
        result = await _get_site_statistics(client, registry, "h", "s")
        assert result == body
        assert "_healthSummary" not in result

    async def test_upstream_field_named_like_summary_is_kept(self, client, registry):
        body = {"meta": {"rc": "ok"}, "_healthSummary": "upstream", "data": [{"subsystem": "lan"}]}
        client.get.return_value = body
        result = await _get_site_statistics(client, registry, "h", "s")
        assert result["_healthSummary"] == "upstream"
        assert result["_wrapperFields"]["_healthSummary"]["notOk"] == ["lan"]
