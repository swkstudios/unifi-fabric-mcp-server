"""Tests for statistics — read-only stat endpoints via Classic REST."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools.statistics import (
    _CLASSIC_STAT_BASE,
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
    r.resolve_host_id = AsyncMock(return_value=HOST_ID)
    r.resolve_site_slug = AsyncMock(return_value=SITE_SLUG)
    return r


# --- get_site_statistics ---


class TestGetSiteStatistics:
    async def test_uses_stat_health_url(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": [{"subsystem": "wlan"}]}
        result = await _get_site_statistics(client, registry, "h", "s")
        client.get.assert_called_once_with(f"{STAT_BASE}/health")
        assert result == [{"subsystem": "wlan"}]

    async def test_resolves_slug_not_uuid(self, client, registry):
        client.get.return_value = {"meta": {"rc": "ok"}, "data": []}
        await _get_site_statistics(client, registry, "h", "s")
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID)

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
        client.get.assert_called_once_with(f"{STAT_BASE}/sysinfo")
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
        client.get.assert_called_once_with(f"{STAT_BASE}/sta")
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
        client.get.assert_called_once_with(f"{STAT_BASE}/device")
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
        registry.resolve_site_slug.assert_called_once_with("s", HOST_ID)
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
        client.get.assert_called_once_with(f"{STAT_BASE}/alluser")
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
