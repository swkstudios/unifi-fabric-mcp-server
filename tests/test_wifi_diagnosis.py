"""diagnose_wifi on fixtures built from real recorded shapes.

The JSON files in ``tests/fixtures/wifi_diagnosis`` are sanitized captures of the dev
console's Wi-Fi reads (MACs, SSIDs and names replaced). The ``stat/device`` and WLAN
records are built here from the field names the console returns, with canary values in
every key-material field so a test can prove none of them reaches the result.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.families.devices import wifi_diagnosis as wd

FIXTURES = Path(__file__).parent / "fixtures" / "wifi_diagnosis"
AP1, AP2, AP3 = "02:00:5e:00:00:a1", "02:00:5e:00:00:a2", "02:00:5e:00:00:a3"
NOW = 1794365940.0  # 2026-11-11T02:59Z, the moment the fixtures were read

CANARIES = {
    name: f"canary value for {name}"
    for name in (  # gitleaks:allow
        "x_authkey",  # gitleaks:allow (synthetic canary)
        "syslog_key",
        "x_vwirekey",
        "guest_token",
        "x_passphrase",
        "x_iapp_key",
    )
}


def fx(name: str) -> Any:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def _radio(band, name, channel, bw, power, *, ext=None, pct=2.0, packets=5000, **extra):
    return {
        "stat": {
            "radio": band,
            "state": "RUN",
            "channel": channel,
            "bw": bw,
            "tx_power": power,
            "tx_packets": packets,
            "tx_retries": int(packets * pct / 100),
            "tx_retries_pct": pct,
            "num_sta": 3,
            "cu_total": 20,
            "cu_interf": 3,
            **({"extchannel": ext} if ext is not None else {}),
            **extra,
        },
        "table": {"radio": band, "name": name, "channel": channel, "ht": str(bw)},
    }


def _ap(mac, name, radios, *, state=1, uplink=None, ssid="Home", **extra):
    vaps = [
        {"radio": r["stat"]["radio"], "essid": ssid, "up": True, "bssid": f"{mac[:-2]}f{i}"}
        for i, r in enumerate(radios)
    ]
    return {
        "_id": "dev-" + name,
        "mac": mac,
        "name": name,
        "model": "U7PXGS",
        "type": "uap",
        "state": state,
        "radio_table_stats": [r["stat"] for r in radios],
        "radio_table": [r["table"] for r in radios],
        "vap_table": vaps,
        "uplink": uplink or {"speed": 1000, "max_speed": 10000, "rx_errors": 0, "rx_dropped": 0},
        **CANARIES,
        **extra,
    }


def devices():
    return [
        _ap(
            AP1,
            "ap-one",
            [
                _radio("ng", "wifi0", 1, 40, 14, ext=1, pct=11.7),
                _radio("na", "wifi1", 60, 160, 24, pct=9.7),
                _radio("6e", "wifi2", 69, 160, 21, pct=12.9),
            ],
        ),
        _ap(
            AP2,
            "ap-two",
            [
                _radio("ng", "wifi0", 11, 20, 6, pct=16.7),
                _radio("na", "wifi1", 112, 80, 20, pct=5.8),
                _radio("6e", "wifi2", 37, 80, 6, pct=11.4),
            ],
        ),
        {
            "_id": "dev-ap-three",
            "mac": AP3,
            "name": "ap-three",
            "model": "U6PRO",
            "type": "uap",
            "state": 0,
            "disconnected_at": 1786829815,
            "last_seen": 1786829815,
            "radio_table_stats": [{"radio": "ng", "state": None}, {"radio": "na", "state": None}],
            "radio_table": [],
            "vap_table": [],
            **CANARIES,
        },
        {"_id": "dev-switch", "mac": "02:00:5e:00:00:b1", "name": "switch", "type": "usw"},
    ]


def wlans():
    base = {
        "enabled": True,
        "wlan_bands": ["2g", "5g", "6g"],
        "b_supported": False,
        "minrate_ng_enabled": True,
        "minrate_ng_data_rate_kbps": 12000,
        "roaming_assistant_na_enabled": False,
        "roaming_assistant_na_rssi": -75,
        "roaming_assistant_6e_enabled": True,
        "roaming_assistant_6e_rssi": -88,
        "bss_transition": True,
        "fast_roaming_enabled": False,
        "rrm_enabled": True,
        "pmf_mode": "required",
        "wpa3_support": True,
        **CANARIES,
    }
    return [
        {**base, "_id": "wlan-4353", "name": "Home"},
        {
            **base,
            "_id": "wlan-0889",
            "name": "Home Legacy",
            "wlan_bands": ["2g"],
            "b_supported": True,
            "minrate_ng_enabled": False,
            "bss_transition": False,
            "rrm_enabled": False,
            "pmf_mode": "optional",
        },
        {**base, "_id": "wlan-a79c", "name": "Home 2", "wlan_bands": ["5g"]},
        {**base, "_id": "wlan-ba91", "name": "Cameras", "wlan_bands": ["5g"]},
    ]


def inputs(**over) -> wd.Inputs:
    base = {
        "devices": devices(),
        "clients": fx("stat_sta")["data"],
        "now": NOW,
        "window_hours": 24,
        "radio_window": fx("wifi_stats_radios")["radio_details"],
        "client_window": fx("wifi_stats_details")["client_details"],
        "connectivity": fx("wifi_connectivity"),
        "neighbors": fx("stat_rogueap")["data"],
        "wlans": wlans(),
        "radio_ai": fx("rest_setting_radio_ai")["data"][0],
        "channel_plan": fx("rest_channelplan")["data"],
        "channels": fx("stat_current_channel")["data"][0],
        "spectrum": fx("stat_spectrum_scan")["data"],
    }
    base.update(over)
    return wd.Inputs(**base)


def run(**over):
    limits = wd.validate_thresholds(over.pop("thresholds", None))
    return wd.analyse(inputs(**over), limits)


def by_rule(report, rule):
    return [f for f in report["findings"] if f["rule"] == rule]


def sta_by_name(name):
    return next(c for c in fx("stat_sta")["data"] if c.get("name") == name)


# --- geometry -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "band,channel,width,ext,expected",
    [
        ("na", 60, 160, None, (5170, 5330)),  # 160 MHz on primary 60 spans channels 36 to 64
        ("na", 112, 80, None, (5490, 5570)),  # 80 MHz on primary 112 spans channels 100 to 112
        ("na", 100, 160, None, (5490, 5650)),
        ("na", 36, 20, None, (5170, 5190)),
        ("ng", 1, 20, None, (2402, 2422)),
        ("ng", 1, 40, 1, (2402, 2442)),
        ("6e", 69, 160, None, (6265, 6425)),
        ("6e", 37, 80, None, (6105, 6185)),
    ],
)
def test_occupied_span_uses_primary_channel_and_width(band, channel, width, ext, expected):
    assert wd.occupied_span(band, channel, width, ext) == expected


@pytest.mark.parametrize("band,channel", [("zz", 1), ("na", None), ("na", "x")])
def test_occupied_span_is_none_for_unknown_input(band, channel):
    assert wd.occupied_span(band, channel, 20) is None


# --- offline APs, key material, composition ---------------------------------------------


def test_offline_ap_is_reported_and_not_counted_as_checked():
    report = run()
    assert report["summary"]["accessPointsChecked"] == 2
    assert report["summary"]["accessPointsNotAssessed"] == 1
    assert report["summary"]["radiosChecked"] == 6
    [finding] = by_rule(report, "ap_offline")
    assert finding["subject"]["name"] == "ap-three"
    assert finding["evidence"]["disconnected_at"] == "2026-08-15T21:36:55Z"
    assert finding["evidence"]["offline_days"] == 87.2
    offline = next(a for a in report["accessPoints"] if a["mac"] == AP3)
    assert offline["online"] is False and offline["radios"] == []


def test_result_never_carries_key_material_or_upstream_bodies():
    report = run()
    text = json.dumps(report)
    for value in CANARIES.values():
        assert value not in text
    forbidden = ("authkey", "syslog_key", "vwirekey", "guest_token", "passphrase", "iapp_key")

    def walk(node):
        if isinstance(node, dict):
            for key, child in node.items():
                assert not any(word in key.lower() for word in forbidden), key
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(report)
    assert set(report) == {"summary", "findings", "skipped", "notAssessed", "accessPoints"}


# --- existing rules, corrected ----------------------------------------------------------


def test_high_power_overlap_sees_different_widths_on_overlapping_channels():
    devs = devices()
    devs[0]["radio_table_stats"][1].update(channel=100, bw=160, tx_power=24)
    devs[1]["radio_table_stats"][1].update(channel=112, bw=80, tx_power=24)
    [finding] = by_rule(run(devices=devs), "high_power_co_channel")
    assert finding["subject"] == {"type": "radio_pair", "band": "na"}
    assert {r["name"] for r in finding["evidence"]["radios"]} == {"ap-one", "ap-two"}
    # the same radios on separate blocks do not overlap
    devs[1]["radio_table_stats"][1].update(channel=149, bw=80)
    assert by_rule(run(devices=devs), "high_power_co_channel") == []
    # a lower power is never reported
    devs[1]["radio_table_stats"][1].update(channel=112, bw=80, tx_power=10)
    assert by_rule(run(devices=devs), "high_power_co_channel") == []


def test_high_power_overlap_on_24ghz_uses_channel_distance():
    devs = devices()
    devs[0]["radio_table_stats"][0].update(channel=1, bw=20, tx_power=22, extchannel=None)
    devs[1]["radio_table_stats"][0].update(channel=4, bw=20, tx_power=22)
    assert len(by_rule(run(devices=devs), "high_power_co_channel")) == 1
    devs[1]["radio_table_stats"][0].update(channel=6)
    assert by_rule(run(devices=devs), "high_power_co_channel") == []


def test_non_standard_2ghz_channel():
    devs = devices()
    devs[1]["radio_table_stats"][0]["channel"] = 4
    [finding] = by_rule(run(devices=devs), "non_standard_2ghz_channel")
    assert finding["evidence"]["channel"] == 4


def test_sticky_threshold_follows_the_ssid_roaming_assistant_per_band():
    sta = copy.deepcopy(sta_by_name("Client 01"))
    sta.update(
        is_wired=False, radio="6e", essid="Home", ap_mac=AP1, signal=-82, rssi=10, uptime=4000
    )
    report = run(clients=[sta])
    assert by_rule(report, "sticky_client") == []  # -82 is better than the 6 GHz setting, -88
    sta["signal"] = -90
    [finding] = by_rule(run(clients=[sta]), "sticky_client")
    ev = finding["evidence"]
    assert ev["threshold_dbm"] == -88 and "roaming_assistant_6e_rssi" in ev["threshold_basis"]
    assert {a["name"] for a in ev["other_aps_with_same_ssid_and_band"]} == {"ap-two"}
    # an explicit threshold overrides the setting
    sta["signal"] = -70
    report = run(clients=[sta], thresholds={"sticky_rssi_dbm": -65})
    assert by_rule(report, "sticky_client")[0]["evidence"]["threshold_basis"].startswith(
        "thresholds"
    )


def test_sticky_client_is_skipped_when_its_snr_is_fine():
    sta = copy.deepcopy(sta_by_name("Client 01"))
    sta.update(is_wired=False, radio="na", essid="Home", ap_mac=AP1, signal=-79, uptime=4000)
    sta["rssi"] = 40
    assert by_rule(run(clients=[sta]), "sticky_client") == []
    sta["rssi"] = 12
    assert len(by_rule(run(clients=[sta]), "sticky_client")) == 1


def test_high_tx_retries_uses_the_window_average_per_band():
    report = run()
    assert by_rule(report, "high_tx_retries") == []  # 11.7 and 16.7 are normal on 2.4 GHz
    [finding] = by_rule(run(thresholds={"high_tx_retries_pct_2ghz": 15}), "high_tx_retries")
    assert finding["evidence"]["basis"] == "24 h average"
    assert finding["evidence"]["tx_retries_pct"] == 16.7
    assert "get_wifi_stats" in finding["recommendation"]
    assert "get_device_tx_retries" not in finding["recommendation"]
    # without the window the snapshot is used
    devs = devices()
    devs[0]["radio_table_stats"][0]["tx_retries_pct"] = 40.0
    report = run(devices=devs, radio_window=None, unavailable={"wifi-stats/radios": "boom"})
    [finding] = by_rule(report, "high_tx_retries")
    assert finding["evidence"]["basis"] == "current snapshot"


# --- new rules, on the recorded shapes --------------------------------------------------


def test_connection_failures_name_the_stage_client_and_ssid():
    report = run()
    found = {
        (f["subject"].get("name"), f["evidence"].get("stage")): f
        for f in by_rule(report, "connection_failures")
        if f["subject"]["type"] == "client"
    }
    ac = found[("Game Room AC", "authentication")]
    assert ac["evidence"]["failed_attempts"] == 20
    assert ac["evidence"]["failure_reasons"] == {"WPA_AUTHENTICATION_FAILURE": 20}
    assert ac["evidence"]["ssid"] == "Home Legacy"
    assert ("Net AC", "authentication") in found
    # one failure is below the threshold: a single DHCP timeout or one auth failure is noise
    assert ("Game Room AC", "dhcp") not in found and ("Phone B", "authentication") not in found
    [site] = [f for f in by_rule(report, "connection_failures") if f["subject"]["type"] == "site"]
    assert site["evidence"]["success_ratio_pct"] == 88
    assert site["evidence"]["stage_ratios_pct"]["dhcp"] == 88


def test_radio_window_health_flags_the_busy_24ghz_radio_only():
    [finding] = by_rule(run(), "radio_window_health")
    assert finding["subject"]["name"] == "ap-one" and finding["subject"]["band"] == "ng"
    ev = finding["evidence"]
    assert ev["utilization_avg_pct"] == 55.9 and ev["interference_avg_pct"] == 29.4
    assert ev["window_hours"] == 24
    assert len(by_rule(run(thresholds={"high_utilization_pct": 40}), "radio_window_health")) == 2


def test_neighbor_co_channel_counts_only_strong_recent_foreign_networks():
    neighbors = [
        {
            "ap_mac": AP2,
            "band": "ng",
            "channel": 11,
            "bw": 20,
            "signal": -60 - i,
            "last_seen": NOW - 60,
            "bssid": f"02:00:5e:00:09:{i:02x}",
            "essid": f"Neighbor-{i}",
        }
        for i in range(6)
    ]
    own = {**neighbors[0], "bssid": devices()[1]["vap_table"][0]["bssid"]}
    stale = {**neighbors[1], "bssid": "02:00:5e:00:09:aa", "last_seen": NOW - 7200}
    weak = {**neighbors[2], "bssid": "02:00:5e:00:09:bb", "signal": -90}
    other_ch = {**neighbors[3], "bssid": "02:00:5e:00:09:cc", "channel": 1}
    report = run(neighbors=[*neighbors[2:], own, stale, weak, other_ch])
    assert by_rule(report, "neighbor_co_channel") == []  # four strong neighbours are below five
    report = run(neighbors=[*neighbors, own, stale, weak, other_ch])
    [finding] = by_rule(report, "neighbor_co_channel")
    assert finding["subject"]["name"] == "ap-two"
    assert finding["evidence"]["strong_neighbors"] == 6
    assert finding["evidence"]["strongest"][0]["signal_dbm"] == -60


def test_neighbor_rule_on_the_recorded_sample_is_quiet_with_defaults():
    # the real sample is mostly weak or stale neighbours: the recency and strength filters
    # keep it from reporting hundreds of channel-1 networks
    assert by_rule(run(), "neighbor_co_channel") == []


def test_spectrum_scan_quality_flags_old_and_implausible_scans_only():
    report = run()
    [finding] = by_rule(report, "spectrum_scan_quality")
    assert finding["subject"]["mac"] == AP3 and finding["evidence"]["ap_offline"] is True
    assert finding["evidence"]["implausible_rows"] == 4  # -21 dBm x3 and +1 dBm
    assert finding["evidence"]["age_hours"] > 2000
    assert any("other_bss_count" in s["reason"] for s in report["skipped"])
    fresh = run(thresholds={"max_spectrum_scan_age_hours": 1})
    assert {f["subject"]["mac"] for f in by_rule(fresh, "spectrum_scan_quality")} == {AP1, AP3}


def test_weak_snr_clients_use_the_snr_field():
    names = {f["subject"]["name"] for f in by_rule(run(), "weak_snr_clients")}
    expected = {
        c["name"]
        for c in fx("stat_sta")["data"]
        if c.get("is_wired") is False and c.get("rssi") is not None and c["rssi"] <= 15
    }
    assert names == expected and expected


def test_band_fit_names_a_client_held_on_a_weak_band_that_the_ssid_could_leave():
    report = run()
    found = by_rule(report, "band_fit")
    assert found
    for finding in found:
        ev = finding["evidence"]
        assert ev["band"] in ("6e", "na") and ev["snr_db"] <= 15
        assert (
            "ng" in ev["other_bands_offered_by_ssid"] or "na" in ev["other_bands_offered_by_ssid"]
        )
        assert "does not say whether the client supports" in ev["note"]


def test_airtime_hog_needs_a_big_share_at_a_low_rate():
    [finding] = by_rule(run(), "airtime_hog")
    assert finding["evidence"]["traffic_share_pct"] == 20
    assert finding["evidence"]["common_link_rate_mbps"] == 72.1
    # a camera with a similar share at 433 Mbps is not a hog
    assert all(f["subject"]["name"] != "Client 21" for f in by_rule(run(), "airtime_hog"))


def test_roam_churn_uses_the_window_roam_count():
    found = {f["evidence"]["roams"] for f in by_rule(run(), "roam_churn")}
    assert found == {12, 15}
    assert {8} == {
        f["evidence"]["roams"]
        for f in by_rule(run(thresholds={"roam_churn_count": 8}), "roam_churn")
    } - found


def test_client_retries_and_experience():
    report = run()
    assert by_rule(report, "client_retries") == []  # the recorded clients stay under 25 percent
    # at 20 percent, the client with 17,870 attempts qualifies and the one with 359 is too quiet
    [retry] = by_rule(run(thresholds={"high_client_retries_pct": 20}), "client_retries")
    assert retry["evidence"]["tx_retries_pct"] == 21.1
    assert by_rule(report, "client_experience") == []
    clients = fx("stat_sta")["data"]
    clients[0].update(is_wired=False, satisfaction=31, satisfaction_reason=2048, anomalies=1)
    [finding] = by_rule(run(clients=clients), "client_experience")
    assert finding["evidence"]["satisfaction"] == 31
    assert finding["evidence"]["satisfaction_reason_code"] == 2048


def test_ap_uplink_bottleneck_compares_uplink_speed_with_client_link_rates():
    clients = fx("stat_sta")["data"]
    fast = next(c for c in clients if c.get("is_wired") is False and c.get("ap_mac") == AP1)
    fast.update(tx_rate=2594100)
    found = {f["subject"]["name"]: f for f in by_rule(run(clients=clients), "ap_uplink_bottleneck")}
    assert found["ap-one"]["severity"] == "info"
    assert found["ap-one"]["evidence"]["fastest_client_link_rate_mbps"] == 2594.1
    assert found["ap-one"]["evidence"]["uplink_speed_mbps"] == 1000
    # a link rate under the uplink speed is not a bottleneck
    for client in clients:
        client.update(tx_rate=300000, rx_rate=300000)
    assert by_rule(run(clients=clients), "ap_uplink_bottleneck") == []
    devs = devices()
    devs[1]["uplink"]["rx_errors"] = 7
    found = by_rule(run(devices=devs), "ap_uplink_bottleneck")
    assert any(f["severity"] == "warning" and f["subject"]["name"] == "ap-two" for f in found)


def test_band_load_reports_the_24ghz_share_and_ap_imbalance():
    [site] = by_rule(run(), "band_load")
    wireless = [c for c in fx("stat_sta")["data"] if c.get("is_wired") is False]
    assert site["evidence"]["wireless_clients"] == len(wireless)
    assert site["evidence"]["clients_on_2ghz"] == sum(1 for c in wireless if c["radio"] == "ng")
    assert by_rule(run(thresholds={"max_2ghz_client_share_pct": 90}), "band_load") == []
    skewed = [{**c, "ap_mac": AP1} for c in wireless]
    found = by_rule(run(clients=skewed), "band_load")
    assert any("clients_per_ap" in f["evidence"] for f in found)


def test_channel_width_policy_flags_wide_24ghz_and_widths_over_the_site_policy():
    found = {
        (f["subject"]["name"], f["subject"]["band"]): f
        for f in by_rule(run(), "channel_width_policy")
    }
    assert ("ap-one", "ng") in found  # 40 MHz on 2.4 GHz
    na = found[("ap-one", "na")]
    assert na["evidence"]["allowed_widths_mhz"] == [20, 40]
    assert na["evidence"]["dfs_channel"] is True  # channel 60 is in the DFS range
    assert na["evidence"]["channel_ai_auto_enabled"] is False
    assert ("ap-two", "na") in found  # 80 MHz is wider than the policy
    assert ("ap-two", "ng") not in found


def test_channel_flap_reports_changes_in_the_window_and_dfs_moves():
    found = {
        (f["subject"]["name"], f["subject"]["radio"]): f for f in by_rule(run(), "channel_flap")
    }
    five = found[("ap-one", "wifi1")]
    assert five["evidence"]["changes"] == [
        {"on": "2026-11-09T09:04:26Z", "from": 100, "to": 60, "width_mhz": 160}
    ]
    assert five["evidence"]["latest_channel_is_dfs"] is True and five["severity"] == "info"
    assert ("ap-two", "wifi1") in found
    quiet = run(thresholds={"flap_window_days": 1})
    assert by_rule(quiet, "channel_flap") == []
    loud = run(thresholds={"flap_window_days": 90, "flap_min_changes": 2})
    assert any(f["severity"] == "warning" for f in by_rule(loud, "channel_flap"))


def test_wlan_config_audit_gives_advice_per_ssid_without_secrets():
    [finding] = by_rule(run(), "wlan_config_audit")
    assert finding["subject"]["name"] == "Home Legacy"
    checks = {i["check"] for i in finding["evidence"]["issues"]}
    assert checks == {"b_supported", "minrate_ng", "bss_transition", "rrm_enabled"}
    assert "passphrase" not in json.dumps(finding)
    # a disabled SSID is not audited
    disabled = wlans()
    disabled[1]["enabled"] = False
    assert by_rule(run(wlans=disabled), "wlan_config_audit") == []
    # 6 GHz without WPA3 is called out
    six = wlans()
    six[0]["wpa3_support"] = False
    [finding] = [
        f for f in by_rule(run(wlans=six), "wlan_config_audit") if f["subject"]["name"] == "Home"
    ]
    assert [i["check"] for i in finding["evidence"]["issues"]] == ["wpa3_support"]


# --- not assessed, never guessed ----------------------------------------------------------


def test_a_missing_read_is_not_assessed_and_never_a_finding():
    none = {
        "radio_window": None,
        "client_window": None,
        "connectivity": None,
        "neighbors": None,
        "wlans": None,
        "radio_ai": None,
        "channel_plan": None,
        "channels": None,
        "spectrum": None,
        "unavailable": {"wifi-connectivity": "HTTP 404"},
    }
    report = run(**none)
    assert set(report["notAssessed"]) >= {
        "radio_window_health",
        "connection_failures",
        "neighbor_co_channel",
        "spectrum_scan_quality",
        "channel_width_policy",
        "channel_flap",
        "wlan_config_audit",
        "band_fit",
        "airtime_hog",
        "roam_churn",
    }
    reason = next(s["reason"] for s in report["skipped"] if s["rule"] == "connection_failures")
    assert reason == "not assessed: wifi-connectivity unavailable (HTTP 404)"
    assert not set(report["summary"]["byRule"]) & {"connection_failures", "channel_flap"}


def test_a_site_without_the_fields_is_not_assessed():
    bare = {"_id": "a", "mac": AP1, "name": "bare", "type": "uap", "radio_table_stats": []}
    report = run(devices=[bare], clients=[])
    assert {"high_power_co_channel", "non_standard_2ghz_channel", "sticky_client"} <= set(
        report["notAssessed"]
    )
    assert by_rule(report, "high_power_co_channel") == []


def test_clean_site_has_no_findings():
    devs = [
        _ap(AP1, "a", [_radio("ng", "wifi0", 1, 20, 10), _radio("na", "wifi1", 36, 80, 14)]),
        _ap(AP2, "b", [_radio("ng", "wifi0", 6, 20, 10), _radio("na", "wifi1", 149, 80, 14)]),
    ]
    quiet = {
        "devices": devs,
        "clients": [],
        "radio_window": [],
        "client_window": [],
        "connectivity": {"attempts": {"success_ratio": 100}, "event_groups": []},
        "neighbors": [],
        "wlans": [],
        "radio_ai": {"ht_modes_na": ["20", "40", "80"], "ht_modes_ng": ["20"]},
        "channel_plan": [],
        "channels": {},
        "spectrum": [],
    }
    report = run(**quiet)
    assert report["findings"] == [], report["findings"]
    assert report["summary"]["clean"] is True and report["summary"]["accessPointsChecked"] == 2


# --- every rule is accounted for ------------------------------------------------------------

QUIET_RULES = {
    "high_power_co_channel",
    "non_standard_2ghz_channel",
    "high_tx_retries",
    "neighbor_co_channel",
    "client_retries",
    "client_experience",
}


def _accounted(report):
    """byRule and notAssessed must split the 20 rules: no rule missing, none in both."""
    by_rule, not_assessed = set(report["summary"]["byRule"]), set(report["notAssessed"])
    assert len(wd.RULES) == 20
    assert by_rule | not_assessed == set(wd.RULES), set(wd.RULES) - (by_rule | not_assessed)
    assert not by_rule & not_assessed, by_rule & not_assessed
    for rule, count in report["summary"]["byRule"].items():
        assert count == len(by_rule_findings(report, rule)), rule


def by_rule_findings(report, rule):
    return [f for f in report["findings"] if f["rule"] == rule]


def test_a_rule_that_ran_and_found_nothing_is_listed_with_a_zero_count():
    # on this fixture six rules run and find nothing: they must not vanish from the summary
    report = run()
    _accounted(report)
    assert report["notAssessed"] == []
    for rule in QUIET_RULES:
        assert report["summary"]["byRule"][rule] == 0, rule
    assert report["summary"]["byRule"]["ap_offline"] == 1
    # the listing follows the rule order, so a caller reads it the same way every time
    assert list(report["summary"]["byRule"]) == list(wd.RULES)


def test_the_split_holds_when_reads_are_missing_and_on_a_clean_site():
    none = {
        "radio_window": None,
        "client_window": None,
        "connectivity": None,
        "neighbors": None,
        "wlans": None,
        "radio_ai": None,
        "channel_plan": None,
        "channels": None,
        "spectrum": None,
    }
    partial = run(**none)
    _accounted(partial)
    assert partial["notAssessed"] and partial["summary"]["byRule"]
    bare = {"_id": "a", "mac": AP1, "name": "bare", "type": "uap", "radio_table_stats": []}
    _accounted(run(devices=[bare], clients=[], **none))
    clean = run(
        devices=[
            _ap(AP1, "a", [_radio("ng", "wifi0", 1, 20, 10), _radio("na", "wifi1", 36, 80, 14)])
        ],
        clients=[],
        radio_window=[],
        client_window=[],
        connectivity={"attempts": {"success_ratio": 100}, "event_groups": []},
        neighbors=[],
        wlans=[],
        radio_ai={"ht_modes_na": ["20", "40", "80"], "ht_modes_ng": ["20"]},
        channel_plan=[],
        channels={},
        spectrum=[],
    )
    _accounted(clean)
    assert clean["summary"]["clean"] is True
    assert all(
        count == 0
        for rule, count in clean["summary"]["byRule"].items()
        if rule not in clean["notAssessed"]
    )


async def test_the_tool_result_accounts_for_every_rule():
    out = await wd._diagnose_wifi(_Client(), _Registry(), "console", "Default", now=NOW)
    _accounted(out)
    assert {r for r, n in out["summary"]["byRule"].items() if n == 0} == QUIET_RULES


SCOPED_TO_APS = {
    "channel_width_policy",
    "high_tx_retries",
    "radio_window_health",
    "neighbor_co_channel",
    "ap_uplink_bottleneck",
}


def _assert_not_examined(report):
    _accounted(report)
    assert SCOPED_TO_APS <= set(report["notAssessed"]), SCOPED_TO_APS - set(report["notAssessed"])
    assert not SCOPED_TO_APS & set(report["summary"]["byRule"])
    reasons = {s["rule"]: s["reason"] for s in report["skipped"] if s["rule"] in SCOPED_TO_APS}
    assert all(r.startswith("not assessed: no ") for r in reasons.values()), reasons
    assert set(reasons) == SCOPED_TO_APS


def test_a_site_whose_aps_are_all_offline_does_not_report_radio_rules_as_clean():
    offline = [d for d in devices() if d.get("mac") == AP3]
    assert offline and offline[0]["state"] == 0
    report = run(devices=offline)
    assert report["summary"]["accessPointsChecked"] == 0
    assert report["summary"]["radiosChecked"] == 0
    _assert_not_examined(report)
    assert report["summary"]["byRule"]["ap_offline"] == 1  # the offline AP itself was examined


def test_a_site_with_no_devices_does_not_report_radio_rules_as_clean():
    report = run(devices=[], clients=[])
    assert report["summary"]["radiosChecked"] == 0
    _assert_not_examined(report)


def test_a_zero_means_the_rule_examined_something_and_found_nothing():
    report = run()
    zero = {rule for rule, n in report["summary"]["byRule"].items() if n == 0}
    assert zero == QUIET_RULES
    assert report["summary"]["radiosChecked"] > 0 and report["summary"]["accessPointsChecked"] > 0
    assert not SCOPED_TO_APS & set(report["notAssessed"])


# --- validation, tool wiring ------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides,match",
    [
        ({"weak_snr_db": "x"}, "'weak_snr_db' must be a number"),
        ({"weak_snr_db": True}, "'weak_snr_db' must be a number"),
        ({"weak_snr_db": 101}, "'weak_snr_db' must be between"),
        ({"high_tx_power_dbm": -1}, "'high_tx_power_dbm' must be between"),
        ({"flap_min_changes": 0}, "'flap_min_changes' must be between"),
        ("nope", "'thresholds' must be an object"),
    ],
)
def test_invalid_thresholds_name_the_threshold(overrides, match):
    with pytest.raises(ValueError, match=match):
        wd.validate_thresholds(overrides)


async def test_every_threshold_default_is_inside_its_range_and_documented():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    doc = " ".join(
        tools["diagnose_wifi"].parameters["properties"]["thresholds"]["description"].split()
    )
    for name, (default, low, high) in wd.THRESHOLD_SPECS.items():
        assert default is None or low <= default <= high
        assert name in doc


@pytest.mark.parametrize("value", [0, 169, "24", True, 1.5])
def test_window_hours_is_validated(value):
    with pytest.raises(ValueError, match="'window_hours'"):
        wd.validate_window_hours(value)


class _Registry:
    async def resolve_key_for_host(self, host):
        return None

    async def resolve_host_id(self, host, key=None):
        return "HOST1"

    async def resolve_site_slug(self, site, host_id, key=None):
        return "default"


ROUTES = {
    "/stat/device": lambda: {"meta": {"rc": "ok"}, "data": devices()},
    "/stat/sta": lambda: fx("stat_sta"),
    "/wifi-stats/radios": lambda: fx("wifi_stats_radios"),
    "/wifi-stats/details": lambda: fx("wifi_stats_details"),
    "/wifi-connectivity": lambda: fx("wifi_connectivity"),
    "/stat/rogueap": lambda: fx("stat_rogueap"),
    "/rest/wlanconf": lambda: {"meta": {"rc": "ok"}, "data": wlans()},
    "/rest/setting/radio_ai": lambda: fx("rest_setting_radio_ai"),
    "/rest/channelplan": lambda: fx("rest_channelplan"),
    "/stat/current-channel": lambda: fx("stat_current_channel"),
    "/stat/spectrum-scan": lambda: fx("stat_spectrum_scan"),
}


class _Client:
    def __init__(self, fail=()):
        self.paths: list[str] = []
        self.params: list[Any] = []
        self.fail = set(fail)

    async def get(self, path, key=None, params=None, **kwargs):
        self.paths.append(path)
        self.params.append(params)
        for suffix, body in ROUTES.items():
            if path.endswith(suffix):
                if suffix in self.fail:
                    raise RuntimeError("upstream said no")
                return body()
        raise AssertionError(f"unexpected read {path}")


async def test_tool_reads_eleven_get_routes_in_order_and_returns_only_used_fields():
    fake = _Client()
    out = await wd._diagnose_wifi(fake, _Registry(), "console", "Default", now=NOW)
    assert [
        p.split("/site/")[-1].split("/api/s/")[-1].split("default/")[-1] for p in fake.paths
    ] == [
        "stat/device",
        "stat/sta",
        "wifi-stats/radios",
        "wifi-stats/details",
        "wifi-connectivity",
        "stat/rogueap",
        "rest/wlanconf",
        "rest/setting/radio_ai",
        "rest/channelplan",
        "stat/current-channel",
        "stat/spectrum-scan",
    ]
    assert out["readOnly"] is True and out["windowHours"] == 24
    assert [s["status"] for s in out["sources"]] == ["read"] * 11
    assert "data" not in out and "_clientsResponse" not in out
    for value in CANARIES.values():
        assert value not in json.dumps(out)
    stats_params = fake.params[2]
    assert stats_params["end"] - stats_params["start"] == 24 * 3_600_000
    assert out["summary"]["accessPointsChecked"] == 2
    assert out["thresholds"]["weak_snr_db"] == 15


async def test_an_optional_read_that_fails_is_listed_not_fatal():
    fake = _Client(fail={"/wifi-connectivity", "/stat/spectrum-scan"})
    out = await wd._diagnose_wifi(fake, _Registry(), "console", "Default", now=NOW)
    statuses = {s["route"]: s for s in out["sources"]}
    assert statuses["wifi-connectivity"]["status"] == "unavailable"
    assert "upstream said no" in statuses["wifi-connectivity"]["reason"]
    assert {"connection_failures", "spectrum_scan_quality"} <= set(out["notAssessed"])
    assert by_rule(out, "radio_window_health")


async def test_a_failing_required_read_raises():
    with pytest.raises(RuntimeError, match="upstream said no"):
        await wd._diagnose_wifi(_Client(fail={"/stat/sta"}), _Registry(), "console", "Default")


async def test_an_unknown_threshold_name_is_ignored_and_reported():
    out = await wd._diagnose_wifi(
        _Client(), _Registry(), "console", "Default", thresholds={"weak_snr_dbb": 30}, now=NOW
    )
    assert out["thresholds"]["weak_snr_db"] == 15
    assert len(out["warnings"]) == 1 and "'weak_snr_dbb'" in out["warnings"][0]
    clean = await wd._diagnose_wifi(_Client(), _Registry(), "console", "Default", now=NOW)
    assert clean["warnings"] == []


async def test_invalid_input_makes_no_request():
    fake = _Client()
    with pytest.raises(ValueError, match="'weak_snr_db' must be between"):
        await wd._diagnose_wifi(
            fake, _Registry(), "console", "Default", thresholds={"weak_snr_db": 500}
        )
    with pytest.raises(ValueError, match="'window_hours'"):
        await wd._diagnose_wifi(fake, _Registry(), "console", "Default", window_hours=0)
    with pytest.raises(ValueError, match="'site'"):
        await wd._diagnose_wifi(fake, _Registry(), "console", " ")
    assert fake.paths == []


async def test_unexpected_shape_raises_with_the_shape_received():
    class Bad(_Client):
        async def get(self, path, key=None, **kwargs):
            return {"meta": {"rc": "ok"}, "data": "nope"}

    with pytest.raises(Exception, match="/stat/device"):
        await wd._diagnose_wifi(Bad(), _Registry(), "console", "Default")


async def test_tool_is_registered_read_only_and_every_property_is_described():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    tool = tools["diagnose_wifi"]
    assert tool.annotations.readOnlyHint is True
    props = tool.parameters["properties"]
    assert set(props) == {"host", "site", "thresholds", "window_hours"}
    assert all(props[name].get("description") for name in props)


async def test_owned_host_routes_every_read_to_the_second_key(
    monkeypatch, multikey_client, multikey_registry
):
    up = uh.FakeUpstream(hosts_by_key={"k-alpha": [], "k-beta": [copy.deepcopy(uh.HOST_RECORD)]})
    original = up._generic

    def serve(req):
        for suffix, body in ROUTES.items():
            if req.url.path.endswith(suffix):
                return body()
        return original(req)

    monkeypatch.setattr(up, "_generic", serve)

    async def http_session(key):
        if key.label not in multikey_client._clients:
            multikey_client._clients[key.label] = httpx.AsyncClient(
                base_url=multikey_client._settings.api_base_url,
                headers={"X-API-KEY": key.key},
                transport=httpx.MockTransport(up),
            )
        return multikey_client._clients[key.label]

    monkeypatch.setattr(multikey_client, "_get_client", http_session)
    out = await wd._diagnose_wifi(multikey_client, multikey_registry, uh.HOST, uh.SITE, now=NOW)
    assert out["summary"]["accessPointsChecked"] == 2
    nonresolution = [s for s in up.served if not s.resolution]
    assert len(nonresolution) >= 11 and all(s.api_key == "k-beta" for s in nonresolution)
    assert all(s.method == "GET" for s in nonresolution)
    await multikey_client.close()
