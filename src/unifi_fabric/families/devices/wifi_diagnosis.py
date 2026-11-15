"""Read-only Wi-Fi diagnosis for one Network site, composed from existing reads.

``diagnose_wifi`` issues GET reads that other read tools already make (Classic
``stat/device`` and ``stat/sta``, Wi-Fi statistics, connectivity, neighbour, WLAN,
channel and spectrum reads), applies rules to the combined result and returns findings.
It never writes, and it is a *composed* tool: it returns only the fields its rules use,
never the upstream bodies. In particular no device key material (``x_authkey``,
``syslog_key``, ``x_vwirekey``, ``guest_token``) and no WLAN passphrase is ever copied
into the result; each rule reads named fields only.

Every finding names the access point, radio, client or SSID, carries the evidence values
it was computed from, and ends in a recommendation written as advice for a person.
Reads other than ``stat/device`` and ``stat/sta`` are optional: when one fails, the rules
that need it are listed under ``skipped`` and ``notAssessed`` with the reason, and a
missing input never produces a finding.

Threshold defaults are project choices (``DEFAULTS``) unless a source is named, and each
is overridable through the ``thresholds`` argument. Public guidance used:

* Minimum RSSI and roaming: Ubiquiti, "Understanding and Implementing Minimum RSSI"
  (https://help.ui.com/hc/en-us/articles/221321728) names -80 dBm as a starting point; the
  sticky-client default follows the WLAN's own ``roaming_assistant_{na,6e}_rssi`` setting
  and falls back to -75 dBm.
* SNR: Meraki Wireless Health calls an SNR over 25 dB good and 15 dB or less poor
  (documentation.meraki.com, MR Access Point Details); ``weak_snr_db`` and
  ``sticky_max_snr_db`` use those two figures.
* 2.4 GHz: channels 1, 6 and 11 are the non-overlapping 20 MHz set; Apple's Wi-Fi router
  guidance (support.apple.com/102766) sets 20 MHz on 2.4 GHz.
* Connection stages: Meraki and Mist both break a failed connect into association,
  authentication, DHCP and DNS; ``connection_failures`` reports the same stages.
* Retry rate, utilization, interference and neighbour counts: no vendor publishes a
  number, so those defaults are this project's own choice.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ...client import UniFiClient, object_records, validate_selector
from ...registry import Registry
from ...shared_shapes._classic_objects import resolve_site_slug
from ..network.network_services_proxy import (
    get_channel_plan,
    get_setting,
    list_rogue_aps,
    list_wlan_configs,
)
from ..network.network_wifi_radio import (
    get_spectrum_scan_results,
    get_wifi_connectivity,
    get_wifi_stats,
    list_available_wifi_channels,
)
from ..statistics.statistics import _classic_stat, _stat_records
from ._device_config import require_classic_success
from .schemas import (  # the family's shapes (family-owned layout)
    _BAND_NAMES,
    _RADIO_RULES,
    _STAGES,
    _WLAN_BANDS,
    RULES,
    STANDARD_2GHZ_CHANNELS,
    STICKY_FALLBACK_DBM,
    THRESHOLD_SPECS,
)

DEFAULTS: dict[str, Any] = {name: spec[0] for name, spec in THRESHOLD_SPECS.items()}


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _records(value: Any) -> list[dict[str, Any]]:
    """The dict items of a list (anything else is an empty list)."""
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def validate_thresholds(overrides: Any) -> dict[str, Any]:
    """Merge the caller's overrides over ``DEFAULTS``; raise naming the threshold and range."""
    if overrides is None:
        return dict(DEFAULTS)
    if not isinstance(overrides, dict):
        raise ValueError(
            "'thresholds' must be an object of threshold names to numbers "
            f"(names: {', '.join(THRESHOLD_SPECS)}), got {type(overrides).__name__}"
        )
    limits = dict(DEFAULTS)
    for name, raw in overrides.items():
        if name not in THRESHOLD_SPECS:
            continue  # reported by unknown_thresholds, never silently applied
        default, low, high = THRESHOLD_SPECS[name]
        value = _number(raw)
        if value is None:
            raise ValueError(f"{name!r} must be a number (default {default}), got {raw!r}")
        if not low <= value <= high:
            raise ValueError(
                f"{name!r} must be between {low} and {high} (default {default}), got {value}"
            )
        limits[name] = value
    return limits


def unknown_thresholds(overrides: Any) -> list[str]:
    """Names in ``overrides`` that are not thresholds; they are ignored and warned about."""
    if not isinstance(overrides, dict):
        return []
    return sorted(str(name) for name in overrides if name not in THRESHOLD_SPECS)


def validate_window_hours(value: Any) -> int:
    """The statistics window in hours, 1 to 168; raise before any request."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"'window_hours' must be a whole number of hours (default 24), got {value!r}"
        )
    if not 1 <= value <= 168:
        raise ValueError(f"'window_hours' must be between 1 and 168 (default 24), got {value}")
    return value


# --- RF geometry ------------------------------------------------------------------------


def _channel_block(band: str, channel: int, width: int) -> list[int]:
    """The 20 MHz channel numbers a primary channel and width occupy (5 and 6 GHz)."""
    if width <= 20:
        return [channel]
    if band == "6e":
        origin, unit = 1, {40: 8, 80: 16, 160: 32, 320: 64}.get(width, 0)
    else:
        origin, unit = (149 if channel >= 149 else 36), {40: 8, 80: 16, 160: 32}.get(width, 0)
    if not unit:
        return [channel]
    base = origin + ((channel - origin) // unit) * unit
    return [base + 4 * index for index in range(width // 20)]


def occupied_span(
    band: Any, channel: Any, width: Any, extchannel: Any = None
) -> tuple[float, float] | None:
    """The (low, high) MHz a radio occupies, from its primary channel and width.

    ``channel`` is the primary 20 MHz channel, as UniFi reports it (a 160 MHz radio on
    channel 60 occupies channels 36 to 64). Unknown input returns None.
    """
    ch, bw = _number(channel), _number(width) or 20
    if ch is None or band not in _BAND_NAMES:
        return None
    ch, bw = int(ch), int(bw)
    if band == "ng":
        centre = 2407 + 5 * ch
        if bw == 40 and extchannel in (1, -1):
            centre += 10 * extchannel
        return (centre - bw / 2, centre + bw / 2)
    block = _channel_block(band, ch, bw)
    start = 5000 if band == "na" else 5950
    return (start + 5 * min(block) - 10, start + 5 * max(block) + 10)


def _overlap(first: tuple[float, float], second: tuple[float, float]) -> bool:
    return first[0] < second[1] and second[0] < first[1]


# --- rows -------------------------------------------------------------------------------


def _ap_ref(device: dict[str, Any]) -> dict[str, Any]:
    return {"id": device.get("_id"), "name": device.get("name"), "mac": device.get("mac")}


def _client_ref(sta: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "client",
        "id": sta.get("_id"),
        "name": sta.get("name") or sta.get("hostname"),
        "mac": sta.get("mac"),
    }


def _finding(
    rule: str, severity: str, subject: dict[str, Any], evidence: dict[str, Any], advice: str
) -> dict[str, Any]:
    return {
        "rule": rule,
        "severity": severity,
        "subject": subject,
        "evidence": evidence,
        "recommendation": advice,
    }


def _mac(value: Any) -> str | None:
    return value.lower() if isinstance(value, str) else None


@dataclass
class Inputs:
    """Everything the rules read, already fetched. ``None`` means the read was unavailable."""

    devices: list[dict[str, Any]]
    clients: list[dict[str, Any]]
    now: float
    window_hours: int = 24
    radio_window: list[dict[str, Any]] | None = None
    client_window: list[dict[str, Any]] | None = None
    connectivity: dict[str, Any] | None = None
    neighbors: list[dict[str, Any]] | None = None
    wlans: list[dict[str, Any]] | None = None
    radio_ai: dict[str, Any] | None = None
    channel_plan: list[dict[str, Any]] | None = None
    channels: dict[str, Any] | None = None
    spectrum: list[dict[str, Any]] | None = None
    unavailable: dict[str, str] = field(default_factory=dict)


@dataclass
class _Context:
    inputs: Inputs
    limits: dict[str, Any]
    skipped: list[dict[str, Any]]
    aps: list[dict[str, Any]]
    offline: list[dict[str, Any]]
    radios: list[dict[str, Any]]
    wlans_by_name: dict[str, dict[str, Any]]
    wlans_by_id: dict[str, dict[str, Any]]
    ap_by_mac: dict[str, dict[str, Any]]
    wireless: list[dict[str, Any]]


def _access_points(
    devices: list[dict[str, Any]], skipped: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Split devices into online APs, offline APs and one row per running radio."""
    online: list[dict[str, Any]] = []
    offline: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    malformed = 0
    for device in devices:
        stats = device.get("radio_table_stats")
        if not isinstance(stats, list):
            continue  # not an access point (switch, gateway, camera)
        if device.get("state") not in (None, 1):
            offline.append(device)  # disconnected, upgrading, adopting: not assessed
            continue
        online.append(device)
        names = {r.get("radio"): r.get("name") for r in _records(device.get("radio_table"))}
        for stat in stats:
            if not isinstance(stat, dict) or not isinstance(stat.get("radio"), str):
                malformed += 1
                continue
            if stat.get("state") not in (None, "RUN"):
                continue  # a radio that is not running is not on the air
            rows.append(
                {
                    "ap": device,
                    "band": stat["radio"],
                    "stat": stat,
                    "name": names.get(stat["radio"]),
                }
            )
    if malformed:
        skipped.append(
            {
                "rule": "all",
                "reason": f"{malformed} radio_table_stats row(s) had no radio band; left out",
            }
        )
    return online, offline, rows


def _need(ctx: _Context, rule: str, source: str, value: Any) -> bool:
    """True when ``value`` was read; otherwise record the rule as not assessed."""
    if value is not None:
        return True
    reason = ctx.inputs.unavailable.get(source, "the read returned nothing")
    ctx.skipped.append({"rule": rule, "reason": f"not assessed: {source} unavailable ({reason})"})
    return False


def _iso(epoch: Any) -> str | None:
    value = _number(epoch)
    if value is None or value <= 0:
        return None
    if value > 10**11:
        value /= 1000
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- rules ------------------------------------------------------------------------------


def _ap_offline(ctx: _Context) -> list[dict[str, Any]]:
    findings = []
    for device in ctx.offline:
        since = _number(device.get("disconnected_at"))
        days = round((ctx.inputs.now - since) / 86400, 1) if since else None
        findings.append(
            _finding(
                "ap_offline",
                "warning",
                {**_ap_ref(device), "type": "access_point"},
                {
                    "state": device.get("state"),
                    "disconnected_at": _iso(since),
                    "offline_days": days,
                    "last_seen": _iso(device.get("last_seen")),
                    "note": "this AP is not counted as checked; none of its radios or clients "
                    "were assessed",
                },
                "Check power, the uplink cable and the console's device page for this AP; if "
                "it was retired on purpose, forget it so reports stop listing it.",
            )
        )
    return findings


def _sticky_limit(ctx: _Context, essid: Any, band: Any) -> tuple[float, str]:
    fixed = ctx.limits["sticky_rssi_dbm"]
    if fixed is not None:
        return fixed, "thresholds.sticky_rssi_dbm"
    key = {"na": "roaming_assistant_na_rssi", "6e": "roaming_assistant_6e_rssi"}.get(band)
    wlan = ctx.wlans_by_name.get(essid) if isinstance(essid, str) else None
    value = _number(wlan.get(key)) if wlan and key else None
    if value is not None:
        return value, f"the SSID's {key} setting"
    return STICKY_FALLBACK_DBM, "default"


def _sticky_clients(ctx: _Context) -> list[dict[str, Any]]:
    by_ssid: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
    for row in ctx.radios:
        for vap in _records(row["ap"].get("vap_table")):
            if (
                vap.get("up") is not False
                and vap.get("radio") == row["band"]
                and isinstance(vap.get("essid"), str)
            ):
                by_ssid.setdefault((vap["essid"], row["band"]), []).append(row)
    findings: list[dict[str, Any]] = []
    unmeasured = 0
    for sta in ctx.wireless:
        signal = _number(sta.get("signal"))
        if signal is None:
            unmeasured += 1
            continue
        band, essid, ap_mac = sta.get("radio"), sta.get("essid"), sta.get("ap_mac")
        limit, basis = _sticky_limit(ctx, essid, band)
        if signal >= limit:
            continue
        snr = _number(sta.get("rssi"))
        if snr is not None and snr >= ctx.limits["sticky_max_snr_db"]:
            continue  # a quiet client with a clean link is not stuck
        associated = _number(sta.get("uptime"))
        if associated is None or associated < ctx.limits["sticky_min_associated_seconds"]:
            continue
        alternatives: dict[str, dict[str, Any]] = {}
        for row in by_ssid.get((essid, band), []):
            mac = row["ap"].get("mac")
            if mac != ap_mac and mac not in alternatives:
                alternatives[mac] = {
                    **_ap_ref(row["ap"]),
                    "channel": row["stat"].get("channel"),
                    "tx_power_dbm": row["stat"].get("tx_power"),
                }
        if not alternatives:
            continue
        current = ctx.ap_by_mac.get(_mac(ap_mac) or "")
        findings.append(
            _finding(
                "sticky_client",
                "warning",
                _client_ref(sta),
                {
                    "signal_dbm": signal,
                    "snr_db": snr,
                    "threshold_dbm": limit,
                    "threshold_basis": basis,
                    "associated_seconds": associated,
                    "band": band,
                    "ssid": essid,
                    "connected_ap": _ap_ref(current) if current else {"mac": ap_mac},
                    "other_aps_with_same_ssid_and_band": list(alternatives.values()),
                },
                "Consider enabling the Roaming Assistant or a Minimum RSSI on "
                f"{_BAND_NAMES.get(str(band), str(band))} for this SSID, or moving or "
                "re-powering the APs, so the client roams to a closer AP. The evidence lists APs "
                "that "
                "broadcast the same SSID on the same band; it does not prove any of them is "
                "stronger for this client, so confirm with a walk test before changing a "
                "setting.",
            )
        )
    if unmeasured:
        ctx.skipped.append(
            {
                "rule": "sticky_client",
                "reason": f"{unmeasured} wireless client(s) reported no numeric signal and "
                "were not assessed",
            }
        )
    return findings


def _high_power_overlap(ctx: _Context) -> list[dict[str, Any]]:
    limit = ctx.limits["high_tx_power_dbm"]
    loud = []
    for row in ctx.radios:
        stat = row["stat"]
        power = _number(stat.get("tx_power"))
        span = occupied_span(
            row["band"], stat.get("channel"), stat.get("bw"), stat.get("extchannel")
        )
        if power is not None and power >= limit and span is not None:
            loud.append((row, span))
    findings = []
    for index, (first, first_span) in enumerate(loud):
        for second, second_span in loud[index + 1 :]:
            if (
                first["band"] != second["band"]
                or first["ap"].get("mac") == second["ap"].get("mac")
                or not _overlap(first_span, second_span)
            ):
                continue
            radios = [
                {
                    **_ap_ref(row["ap"]),
                    "channel": row["stat"].get("channel"),
                    "width_mhz": row["stat"].get("bw"),
                    "tx_power_dbm": row["stat"].get("tx_power"),
                    "occupied_mhz": [span[0], span[1]],
                }
                for row, span in ((first, first_span), (second, second_span))
            ]
            findings.append(
                _finding(
                    "high_power_co_channel",
                    "warning",
                    {"type": "radio_pair", "band": first["band"]},
                    {
                        "radios": radios,
                        "threshold_dbm": limit,
                        "note": "the two radios occupy overlapping spectrum (primary channel "
                        "and width taken into account) and are treated as audible to each "
                        "other; no neighbour scan is used for this rule",
                    },
                    "Consider lowering transmit power on one of these "
                    f"{_BAND_NAMES.get(first['band'], first['band'])} radios, or moving them to "
                    "channels that do not overlap, so they do not contend for the same airtime.",
                )
            )
    return findings


def _non_standard_2ghz(ctx: _Context) -> list[dict[str, Any]]:
    findings = []
    for row in ctx.radios:
        channel = _number(row["stat"].get("channel"))
        if row["band"] == "ng" and channel is not None and channel not in STANDARD_2GHZ_CHANNELS:
            findings.append(
                _finding(
                    "non_standard_2ghz_channel",
                    "info",
                    {**_ap_ref(row["ap"]), "type": "radio", "band": "ng"},
                    {"channel": channel, "standard_channels": list(STANDARD_2GHZ_CHANNELS)},
                    "Consider setting this 2.4 GHz radio to channel 1, 6 or 11, the "
                    "non-overlapping set, with update_device_radio after reading "
                    "get_device_radios.",
                )
            )
    return findings


def _window_by_radio(ctx: _Context) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (_mac(row.get("device_mac")) or "", str(row.get("radio_name"))): row
        for row in ctx.inputs.radio_window or []
    }


def _tx_retries(ctx: _Context) -> list[dict[str, Any]]:
    window = _window_by_radio(ctx)
    findings = []
    quiet = 0
    for row in ctx.radios:
        stat = row["stat"]
        rolled = window.get((_mac(row["ap"].get("mac")) or "", str(row["name"])))
        pct = _number(rolled.get("tx_retries_percentage")) if rolled else None
        basis = f"{ctx.inputs.window_hours} h average"
        if pct is None:
            pct, basis = _number(stat.get("tx_retries_pct")), "current snapshot"
            packets = _number(stat.get("tx_packets"))
            if pct is None or packets is None:
                continue
            if packets < ctx.limits["min_tx_packets"]:
                quiet += 1
                continue
        limit = (
            ctx.limits["high_tx_retries_pct_2ghz"]
            if row["band"] == "ng"
            else ctx.limits["high_tx_retries_pct"]
        )
        if pct >= limit:
            findings.append(
                _finding(
                    "high_tx_retries",
                    "warning",
                    {**_ap_ref(row["ap"]), "type": "radio", "band": row["band"]},
                    {
                        "tx_retries_pct": pct,
                        "basis": basis,
                        "threshold_pct": limit,
                        "channel": stat.get("channel"),
                        "clients": stat.get("num_sta"),
                    },
                    "Consider checking this radio for interference or weak client links "
                    "(get_wifi_stats with view radios shows the retry rate over a window), "
                    "then adjusting channel, width or power.",
                )
            )
    if quiet:
        ctx.skipped.append(
            {
                "rule": "high_tx_retries",
                "reason": f"{quiet} radio(s) sent fewer than {ctx.limits['min_tx_packets']} "
                "packets and were not judged on the snapshot",
            }
        )
    return findings


def _radio_window_health(ctx: _Context) -> list[dict[str, Any]]:
    if not _need(ctx, "radio_window_health", "wifi-stats/radios", ctx.inputs.radio_window):
        return []
    window = _window_by_radio(ctx)
    findings = []
    for row in ctx.radios:
        rolled = window.get((_mac(row["ap"].get("mac")) or "", str(row["name"])))
        if not rolled:
            continue
        util = _number(rolled.get("utilization_avg"))
        interference = _number(rolled.get("interference_avg"))
        reasons = []
        if util is not None and util >= ctx.limits["high_utilization_pct"]:
            reasons.append(f"airtime utilization {util} percent")
        if interference is not None and interference >= ctx.limits["high_interference_pct"]:
            reasons.append(f"interference {interference} percent")
        if not reasons:
            continue
        stat = row["stat"]
        findings.append(
            _finding(
                "radio_window_health",
                "warning",
                {**_ap_ref(row["ap"]), "type": "radio", "band": row["band"]},
                {
                    "window_hours": ctx.inputs.window_hours,
                    "utilization_avg_pct": util,
                    "interference_avg_pct": interference,
                    "utilization_threshold_pct": ctx.limits["high_utilization_pct"],
                    "interference_threshold_pct": ctx.limits["high_interference_pct"],
                    "tx_retries_avg_pct": _number(rolled.get("tx_retries_percentage")),
                    "client_signal_avg_dbm": _number(rolled.get("client_signal_avg")),
                    "channel_now": stat.get("channel"),
                    "cu_total_now": stat.get("cu_total"),
                    "cu_interf_now": stat.get("cu_interf"),
                },
                f"{' and '.join(reasons).capitalize()} over {ctx.inputs.window_hours} hours on "
                "this radio. Consider a quieter channel, a narrower width, or moving clients "
                "to another band; get_spectrum_scan_results shows per-channel load.",
            )
        )
    return findings


def _neighbor_co_channel(ctx: _Context) -> list[dict[str, Any]]:
    if not _need(ctx, "neighbor_co_channel", "stat/rogueap", ctx.inputs.neighbors):
        return []
    own = {
        _mac(vap.get("bssid")) for row in ctx.radios for vap in _records(row["ap"].get("vap_table"))
    }
    cutoff = ctx.inputs.now - ctx.limits["neighbor_max_age_minutes"] * 60
    floor = ctx.limits["neighbor_min_signal_dbm"]
    findings = []
    for row in ctx.radios:
        mine = occupied_span(
            row["band"],
            row["stat"].get("channel"),
            row["stat"].get("bw"),
            row["stat"].get("extchannel"),
        )
        if mine is None:
            continue
        hits = []
        for neighbor in ctx.inputs.neighbors or []:
            signal, seen = _number(neighbor.get("signal")), _number(neighbor.get("last_seen"))
            span = occupied_span(
                neighbor.get("band"), neighbor.get("channel"), neighbor.get("bw") or 20
            )
            if (
                _mac(neighbor.get("ap_mac")) == _mac(row["ap"].get("mac"))
                and neighbor.get("band") == row["band"]
                and signal is not None
                and signal >= floor
                and seen is not None
                and seen >= cutoff
                and _mac(neighbor.get("bssid")) not in own
                and span is not None
                and _overlap(mine, span)
            ):
                hits.append(neighbor)
        if len(hits) < ctx.limits["max_strong_neighbors"]:
            continue
        hits.sort(key=lambda n: -(_number(n.get("signal")) or -999))
        findings.append(
            _finding(
                "neighbor_co_channel",
                "warning",
                {**_ap_ref(row["ap"]), "type": "radio", "band": row["band"]},
                {
                    "channel": row["stat"].get("channel"),
                    "width_mhz": row["stat"].get("bw"),
                    "strong_neighbors": len(hits),
                    "threshold_count": ctx.limits["max_strong_neighbors"],
                    "min_signal_dbm": floor,
                    "seen_within_minutes": ctx.limits["neighbor_max_age_minutes"],
                    "strongest": [
                        {
                            "ssid": n.get("essid"),
                            "channel": n.get("channel"),
                            "signal_dbm": n.get("signal"),
                        }
                        for n in hits[:3]
                    ],
                },
                "Other networks occupy this radio's spectrum at a strength that costs airtime. "
                "Consider another channel (get_channel_plan and get_spectrum_scan_results show "
                "the options); neighbour networks are outside your control.",
            )
        )
    return findings


def _spectrum_scan_quality(ctx: _Context) -> list[dict[str, Any]]:
    if not _need(ctx, "spectrum_scan_quality", "stat/spectrum-scan", ctx.inputs.spectrum):
        return []
    findings = []
    offline_macs = {_mac(d.get("mac")) for d in ctx.offline}
    for scan in ctx.inputs.spectrum or []:
        stamp = _number(scan.get("spectrum_scan_timestamp"))
        if stamp is None:
            continue
        age_hours = round((ctx.inputs.now - stamp / 1000) / 3600, 1)
        tables = [
            entry
            for item in _records(scan.get("scans"))
            for entry in _records(item.get("spectrum_table"))
        ]
        implausible = sum(
            1
            for e in tables
            if (_number(e.get("interference")) or -96) > -30
            or not 0 <= (_number(e.get("utilization")) or 0) <= 100
        )
        issues = []
        if age_hours > ctx.limits["max_spectrum_scan_age_hours"]:
            issues.append(f"the scan is {age_hours} hours old")
        if implausible:
            issues.append(f"{implausible} table row(s) hold values no radio can measure")
        if not issues:
            continue
        ap = ctx.ap_by_mac.get(_mac(scan.get("mac")) or "")
        findings.append(
            _finding(
                "spectrum_scan_quality",
                "info",
                {
                    "type": "spectrum_scan",
                    "mac": scan.get("mac"),
                    "name": ap.get("name") if ap else None,
                },
                {
                    "scan_taken": _iso(stamp),
                    "age_hours": age_hours,
                    "max_age_hours": ctx.limits["max_spectrum_scan_age_hours"],
                    "implausible_rows": implausible,
                    "table_rows": len(tables),
                    "ap_offline": _mac(scan.get("mac")) in offline_macs,
                },
                f"Do not rely on this scan: {'; '.join(issues)}. Start a fresh scan with "
                "start_spectrum_scan (a write, run by a person) before choosing channels.",
            )
        )
    if all(
        (_number(e.get("other_bss_count")) or 0) == 0 and not e.get("interference_type")
        for scan in ctx.inputs.spectrum or []
        for item in _records(scan.get("scans"))
        for e in _records(item.get("spectrum_table"))
    ):
        ctx.skipped.append(
            {
                "rule": "spectrum_scan_quality",
                "reason": "other_bss_count and interference_type were empty on every scan row, "
                "so they are not used",
            }
        )
    return findings


def _stage_of(group_stage: Any, reason: Any) -> str:
    text = f"{group_stage or ''} {reason or ''}".upper()
    for token, name in _STAGES:
        if token in text:
            return name
    return "other"


def _connection_failures(ctx: _Context) -> list[dict[str, Any]]:
    data = ctx.inputs.connectivity
    if data is None:
        _need(ctx, "connection_failures", "wifi-connectivity", data)
        return []
    findings = []
    counts: dict[tuple[str, str], dict[str, Any]] = {}
    for group in _records(data.get("event_groups")):
        client = _dict(group.get("client"))
        for event in _records(group.get("events")):
            reason = event.get("failure_reason")
            if reason in (None, "SUCCESS"):
                continue
            stage = _stage_of(group.get("failure_stage"), reason)
            slot = counts.setdefault(
                (str(client.get("mac")), stage),
                {"client": client, "reasons": Counter(), "aps": Counter(), "count": 0},
            )
            slot["count"] += 1
            slot["reasons"][str(reason)] += 1
            slot["aps"][str(event.get("ap_mac"))] += 1
    for (_, stage), slot in sorted(counts.items(), key=lambda kv: -kv[1]["count"]):
        if slot["count"] < ctx.limits["min_connect_failures"]:
            continue
        client = slot["client"]
        wlan = ctx.wlans_by_id.get(str(client.get("wlanconf_id")))
        findings.append(
            _finding(
                "connection_failures",
                "warning",
                {
                    "type": "client",
                    "name": client.get("name") or client.get("hostname"),
                    "mac": client.get("mac"),
                },
                {
                    "stage": stage,
                    "failed_attempts": slot["count"],
                    "threshold_count": ctx.limits["min_connect_failures"],
                    "failure_reasons": dict(slot["reasons"]),
                    "access_points": dict(slot["aps"]),
                    "ssid": wlan.get("name") if wlan else None,
                    "window_hours": ctx.inputs.window_hours,
                },
                {
                    "authentication": "Repeated authentication failures usually mean a wrong "
                    "passphrase, an SSID security mode the device does not support, or a "
                    "changed key; check the device's saved network before touching RF settings.",
                    "dhcp": "The client got on the air but not an address; check the VLAN's DHCP "
                    "server and scope rather than RF settings.",
                    "dns": "The client got an address but DNS failed; check the network's DNS "
                    "servers.",
                    "association": "The client fails to join the radio; check minimum data "
                    "rate, band and security settings for the SSID and the client's signal.",
                }.get(stage, "Check the SSID settings and the client's own logs."),
            )
        )
    attempts = _dict(data.get("attempts"))
    success = _number(attempts.get("success_ratio"))
    if success is not None and success < ctx.limits["min_connect_success_pct"]:
        findings.append(
            _finding(
                "connection_failures",
                "info",
                {"type": "site"},
                {
                    "success_ratio_pct": success,
                    "threshold_pct": ctx.limits["min_connect_success_pct"],
                    "total_attempts": attempts.get("total_attempts"),
                    "failed_client_connections": attempts.get("failed_client_connections"),
                    "stage_ratios_pct": {
                        stage: attempts.get(f"{stage}_ratio")
                        for stage in ("association", "authentication", "dhcp", "dns")
                    },
                    "latencies_as_returned": _latencies(data.get("latencies")),
                    "window_hours": ctx.inputs.window_hours,
                },
                "Fewer connects succeeded than the threshold over the window. The stage "
                "ratios show where they fail; the per-client findings name the devices.",
            )
        )
    return findings


def _latencies(value: Any) -> dict[str, Any]:
    keys = ("association", "authentication", "dhcp", "total", "traffic")
    block = value if isinstance(value, dict) else {}
    return {f"{key}_latency": block.get(f"{key}_latency") for key in keys}


def _weak_snr_clients(ctx: _Context) -> list[dict[str, Any]]:
    findings = []
    for sta in ctx.wireless:
        snr = _number(sta.get("rssi"))
        if snr is None or snr > ctx.limits["weak_snr_db"]:
            continue
        findings.append(
            _finding(
                "weak_snr_clients",
                "warning",
                _client_ref(sta),
                {
                    "snr_db": snr,
                    "signal_dbm": _number(sta.get("signal")),
                    "noise_dbm": _number(sta.get("noise")),
                    "threshold_db": ctx.limits["weak_snr_db"],
                    "band": sta.get("radio"),
                    "ssid": sta.get("essid"),
                    "ap_mac": sta.get("ap_mac"),
                },
                "The client's signal sits close to the noise, so its link rate and reliability "
                "suffer. Consider moving the client or an AP closer, or a lower band.",
            )
        )
    return findings


def _wlan_bands(wlan: dict[str, Any]) -> set[str]:
    return {
        _WLAN_BANDS[str(band).lower()]
        for band in wlan.get("wlan_bands") or []
        if str(band).lower() in _WLAN_BANDS
    }


def _band_fit(ctx: _Context) -> list[dict[str, Any]]:
    if not _need(ctx, "band_fit", "rest/wlanconf", ctx.inputs.wlans):
        return []
    findings = []
    for sta in ctx.wireless:
        snr, band = _number(sta.get("rssi")), sta.get("radio")
        if snr is None or snr > ctx.limits["weak_snr_db"] or band not in ("6e", "na"):
            continue
        wlan = ctx.wlans_by_id.get(str(sta.get("wlanconf_id"))) or ctx.wlans_by_name.get(
            str(sta.get("essid"))
        )
        others = sorted(_wlan_bands(wlan) - {band}) if wlan else []
        if not others:
            continue
        findings.append(
            _finding(
                "band_fit",
                "info",
                _client_ref(sta),
                {
                    "band": band,
                    "snr_db": snr,
                    "signal_dbm": _number(sta.get("signal")),
                    "ssid": sta.get("essid"),
                    "other_bands_offered_by_ssid": others,
                    "note": "the data does not say whether the client supports the other bands",
                },
                f"This client holds a {_BAND_NAMES[band]} link at low SNR while its SSID also "
                "offers other bands. A lower band often reaches further; if the client "
                "supports it, consider a separate SSID or a client-side band setting.",
            )
        )
    return findings


def _airtime_hog(ctx: _Context) -> list[dict[str, Any]]:
    if not _need(ctx, "airtime_hog", "wifi-stats/details", ctx.inputs.client_window):
        return []
    findings = []
    for row in ctx.inputs.client_window or []:
        share, rate = (
            _number(row.get("total_traffic_percentage")),
            _number(row.get("phy_rate_most_common")),
        )
        if share is None or rate is None:
            continue
        if (
            share < ctx.limits["hog_traffic_share_pct"]
            or rate > ctx.limits["hog_max_phy_mbps"] * 1000
        ):
            continue
        client = _dict(row.get("client"))
        findings.append(
            _finding(
                "airtime_hog",
                "info",
                {
                    "type": "client",
                    "name": client.get("name") or client.get("hostname"),
                    "mac": client.get("mac"),
                },
                {
                    "traffic_share_pct": share,
                    "common_link_rate_mbps": round(rate / 1000, 1),
                    "traffic_share_threshold_pct": ctx.limits["hog_traffic_share_pct"],
                    "link_rate_threshold_mbps": ctx.limits["hog_max_phy_mbps"],
                    "band": row.get("band"),
                    "signal_avg_dbm": _number(row.get("signal_avg")),
                    "window_hours": ctx.inputs.window_hours,
                    "note": "airtime is not reported; traffic share at a low link rate is the "
                    "proxy",
                },
                "A slow link carrying a large share of traffic uses more airtime than its "
                "share suggests. Improving this client's signal or band helps every client "
                "on the radio.",
            )
        )
    return findings


def _roam_churn(ctx: _Context) -> list[dict[str, Any]]:
    if not _need(ctx, "roam_churn", "wifi-stats/details", ctx.inputs.client_window):
        return []
    findings = []
    for row in ctx.inputs.client_window or []:
        roams = _number(row.get("roams_count"))
        if roams is None or roams < ctx.limits["roam_churn_count"]:
            continue
        client = _dict(row.get("client"))
        findings.append(
            _finding(
                "roam_churn",
                "warning",
                {
                    "type": "client",
                    "name": client.get("name") or client.get("hostname"),
                    "mac": client.get("mac"),
                },
                {
                    "roams": roams,
                    "threshold": ctx.limits["roam_churn_count"],
                    "window_hours": ctx.inputs.window_hours,
                    "signal_avg_dbm": _number(row.get("signal_avg")),
                    "band": row.get("band"),
                    "note": "a roam count alone does not say whether each roam improved the signal",
                },
                "This client roamed often. A mobile device does that on purpose; a stationary "
                "one usually sits between two APs. Consider a Roaming Assistant or Minimum "
                "RSSI on the SSID, or moving an AP.",
            )
        )
    return findings


def _client_retries(ctx: _Context) -> list[dict[str, Any]]:
    findings = []
    for sta in ctx.wireless:
        pct = _number(sta.get("wifi_tx_retries_percentage"))
        bursts = _number(sta.get("tx_retry_burst_count")) or 0
        attempts = _number(sta.get("wifi_tx_attempts"))
        if attempts is not None and attempts < ctx.limits["min_tx_packets"]:
            continue
        if (pct is None or pct < ctx.limits["high_client_retries_pct"]) and bursts <= 0:
            continue
        findings.append(
            _finding(
                "client_retries",
                "info",
                _client_ref(sta),
                {
                    "tx_retries_pct": pct,
                    "threshold_pct": ctx.limits["high_client_retries_pct"],
                    "retry_bursts": bursts,
                    "tx_dropped": _number(sta.get("wifi_tx_dropped")),
                    "band": sta.get("radio"),
                    "signal_dbm": _number(sta.get("signal")),
                },
                "Many of this client's frames are sent more than once. Check its signal and "
                "the radio's interference and utilization (radio_window_health).",
            )
        )
    return findings


def _client_experience(ctx: _Context) -> list[dict[str, Any]]:
    findings = []
    for sta in ctx.wireless:
        score = _number(sta.get("satisfaction"))
        if score is None or score > ctx.limits["low_satisfaction"]:
            continue
        findings.append(
            _finding(
                "client_experience",
                "warning",
                _client_ref(sta),
                {
                    "satisfaction": score,
                    "threshold": ctx.limits["low_satisfaction"],
                    "satisfaction_reason_code": sta.get("satisfaction_reason"),
                    "anomalies": sta.get("anomalies"),
                    "band": sta.get("radio"),
                    "note": "the console's own score; the reason code is not documented and "
                    "is shown as returned",
                },
                "The console rates this client's experience low. Check its signal, retries "
                "and connection failures for the cause.",
            )
        )
    return findings


def _ap_uplink_bottleneck(ctx: _Context) -> list[dict[str, Any]]:
    best: dict[str, float] = {}
    for sta in ctx.wireless:
        mac = _mac(sta.get("ap_mac"))
        rate = max(_number(sta.get("tx_rate")) or 0, _number(sta.get("rx_rate")) or 0)
        if mac:
            best[mac] = max(best.get(mac, 0), rate)
    findings = []
    for device in ctx.aps:
        uplink = _dict(device.get("uplink"))
        speed, cap = _number(uplink.get("speed")), _number(uplink.get("max_speed"))
        errors = (_number(uplink.get("rx_errors")) or 0) + (_number(uplink.get("rx_dropped")) or 0)
        top_mbps = round(best.get(_mac(device.get("mac")) or "", 0) / 1000, 1)
        notes = []
        if speed and cap and speed < cap and top_mbps > speed:
            notes.append(
                f"the uplink negotiated {speed} Mbps on a port that can do {cap}, below the "
                f"{top_mbps} Mbps link rate of its fastest client"
            )
        if errors > 0:
            notes.append(f"the uplink counted {errors} receive errors or drops")
        if not notes:
            continue
        findings.append(
            _finding(
                "ap_uplink_bottleneck",
                "warning" if errors > 0 else "info",
                {**_ap_ref(device), "type": "access_point"},
                {
                    "uplink_speed_mbps": speed,
                    "uplink_max_speed_mbps": cap,
                    "full_duplex": uplink.get("full_duplex"),
                    "rx_errors": _number(uplink.get("rx_errors")),
                    "rx_dropped": _number(uplink.get("rx_dropped")),
                    "fastest_client_link_rate_mbps": top_mbps,
                    "note": "a link rate is not throughput; this explains fast link rates with "
                    "slow speed tests, it does not prove a bottleneck",
                },
                f"{'; '.join(notes).capitalize()}. Check the cable and the switch port's speed.",
            )
        )
    return findings


def _band_load(ctx: _Context) -> list[dict[str, Any]]:
    findings = []
    total = len(ctx.wireless)
    on_24 = sum(1 for sta in ctx.wireless if sta.get("radio") == "ng")
    if total:
        share = round(100 * on_24 / total, 1)
        if share > ctx.limits["max_2ghz_client_share_pct"]:
            findings.append(
                _finding(
                    "band_load",
                    "info",
                    {"type": "site"},
                    {
                        "clients_on_2ghz": on_24,
                        "wireless_clients": total,
                        "share_pct": share,
                        "threshold_pct": ctx.limits["max_2ghz_client_share_pct"],
                    },
                    "Many clients sit on 2.4 GHz, the slowest and busiest band. Devices that "
                    "support 5 GHz or 6 GHz may be held on 2.4 GHz by a legacy SSID or weak "
                    "signal; check band_fit and the SSID's bands.",
                )
            )
    per_ap = Counter(_mac(sta.get("ap_mac")) for sta in ctx.wireless)
    counts = {d.get("mac"): per_ap.get(_mac(d.get("mac")), 0) for d in ctx.aps if d.get("mac")}
    if len(counts) >= 2 and max(counts.values()) >= 2:
        low = min(counts.values())
        high = max(counts.values())
        if high >= ctx.limits["ap_load_ratio"] * max(low, 1):
            findings.append(
                _finding(
                    "band_load",
                    "info",
                    {"type": "site"},
                    {
                        "clients_per_ap": {
                            str(ctx.ap_by_mac[_mac(mac) or ""].get("name") or mac): n
                            for mac, n in counts.items()
                        },
                        "ratio_threshold": ctx.limits["ap_load_ratio"],
                    },
                    "One AP carries far more clients than another. Consider moving an AP or "
                    "adjusting transmit power so load spreads.",
                )
            )
    return findings


def _channel_width_policy(ctx: _Context) -> list[dict[str, Any]]:
    if not _need(ctx, "channel_width_policy", "rest/setting/radio_ai", ctx.inputs.radio_ai):
        return []
    ai = ctx.inputs.radio_ai or {}
    allowed = {
        "ng": {int(v) for v in ai.get("ht_modes_ng") or [] if str(v).isdigit()},
        "na": {int(v) for v in ai.get("ht_modes_na") or [] if str(v).isdigit()},
    }
    dfs = set((ctx.inputs.channels or {}).get("channels_na_dfs") or [])
    findings = []
    for row in ctx.radios:
        stat, band = row["stat"], row["band"]
        bw, channel = _number(stat.get("bw")), _number(stat.get("channel"))
        if bw is None:
            continue
        issues: list[str] = []
        if band == "ng" and bw != 20:
            issues.append(f"{bw} MHz on 2.4 GHz takes about half the band; 20 MHz is the norm")
        if allowed.get(band) and int(bw) not in allowed[band]:
            issues.append(
                f"{int(bw)} MHz is wider than the site's Channel AI width policy "
                f"({sorted(allowed[band])} MHz)"
            )
        if band == "na" and channel in dfs and bw >= 80:
            issues.append("a wide channel in the DFS range can be vacated by a radar event")
        if not issues:
            continue
        findings.append(
            _finding(
                "channel_width_policy",
                "info",
                {**_ap_ref(row["ap"]), "type": "radio", "band": band},
                {
                    "width_mhz": bw,
                    "channel": channel,
                    "allowed_widths_mhz": sorted(allowed.get(band, set())) or None,
                    "dfs_channel": channel in dfs if band == "na" and dfs else None,
                    "channel_ai_auto_enabled": ai.get("auto_enabled"),
                },
                f"{issues[0].capitalize()}"
                + ("".join(f"; also {i}" for i in issues[1:]))
                + ". If this was set on purpose, change the policy; otherwise consider "
                "update_device_radio after reading get_device_radios.",
            )
        )
    return findings


def _channel_flap(ctx: _Context) -> list[dict[str, Any]]:
    if not _need(ctx, "channel_flap", "rest/channelplan", ctx.inputs.channel_plan):
        return []
    plans: list[tuple[float, dict[str, Any]]] = []
    for plan in ctx.inputs.channel_plan or []:
        try:
            stamped = datetime.fromisoformat(str(plan.get("date")).replace("Z", "+00:00"))
        except ValueError:
            continue
        plans.append((stamped.timestamp(), plan))
    plans.sort(key=lambda item: item[0])
    cutoff = ctx.inputs.now - ctx.limits["flap_window_days"] * 86400
    dfs = set((ctx.inputs.channels or {}).get("channels_na_dfs") or [])
    history: dict[tuple[str, str], list[tuple[float, Any, Any]]] = {}
    for when, plan in plans:
        for entry in _records(plan.get("radio_table")):
            key = (_mac(entry.get("device_mac")) or "", str(entry.get("name")))
            history.setdefault(key, []).append((when, entry.get("channel"), entry.get("width")))
    findings = []
    for (mac, name), points in history.items():
        changes = [
            {"on": _iso(cur[0]), "from": prev[1], "to": cur[1], "width_mhz": cur[2]}
            for prev, cur in zip(points, points[1:], strict=False)
            if cur[1] != prev[1] and cur[0] >= cutoff
        ]
        if not changes:
            continue
        ap = ctx.ap_by_mac.get(mac)
        last_to = changes[-1]["to"]
        findings.append(
            _finding(
                "channel_flap",
                "warning" if len(changes) >= ctx.limits["flap_min_changes"] else "info",
                {
                    "type": "radio",
                    "mac": mac,
                    "name": ap.get("name") if ap else None,
                    "radio": name,
                },
                {
                    "changes": changes,
                    "window_days": ctx.limits["flap_window_days"],
                    "warning_threshold": ctx.limits["flap_min_changes"],
                    "latest_channel_is_dfs": (last_to in dfs) if dfs else None,
                    "plans_read": len(plans),
                },
                "The stored channel plans show this radio changing channel inside the window. "
                "A client on it sees a short outage at each change, longer when the new "
                "channel is a DFS channel. Many changes suggest fixing the channel by hand.",
            )
        )
    return findings


def _wlan_config_audit(ctx: _Context) -> list[dict[str, Any]]:
    if not _need(ctx, "wlan_config_audit", "rest/wlanconf", ctx.inputs.wlans):
        return []
    findings = []
    for wlan in ctx.inputs.wlans or []:
        if wlan.get("enabled") is False:
            continue
        bands = _wlan_bands(wlan)
        issues: list[dict[str, Any]] = []

        def add(check: str, value: Any, advice: str, issues: list[dict[str, Any]] = issues) -> None:
            issues.append({"check": check, "value": value, "advice": advice})

        if wlan.get("b_supported") is True:
            add("b_supported", True, "802.11b rates are on; they slow every client on the SSID.")
        if "ng" in bands:
            floor = _number(wlan.get("minrate_ng_data_rate_kbps"))
            if wlan.get("minrate_ng_enabled") is not True or (
                floor is not None and floor < ctx.limits["min_legacy_rate_kbps"]
            ):
                add(
                    "minrate_ng",
                    floor if wlan.get("minrate_ng_enabled") is True else "off",
                    "A 2.4 GHz minimum data rate of 12 Mbps or more keeps slow legacy "
                    "clients from holding the air.",
                )
        if wlan.get("bss_transition") is False:
            add("bss_transition", False, "802.11v BSS transition is off; steering is weaker.")
        if wlan.get("rrm_enabled") is False:
            add("rrm_enabled", False, "802.11k neighbour reports are off; roaming is slower.")
        if "6e" in bands and wlan.get("wpa3_support") is not True:
            add("wpa3_support", wlan.get("wpa3_support"), "6 GHz requires WPA3.")
        if wlan.get("pmf_mode") not in (None, "required", "optional"):
            add("pmf_mode", wlan.get("pmf_mode"), "Protected management frames are disabled.")
        if not issues:
            continue
        findings.append(
            _finding(
                "wlan_config_audit",
                "info",
                {"type": "ssid", "id": wlan.get("_id"), "name": wlan.get("name")},
                {
                    "bands": sorted(bands),
                    "issues": issues,
                    "pmf_mode": wlan.get("pmf_mode"),
                    "fast_roaming_enabled": wlan.get("fast_roaming_enabled"),
                },
                "These SSID settings can cost performance or roaming. An SSID kept for old "
                "devices may need them on purpose, so treat each as advice, not a fault.",
            )
        )
    return findings


_RULE_FUNCTIONS: tuple[Callable[[_Context], list[dict[str, Any]]], ...] = (
    _ap_offline,
    _sticky_clients,
    _high_power_overlap,
    _non_standard_2ghz,
    _channel_width_policy,
    _channel_flap,
    _tx_retries,
    _radio_window_health,
    _neighbor_co_channel,
    _spectrum_scan_quality,
    _connection_failures,
    _weak_snr_clients,
    _band_fit,
    _airtime_hog,
    _roam_churn,
    _client_retries,
    _client_experience,
    _ap_uplink_bottleneck,
    _band_load,
    _wlan_config_audit,
)


def _not_assessed_basic(ctx: _Context) -> None:
    """Rules whose input fields are absent from the data: reported, never guessed at."""
    radios, clients = ctx.radios, ctx.wireless
    checks = (
        (
            "high_power_co_channel",
            any(
                _number(r["stat"].get("tx_power")) is not None
                and r["stat"].get("channel") is not None
                for r in radios
            ),
            "no running radio reported tx_power and channel",
        ),
        (
            "non_standard_2ghz_channel",
            any(
                r["band"] == "ng" and _number(r["stat"].get("channel")) is not None for r in radios
            ),
            "no running 2.4 GHz radio reported a channel",
        ),
        (
            "high_tx_retries",
            any(_number(r["stat"].get("tx_retries_pct")) is not None for r in radios)
            or bool(ctx.inputs.radio_window),
            "no running radio reported a retry rate",
        ),
        (
            "sticky_client",
            any(_number(c.get("signal")) is not None for c in clients),
            "no wireless client reported a numeric signal",
        ),
        (
            "weak_snr_clients",
            any(_number(c.get("rssi")) is not None for c in clients),
            "no wireless client reported an SNR (rssi)",
        ),
        (
            "client_experience",
            any(_number(c.get("satisfaction")) is not None for c in clients),
            "no wireless client reported a satisfaction score",
        ),
    )
    for rule, present, reason in checks:
        if not present:
            ctx.skipped.append({"rule": rule, "reason": f"not assessed: {reason}"})


def _nothing_to_examine(ctx: _Context) -> None:
    """A rule with no record to examine is not assessed: 0 only ever means assessed and clean."""
    if not ctx.radios:
        for rule in _RADIO_RULES:
            ctx.skipped.append(
                {
                    "rule": rule,
                    "reason": "not assessed: no running radio to examine (every access point is "
                    "offline or the site has no access point)",
                }
            )
    if not ctx.aps:
        ctx.skipped.append(
            {
                "rule": "ap_uplink_bottleneck",
                "reason": "not assessed: no online access point to examine (every access point "
                "is offline or the site has no access point)",
            }
        )


def analyse(inputs: Inputs, limits: dict[str, Any]) -> dict[str, Any]:
    """Apply every rule to already-read records (pure, no I/O)."""
    skipped: list[dict[str, Any]] = []
    aps, offline, radios = _access_points(inputs.devices, skipped)
    wlans = _records(inputs.wlans)
    ctx = _Context(
        inputs=inputs,
        limits=limits,
        skipped=skipped,
        aps=aps,
        offline=offline,
        radios=radios,
        wlans_by_name={w["name"]: w for w in wlans if isinstance(w.get("name"), str)},
        wlans_by_id={w["_id"]: w for w in wlans if isinstance(w.get("_id"), str)},
        ap_by_mac={m: d for d in [*aps, *offline] if (m := _mac(d.get("mac")))},
        wireless=[c for c in inputs.clients if c.get("is_wired") is False],
    )
    _not_assessed_basic(ctx)
    _nothing_to_examine(ctx)
    findings = [item for rule in _RULE_FUNCTIONS for item in rule(ctx)]
    by_rule = Counter(item["rule"] for item in findings)
    by_severity = Counter(item["severity"] for item in findings)
    # A rule is either assessed (listed in byRule, with 0 when it found nothing) or not
    # assessed (listed in notAssessed); every one of the RULES is in exactly one of the two.
    # A rule that produced findings was assessed, whatever a skipped note says.
    not_assessed = sorted(
        {x["rule"] for x in skipped if x["reason"].startswith("not assessed")} - set(by_rule)
    )
    return {
        "summary": {
            "findingCount": len(findings),
            "byRule": {rule: by_rule[rule] for rule in RULES if rule not in not_assessed},
            "bySeverity": dict(by_severity),
            "accessPointsChecked": len(aps),
            "accessPointsNotAssessed": len(offline),
            "radiosChecked": len(radios),
            "wirelessClientsChecked": len(ctx.wireless),
            "clean": not findings,
        },
        "findings": findings,
        "skipped": skipped,
        "notAssessed": not_assessed,
        "accessPoints": [_ap_summary(d, online=True) for d in aps]
        + [_ap_summary(d, online=False) for d in offline],
    }


def _ap_summary(device: dict[str, Any], *, online: bool) -> dict[str, Any]:
    """The AP fields the rules used, and nothing else (no key material, no config)."""
    return {
        **_ap_ref(device),
        "model": device.get("model"),
        "state": device.get("state"),
        "online": online,
        "radios": [
            {
                "band": s.get("radio"),
                "channel": s.get("channel"),
                "width_mhz": s.get("bw"),
                "tx_power_dbm": s.get("tx_power"),
                "clients": s.get("num_sta"),
            }
            for s in _records(device.get("radio_table_stats"))
            if online
        ],
    }


# --- reads ------------------------------------------------------------------------------


def _envelope_rows(response: Any, label: str) -> list[dict[str, Any]]:
    return _stat_records(response, label)


async def _optional(unavailable: dict[str, str], source: str, call: Callable[[], Any]) -> Any:
    """Run one optional read; on failure record why and return None."""
    try:
        return await call()
    except Exception as exc:  # noqa: BLE001 - any upstream failure only means "not assessed"
        unavailable[source] = f"{type(exc).__name__}: {exc}"
        return None


async def _gather(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    window_hours: int,
    now: float,
) -> tuple[Inputs, list[dict[str, str]]]:
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    devices_response = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
    require_classic_success(devices_response, "/stat/device")
    devices = _stat_records(devices_response, "/stat/device")
    clients_response = await client.get(_classic_stat(host_id, site_slug, "/sta"), key=key)
    require_classic_success(clients_response, "/stat/sta")
    clients = _stat_records(clients_response, "/stat/sta")

    end_ms = int(now * 1000)
    start_ms = end_ms - window_hours * 3_600_000
    unavailable: dict[str, str] = {}

    async def rows(source: str, call: Callable[[], Any]) -> list[dict[str, Any]] | None:
        response = await _optional(unavailable, source, call)
        if response is None:
            return None
        try:
            return _envelope_rows(response, source)
        except Exception as exc:  # noqa: BLE001
            unavailable[source] = f"{type(exc).__name__}: {exc}"
            return None

    async def block(source: str, call: Callable[[], Any], name: str) -> Any:
        response = await _optional(unavailable, source, call)
        if isinstance(response, dict) and isinstance(response.get(name), list):
            try:
                return object_records(response[name], source)
            except Exception as exc:  # noqa: BLE001 - a malformed list is only "not assessed"
                unavailable[source] = f"{type(exc).__name__}: {exc}"
                return None
        if response is not None:
            unavailable[source] = f"unexpected response shape: no {name!r} list"
        return None

    radio_window = await block(
        "wifi-stats/radios",
        lambda: get_wifi_stats(client, registry, host, site, "radios", start_ms, end_ms),
        "radio_details",
    )
    client_window = await block(
        "wifi-stats/details",
        lambda: get_wifi_stats(client, registry, host, site, "details", start_ms, end_ms),
        "client_details",
    )
    connectivity = await _optional(
        unavailable,
        "wifi-connectivity",
        lambda: get_wifi_connectivity(client, registry, host, site, start_ms, end_ms),
    )
    if connectivity is not None and not isinstance(connectivity, dict):
        unavailable["wifi-connectivity"] = "unexpected response shape"
        connectivity = None
    neighbors = await rows("stat/rogueap", lambda: list_rogue_aps(client, registry, host, site))
    wlans = await rows("rest/wlanconf", lambda: list_wlan_configs(client, registry, host, site))
    setting = await rows(
        "rest/setting/radio_ai", lambda: get_setting(client, registry, host, site, "radio_ai")
    )
    plans = await rows("rest/channelplan", lambda: get_channel_plan(client, registry, host, site))
    channel_rows = await rows(
        "stat/current-channel", lambda: list_available_wifi_channels(client, registry, host, site)
    )
    spectrum = await rows(
        "stat/spectrum-scan", lambda: get_spectrum_scan_results(client, registry, host, site)
    )
    inputs = Inputs(
        devices=devices,
        clients=clients,
        now=now,
        window_hours=window_hours,
        radio_window=radio_window,
        client_window=client_window,
        connectivity=connectivity,
        neighbors=neighbors,
        wlans=wlans,
        radio_ai=setting[0] if setting else None,
        channel_plan=plans,
        channels=channel_rows[0] if channel_rows else None,
        spectrum=spectrum,
        unavailable=unavailable,
    )
    sources = [
        {"route": "stat/device", "status": "read"},
        {"route": "stat/sta", "status": "read"},
    ]
    for name, got in (
        ("wifi-stats/radios", radio_window),
        ("wifi-stats/details", client_window),
        ("wifi-connectivity", connectivity),
        ("stat/rogueap", neighbors),
        ("rest/wlanconf", wlans),
        ("rest/setting/radio_ai", inputs.radio_ai),
        ("rest/channelplan", plans),
        ("stat/current-channel", inputs.channels),
        ("stat/spectrum-scan", spectrum),
    ):
        entry = {"route": name, "status": "read" if got is not None else "unavailable"}
        if got is None:
            entry["reason"] = unavailable.get(name, "the read returned no usable record")
        sources.append(entry)
    return inputs, sources


async def _diagnose_wifi(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    *,
    thresholds: Any = None,
    window_hours: Any = 24,
    now: float | None = None,
) -> dict[str, Any]:
    validate_selector(host, "host")
    validate_selector(site, "site")
    limits = validate_thresholds(thresholds)
    hours = validate_window_hours(window_hours)
    warnings = [
        f"threshold {name!r} is not a known threshold name and was ignored; valid names: "
        f"{', '.join(THRESHOLD_SPECS)}"
        for name in unknown_thresholds(thresholds)
    ]
    inputs, sources = await _gather(
        client, registry, host, site, hours, time.time() if now is None else now
    )
    report = analyse(inputs, limits)
    return {
        "host": host,
        "site": site,
        "readOnly": True,
        "windowHours": hours,
        "warnings": warnings,
        "sources": sources,
        **report,
        "thresholds": limits,
    }
