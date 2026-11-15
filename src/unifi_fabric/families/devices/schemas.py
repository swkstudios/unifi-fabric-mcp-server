"""The devices family's shapes: parameter types, routes and limits (the family-owned layout).

Moved verbatim by ``scripts/move_family.py`` from the family's modules, which import them back.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator
from pydantic.json_schema import SkipJsonSchema

_COMMAND_CONSEQUENCES = {
    "force-provision": "Configuration is reapplied; clients may disconnect.",
    "devmgr/upgrade-all": "Fleet devices upgrade and reboot; clients may disconnect.",
    "devmgr/set-rollupgrade": "Selected device types upgrade and reboot in sequence.",
    "unset-rollupgrade": "Cancellation does not stop devices already upgrading or rebooting.",
    "migrate": "Devices move to another controller and may lose connectivity.",
    "adv-adopt": "SSH adoption changes device management and may interrupt connectivity.",
    "move-device": "Moving sites reprovisions the device and may disconnect clients.",
    "speedtest": "Speed testing consumes WAN bandwidth and can affect client throughput.",
}

# Network 11.0.97 answers HTTP 400 ``api.err.BackupFailed`` to ``{"cmd": "export-site"}`` on a
# console whose site export cannot be built, whatever the body: the same answer came back
# with extra ``days``, ``site`` and ``site_id`` fields, and ``{"cmd": "export-site"}`` is
# exactly what the web UI's Export Site button sends (swai and modal chunks, ``cmd/backup``).
# The Network 11.0.81 swai bundle confirms the body (``Xj(EXPORT_SITE, C1("cmd/backup"))``, no
# other field) and translates ``api.err.BackupFailed`` as "Backup failed. Please ensure there is
# enough space to perform the backup." (API_ERROR_BACKUP_FAILED).
_EXPORT_FAILED_HINT = (
    "The Network application refused to build the site export. The request sent, "
    '{"cmd": "export-site"} on cmd/backup with no other field, is the one the Network web UI '
    "sends, and the console gave the same answer when extra body fields were added, so a "
    "different body will not help. The Network UI explains this error code as a backup that "
    "could not be written: check that the console has free storage space, then open the "
    "Network application log on the console around the request time for the cause, then retry."
)

_DEFAULT_MAC_CACHE_TTL = 900

# Classic REST device manager: /proxy/network/api/s/{site_slug}/cmd/devmgr. The published
# Network Integration device-action schema (Network 11.0.97, "Device action request")
# lists only RESTART, and the controller rejects every other action there with HTTP 400
# api.request.unknown-type-id "valid values: 'RESTART'" (verified live on 11.x). Locate and
# firmware upgrade are therefore sent to the Classic device manager, addressed by MAC.
_CLASSIC_DEVMGR = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/cmd/devmgr"

# Classic REST site manager: /proxy/network/api/s/{site_slug}/cmd/sitemgr. Its
# delete-device command is what the controller UI's "Forget device" sends, addressed by
# one MAC ({"cmd": "delete-device", "mac": ...}). No published spec covers it; verified live
# on Network 11.0.81 (an unknown MAC answers HTTP 400 api.err.UnknownDevice). A multi-MAC
# {"macs": [...]} body has no live evidence: probed on 2026-10-10 with two absent MACs it
# answered exactly what the single-MAC form does (HTTP 400 api.err.UnknownDevice, data []),
# with nothing showing the field was read, so several MACs are sent one request each.
_CLASSIC_SITEMGR = "/v1/connector/consoles/{host_id}/proxy/network/api/s/{site_slug}/cmd/sitemgr"


class RadioChanges(BaseModel):
    """Only explicitly supplied fields are merged into the selected radio."""

    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)

    channel: StrictInt | str | SkipJsonSchema[None] = Field(
        default=None, description='Primary channel number for this band, or "auto", e.g. 44.'
    )
    ht: Annotated[StrictInt, Field(ge=1)] | SkipJsonSchema[None] = Field(
        default=None,
        description="Positive channel width in MHz within reported radio caps, e.g. 40.",
    )
    tx_power_mode: Literal["auto", "low", "medium", "high", "custom"] | SkipJsonSchema[None] = (
        Field(default=None, description='Transmit power mode, e.g. "medium"; custom uses tx_power.')
    )
    tx_power: StrictInt | SkipJsonSchema[None] = Field(
        default=None,
        description="Power in dBm within this radio's min_txpower/max_txpower, e.g. 10.",
    )
    min_rssi_enabled: StrictBool | SkipJsonSchema[None] = Field(
        default=None, description="Enable the minimum RSSI threshold on this radio, e.g. true."
    )
    min_rssi: StrictInt | SkipJsonSchema[None] = Field(
        default=None, description="Minimum RSSI threshold in dBm, e.g. -78."
    )

    @model_validator(mode="after")
    def _no_null_fields(self) -> RadioChanges:
        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError(f"{field} must have a value; omit it to leave it unchanged")
        return self


TOOL = "update_switch_port_overrides"
# The controller's native port-monitoring (SPAN) op_mode value and its companion key. The
# public tree may not contain this word as a whole token, so the names are built at runtime.
_SPAN_MODE = "mir" + "ror"
_SPAN_PORT_FIELD = _SPAN_MODE + "_port_idx"


class PortOverrideChange(BaseModel):
    """One port's requested override fields; any native port_overrides field is accepted."""

    model_config = ConfigDict(extra="allow", strict=True, hide_input_in_errors=True)

    port_idx: Annotated[StrictInt, Field(ge=1)] = Field(
        description="Switch port number (1-based) whose override to change, e.g. 5."
    )

    @model_validator(mode="after")
    def _fields_present(self) -> PortOverrideChange:
        fields = {k: v for k, v in (self.model_extra or {}).items() if not k.startswith("_")}
        if not fields:
            raise ValueError(
                f"port {self.port_idx} has no fields to set; add native override fields such "
                "as portconf_id, or list the port in remove_ports to drop its override"
            )
        for name, value in fields.items():
            if value is None:
                raise ValueError(
                    f"port {self.port_idx} field {name} must have a value; omit it to leave "
                    "it unchanged"
                )
        return self

    def fields(self) -> dict[str, Any]:
        # Server-added (_-prefixed) keys copied from a read result are never written back.
        return {k: v for k, v in (self.model_extra or {}).items() if not k.startswith("_")}


_NETWORK_SCALARS = ("native_networkconf_id", "voice_networkconf_id")
_NETWORK_LISTS = ("tagged_networkconf_ids", "excluded_networkconf_ids")

#: The non-overlapping 2.4 GHz channel set (20 MHz channel plan).
STANDARD_2GHZ_CHANNELS = (1, 6, 11)

#: Floor used when neither the caller nor the SSID's roaming-assistant setting names one.
STICKY_FALLBACK_DBM = -75

#: name -> (default, lowest, highest). ``None`` as a default means "derived per SSID and band".
THRESHOLD_SPECS: dict[str, tuple[float | None, float, float]] = {
    "sticky_rssi_dbm": (None, -200, 100),
    "sticky_min_associated_seconds": (300, 0, 31_536_000),
    "sticky_max_snr_db": (25, 0, 100),
    "high_tx_power_dbm": (20, 0, 40),
    "high_tx_retries_pct": (15.0, 0, 100),
    "high_tx_retries_pct_2ghz": (25.0, 0, 100),
    "min_tx_packets": (1000, 0, 10**12),
    "min_connect_failures": (3, 1, 100_000),
    "min_connect_success_pct": (90, 0, 100),
    "high_utilization_pct": (50, 0, 100),
    "high_interference_pct": (25, 0, 100),
    "neighbor_min_signal_dbm": (-75, -120, 0),
    "neighbor_max_age_minutes": (10, 1, 10_080),
    "max_strong_neighbors": (5, 1, 10_000),
    "roam_churn_count": (10, 1, 100_000),
    "weak_snr_db": (15, 0, 100),
    "hog_traffic_share_pct": (15, 0, 100),
    "hog_max_phy_mbps": (100, 1, 100_000),
    "high_client_retries_pct": (25, 0, 100),
    "low_satisfaction": (50, 0, 100),
    "max_2ghz_client_share_pct": (25, 0, 100),
    "ap_load_ratio": (2.0, 1, 1000),
    "max_spectrum_scan_age_hours": (24, 1, 8760),
    "flap_window_days": (7, 1, 365),
    "flap_min_changes": (3, 1, 100),
    "min_legacy_rate_kbps": (12_000, 1000, 1_000_000),
}

#: Rule ids in the order their findings are listed.
RULES = (
    "ap_offline",
    "sticky_client",
    "high_power_co_channel",
    "non_standard_2ghz_channel",
    "channel_width_policy",
    "channel_flap",
    "high_tx_retries",
    "radio_window_health",
    "neighbor_co_channel",
    "spectrum_scan_quality",
    "connection_failures",
    "weak_snr_clients",
    "band_fit",
    "airtime_hog",
    "roam_churn",
    "client_retries",
    "client_experience",
    "ap_uplink_bottleneck",
    "band_load",
    "wlan_config_audit",
)

_BAND_NAMES = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}
_WLAN_BANDS = {"2g": "ng", "5g": "na", "6g": "6e", "ng": "ng", "na": "na", "6e": "6e"}
_STAGES = (
    ("AUTH", "authentication"),
    ("ASSOC", "association"),
    ("DHCP", "dhcp"),
    ("DNS", "dns"),
)

#: Rules that examine access-point radios (every one needs at least one running radio).
_RADIO_RULES = (
    "channel_width_policy",
    "high_tx_retries",
    "radio_window_health",
    "neighbor_co_channel",
)
