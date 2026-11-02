"""Typed AP radio configuration via Classic device statistics and full-table updates.

There is no pinned Integration write schema for radio_table. Capabilities come from
stat/device, not a guessed model list. Never PUT a partial radio_table: controllers
can reorder its radios and reprovision the AP when presented with partial tables.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import Annotated, Any, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator
from pydantic.json_schema import SkipJsonSchema

from ..client import (
    UniFiClient,
    UniFiConnectionError,
    object_records,
    upstream_error_text,
    validate_id,
    validate_selector,
)
from ..config import APIKeyConfig
from ..macs import colon_mac, is_mac
from ..read_only import ReadOnlyModeError, guard_action
from ..registry import Registry
from ..switches import env_flag
from ..tool_annotations import READ_ONLY, WRITE
from ._classic_objects import classic_rest, resolve_site_slug
from ._device_config import require_classic_success, update_device_config
from ._keys import with_context
from ._results import leaf_equal
from .connector import CONNECTOR_WRITE_ENV, connector_write_refusal
from .statistics import _classic_stat, _select_one_record, _stat_records


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


def _radio_rows(record: dict[str, Any], field: str) -> list[dict[str, Any]]:
    if field not in record:
        ident = record.get("_id") or record.get("mac") or "unknown"
        raise UniFiConnectionError(
            f"Unexpected /stat/device: missing {field} in device {upstream_error_text(ident)}"
        )
    return object_records(record[field], f"/stat/device {field}")


def _radios_by_band(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    bands: dict[str, dict[str, Any]] = {}
    for row in rows:
        band = row.get("radio")
        if not isinstance(band, str):
            raise UniFiConnectionError("Unexpected /stat/device radio row without a radio band")
        if band in bands:
            raise ValueError(
                f"Ambiguous radio band "
                f"{upstream_error_text(band)}: multiple radio_table entries for band"
            )
        bands[band] = row
    return bands


async def _read_device(
    client: UniFiClient, host_id: str, site_slug: str, device: str, key: APIKeyConfig | None
) -> tuple[dict[str, Any], dict[str, Any]]:
    # MAC addresses are validated and canonicalised before interpolation. Classic ids
    # are resolved in the collection, never used as an Integration id or a GET rest id.
    if is_mac(device):
        path = _classic_stat(host_id, site_slug, f"/device/{colon_mac(device)}")
    else:
        path = _classic_stat(host_id, site_slug, "/device")
    response = await client.get(path, key=key)
    require_classic_success(response, path)
    records = _stat_records(response, "/stat/device")
    try:
        record = _select_one_record(records, device, "device", "/stat/device")
    except ValueError:
        if not is_mac(device):
            raise
        # The item route can answer [] for an unknown MAC. List the complete set of
        # choices using the same selector rules as get_device_port_state.
        choices = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
        require_classic_success(choices, "/stat/device")
        return choices, _select_one_record(
            _stat_records(choices, "/stat/device"), device, "device", "/stat/device"
        )
    return response, record


def _channel_valid(band: str, channel: int) -> bool:
    if band == "ng":
        return 1 <= channel <= 14
    if band == "na":
        return channel in {
            *range(32, 65, 4),
            *range(100, 145, 4),
            34,
            38,
            42,
            46,
            *range(149, 178, 4),
        }
    if band == "6e":
        return channel == 2 or channel in range(1, 234, 4)
    return False


def _validate_channel(band: str, fields: dict[str, Any]) -> None:
    """Band/channel syntax is intrinsic: validate before any resolution GET."""
    if "channel" in fields:
        channel = fields["channel"]
        if channel != "auto":
            if isinstance(channel, str) and channel.isascii() and channel.isdecimal():
                channel = int(channel)
            if (
                not isinstance(channel, int)
                or isinstance(channel, bool)
                or not _channel_valid(band, channel)
            ):
                valid = [n for n in range(1, 234) if _channel_valid(band, n)]
                raise ValueError(
                    f"Invalid channel {fields['channel']!r} for radio band {band!r}; "
                    f"valid channels: auto or {valid}"
                )
            fields["channel"] = str(channel)


def _validated_changes(band: str, row: dict[str, Any], change: RadioChanges) -> dict[str, Any]:
    fields = change.model_dump(exclude_unset=True)
    _validate_channel(band, fields)
    if "ht" in fields:
        widths = {20, 40}
        if band == "6e" or (
            band == "na" and any(row.get(k) for k in ("is_11ac", "is_11ax", "is_11be"))
        ):
            widths.add(80)
        for width, capability in ((160, "has_ht160"), (240, "has_eht240"), (320, "has_eht320")):
            if row.get(capability) is True:
                widths.add(width)
        # A reported configured width is itself evidence the device supports it.
        if isinstance(row.get("ht"), int):
            widths.add(row["ht"])
        if fields["ht"] not in widths:
            raise ValueError(
                f"Invalid ht {fields['ht']!r} for {band}: "
                f"device radio_table supports {sorted(widths)} MHz"
            )
    if "tx_power" in fields:
        power = fields["tx_power"]
        for capability, too_far in (
            ("min_txpower", lambda bound: power < bound),
            ("max_txpower", lambda bound: power > bound),
        ):
            bound = row.get(capability)
            if isinstance(bound, (int, float)) and not isinstance(bound, bool) and too_far(bound):
                raise ValueError(
                    f"tx_power {power} for {band} is outside the device's {capability}={bound}"
                )
    return fields


def _diff(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    old = _radios_by_band(before)
    new = _radios_by_band(after)
    changed: dict[str, Any] = {}
    for band in dict.fromkeys([*old, *new]):
        left, right = old.get(band, {}), new.get(band, {})
        fields = {
            field: {"before": left.get(field), "after": right.get(field)}
            for field in dict.fromkeys([*left, *right])
            if (field in left) != (field in right)
            or not leaf_equal(left.get(field), right.get(field))
        }
        if fields:
            changed[band] = fields
    return changed


async def _get_device_radios(
    client: UniFiClient, registry: Registry, host: str, site: str, device: str
) -> dict[str, Any]:
    validate_selector(device, "device")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    response = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
    require_classic_success(response, "/stat/device")
    record = _select_one_record(
        _stat_records(response, "/stat/device"), device, "device", "/stat/device"
    )
    table = _radio_rows(record, "radio_table")
    stats = _radio_rows(record, "radio_table_stats")
    # Keep the entire upstream device and envelope; projections are additive only, and a
    # colliding upstream key keeps its value (the projection goes in _wrapperFields).
    return with_context(
        response,
        {
            "_device": record,
            "_radio_table": table,
            "_radio_table_stats": stats,
            "_radios": {
                band: {
                    "radio_table": row,
                    "radio_table_stats": [s for s in stats if s.get("radio") == band],
                }
                for band, row in _radios_by_band(table).items()
            },
        },
    )


async def _update_device_radio(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    device: str,
    radios: dict[str, RadioChanges | dict[str, Any]],
    /,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    try:
        guard_action("update_device_radio")
    except ReadOnlyModeError:
        client.audit_refusal(tool="update_device_radio", reason="UNIFI_READ_ONLY")
        raise
    if not env_flag(CONNECTOR_WRITE_ENV, True):
        client.audit_refusal(tool="update_device_radio", reason=CONNECTOR_WRITE_ENV)
        raise PermissionError(connector_write_refusal("update_device_radio"))
    validate_selector(device, "device")
    if not radios:
        raise ValueError("No fields provided in radios: supply at least one radio field to update")
    parsed = {
        band: values if isinstance(values, RadioChanges) else RadioChanges.model_validate(values)
        for band, values in radios.items()
    }
    for band, change in parsed.items():
        if band not in ("ng", "na", "6e"):
            raise ValueError(f"Unknown radio band {band!r}; valid bands: ng, na, 6e")
        _validate_channel(band, change.model_dump(exclude_unset=True))
    if not any(change.model_fields_set for change in parsed.values()):
        raise ValueError("No fields provided in radios: supply at least one radio field to update")
    key, host_id, site_slug = await resolve_site_slug(registry, host, site)
    lookup = await client.get(_classic_stat(host_id, site_slug, "/device"), key=key)
    require_classic_success(lookup, "/stat/device")
    resolved = _select_one_record(
        _stat_records(lookup, "/stat/device"), device, "device", "/stat/device"
    )
    before_response = lookup
    mac, classic_id = resolved.get("mac"), resolved.get("_id")
    if not isinstance(mac, str) or not is_mac(mac) or not isinstance(classic_id, str):
        raise UniFiConnectionError(
            f"Unexpected /stat/device: a radio write needs mac and Classic _id, got "
            f"{upstream_error_text(resolved, client)}"
        )
    # Even when selecting a Classic id, capture the full current table from the MAC
    # item route immediately before constructing the write (rest/device has no GET).
    validate_id(classic_id, "Classic device _id")
    before_response, resolved = await _read_device(client, host_id, site_slug, mac, key)
    if resolved.get("_id") != classic_id:
        raise ValueError(
            f"Device identity changed during resolution; read back before retrying "
            f"({classic_id!r} -> {upstream_error_text(resolved.get('_id'), client)})"
        )
    before = _radio_rows(resolved, "radio_table")
    bands = _radios_by_band(before)
    desired = deepcopy(before)
    desired_bands = _radios_by_band(desired)
    for band, change in parsed.items():
        if band not in ("ng", "na", "6e") or band not in bands:
            raise ValueError(f"Unknown radio band {band!r}; valid device bands: {list(bands)}")
        desired_bands[band].update(_validated_changes(band, bands[band], change))
    body = {"radio_table": desired}
    path = classic_rest(host_id, site_slug, f"/device/{classic_id}")

    async def read_after() -> tuple[dict[str, Any], Any, dict[str, Any]]:
        response, record = await _read_device(client, host_id, site_slug, mac, key)
        if record.get("_id") != classic_id:
            raise UniFiConnectionError(
                "Device identity changed on read-after; read back before retrying"
            )
        return (
            response,
            _radio_rows(record, "radio_table"),
            {"radio_table_stats": _radio_rows(record, "radio_table_stats")},
        )

    result = await update_device_config(
        client, path, before, desired, body, read_after, _diff, key=key, dry_run=dry_run
    )
    return with_context(result, {"_readBeforeResponse": before_response, "_lookupResponse": lookup})


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register the typed read and full-table write tools."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_device_radios(host: str, site: str, device: str) -> dict[str, Any]:
        """Read an AP's radio configuration, capabilities and operating state per band.

        Returns the complete upstream envelope and every device record unchanged.
        _device selects the requested AP; _radio_table and _radio_table_stats project its
        configuration and operating state. _radios is keyed by ng (2.4 GHz), na (5 GHz),
        6e (6 GHz). Classic stat/device is used; rest/device has no GET.
        Provide host (console name or id from list_hosts) and site (network site name or UUID
        from list_local_sites).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            device: AP MAC, e.g. "02:00:5e:00:00:a1", or Classic _id from list_device_stats.
                Unknown or ambiguous devices fail listing choices; Integration ids differ.
        """
        client, registry = deps_fn()
        return await _get_device_radios(client, registry, host, site, device)

    @mcp.tool(annotations=WRITE)
    async def update_device_radio(
        host: str,
        site: str,
        device: str,
        radios: dict[Literal["ng", "na", "6e"], RadioChanges],
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Update selected AP radio fields while preserving the full radio_table and its order.

        Reads stat/device by MAC, validates against the device's own radio capabilities,
        and PUTs the entire table to rest/device using its Classic _id. Other radios and
        fields stay unchanged. DFS channels may sit in DFS_WAIT for about 60 s; clients
        may roam; configuration can reprovision the AP. Never co-channel a mesh AP's
        only wireless uplink. Never auto-retried; a timeout reports outcome unknown.
        Read back before retrying. Returns readBefore/readAfter, changed per band/field, noOp and
        radio_table_stats, with the upstream write response verbatim under response.
        _diff is the requested diff; _noOp is an alias of noOp.
        UNIFI_DRY_RUN or dry_run=true returns status "dry_run", dryRun, sent: false, message,
        preview (method, path, params, body), and diff; changed/noOp are null, never write results;
        no-op skips PUT. Honours UNIFI_READ_ONLY and UNIFI_ENABLE_CONNECTOR_WRITE.
        _lookupResponse and _readBeforeResponse preserve the lookup and before envelopes;
        _readAfterResponse preserves the after envelope. readAfterError means verification
        failed on the fresh read-after; changed/noOp/_verified are null. _verified compares
        the complete desired table to the successful read-after; false means a mismatch.
        Even a skipped no-op PUT requires a new successful read; read back before retrying.
        Provide host (console name or id from list_hosts) and site (network site name or UUID
        from list_local_sites).

        Args:
            host: Console name or id from list_hosts, e.g. "my-console".
            site: Network site name or UUID from list_local_sites, e.g. "Default".
            device: AP MAC, e.g. "02:00:5e:00:00:a1", or Classic _id from list_device_stats.
                Unknown or ambiguous devices fail listing choices; Integration ids differ.
            radios: Changes keyed by band ng, na or 6e, e.g. {"na": {"channel": 44, "ht": 40},
                "ng": {"tx_power_mode": "medium"}}. Set only fields to change: channel (auto
                or a primary channel number), ht (MHz, device capabilities), tx_power_mode,
                tx_power (dBm, reported min/max), min_rssi_enabled or min_rssi (dBm).
                Shape: {ng?:RADIO,na?:RADIO,'6e'?:RADIO}; RADIO keys the server reads:
                {channel?:integer|'auto',ht?:integer,
                tx_power_mode?:'auto'|'low'|'medium'|'high'|'custom',tx_power?:integer,
                min_rssi_enabled?:boolean,min_rssi?:integer}
            dry_run: Preview the exact full-table PUT body and diff without writing, e.g. true.
                UNIFI_DRY_RUN also previews; read-only and write opt-outs still apply.
        """
        client, registry = deps_fn()
        return await _update_device_radio(
            client,
            registry,
            host,
            site,
            device,
            {str(band): change for band, change in radios.items()},
            dry_run=dry_run,
        )
