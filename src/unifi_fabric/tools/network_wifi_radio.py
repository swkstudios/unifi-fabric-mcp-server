"""Network WiFi radio observability and guarded scan controls."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal, cast

from fastmcp import FastMCP

from ..client import (
    DRY_RUN_MESSAGE,
    UniFiClient,
    UniFiConnectionError,
    upstream_error_value,
    validate_id,
)
from ..config import APIKeyConfig
from ..macs import colon_mac, is_mac
from ..read_only import ReadOnlyModeError, guard_action, mark_write_denied
from ..registry import Registry
from ..selector_args import check_selector
from ..switches import connector_writes_enabled
from ..tool_annotations import READ_ONLY, WRITE
from . import network
from ._classic_cmd import classic_command_for_site
from ._classic_objects import (
    addressed_body,
    classic_rest,
    networkconf_records,
    resolve_site_slug,
    select_classic_record,
    v2_site,
)
from ._keys import with_context
from ._payload import strip_empty_list_values, upstream_hint
from ._results import requested_leaves_match, safe_read_after, with_read_after_error
from .connector import CONNECTOR_WRITE_ENV, connector_write_refusal


def _mac(value: str, name: str) -> str:
    if not isinstance(value, str) or not is_mac(value):
        raise ValueError(f"{name} must be a MAC address such as '02:00:5e:00:00:a1'")
    return colon_mac(value)


def _epoch(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer Unix epoch in milliseconds")
    return value


def _with_epoch_warnings(response: Any, **values: int | None) -> Any:
    """Add declared epoch-milliseconds unit details as an additive response key."""
    if not isinstance(response, dict):
        return response
    return with_context(
        response,
        {
            "_warnings": [
                {
                    "code": "EPOCH_MILLISECONDS",
                    "argument": name,
                    "value": value,
                    "message": f"{name} is a Unix epoch in milliseconds, e.g. 1710000000000.",
                }
                for name, value in values.items()
                if value is not None
            ]
        },
    )


def _wifi_security(value: str) -> str:
    choices = {"OPEN", "WPA2_PERSONAL", "WPA3_PERSONAL", "WPA2_ENTERPRISE", "WPA3_ENTERPRISE"}
    if value not in choices:
        raise ValueError(f"uplink_security must be one of {sorted(choices)}")
    return value


def _wifi_band(value: str) -> str:
    choices = {"RADIO_NG", "RADIO_NA", "RADIO_6E"}
    if value not in choices:
        raise ValueError(f"uplink_band must be one of {sorted(choices)}")
    return value


def _wifi_string(value: str, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


async def _site(registry: Registry, host: str, site: str) -> tuple[APIKeyConfig | None, str, str]:
    check_selector("host", host)
    check_selector("site", site)
    return await resolve_site_slug(registry, host, site)


async def _get(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    suffix: str,
    params: dict[str, Any] | None = None,
) -> Any:
    key, host_id, slug = await _site(registry, host, site)
    return await client.get(v2_site(host_id, slug, suffix), key=key, params=params)


async def _post(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    suffix: str,
    body: dict[str, Any] | None,
    tool: str,
    dry_run: bool,
) -> Any:
    try:
        guard_action(tool)
    except ReadOnlyModeError:
        client.audit_refusal(tool=tool, reason="UNIFI_WRITE_POLICY")
        raise
    if not connector_writes_enabled():
        client.audit_refusal(tool=tool, reason=CONNECTOR_WRITE_ENV)
        raise mark_write_denied(PermissionError(connector_write_refusal(tool)))
    key, host_id, slug = await _site(registry, host, site)
    path = v2_site(host_id, slug, suffix)
    if dry_run or client.dry_run:
        client._audit_write("POST", path, "dry_run", None, body=body)
        return {
            "status": "dry_run",
            "dryRun": True,
            "sent": False,
            "message": DRY_RUN_MESSAGE,
            "preview": {"method": "POST", "path": path, "params": None, "body": body},
        }
    return await client.post(path, key=key, json=body)


async def get_radio_ai_isolation_matrix(
    client: UniFiClient, registry: Registry, host: str, site: str, radio_band: str | None = None
) -> Any:
    return await _get(
        client,
        registry,
        host,
        site,
        "/radio-ai/isolation-matrix",
        {"radioBand": radio_band} if radio_band else None,
    )


async def preview_radio_ai_optimization(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    calculation_id: str,
    radios: list[dict[str, Any]],
    method: str,
    *,
    dry_run: bool = False,
) -> Any:
    if (
        not isinstance(calculation_id, str)
        or not calculation_id.strip()
        or not isinstance(radios, list)
        or not radios
        or not isinstance(method, str)
        or not method.strip()
    ):
        raise ValueError(
            "calculation_id, a non-empty radios array, and a non-empty method are required"
        )
    return await _post(
        client,
        registry,
        host,
        site,
        "/radio-ai/optimize/preview",
        {"calculation_id": calculation_id, "radios": radios, "method": method},
        "preview_radio_ai_optimization",
        dry_run,
    )


async def apply_radio_ai_optimization(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    radios: list[dict[str, Any]],
    calculation_id: str | None = None,
    *,
    dry_run: bool = False,
) -> Any:
    if not isinstance(radios, list) or not radios:
        raise ValueError("radios must be a non-empty JSON array from preview_radio_ai_optimization")
    if calculation_id is not None:
        validate_id(calculation_id, "calculation_id")
        return await _post(
            client,
            registry,
            host,
            site,
            f"/radio-ai/optimize/apply/{calculation_id}",
            None,
            "apply_radio_ai_optimization",
            dry_run,
        )
    return await _post(
        client,
        registry,
        host,
        site,
        "/radio-ai/optimize/apply-last",
        {"radios": radios},
        "apply_radio_ai_optimization",
        dry_run,
    )


async def get_radio_history(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    view: Literal["timeline", "timestamps", "at"],
    start: int | None = None,
    end: int | None = None,
    access_point: str | None = None,
) -> Any:
    access_point_mac = _mac(access_point, "access_point") if access_point is not None else None
    if view == "at":
        if start is None:
            raise ValueError("start is required for view='at' and is a Unix epoch in milliseconds")
        ignored = [n for n, v in (("end", end), ("access_point", access_point)) if v is not None]
        if ignored:
            raise ValueError(
                f"view 'at' takes only start (the snapshot time); {' and '.join(ignored)} do "
                "not apply to it and would be silently dropped. Nothing was sent."
            )
        start_ms = _epoch(start, "start")
        response = await _get(client, registry, host, site, f"/radios/history/at/{start_ms}")
        return _with_epoch_warnings(response, start=start_ms)
    if view not in {"timeline", "timestamps"} or start is None or end is None:
        raise ValueError("view is timeline or timestamps and requires start and end")
    suffix = (
        f"/radios/history/{view}"
        if access_point_mac is None
        else f"/radios/history/{access_point_mac}/{view}"
    )
    start_ms, end_ms = _epoch(start, "start"), _epoch(end, "end")
    response = await _get(client, registry, host, site, suffix, {"start": start_ms, "end": end_ms})
    return _with_epoch_warnings(response, start=start_ms, end=end_ms)


async def get_wifi_connectivity(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    start: int,
    end: int,
    access_point: str | None = None,
    client_mac: str | None = None,
    radio_band: str | None = None,
) -> Any:
    params: dict[str, Any] = {
        "start": _epoch(start, "start"),
        "end": _epoch(end, "end"),
        "apMac": "all",
        "clientMac": "all",
        "radioBand": "all",
    }
    if access_point is not None:
        params["apMac"] = _mac(access_point, "access_point")
    if client_mac is not None:
        params["clientMac"] = _mac(client_mac, "client_mac")
    if radio_band is not None:
        params["radioBand"] = radio_band
    response = await _get(client, registry, host, site, "/wifi-connectivity", params)
    return _with_epoch_warnings(response, start=params["start"], end=params["end"])


async def control_wifi_doctor_optimization(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    action: Literal["start", "stop"],
    *,
    dry_run: bool = False,
) -> Any:
    if action not in {"start", "stop"}:
        raise ValueError("action must be start or stop")
    return await _post(
        client,
        registry,
        host,
        site,
        f"/wifi-doctor/optimization/{action}",
        None,
        "control_wifi_doctor_optimization",
        dry_run,
    )


async def get_wifi_stats(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    view: Literal["details", "radios"],
    start: int,
    end: int,
    access_point: str | None = None,
) -> Any:
    if view not in {"details", "radios"}:
        raise ValueError("view must be details or radios")
    params: dict[str, Any] = {"start": _epoch(start, "start"), "end": _epoch(end, "end")}
    if access_point is not None:
        params["apMac"] = _mac(access_point, "access_point")
    response = await _get(client, registry, host, site, f"/wifi-stats/{view}", params)
    return _with_epoch_warnings(response, start=params["start"], end=params["end"])


async def get_wifi_tethering_scan(
    client: UniFiClient, registry: Registry, host: str, site: str, gateway_mac: str
) -> Any:
    return await _get(
        client, registry, host, site, f"/wifi-tethering/scan/{_mac(gateway_mac, 'gateway_mac')}"
    )


async def get_wifiman_settings(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    return await _get(client, registry, host, site, "/wifiman")


async def get_wlan_capabilities(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    return await _get(client, registry, host, site, "/wlan-capabilities")


async def list_available_wifi_channels(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    key, host_id, slug = await _site(registry, host, site)
    return await client.get(
        f"/v1/connector/consoles/{host_id}/proxy/network/api/s/{slug}/stat/current-channel", key=key
    )


async def get_access_point_neighbors(
    client: UniFiClient, registry: Registry, host: str, site: str, access_point: str
) -> Any:
    return await _get(
        client, registry, host, site, f"/ap/{_mac(access_point, 'access_point')}/neighbors"
    )


async def start_spectrum_scan(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    access_point: str,
    *,
    dry_run: bool = False,
) -> Any:
    mac = _mac(access_point, "access_point")
    try:
        guard_action("start_spectrum_scan")
    except ReadOnlyModeError:
        client.audit_refusal(tool="start_spectrum_scan", reason="UNIFI_WRITE_POLICY")
        raise
    if not connector_writes_enabled():
        client.audit_refusal(tool="start_spectrum_scan", reason=CONNECTOR_WRITE_ENV)
        raise mark_write_denied(PermissionError(connector_write_refusal("start_spectrum_scan")))
    if dry_run or client.dry_run:
        key, host_id, slug = await _site(registry, host, site)
        client._audit_write(
            "POST",
            f"/v1/connector/consoles/{host_id}/proxy/network/api/s/{slug}/cmd/devmgr",
            "dry_run",
            None,
            body={"cmd": "spectrum-scan", "mac": mac},
        )
        return {
            "status": "dry_run",
            "dryRun": True,
            "sent": False,
            "message": DRY_RUN_MESSAGE,
            "preview": {
                "method": "POST",
                "path": f"/v1/connector/consoles/{host_id}/proxy/network/api/s/{slug}/cmd/devmgr",
                "params": None,
                "body": {"cmd": "spectrum-scan", "mac": mac},
            },
        }
    return await classic_command_for_site(
        client, registry, host, site, "devmgr", "spectrum-scan", {"mac": mac}
    )


async def get_spectrum_scan_results(
    client: UniFiClient, registry: Registry, host: str, site: str, access_point: str | None = None
) -> Any:
    mac = _mac(access_point, "access_point") if access_point is not None else None
    key, host_id, slug = await _site(registry, host, site)
    suffix = "/stat/spectrum-scan" if mac is None else f"/stat/spectrum-scan/{mac}"
    return await client.get(
        f"/v1/connector/consoles/{host_id}/proxy/network/api/s/{slug}{suffix}", key=key
    )


async def start_wifi_quick_scan(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    radio_band: str,
    *,
    dry_run: bool = False,
) -> Any:
    if not isinstance(radio_band, str) or not radio_band.strip():
        raise ValueError("radio_band must be a non-empty band name such as 'na'")
    return await _post(
        client,
        registry,
        host,
        site,
        "/quick-scan",
        {"band": radio_band},
        "start_wifi_quick_scan",
        dry_run,
    )


#: The radio bands quick-scan/status answers for (live, Network 11.0.89, 2026-10-28: ng, na
#: and 6e answer 200; an omitted or unknown band answers HTTP 400). The web app sends one
#: band per status read.
QuickScanBand = Literal["ng", "na", "6e"]


async def get_wifi_quick_scan_status(
    client: UniFiClient, registry: Registry, host: str, site: str, radio_band: str | None = None
) -> Any:
    try:
        return await _get(
            client,
            registry,
            host,
            site,
            "/quick-scan/status",
            {"band": radio_band} if radio_band else None,
        )
    except UniFiConnectionError as exc:
        if exc.status == 400 and radio_band is None:
            upstream_hint(
                exc,
                (
                    "The Network UI sends a band for quick scan status; "
                    "pass radio_band, for example na."
                ),
            )
            raise
        raise


async def get_wifi_uplink_scan_status(
    client: UniFiClient, registry: Registry, host: str, site: str
) -> Any:
    return await _get(client, registry, host, site, "/quick-scan/wifi-uplink/status")


def _select_wan(records: list[dict[str, Any]], wan_id: str | None) -> dict[str, Any]:
    """The WAN networkconf record named by ``wan_id``, or the site's only WAN record."""
    if wan_id is not None:
        return select_classic_record(records, wan_id, "WiFi WAN", "list_wan_interfaces")
    if len(records) == 1:
        return records[0]
    valid = (
        "; ".join(
            f"{upstream_error_value(r.get('name'))!r}: "
            f"id={upstream_error_value(r.get('external_id'))}, "
            f"_id={upstream_error_value(r.get('_id'))}"
            for r in records
        )
        or "(none)"
    )
    raise ValueError(
        f"WiFi WAN is ambiguous without wan_id: the site has {len(records)} networkconf "
        f"records of purpose 'wan'; valid: {valid}. Pass wan_id from list_wan_interfaces."
    )


async def configure_wifi_wan(
    client: UniFiClient,
    registry: Registry,
    host: str,
    site: str,
    is_wifi_tethering: bool,
    enabled: bool,
    port: int,
    uplink_ssid: str,
    uplink_security: str,
    uplink_band: str,
    x_uplink_password: str | None = None,
    uplink_identity: str | None = None,
    wan_id: str | None = None,
    *,
    dry_run: bool = False,
) -> Any:
    """Configure a Classic WAN record for WiFi tethering (read-merge-write).

    Discovery reads ``rest/networkconf`` and picks the ``purpose == "wan"`` record (by
    ``wan_id``, or the only one); the merged record, unrelated read-back fields included,
    is written through :func:`network.update_wan_interface` (``purpose`` pinned to
    ``wan``) and the upstream envelope is returned with additive ``_readAfter`` /
    ``_verified`` keys.
    A non-object write body is kept whole under ``response`` so the verdict keys are never dropped.
    """
    if wan_id is not None:
        validate_id(wan_id, "wan_id")
    if not isinstance(is_wifi_tethering, bool) or not isinstance(enabled, bool):
        raise ValueError("is_wifi_tethering and enabled must be booleans")
    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError("port must be an integer")
    security, band = _wifi_security(uplink_security), _wifi_band(uplink_band)
    ssid = _wifi_string(uplink_ssid, "uplink_ssid")
    protected, enterprise = security != "OPEN", security in {"WPA2_ENTERPRISE", "WPA3_ENTERPRISE"}
    if protected and x_uplink_password is None:
        raise ValueError("x_uplink_password is required for protected WiFi security")
    if enterprise and uplink_identity is None:
        raise ValueError("uplink_identity is required for enterprise WiFi security")
    if x_uplink_password is not None:
        _wifi_string(x_uplink_password, "x_uplink_password")
    if uplink_identity is not None:
        _wifi_string(uplink_identity, "uplink_identity")
    try:
        guard_action("configure_wifi_wan")
    except ReadOnlyModeError:
        client.audit_refusal(tool="configure_wifi_wan", reason="UNIFI_WRITE_POLICY")
        raise
    if not connector_writes_enabled():
        client.audit_refusal(tool="configure_wifi_wan", reason=CONNECTOR_WRITE_ENV)
        raise mark_write_denied(PermissionError(connector_write_refusal("configure_wifi_wan")))
    key, host_id, slug = await _site(registry, host, site)
    records = await networkconf_records(client, host_id, slug, "wan", key=key)
    current = _select_wan(records, wan_id)
    classic_id = cast(str, current.get("_id"))
    validate_id(classic_id, "_id")
    requested: dict[str, Any] = {
        "purpose": "wan",
        "is_wifi_tethering": is_wifi_tethering,
        "enabled": enabled,
        "port": port,
        "uplink_ssid": ssid,
        "uplink_security": security,
        "uplink_band": band,
    }
    if x_uplink_password is not None:
        requested["x_uplink_password"] = x_uplink_password
    if uplink_identity is not None:
        requested["uplink_identity"] = uplink_identity
    desired = {**current, **requested}
    if dry_run or client.dry_run:
        body = addressed_body(
            strip_empty_list_values(desired), classic_id, current.get("external_id")
        )
        client._audit_write(
            "PUT",
            classic_rest(host_id, slug, f"/networkconf/{classic_id}"),
            "dry_run",
            None,
            body=body,
        )
        return {
            "status": "dry_run",
            "dryRun": True,
            "sent": False,
            "message": DRY_RUN_MESSAGE,
            "preview": {
                "method": "PUT",
                "path": classic_rest(host_id, slug, f"/networkconf/{classic_id}"),
                "params": None,
                "body": body,
            },
        }
    response = await network.update_wan_interface(client, registry, host, site, classic_id, desired)

    async def read_after() -> dict[str, Any]:
        after_records = await networkconf_records(client, host_id, slug, "wan", key=key)
        for record in after_records:
            if record.get("_id") == classic_id:
                return record
        raise ValueError(f"WAN networkconf record {classic_id!r} is absent after the write")

    after, error = await safe_read_after(read_after)
    verified = (
        requested_leaves_match(requested, after)
        if error is None and isinstance(after, dict)
        else None
    )
    if not isinstance(response, dict):
        response = {"response": response}
    result = with_context(response, {"_readAfter": after, "_verified": verified})
    return with_read_after_error(result, error, additive=True)


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register N10 WiFi-radio tools as typed FastMCP functions."""

    def deps() -> tuple[UniFiClient, Registry]:
        return cast(tuple[UniFiClient, Registry], deps_fn())

    @mcp.tool(name="get_radio_ai_isolation_matrix", annotations=READ_ONLY)
    async def radio_ai_isolation(host: str, site: str, radio_band: str | None = None) -> Any:
        """Read the radio-AI isolation matrix (per-AP RF isolation used by channel AI).

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            radio_band: Optional radio band filter, e.g. "na".
        """
        return await get_radio_ai_isolation_matrix(*deps(), host, site, radio_band)

    @mcp.tool(name="preview_radio_ai_optimization", annotations=WRITE)
    async def radio_ai_preview(
        host: str,
        site: str,
        calculation_id: str,
        radios: list[dict[str, Any]],
        method: str,
        dry_run: bool = False,
    ) -> Any:
        """Create radio-AI preview. Consequence: creates controller calculation state.

        POSTs calculation_id, radios and method to radio-ai/optimize/preview.
        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body) without sending; never a write result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, calculation_id, radios, method.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            calculation_id: Required calculation UUID, e.g. "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            radios: Required non-empty plan array, e.g. [{"mac":"02:00:5e:00:00:a1"}].
                Shape: {mac:string}[]; keys the server reads: none, each entry is sent as given
            method: Required optimization method, e.g. "balanced".
            dry_run: Preview without POST, e.g. true.
        """
        return await preview_radio_ai_optimization(
            *deps(), host, site, calculation_id, radios, method, dry_run=dry_run
        )

    @mcp.tool(name="apply_radio_ai_optimization", annotations=WRITE)
    async def radio_ai_apply(
        host: str,
        site: str,
        radios: list[dict[str, Any]],
        calculation_id: str | None = None,
        dry_run: bool = False,
    ) -> Any:
        """Apply radio-AI plan. Consequence: channels may change and clients may roam.

        With calculation_id POSTs radio-ai/optimize/apply/{calculation_id}; without it
        POSTs radios to radio-ai/optimize/apply-last. Never auto-retried.
        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body) without sending; never a write result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, radios.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            radios: Required non-empty radio array, e.g. [{"mac":"02:00:5e:00:00:a1"}].
                Shape: {mac:string}[]; keys the server reads: none, each entry is sent as given
            calculation_id: Optional preview UUID, e.g. "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            dry_run: Preview without POST, e.g. true.
        """
        return await apply_radio_ai_optimization(
            *deps(), host, site, radios, calculation_id, dry_run=dry_run
        )

    @mcp.tool(name="get_radio_history", annotations=READ_ONLY)
    async def radio_history(
        host: str,
        site: str,
        view: Literal["timeline", "timestamps", "at"],
        start: int | None = None,
        end: int | None = None,
        access_point: str | None = None,
    ) -> Any:
        """Read AP radio history (timeline, timestamps, or the snapshot at start).

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        View "at" takes only start; end or access_point with it fails before any request.
        _warnings lists each epoch argument with its unit (EPOCH_MILLISECONDS).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, view.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            view: Required history view, e.g. "timeline".
            start: Required epoch milliseconds, e.g. 1710000000000.
            end: Required for range views, epoch milliseconds, e.g. 1710003600000.
            access_point: Optional AP MAC, e.g. "02:00:5e:00:00:a1".
        """
        return await get_radio_history(*deps(), host, site, view, start, end, access_point)

    @mcp.tool(name="get_wifi_connectivity", annotations=READ_ONLY)
    async def wifi_connectivity(
        host: str,
        site: str,
        start: int,
        end: int,
        access_point: str | None = None,
        client_mac: str | None = None,
        radio_band: str | None = None,
    ) -> Any:
        """Read WiFi connectivity for a time range, optionally per AP, client or band.

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        _warnings lists each epoch argument with its unit (EPOCH_MILLISECONDS).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, start, end.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            start: Required epoch milliseconds, e.g. 1710000000000.
            end: Required epoch milliseconds, e.g. 1710003600000.
            access_point: Optional AP MAC, e.g. "02:00:5e:00:00:a1".
            client_mac: Optional client MAC, e.g. "02:00:5e:00:00:b2".
            radio_band: Optional band, e.g. "na".
        """
        return await get_wifi_connectivity(
            *deps(), host, site, start, end, access_point, client_mac, radio_band
        )

    @mcp.tool(name="control_wifi_doctor_optimization", annotations=WRITE)
    async def wifi_doctor(
        host: str, site: str, action: Literal["start", "stop"], dry_run: bool = False
    ) -> Any:
        """Start or stop WiFi Doctor. Consequence: may change radio behavior and client service.

        POSTs wifi-doctor/optimization/{action}. Never auto-retried.
        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body) without sending; never a write result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, action.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            action: Required action, e.g. "start".
            dry_run: Preview without POST, e.g. true.
        """
        return await control_wifi_doctor_optimization(*deps(), host, site, action, dry_run=dry_run)

    @mcp.tool(name="get_wifi_stats", annotations=READ_ONLY)
    async def wifi_stats(
        host: str,
        site: str,
        view: Literal["details", "radios"],
        start: int,
        end: int,
        access_point: str | None = None,
    ) -> Any:
        """Read WiFi statistics (details or per-radio) for a time range.

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        _warnings lists each epoch argument with its unit (EPOCH_MILLISECONDS).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, view, start, end.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            view: Required view, e.g. "details".
            start: Required epoch milliseconds, e.g. 1710000000000.
            end: Required epoch milliseconds, e.g. 1710003600000.
            access_point: Optional AP MAC, e.g. "02:00:5e:00:00:a1".
        """
        return await get_wifi_stats(*deps(), host, site, view, start, end, access_point)

    @mcp.tool(name="get_wifi_tethering_scan", annotations=READ_ONLY)
    async def tethering_scan(host: str, site: str, gateway_mac: str) -> Any:
        """Read the WiFi networks a gateway saw in its tethering scan.

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, gateway_mac.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            gateway_mac: Required gateway MAC, e.g. "02:00:5e:00:00:a1".
        """
        return await get_wifi_tethering_scan(*deps(), host, site, gateway_mac)

    @mcp.tool(name="get_wifiman_settings", annotations=READ_ONLY)
    async def wifiman_settings(host: str, site: str) -> Any:
        """Read the site WiFiman settings.

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
        """
        return await get_wifiman_settings(*deps(), host, site)

    @mcp.tool(name="get_wlan_capabilities", annotations=READ_ONLY)
    async def wlan_capabilities(host: str, site: str) -> Any:
        """Read the site WLAN capabilities (supported bands, security and features).

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
        """
        return await get_wlan_capabilities(*deps(), host, site)

    @mcp.tool(name="list_available_wifi_channels", annotations=READ_ONLY)
    async def available_channels(host: str, site: str) -> Any:
        """List the WiFi channels available per band (Classic stat/current-channel).

        Returns the upstream Classic envelope verbatim (meta and data); an array is wrapped as
        result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
        """
        return await list_available_wifi_channels(*deps(), host, site)

    @mcp.tool(name="get_access_point_neighbors", annotations=READ_ONLY)
    async def ap_neighbors(host: str, site: str, access_point: str) -> Any:
        """Read the neighbouring APs an access point hears.

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, access_point.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            access_point: Required AP MAC, e.g. "02:00:5e:00:00:a1".
        """
        return await get_access_point_neighbors(*deps(), host, site, access_point)

    @mcp.tool(name="start_spectrum_scan", annotations=WRITE)
    async def spectrum_scan(host: str, site: str, access_point: str, dry_run: bool = False) -> Any:
        """Start spectrum scan. Consequence: may interrupt service on selected AP.

        Sends Classic cmd/devmgr {"cmd": "spectrum-scan", "mac": ...}; success needs
        meta.rc "ok", otherwise the full upstream meta is raised. Never auto-retried.
        Returns the upstream Classic envelope verbatim (meta and data).
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body) without sending; never a write result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, access_point.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            access_point: Required free AP MAC, e.g. "02:00:5e:00:00:a1".
            dry_run: Preview without POST, e.g. true.
        """
        return await start_spectrum_scan(*deps(), host, site, access_point, dry_run=dry_run)

    @mcp.tool(name="get_spectrum_scan_results", annotations=READ_ONLY)
    async def spectrum_results(host: str, site: str, access_point: str | None = None) -> Any:
        """Read spectrum scan results, for every AP or one access_point.

        Returns the upstream Classic envelope verbatim (meta and data); an array is wrapped as
        result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            access_point: Optional AP MAC, e.g. "02:00:5e:00:00:a1".
        """
        return await get_spectrum_scan_results(*deps(), host, site, access_point)

    @mcp.tool(name="start_wifi_quick_scan", annotations=WRITE)
    async def quick_scan(host: str, site: str, radio_band: str, dry_run: bool = False) -> Any:
        """Start WiFi quick scan. Consequence: may interrupt radio service while scanning.

        POSTs {"band": radio_band} to quick-scan. Never auto-retried.
        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body) without sending; never a write result.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, radio_band.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            radio_band: Required radio band: ng (2.4 GHz), na (5 GHz) or 6e (6 GHz), e.g. "na".
            dry_run: Preview without POST, e.g. true.
        """
        return await start_wifi_quick_scan(*deps(), host, site, radio_band, dry_run=dry_run)

    @mcp.tool(name="get_wifi_quick_scan_status", annotations=READ_ONLY)
    async def quick_scan_status(host: str, site: str, radio_band: str | None = None) -> Any:
        """Read the WiFi quick-scan status for one radio band.

        GET quick-scan/status?band={radio_band}, one band per call as the web app reads it
        (the console answers HTTP 400 without a band), e.g. {"in_progress": false}.
        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            radio_band: Optional band; observed values include ng, na and 6e, e.g. "na".
        """
        return await get_wifi_quick_scan_status(*deps(), host, site, radio_band)

    @mcp.tool(name="get_wifi_uplink_scan_status", annotations=READ_ONLY)
    async def wifi_uplink_scan_status(host: str, site: str) -> Any:
        """Read the WiFi-uplink quick-scan status (SSIDs a gateway can tether to).

        Returns the upstream v2 body verbatim (an object, or an array wrapped as result).
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
        """
        return await get_wifi_uplink_scan_status(*deps(), host, site)

    @mcp.tool(name="configure_wifi_wan", annotations=WRITE)
    async def wifi_wan(
        host: str,
        site: str,
        is_wifi_tethering: bool,
        enabled: bool,
        port: int,
        uplink_ssid: str,
        uplink_security: Literal[
            "OPEN", "WPA2_PERSONAL", "WPA3_PERSONAL", "WPA2_ENTERPRISE", "WPA3_ENTERPRISE"
        ],
        uplink_band: Literal["RADIO_NG", "RADIO_NA", "RADIO_6E"],
        x_uplink_password: str | None = None,
        uplink_identity: str | None = None,
        wan_id: str | None = None,
        dry_run: bool = False,
    ) -> Any:
        """Configure a WAN for WiFi tethering. Consequence: can disconnect the site's WAN.

        Reads the site's Classic networkconf records, picks the WAN record (wan_id, or the
        only one), merges these fields over it and PUTs the whole record with purpose
        "wan". Returns the upstream envelope verbatim plus _readAfter (the WAN record read
        back) and _verified (requested fields match, type-strict); _readAfterError is added
        when the read-back fails. A non-object write body is returned whole under response
        with those keys beside it. x_uplink_password passes through unless
        UNIFI_REDACT_SECRETS. Several WANs without wan_id fail listing valid records.
        dry-run policy or dry_run=true returns status "dry_run", dryRun, sent: false, message and
        preview (method, path, params, body: the merged record) without writing or verifying.
        Provide host (console name or id from list_hosts) and site (Network site name or UUID
        from list_local_sites).

        Required arguments: host, site, is_wifi_tethering, enabled, port, uplink_ssid,
        uplink_security, uplink_band.

        Args:
            host: Required console name or id, e.g. "my-console".
            site: Required Network site name or UUID, e.g. "Default".
            is_wifi_tethering: Required tethering state, e.g. true.
            enabled: Required WAN state, e.g. true.
            port: Required WAN port number, e.g. 9.
            uplink_ssid: Required upstream WiFi SSID, e.g. "example-uplink".
            uplink_security: Required security mode, e.g. "WPA2_PERSONAL".
            uplink_band: Required WiFi band, e.g. "RADIO_NA".
            x_uplink_password: Passphrase, required unless OPEN, e.g. "example-passphrase".
            uplink_identity: Identity, required for enterprise security, e.g. "example-uplink".
            wan_id: WAN id (Integration id or Classic _id) when the site has several WANs,
                e.g. "3fa85f64-5717-4562-b3fc-2c963f66afa6".
            dry_run: Preview the merged PUT without writing, e.g. true.
        """
        return await configure_wifi_wan(
            *deps(),
            host,
            site,
            is_wifi_tethering,
            enabled,
            port,
            uplink_ssid,
            uplink_security,
            uplink_band,
            x_uplink_password,
            uplink_identity,
            wan_id,
            dry_run=dry_run,
        )
