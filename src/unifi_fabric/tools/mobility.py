"""UniFi Mobility tools — workspace-scoped identity, kept separate from host/site.

The UniFi Mobility API (https://developer.ui.com/mobility/v1.0.0) is a *cloud*
resource family served directly from the Site Manager gateway (base
``https://api.ui.com``) under ``/v1/mobility/...``. Its identity model is
**workspace-based**: a workspace (a "mobility cloud site") owns UMR mobile
routers (devices), each of which has clients. This is deliberately NOT the
console host/site model used by the Network and Protect tools — a Mobility
workspace is not a UniFi console, and there is no ``host``/``site`` resolution
here. The tools therefore take a ``workspace_id`` (and ``device_id``) directly
and never touch the host/site registry.

Auth is the same Fabric / Site Manager API key used everywhere else in this
server; an optional ``key_label`` selects a specific configured key for
multi-key deployments (``APIKeyConfig.label``). A missing Mobility scope on the
key, or a workspace whose Mobility subscription is unavailable, surfaces as the
upstream error verbatim (HTTP 401/403 with the gateway's ``code`` / ``message``
/ ``traceId`` body) — the server does not mask it.

Reads are typed pass-throughs. The three documented ``PUT`` writes (device name,
LAN/DHCP, wireless) are guarded: each does a read-before, detects a no-op
against the observable current device state, requires ``confirm=true``, honours
an environment kill-switch, and re-reads the device afterwards to report what
actually changed. A ``PUT`` is never silently treated as a partial merge — the
LAN/DHCP endpoint is a *documented* partial update and is labelled as such;
device-name and wireless send the full documented body.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any

from ..client import UniFiClient, validate_id
from ..config import APIKeyConfig

#: Cloud gateway base for the Mobility resource family (served from api.ui.com).
MOBILITY_BASE = "/v1/mobility"
_WORKSPACES = f"{MOBILITY_BASE}/workspaces"

#: Documented page-size cap for the offset-paginated device/client collections.
_MAX_PAGE_SIZE = 200

#: Environment write-gate for the three Mobility PUT writes. Gated OFF by default:
#: an *unset* variable leaves writes DISABLED. Writes are held pending live
#: verification of the PUT replace-vs-merge semantics (the official getting-started
#: page describes PUT as full replacement while the network endpoint documents a
#: partial merge -- issue #186 comment gate). Enable only after that semantics probe
#: is logged on the issue, by setting the variable to a truthy value ("1"/"true"/
#: "yes"/"on"). ``confirm=true`` remains independently required.
WRITE_ENABLED_ENV = "UNIFI_ENABLE_MOBILITY_WRITE"

_DISABLED_MSG = (
    "Mobility writes are gated OFF: environment variable "
    f"{WRITE_ENABLED_ENV} is unset or not truthy. Writes are held pending live "
    "verification of the PUT replace-vs-merge semantics (issue #186 comment gate); "
    "set it to a truthy value (1/true/yes/on) to enable. confirm=true remains required."
)


def _select_key(client: UniFiClient, key_label: str | None) -> APIKeyConfig | None:
    """Resolve the optional API-key label to a key config (None → default key).

    Raises ``KeyError`` (via ``get_key_by_label``) when the label is unknown, so a
    typo'd label fails loudly rather than silently riding the default key.
    """
    if key_label is None:
        return None
    return client.get_key_by_label(key_label)


def _writes_enabled() -> bool:
    """True only when the write-gate env var is explicitly set to a truthy value.

    Gated OFF by default (unset -> disabled) pending live verification of the PUT
    replace-vs-merge semantics documented on issue #186. confirm=true is a separate,
    always-required guard.
    """
    raw = os.environ.get(WRITE_ENABLED_ENV)
    if raw is None:
        return False
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _extract_list(raw: Any) -> list[dict[str, Any]]:
    """Return the ``data`` array from a paginated envelope (empty list otherwise)."""
    if isinstance(raw, dict):
        data = raw.get("data")
        if isinstance(data, list):
            return data
    return []


def _list_result(key: str, raw: Any) -> dict[str, Any]:
    """Shape a single-GET list response as ``{<key>: items, count, [total]}``."""
    items = _extract_list(raw)
    result: dict[str, Any] = {key: items, "count": len(items)}
    if isinstance(raw, dict) and isinstance(raw.get("total"), int):
        result["total"] = raw["total"]
    return result


def _device_path(workspace_id: str, device_id: str) -> str:
    return f"{_WORKSPACES}/{workspace_id}/devices/{device_id}"


# --- Validation helpers ------------------------------------------------------


def _validate_ipv4(value: str, name: str) -> None:
    """Reject a non-IPv4 string with a clear local error before it reaches the API."""
    try:
        ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError):
        raise ValueError(f"Invalid {name!r} {value!r}: expected an IPv4 address") from None


def _validate_len(value: str, name: str, low: int, high: int) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name!r} must be a string")
    if not (low <= len(value) <= high):
        raise ValueError(f"{name!r} must be {low}-{high} characters (got {len(value)})")


# --- Reads -------------------------------------------------------------------


async def list_mobility_workspaces(
    client: UniFiClient,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List UniFi Mobility workspaces visible to the authenticated API key.

    A workspace is a mobility "cloud site" (``workspace_id``, ``workspace_name``,
    ``is_owner``, ``status``). Returned verbatim. This endpoint is not query-
    paginated by the API; the full set is returned in one call.

    key_label: optional configured API-key label to route the request on a
    specific key (multi-key deployments). Omit to use the default key.
    """
    key = _select_key(client, key_label)
    raw = await client.get(_WORKSPACES, key=key)
    return _list_result("workspaces", raw)


async def list_mobility_admins(
    client: UniFiClient,
    workspace_id: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the admins of a Mobility workspace (mobility permissions only).

    Each admin carries ``name``, ``email``, ``status``, ``is_owner`` and a
    ``permissions`` object exposing the ``umr`` (Mobile Routing) level
    (ALL/VIEW_ONLY/NONE); ``permissions`` is ``null`` for a pending invite.
    Returned verbatim.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    key = _select_key(client, key_label)
    raw = await client.get(f"{_WORKSPACES}/{workspace_id}/admins", key=key)
    return _list_result("admins", raw)


async def list_mobility_devices(
    client: UniFiClient,
    workspace_id: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the UMR devices in a Mobility workspace.

    Each device is the lightweight summary (``id``, ``name``, ``model``,
    ``state``, ``firmware_version``, ``mac_address``). This collection is
    offset-paginated by the API (``limit``/``offset``, 200 max); every page is
    drained and the complete list is returned.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    key = _select_key(client, key_label)
    path = f"{_WORKSPACES}/{workspace_id}/devices"
    items = await client.paginate_offset(path, key=key, page_size=_MAX_PAGE_SIZE)
    return {"devices": items, "count": len(items)}


async def get_mobility_device(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Get full detail for one UMR device in a Mobility workspace.

    Returns the complete DeviceDetail (WAN/cellular/WiFi/VPN/subscription/GPS,
    counts, and the summary fields) verbatim under ``device``.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    validate_id(device_id, "device_id")
    key = _select_key(client, key_label)
    detail = await _fetch_device_detail(client, workspace_id, device_id, key)
    return {"device": detail}


async def list_mobility_clients(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    *,
    key_label: str | None = None,
) -> dict[str, Any]:
    """List the clients associated with a UMR device.

    Each client carries ``mac``, ``name``, ``type`` (WIRED/WIRELESS),
    ``connection_status``, ``ip_address``, ``is_blocked`` and (wireless only) a
    ``wifi_experience`` score. This collection is offset-paginated by the API
    (``limit``/``offset``, 200 max); every page is drained.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    validate_id(device_id, "device_id")
    key = _select_key(client, key_label)
    path = f"{_device_path(workspace_id, device_id)}/clients"
    items = await client.paginate_offset(path, key=key, page_size=_MAX_PAGE_SIZE)
    return {"clients": items, "count": len(items)}


async def _fetch_device_detail(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    key: APIKeyConfig | None,
) -> dict[str, Any]:
    """GET a device detail and unwrap its ``{"data": {...}}`` envelope."""
    raw = await client.get(_device_path(workspace_id, device_id), key=key)
    if isinstance(raw, dict):
        inner = raw.get("data")
        if isinstance(inner, dict):
            return inner
        return raw
    return {}


# --- Writes ------------------------------------------------------------------
#
# Each of the three documented PUT resources follows the same guarded flow:
#   1. read-before  — GET the device detail (proves it exists; snapshot state);
#   2. no-op detect — if the change is fully observable in the detail AND already
#                     matches, return status="no_op" without writing;
#   3. confirm gate — confirm must be True (the operative guard), else
#                     status="unconfirmed" with a current-vs-proposed preview;
#   4. env gate     — the write kill-switch (OFF by default, issue #186) blocks writes;
#   5. PUT          — issue the write. The endpoints answer 204 No Content, so the
#                     raw client.request is used (client.put would try to JSON-decode
#                     an empty body); the write is confirmed by the read-after, not a
#                     response body.
#   6. read-after   — GET again and report changed fields + a verified flag for the
#                     fields that ARE observable in the detail.


async def _put_no_content(
    client: UniFiClient,
    path: str,
    body: dict[str, Any],
    key: APIKeyConfig | None,
) -> None:
    """Issue a PUT whose success is a 204 No Content (no JSON body to decode).

    ``client.put`` decodes the response as JSON, which fails on the empty 204 body
    these Mobility writes return, so the raw request is used and the empty body is
    intentionally discarded. Any non-2xx is already raised by ``client.request``.
    """
    await client.request("PUT", path, key=key, json=body)


async def update_mobility_device_name(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    name: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Rename a UMR device (PUT .../devices/{deviceID}). Guarded write.

    Sends the full documented body ``{"name": name}`` (1-32 characters). Does a
    read-before, returns status="no_op" when the device already has this name,
    requires confirm=true (returning a current-vs-proposed preview otherwise),
    honours the write kill-switch, and re-reads the device to verify the rename.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    name: the new device name (1-32 characters).
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    validate_id(device_id, "device_id")
    _validate_len(name, "name", 1, 32)
    key = _select_key(client, key_label)

    before = await _fetch_device_detail(client, workspace_id, device_id, key)
    current = before.get("name")
    if current == name:
        return {
            "status": "no_op",
            "reason": f"Device name is already {name!r}; no write performed.",
            "device": before,
        }
    if not confirm:
        return {
            "status": "unconfirmed",
            "reason": "Set confirm=true to apply this device rename.",
            "current_name": current,
            "proposed_name": name,
        }
    if not _writes_enabled():
        return {"status": "disabled", "reason": _DISABLED_MSG}

    path = _device_path(workspace_id, device_id)
    await _put_no_content(client, path, {"name": name}, key)
    after = await _fetch_device_detail(client, workspace_id, device_id, key)
    return {
        "status": "updated",
        "changed": {"name": {"from": current, "to": name}},
        "verified": after.get("name") == name,
        "device": after,
    }


async def update_mobility_device_network(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    *,
    host_address: str | None = None,
    dhcp_mode: str | None = None,
    dhcp_range_start: str | None = None,
    dhcp_range_stop: str | None = None,
    dhcp_lease_time: int | None = None,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Update a UMR device's LAN / DHCP settings (PUT .../devices/{deviceID}/network).

    This endpoint is a DOCUMENTED partial update: only the fields you provide are
    applied (WAN, IPv6 and InternetSource are not configurable here). At least one
    field must be provided. WARNING: the official docs CONFLICT on whether Mobility
    PUTs are full-replacement or partial-merge; if PUT is actually full-replacement a
    write here could silently wipe unsupplied LAN/DHCP fields. Writes are therefore
    gated OFF by default until the semantics are verified live (issue #186).
    ``dhcp_mode`` is ``"dhcp"`` (enabled) or ``"none"``
    (disabled); IP fields must be IPv4; ``dhcp_lease_time`` is seconds (0 =
    infinite). Guarded: read-before, no-op detection for the observable
    ``host_address`` (the DHCP fields are not reflected in device detail and so
    cannot be locally verified), confirm=true, write kill-switch, read-after.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    host_address: optional new LAN gateway IPv4.
    dhcp_mode: optional 'dhcp' or 'none'.
    dhcp_range_start: optional DHCP pool start IPv4.
    dhcp_range_stop: optional DHCP pool end IPv4.
    dhcp_lease_time: optional DHCP lease seconds (>=0; 0 = infinite).
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    validate_id(device_id, "device_id")
    key = _select_key(client, key_label)

    body: dict[str, Any] = {}
    if host_address is not None:
        _validate_ipv4(host_address, "host_address")
        body["host_address"] = host_address
    if dhcp_mode is not None:
        if dhcp_mode not in ("dhcp", "none"):
            raise ValueError(f"Invalid dhcp_mode {dhcp_mode!r}: expected 'dhcp' or 'none'")
        body["dhcp_mode"] = dhcp_mode
    if dhcp_range_start is not None:
        _validate_ipv4(dhcp_range_start, "dhcp_range_start")
        body["dhcp_range_start"] = dhcp_range_start
    if dhcp_range_stop is not None:
        _validate_ipv4(dhcp_range_stop, "dhcp_range_stop")
        body["dhcp_range_stop"] = dhcp_range_stop
    if dhcp_lease_time is not None:
        if not isinstance(dhcp_lease_time, int) or isinstance(dhcp_lease_time, bool):
            raise ValueError("dhcp_lease_time must be an integer")
        if dhcp_lease_time < 0:
            raise ValueError(f"dhcp_lease_time must be >= 0 (got {dhcp_lease_time})")
        body["dhcp_lease_time"] = dhcp_lease_time

    if not body:
        raise ValueError(
            "No fields provided: supply at least one of host_address, dhcp_mode, "
            "dhcp_range_start, dhcp_range_stop, dhcp_lease_time"
        )

    before = await _fetch_device_detail(client, workspace_id, device_id, key)
    # Only host_address is observable in the device detail; the DHCP pool/lease are
    # not, so a no-op can only be asserted when host_address is the sole change.
    only_host = set(body) == {"host_address"}
    if only_host and before.get("host_address") == body["host_address"]:
        return {
            "status": "no_op",
            "reason": (
                f"host_address is already {body['host_address']!r} and it is the only "
                "provided field; no write performed."
            ),
            "device": before,
        }
    if not confirm:
        return {
            "status": "unconfirmed",
            "reason": "Set confirm=true to apply this LAN/DHCP update.",
            "proposed": body,
            "current_host_address": before.get("host_address"),
        }
    if not _writes_enabled():
        return {"status": "disabled", "reason": _DISABLED_MSG}

    path = f"{_device_path(workspace_id, device_id)}/network"
    await _put_no_content(client, path, body, key)
    after = await _fetch_device_detail(client, workspace_id, device_id, key)
    result: dict[str, Any] = {
        "status": "updated",
        "changed": body,
        "device": after,
        "note": (
            "Partial update applied. Only host_address is reflected in device detail; "
            "dhcp_mode / dhcp_range_* / dhcp_lease_time are not surfaced there and are "
            "not locally verifiable."
        ),
    }
    if "host_address" in body:
        result["verified"] = {"host_address": after.get("host_address") == body["host_address"]}
    return result


async def update_mobility_device_wireless(
    client: UniFiClient,
    workspace_id: str,
    device_id: str,
    ssid: str,
    password: str,
    *,
    confirm: bool = False,
    key_label: str | None = None,
) -> dict[str, Any]:
    """Update a UMR device's WiFi SSID + password (PUT .../devices/{deviceID}/wireless).

    Both fields are required by the API (channel, TX power and security protocol
    are not configurable here). ``ssid`` is 1-32 characters; ``password`` is a
    WPA2-PSK secret of 8-63 characters. Guarded: read-before, confirm=true, write
    kill-switch, read-after. NOTE: there is no no-op short-circuit — the password
    is not observable in device detail, so the server can never prove the wireless
    config is unchanged. The supplied password is NOT echoed back in the result.

    workspace_id: the workspace UUID from list_mobility_workspaces.
    device_id: the device UUID from list_mobility_devices.
    ssid: the new WiFi SSID (1-32 characters).
    password: the new WPA2-PSK password (8-63 characters).
    confirm: must be true to apply the change.
    key_label: optional configured API-key label to route on a specific key.
    """
    validate_id(workspace_id, "workspace_id")
    validate_id(device_id, "device_id")
    _validate_len(ssid, "ssid", 1, 32)
    _validate_len(password, "password", 8, 63)
    key = _select_key(client, key_label)

    before = await _fetch_device_detail(client, workspace_id, device_id, key)
    if not confirm:
        return {
            "status": "unconfirmed",
            "reason": "Set confirm=true to apply this wireless update.",
            "current_ssid": before.get("wifi_ssid"),
            "proposed_ssid": ssid,
        }
    if not _writes_enabled():
        return {"status": "disabled", "reason": _DISABLED_MSG}

    path = f"{_device_path(workspace_id, device_id)}/wireless"
    await _put_no_content(client, path, {"ssid": ssid, "password": password}, key)
    after = await _fetch_device_detail(client, workspace_id, device_id, key)
    return {
        "status": "updated",
        # Password intentionally not echoed (caller-supplied secret; keep it out of
        # the result payload and any downstream log).
        "changed": {"ssid": {"from": before.get("wifi_ssid"), "to": ssid}, "password": "updated"},
        "verified": {"ssid": after.get("wifi_ssid") == ssid},
        "device": after,
    }
