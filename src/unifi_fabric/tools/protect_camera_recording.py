"""UniFi Protect camera controls, camera WiFi and on-camera (edge) recording storage.

Route choice (official published API first, else the private API the web app calls). The
official Protect Integration API pinned in ``tests/fixtures/spec_drift/baseline_snapshot.json``
(protect 7.3.70) has no route for any capability in this module: its camera surface is
``GET/PATCH /v1/cameras/{id}`` (name, OSD, LED, LCD message, mic volume, video mode, HDR,
smart detection), snapshots, RTSPS streams, talkback, PTZ and the permanent mic disable.
Every tool here therefore uses the private ``/proxy/protect/api`` route the Protect web
app calls, as inventoried in ``tests/fixtures/private_api/inventory_protect_5.3.18.json``
(UI bundle 5.3.18, ``swai.js``). There is no older generation of these routes.

Every response body is passed through verbatim (server pass-through invariant). A body
that is not JSON or text (an image or a recording file) is returned base64-encoded with
the upstream Content-Type, never decoded.

Validation before any request uses only the server's registered refusals (path-safe ids,
integer epoch seconds, the empty-body guard, the Protect write opt-out and read-only
mode, and the declared argument types and closed choices); every other value is the
upstream's to judge. Where the inventory records no body keys for a route, the tool takes
a free-form body object and sends it as given.

``cameras/{id}/enable-control`` and ``disable-control`` change state on a GET. The tool
that sends them is a write by behaviour: it is registered with
:func:`unifi_fabric._read_only_audit.state_changing_get`, refused under read-only mode
and the Protect write opt-out, previewed under dry-run and never retried automatically.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any, Literal

from fastmcp import FastMCP
from pydantic import StrictBool, TypeAdapter

from .._read_only_audit import state_changing_get
from ..client import (
    UniFiClient,
    UniFiConnectionError,
    decode_body,
    is_dry_run_preview,
    path_segment,
    validate_selector,
)
from ..config import APIKeyConfig
from ..read_only import guard_action
from ..registry import Registry
from ..tool_annotations import READ_ONLY, WRITE
from ._history_common import epoch_warnings, require_epoch_seconds, seconds_to_millis
from ._keys import with_context
from ._payload import upstream_hint, with_upstream_hint
from ._results import deletion_result
from .protect import _fields_to_send, _private, _require_mutations, _resolve

AnalyticsKind = Literal["detections", "heatmap"]
EdgeExportAction = Literal["prepare", "download"]

#: The analytics route of each kind (``/cameras/{id}/<suffix>``).
_ANALYTICS_SUFFIX: dict[str, str] = {
    "detections": "analytics-detections",
    "heatmap": "analytics-heatmap",
}

_ANALYTICS_KIND = TypeAdapter(AnalyticsKind)
_EDGE_EXPORT_ACTION = TypeAdapter(EdgeExportAction)
_STRICT_BOOL = TypeAdapter(StrictBool)

_TEXT_TYPES = ("json", "text/")


async def _get_body(
    client: UniFiClient,
    path: str,
    *,
    key: APIKeyConfig | None,
    params: dict[str, Any] | None = None,
) -> Any:
    """GET ``path`` and return its body: JSON or text verbatim, anything else as base64.

    A JSON or text body (by Content-Type, or JSON by content when no type is sent) is
    decoded by the server's one pass-through rule. An image or file body is returned as
    ``{content_base64, content_type, size_bytes}`` with the upstream Content-Type as sent.
    """
    resp = await client.request("GET", path, key=key, params=params or None)
    content_type = resp.headers.get("content-type")
    lowered = (content_type or "").lower()
    if resp.status_code == 204 or not resp.content or any(t in lowered for t in _TEXT_TYPES):
        return decode_body(resp)
    if content_type is None:
        try:
            return resp.json()
        except ValueError:
            pass
    return {
        "content_base64": base64.b64encode(resp.content).decode(),
        "content_type": content_type,
        "size_bytes": len(resp.content),
    }


def _given(**params: Any) -> dict[str, Any]:
    """Only the query parameters the caller actually gave (no invented defaults)."""
    return {name: value for name, value in params.items() if value is not None}


def _epoch_ms(value: int, name: str) -> int:
    """A required epoch-seconds argument as epoch milliseconds (type-checked first)."""
    return seconds_to_millis(require_epoch_seconds(value, name))


def _with_epoch_unit(body: Any, **values: int | None) -> Any:
    """``body`` plus the shared ``_warnings`` epoch entries of the epoch arguments given.

    The entries are :func:`epoch_warnings`: one per argument that is negative or looks like
    epoch milliseconds. A plausible epoch-seconds value adds none, so the body is returned as
    is. With entries, an object body keeps every upstream key; any other body (an array) is
    returned under ``result`` so the entries have a place.
    """
    warnings = epoch_warnings(**values)
    if not warnings:
        return body
    if isinstance(body, dict):
        return with_context(body, {"_warnings": warnings})
    return {"result": body, "_warnings": warnings}


def _action_result(status: str, response: Any) -> dict[str, Any]:
    """A write's result: ``{status, response}`` with the upstream body verbatim.

    Under ``UNIFI_DRY_RUN`` nothing was sent and ``response`` is the client's preview;
    the preview itself is returned (``{status: "dry_run", dryRun, sent: false, message, preview}``).
    """
    if is_dry_run_preview(response):
        return dict(response)
    return {"status": status, "response": response}


def _camera_path(host_id: str, camera_seg: str, suffix: str) -> str:
    return _private(host_id, f"/cameras/{camera_seg}/{suffix}")


def _edge_path(host_id: str, camera_seg: str, suffix: str) -> str:
    return _private(host_id, f"/edge-recording/{camera_seg}/{suffix}")


def _write_guards(method: str) -> None:
    """The Protect write opt-out and read-only mode, before any request."""
    _require_mutations()
    guard_action(method)


async def _post_action(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_seg: str,
    suffix: str,
    status: str,
    *,
    edge: bool = False,
    json: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """POST one camera (or edge-storage) action, sent once (never auto-retried)."""
    key, host_id = await _resolve(registry, host)
    path = (_edge_path if edge else _camera_path)(host_id, camera_seg, suffix)
    response = await client.post(path, key=key, json=json, params=params)
    return _action_result(status, response)


# --- Camera reads -----------------------------------------------------------------------


_QR_REMOVED_HINT = (
    "this console's Protect version serves no camera adoption QR route (Protect 7.3 removed "
    "it and reads cameras/qr as a camera id); add a WiFi camera with the UniFi Protect "
    "mobile app, then adopt it with adopt_protect_device."
)


async def get_camera_adoption_qr(
    client: UniFiClient,
    registry: Registry,
    host: str,
    ssid: str | None = None,
    wifi_password: str | None = None,
) -> Any:
    """GET the camera adoption QR code (``/cameras/qr``), with the WiFi to join.

    Protect 7.3 serves no QR route (neither its server nor its web app has one), so it
    reads ``cameras/qr`` as camera id ``qr`` and answers 404; that error gets a hint.
    """
    key, host_id = await _resolve(registry, host)
    params = _given(ssid=ssid, password=wifi_password)
    try:
        return await _get_body(client, _private(host_id, "/cameras/qr"), key=key, params=params)
    except UniFiConnectionError as exc:
        if exc.status != 404 or '"id":"qr"' not in str(exc).replace(" ", ""):
            raise
        upstream_hint(exc, _QR_REMOVED_HINT)
        raise


async def get_camera_analytics(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    kind: str,
    start: int,
    end: int,
    step: int | None = None,
    heatmap_type: str | None = None,
) -> Any:
    """GET a camera's detection counts or analytics heatmap over a window."""
    kind = _ANALYTICS_KIND.validate_python(kind)
    camera_seg = path_segment(camera_id, "camera_id")
    params = _given(
        start=_epoch_ms(start, "start"),
        end=_epoch_ms(end, "end"),
        step=step,
        type=heatmap_type,
    )
    key, host_id = await _resolve(registry, host)
    path = _camera_path(host_id, camera_seg, _ANALYTICS_SUFFIX[kind])
    body = await _get_body(client, path, key=key, params=params)
    return _with_epoch_unit(body, start=start, end=end)


async def get_camera_lux(client: UniFiClient, registry: Registry, host: str, camera_id: str) -> Any:
    """GET a camera's current light level reading (``/cameras/{id}/lux``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    key, host_id = await _resolve(registry, host)
    return await client.get(_camera_path(host_id, camera_seg, "lux"), key=key)


async def get_camera_playback_history(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    start: int,
    end: int,
    resolution: int | None = None,
) -> Any:
    """GET a camera's recording (playback) history over a window."""
    camera_seg = path_segment(camera_id, "camera_id")
    params = _given(
        start=_epoch_ms(start, "start"), end=_epoch_ms(end, "end"), resolution=resolution
    )
    key, host_id = await _resolve(registry, host)
    body = await client.get(
        _camera_path(host_id, camera_seg, "playback-history"), key=key, params=params
    )
    return _with_epoch_unit(body, start=start, end=end)


async def get_camera_wifi_networks(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> Any:
    """GET the WiFi networks a camera can see (``/cameras/{id}/wifi-list``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    key, host_id = await _resolve(registry, host)
    return await with_upstream_hint(
        client.get(_camera_path(host_id, camera_seg, "wifi-list"), key=key),
        "Camera WiFi scan failed; check camera support and connectivity.",
    )


# --- Camera writes and actions ----------------------------------------------------------


@state_changing_get
async def _send_control_get(
    client: UniFiClient, key: APIKeyConfig | None, path: str
) -> dict[str, Any]:
    """Send the state-changing control GET (or return the client's dry-run preview).

    The route is on the write classifier's state-changing GET list
    (``read_only.STATE_CHANGING_GET_ROUTES``), so the client chokepoint treats this GET as
    a write: refused in read-only mode, previewed under ``UNIFI_DRY_RUN`` and audited. It
    is sent once (``max_retries=0``: a retried GET could repeat the state change).
    """
    response = decode_body(await client.request("GET", path, key=key, max_retries=0))
    return _action_result("sent", response)


async def set_camera_control_enabled(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, enabled: bool
) -> dict[str, Any]:
    """Enable or disable a camera's control (``GET /cameras/{id}/enable-|disable-control``)."""
    enabled = _STRICT_BOOL.validate_python(enabled)
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("GET")
    key, host_id = await _resolve(registry, host)
    suffix = "enable-control" if enabled else "disable-control"
    result = await _send_control_get(client, key, _camera_path(host_id, camera_seg, suffix))
    if result.get("status") == "sent":
        result["status"] = "enabled" if enabled else "disabled"
    return result


async def set_camera_door_lock(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, locked: bool
) -> dict[str, Any]:
    """Lock or unlock the door lock wired to a camera (``POST /cameras/{id}/lock|unlock``)."""
    locked = _STRICT_BOOL.validate_python(locked)
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    action = "lock" if locked else "unlock"
    return await _post_action(
        client, registry, host, camera_seg, action, "locked" if locked else "unlocked"
    )


async def reset_camera_image_settings(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    """Reset a camera's image (ISP) settings (``POST /cameras/{id}/reset-isp``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    return await _post_action(client, registry, host, camera_seg, "reset-isp", "reset")


async def set_camera_resolution_scale(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, scale: str
) -> dict[str, Any]:
    """Set a camera's resolution scale (``POST /cameras/{id}/resolutionScale/{scale}``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    scale_seg = path_segment(scale, "scale")
    _write_guards("POST")
    return await _post_action(
        client, registry, host, camera_seg, f"resolutionScale/{scale_seg}", "sent"
    )


async def transfer_camera_management(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, nvr_mac: str
) -> dict[str, Any]:
    """Transfer a camera to another NVR (``POST /cameras/{id}/transfer-mgmt {nvrMac}``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    validate_selector(nvr_mac, "nvr_mac")
    _write_guards("POST")
    return await _post_action(
        client, registry, host, camera_seg, "transfer-mgmt", "sent", json={"nvrMac": nvr_mac}
    )


async def turn_on_camera_flashlight(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    """Turn on a camera's flashlight (``POST /cameras/{id}/turnon-flashlight``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    return await _post_action(client, registry, host, camera_seg, "turnon-flashlight", "sent")


async def configure_camera_wifi(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, settings: dict[str, Any]
) -> dict[str, Any]:
    """Send a camera's WiFi setup (``POST /cameras/{id}/wifi-setup``, free-form body)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    body = _fields_to_send(dict(settings), "camera wifi-setup")
    return await _post_action(client, registry, host, camera_seg, "wifi-setup", "sent", json=body)


async def set_camera_video_codec(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, codec: str
) -> dict[str, Any]:
    """Set a camera's video codec (``POST /cameras/{id}/videoCodec?name=CODEC``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    return await _post_action(
        client, registry, host, camera_seg, "videoCodec", "sent", params={"name": codec}
    )


# --- Edge (on-camera) recording storage -------------------------------------------------


async def export_edge_recording(
    client: UniFiClient,
    registry: Registry,
    host: str,
    camera_id: str,
    action: str,
    filename: str | None = None,
    start: int | None = None,
    end: int | None = None,
) -> Any:
    """Prepare, or download, a recording export from a camera's own (edge) storage.

    Protect 7.3 requires ``filename``, ``start`` and ``end`` (epoch ms) for prepare: the
    console stores the export under that file name, and download fetches it by name. Only
    the arguments given are sent; the console reports a missing one.
    """
    action = _EDGE_EXPORT_ACTION.validate_python(action)
    if action == "download" and (start is not None or end is not None):
        raise ValueError(
            "start and end only apply to action 'prepare', not action 'download'; they would "
            "be silently dropped. Nothing was sent."
        )
    params = _given(
        filename=filename,
        start=None if start is None else _epoch_ms(start, "start"),
        end=None if end is None else _epoch_ms(end, "end"),
    )
    camera_seg = path_segment(camera_id, "camera_id")
    key, host_id = await _resolve(registry, host)
    missing = action == "prepare" and any(x is None for x in (filename, start, end))
    try:
        body = await with_upstream_hint(
            _get_body(
                client, _edge_path(host_id, camera_seg, action), key=key, params=params or None
            ),
            "Prepare requires filename, start and end; times are epoch seconds."
            if missing
            else None,
        )
    except UniFiConnectionError as exc:
        if missing or exc.status != 500:
            raise
        upstream_hint(
            exc,
            "The console could not prepare this export; check that the camera has edge "
            "(SD card) storage with recordings between start and end.",
        )
        raise
    return _with_epoch_unit(body, start=start, end=end)


async def set_edge_storage_mount_state(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, mount_state: str
) -> dict[str, Any]:
    """Mount or unmount a camera's storage (``POST /edge-recording/{id}/mount-state``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    return await _post_action(
        client,
        registry,
        host,
        camera_seg,
        "mount-state",
        "sent",
        edge=True,
        json={"mountState": mount_state},
    )


async def reformat_edge_storage(
    client: UniFiClient, registry: Registry, host: str, camera_id: str
) -> dict[str, Any]:
    """Reformat a camera's own storage (``POST /edge-recording/{id}/reformat``)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("POST")
    return await _post_action(client, registry, host, camera_seg, "reformat", "sent", edge=True)


async def update_edge_recording_settings(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, settings: dict[str, Any]
) -> dict[str, Any]:
    """PATCH a camera's edge recording settings (free-form body, sent as given)."""
    camera_seg = path_segment(camera_id, "camera_id")
    _write_guards("PATCH")
    body = _fields_to_send(dict(settings), "edge recording")
    key, host_id = await _resolve(registry, host)
    path = _edge_path(host_id, camera_seg, "recording-settings")
    response = await client.patch(path, key=key, json=body)
    if is_dry_run_preview(response):
        return dict(response)
    # The Protect update shape. No route reads these settings, so nothing is read before
    # or after the PATCH and the change cannot be verified (verified is null, not false).
    return {
        "status": "updated",
        "verified": None,
        "before": None,
        "after": None,
        "response": response,
    }


async def delete_recordings(
    client: UniFiClient, registry: Registry, host: str, camera_id: str, start: int, end: int
) -> dict[str, Any]:
    """Delete a camera's recordings in a window (``DELETE /video?camera&start&end``).

    The result (or the dry-run result) carries a ``_warnings`` entry for each of start and
    end that is negative or looks like epoch milliseconds.
    """
    path_segment(camera_id, "camera_id")
    params = {"camera": camera_id, "start": _epoch_ms(start, "start"), "end": _epoch_ms(end, "end")}
    _write_guards("DELETE")
    key, host_id = await _resolve(registry, host)
    response = await client.delete(_private(host_id, "/video"), key=key, params=params)
    if is_dry_run_preview(response):
        return _with_epoch_unit(
            deletion_result(f"Recordings of camera {camera_id} deleted.", response),
            start=start,
            end=end,
        )
    return _with_epoch_unit(
        deletion_result(f"Recordings of camera {camera_id} deleted.", response),
        start=start,
        end=end,
    )


# Module-level aliases: the registered tools below shadow these names inside register().
_get_camera_adoption_qr = get_camera_adoption_qr
_get_camera_analytics = get_camera_analytics
_set_camera_control_enabled = set_camera_control_enabled
_set_camera_door_lock = set_camera_door_lock
_get_camera_lux = get_camera_lux
_get_camera_playback_history = get_camera_playback_history
_reset_camera_image_settings = reset_camera_image_settings
_set_camera_resolution_scale = set_camera_resolution_scale
_transfer_camera_management = transfer_camera_management
_turn_on_camera_flashlight = turn_on_camera_flashlight
_get_camera_wifi_networks = get_camera_wifi_networks
_configure_camera_wifi = configure_camera_wifi
_set_camera_video_codec = set_camera_video_codec
_export_edge_recording = export_edge_recording
_set_edge_storage_mount_state = set_edge_storage_mount_state
_reformat_edge_storage = reformat_edge_storage
_update_edge_recording_settings = update_edge_recording_settings
_delete_recordings = delete_recordings


def register(mcp: FastMCP, deps_fn: Callable[..., Any]) -> None:
    """Register this module's tools on ``mcp`` (called once by the server)."""

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_adoption_qr(
        host: str, ssid: str | None = None, wifi_password: str | None = None
    ) -> Any:
        """Get the QR code a new Protect camera scans to join WiFi and adopt to this console.

        Sends GET /cameras/qr with ssid and password (wifi_password) only when given.
        Protect 7.3 and later serve no QR route and answer 404 (camera "qr" not found);
        that error keeps the upstream text and adds a hint (use the UniFi Protect app).
        Returns the upstream body verbatim: JSON as sent (an upstream array under result),
        or an image as {content_base64, content_type, size_bytes} with the upstream
        Content-Type. wifi_password is a
        registered credential: errors and logs never carry it.

        Required arguments: host (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            ssid: WiFi network name the camera should join, sent as ssid; for example
                "Cameras-IoT".
            wifi_password: WiFi password for that network, sent as password; for example
                "correct-horse-battery".
        """
        client, registry = deps_fn()
        return await _get_camera_adoption_qr(
            client, registry, host, ssid=ssid, wifi_password=wifi_password
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_analytics(
        host: str,
        camera_id: str,
        kind: AnalyticsKind,
        start: int,
        end: int,
        step: int | None = None,
        heatmap_type: str | None = None,
    ) -> Any:
        """Get a Protect camera's analytics over a time window.

        Kind "detections" reads GET /cameras/{camera_id}/analytics-detections (detection
        counts, bucketed by step); kind "heatmap" reads analytics-heatmap (heatmap_type
        sent as type). start and end are epoch SECONDS, sent as epoch milliseconds.
        Returns the upstream body verbatim, and an image as {content_base64,
        content_type, size_bytes}. _warnings is added (one entry per such time
        argument) only when start or end is negative or looks like epoch milliseconds;
        an array body then is returned under result.

        Required arguments: host, camera_id, kind, start, end (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            kind: "detections" or "heatmap"; for example "detections".
            start: Window start, epoch SECONDS; for example 1760227200.
            end: Window end, epoch SECONDS; for example 1760313600.
            step: Bucket size for detections, sent as step; for example 3600000.
            heatmap_type: Heatmap object type, sent as type; for example "person".
        """
        client, registry = deps_fn()
        return await _get_camera_analytics(
            client,
            registry,
            host,
            camera_id,
            kind,
            start,
            end,
            step=step,
            heatmap_type=heatmap_type,
        )

    @mcp.tool(annotations=WRITE)
    async def set_camera_control_enabled(
        host: str, camera_id: str, enabled: bool, confirm: bool = False
    ) -> dict[str, Any]:
        """Enable or disable control of a Protect camera.

        Sends GET /cameras/{camera_id}/enable-control (enabled=true) or disable-control
        (false). The console changes state on this GET, so it is a write: refused under
        read-only mode and the Protect write opt-out, and sent once (never retried).
        Returns {status: "enabled" | "disabled", response} (response is the upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: changes whether the camera can be controlled until it is set back.

        Required arguments: host, camera_id, enabled (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            enabled: true sends enable-control, false sends disable-control; for example
                false.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _set_camera_control_enabled(client, registry, host, camera_id, enabled)

    @mcp.tool(annotations=WRITE)
    async def set_camera_door_lock(
        host: str, camera_id: str, locked: bool, confirm: bool = False
    ) -> dict[str, Any]:
        """Lock or unlock the door lock connected to a Protect camera (a doorbell or access
        reader with a lock).

        Sends POST /cameras/{camera_id}/lock (locked=true) or /unlock (false), once.
        Returns {status: "locked" | "unlocked", response} (response is the upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: physically locks or unlocks the door; unlocking lets anyone in.

        Required arguments: host, camera_id, locked (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            locked: true locks, false unlocks; for example true.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _set_camera_door_lock(client, registry, host, camera_id, locked)

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_lux(host: str, camera_id: str) -> Any:
        """Get a Protect camera's current light level (lux) reading.

        Sends GET /cameras/{camera_id}/lux. Returns the upstream body verbatim (an
        upstream array is returned under result).

        Required arguments: host, camera_id (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
        """
        client, registry = deps_fn()
        return await _get_camera_lux(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_playback_history(
        host: str, camera_id: str, start: int, end: int, resolution: int | None = None
    ) -> Any:
        """Get a Protect camera's recording (playback) history over a time window.

        Sends GET /cameras/{camera_id}/playback-history with start and end (epoch
        SECONDS, sent as epoch milliseconds) and resolution only when given. Returns the
        upstream body verbatim. _warnings is added (one entry per such time argument)
        only when start or end is negative or looks like epoch milliseconds; an array
        body then is returned under result.

        Required arguments: host, camera_id, start, end (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            start: Window start, epoch SECONDS; for example 1760227200.
            end: Window end, epoch SECONDS; for example 1760313600.
            resolution: Timeline resolution, sent as resolution; for example 3600000.
        """
        client, registry = deps_fn()
        return await _get_camera_playback_history(
            client, registry, host, camera_id, start, end, resolution=resolution
        )

    @mcp.tool(annotations=WRITE)
    async def reset_camera_image_settings(
        host: str, camera_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Reset a Protect camera's image (ISP) settings to their defaults.

        Sends POST /cameras/{camera_id}/reset-isp, once. Returns {status: "reset",
        response} (response is the upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: discards the camera's tuned image settings; they are not restored.

        Required arguments: host, camera_id (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _reset_camera_image_settings(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def set_camera_resolution_scale(
        host: str, camera_id: str, scale: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Set a Protect camera's resolution scale.

        Sends POST /cameras/{camera_id}/resolutionScale/{scale}, once; the console judges
        the value. Returns {status: "sent", response} (response is the upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: changes the resolution the camera streams and records at.

        Required arguments: host, camera_id, scale (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            scale: Scale value sent as one path segment; for example "1".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _set_camera_resolution_scale(client, registry, host, camera_id, scale)

    @mcp.tool(annotations=WRITE)
    async def transfer_camera_management(
        host: str, camera_id: str, nvr_mac: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Transfer management of a Protect camera to another NVR.

        Sends POST /cameras/{camera_id}/transfer-mgmt with {nvrMac}, once (never retried).
        Returns {status: "sent", response} (response is the upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: irreversible from this console: the camera leaves it for the other
        NVR and is managed (and recorded) there; only that NVR can transfer it back.

        Required arguments: host, camera_id, nvr_mac (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            nvr_mac: MAC address of the NVR to take over the camera, sent as nvrMac; for
                example "02:00:5e:00:53:01".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _transfer_camera_management(client, registry, host, camera_id, nvr_mac)

    @mcp.tool(annotations=WRITE)
    async def turn_on_camera_flashlight(
        host: str, camera_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Turn on a Protect camera's flashlight (its built-in light).

        Sends POST /cameras/{camera_id}/turnon-flashlight, once. Returns {status: "sent",
        response} (response is the upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: physically switches on the camera's light.

        Required arguments: host, camera_id (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _turn_on_camera_flashlight(client, registry, host, camera_id)

    @mcp.tool(annotations=READ_ONLY)
    async def get_camera_wifi_networks(host: str, camera_id: str) -> Any:
        """Get the WiFi networks a Protect camera can see (for a WiFi camera).

        Sends GET /cameras/{camera_id}/wifi-list. Returns the upstream body verbatim (an
        upstream array is returned under result).

        Required arguments: host, camera_id (see each parameter's description).

        A console HTTP 500 may require checking camera WiFi support and connectivity.

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
        """
        client, registry = deps_fn()
        return await _get_camera_wifi_networks(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def configure_camera_wifi(
        host: str, camera_id: str, settings: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Configure the WiFi network a Protect WiFi camera connects to.

        Sends settings as the body of POST /cameras/{camera_id}/wifi-setup, once. The body
        is free-form: its keys are not published, so it is sent exactly as given and the
        console judges it. An empty settings object fails before any request. Returns
        {status: "sent", response} (response is the upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: the camera rejoins WiFi with these settings; wrong ones take it
        offline until it is set up again on site.

        Required arguments: host, camera_id, settings (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            settings: Free-form wifi-setup body, sent as given (keys unpublished); for
                example {"ssid": "Cameras-IoT", "password": "correct-horse-battery"}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _configure_camera_wifi(client, registry, host, camera_id, settings)

    @mcp.tool(annotations=WRITE)
    async def set_camera_video_codec(
        host: str, camera_id: str, codec: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Set the video codec a Protect camera encodes with.

        Sends POST /cameras/{camera_id}/videoCodec?name=CODEC, once; the console judges
        the codec name. Returns {status: "sent", response} (response is the upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: changes the codec of the camera's streams and new recordings.

        Required arguments: host, camera_id, codec (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            codec: Codec name, sent as the name query parameter; for example "h265".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _set_camera_video_codec(client, registry, host, camera_id, codec)

    @mcp.tool(annotations=READ_ONLY)
    async def export_edge_recording(
        host: str,
        camera_id: str,
        action: EdgeExportAction,
        filename: str | None = None,
        start: int | None = None,
        end: int | None = None,
    ) -> Any:
        """Export a recording from a Protect camera's own (edge) storage, in two steps.

        Action "prepare" sends GET /edge-recording/{camera_id}/prepare with filename, start
        and end (the console requires all three; start and end are epoch SECONDS sent as
        ms); the console creates an export job, copies that window off the camera and answers
        {filename, expiresAfter}, without changing configuration. This read is allowed in
        read-only mode and executes under UNIFI_DRY_RUN. Action "download" sends GET
        /edge-recording/{camera_id}/download with the same filename. Only the arguments given
        are sent (start or end with download fails before any request). Returns the upstream
        body verbatim: JSON or text as sent (an upstream array under result), and a file as
        {content_base64, content_type, size_bytes} with the upstream Content-Type; start or end
        values that look like milliseconds or are negative add _warnings.

        Required arguments: host, camera_id, action (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Id of the camera whose storage holds the recording, from
                list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            action: "prepare" or "download"; for example "prepare".
            filename: Export file name, sent as filename: the name to store it under
                (prepare) and to fetch (download); for example "edge-export.mp4".
            start: Window start for prepare, epoch SECONDS (sent as ms); for example
                1760227200.
            end: Window end for prepare, epoch SECONDS (sent as ms); for example 1760227260.
        """
        client, registry = deps_fn()
        return await _export_edge_recording(
            client, registry, host, camera_id, action, filename=filename, start=start, end=end
        )

    @mcp.tool(annotations=WRITE)
    async def set_edge_storage_mount_state(
        host: str, camera_id: str, mount_state: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Mount or unmount a Protect camera's own (edge) recording storage.

        Sends POST /edge-recording/{camera_id}/mount-state with {mountState}, once; the
        console judges the value. Returns {status: "sent", response} (response is the
        upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: an unmounted card stops on-camera recording until it is mounted.

        Required arguments: host, camera_id, mount_state (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Id of the camera whose storage to mount or unmount, from
                list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            mount_state: Value sent as mountState; for example "unmounted".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _set_edge_storage_mount_state(client, registry, host, camera_id, mount_state)

    @mcp.tool(annotations=WRITE)
    async def reformat_edge_storage(
        host: str, camera_id: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Reformat a Protect camera's own (edge) recording storage.

        Sends POST /edge-recording/{camera_id}/reformat, once (never retried). Returns
        {status: "sent", response} (response is the upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: irreversible: erases every recording on the camera's own storage.

        Required arguments: host, camera_id (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Id of the camera whose storage to reformat, from list_cameras;
                for example "65d4f1e2a1b2c3d4e5f60718".
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _reformat_edge_storage(client, registry, host, camera_id)

    @mcp.tool(annotations=WRITE)
    async def update_edge_recording_settings(
        host: str, camera_id: str, settings: dict[str, Any], confirm: bool = False
    ) -> dict[str, Any]:
        """Update a Protect camera's edge (on-camera) recording settings.

        Sends settings as the body of PATCH /edge-recording/{camera_id}/recording-settings,
        once. The body is free-form: its keys are not published, so it is sent exactly
        as given and the console judges it. An empty settings object fails before any
        request. Returns {status: "updated", verified, before, after, response} (response
        is the upstream body verbatim). There is no read route for these settings, so
        nothing is read back: verified, before and after are always null.
        With UNIFI_DRY_RUN, returns a dry-run preview {status: "dry_run", dryRun, sent: false,
        message,
        preview: {method, path, params, body}} and sends nothing.

        Consequence: changes what and how the camera records to its own storage.

        Required arguments: host, camera_id, settings (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras; for example "65d4f1e2a1b2c3d4e5f60718".
            settings: Free-form recording-settings body, sent as given (keys
                unpublished); for example {"enabled": true}.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _update_edge_recording_settings(client, registry, host, camera_id, settings)

    @mcp.tool(annotations=WRITE)
    async def delete_recordings(
        host: str, camera_id: str, start: int, end: int, confirm: bool = False
    ) -> dict[str, Any]:
        """Delete a Protect camera's recordings in a time window.

        Sends DELETE /video?camera=CAMERA_ID&start&end, once (never retried); start and
        end are epoch SECONDS, sent as epoch milliseconds. Returns {deleted:
        true, message, response} (response is the upstream body verbatim).
        With UNIFI_DRY_RUN, returns a dry-run preview wrapped as {status: "dry_run",
        deleted: false, message, response} (response is the preview {status:
        "dry_run", dryRun, sent: false, message, preview: {method, path, params, body}}) and sends
        nothing. Either result also carries _warnings (one entry per such time argument) when
        start or end is negative or looks like epoch milliseconds.

        Consequence: irreversible: the camera's recordings in the window are erased
        from the NVR and cannot be recovered.

        Required arguments: host, camera_id, start, end (see each parameter's description).

        Args:
            host: Protect console name or composite id from list_hosts; for example "Home NVR".
            camera_id: Camera id from list_cameras, sent as camera; for example
                "65d4f1e2a1b2c3d4e5f60718".
            start: Window start, epoch SECONDS; for example 1760227200.
            end: Window end, epoch SECONDS; for example 1760230800.
            confirm: Accepted and ignored for compatibility; for example false.
        """
        client, registry = deps_fn()
        return await _delete_recordings(client, registry, host, camera_id, start, end)
